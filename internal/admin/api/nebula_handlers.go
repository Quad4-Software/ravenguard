// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/Quad4-Software/ravenguard/internal/admin/rbac"
	"github.com/Quad4-Software/ravenguard/internal/admin/store"
	"github.com/Quad4-Software/ravenguard/internal/config"
	"github.com/Quad4-Software/ravenguard/internal/nebulapki"
)

var nebulaNameRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$`)

func (s *Server) nebulaPaths() (certPath, keyPath string) {
	cfg := s.Runtime.Config()
	certPath = strings.TrimSpace(cfg.Nebula.CACertFile)
	keyPath = strings.TrimSpace(cfg.Nebula.CAKeyFile)
	if certPath == "" {
		certPath = filepath.Join(cfg.Admin.DataDir, "nebula", "ca.crt")
	}
	if keyPath == "" {
		keyPath = filepath.Join(cfg.Admin.DataDir, "nebula", "ca.key")
	}
	return certPath, keyPath
}

func (s *Server) loadNebulaCA() (*nebulapki.CA, error) {
	certPath, keyPath := s.nebulaPaths()
	return nebulapki.LoadCA(certPath, keyPath)
}

func (s *Server) handleNebula(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "method")
		return
	}
	actor := actorFrom(r)
	if !rbac.CanRead(actor.User.Role) {
		writeErr(w, http.StatusForbidden, "forbidden")
		return
	}
	cfg := s.Runtime.Config()
	out := map[string]any{
		"cidr":            cfg.Nebula.CIDR,
		"groups":          cfg.Nebula.Groups,
		"cert_ttl":        cfg.Nebula.CertTTL.Duration.String(),
		"cert_version":    cfg.Nebula.CertVersion,
		"static_host_map": cfg.Nebula.StaticHostMap,
		"lighthouse_ips":  cfg.Nebula.LighthouseIPs,
		"configured":      strings.TrimSpace(cfg.Nebula.CIDR) != "",
	}
	ca, err := s.loadNebulaCA()
	if err == nil && ca != nil {
		out["ca_present"] = true
		out["ca_name"] = ca.Name()
		out["ca_fingerprint"] = ca.Fingerprint()
		out["ca_not_after"] = ca.NotAfter()
		out["ca_pem"] = string(ca.CertPEM())
	}
	hosts, err := s.Store.ListNebulaHosts()
	if err == nil {
		active, revoked := 0, 0
		for _, h := range hosts {
			if h.Revoked {
				revoked++
			} else {
				active++
			}
		}
		out["hosts_active"] = active
		out["hosts_revoked"] = revoked
	}
	writeJSON(w, http.StatusOK, out)
}

// handleNebulaCA bootstraps the overlay CA. It refuses when CA material
// already exists on disk.
func (s *Server) handleNebulaCA(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method")
		return
	}
	actor := actorFrom(r)
	if !rbac.CanWriteOps(actor.User.Role) {
		writeErr(w, http.StatusForbidden, "forbidden")
		return
	}
	if !s.checkCSRF(w, r, actor) {
		return
	}
	var body struct {
		Name string `json:"name"`
		TTL  string `json:"ttl"`
	}
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&body)
	}
	name := strings.TrimSpace(body.Name)
	if name == "" {
		name = "ravenguard"
	}
	if !nebulaNameRe.MatchString(name) {
		writeErr(w, http.StatusBadRequest, "invalid ca name")
		return
	}
	ttl := 10 * 365 * 24 * time.Hour
	if body.TTL != "" {
		if d, err := time.ParseDuration(body.TTL); err == nil && d > 0 {
			ttl = d
		}
	}
	certPath, keyPath := s.nebulaPaths()
	if _, err := os.Stat(keyPath); err == nil {
		writeErr(w, http.StatusConflict, "ca already exists")
		return
	}
	certPEM, keyPEM, fp, err := nebulapki.GenerateCA(name, ttl)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := os.MkdirAll(filepath.Dir(certPath), 0o700); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := writeNewFile(certPath, certPEM, 0o644); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := writeNewFile(keyPath, keyPEM, 0o600); err != nil {
		_ = os.Remove(certPath)
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(actor, r, "nebula.ca.create", name, fp)
	writeJSON(w, http.StatusOK, map[string]any{
		"ca_pem":      string(certPEM),
		"fingerprint": fp,
		"ca_crt":      certPath,
		"ca_key":      keyPath,
	})
}

func writeNewFile(path string, data []byte, perm os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

func (s *Server) handleNebulaHosts(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		actor := actorFrom(r)
		if !rbac.CanRead(actor.User.Role) {
			writeErr(w, http.StatusForbidden, "forbidden")
			return
		}
		hosts, err := s.Store.ListNebulaHosts()
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		for i := range hosts {
			hosts[i].CertPEM = ""
		}
		writeJSON(w, http.StatusOK, map[string]any{"hosts": hosts})
	case http.MethodPost:
		s.issueNebulaHost(w, r)
	default:
		writeErr(w, http.StatusMethodNotAllowed, "method")
	}
}

func (s *Server) issueNebulaHost(w http.ResponseWriter, r *http.Request) {
	actor := actorFrom(r)
	if !rbac.CanWriteOps(actor.User.Role) {
		writeErr(w, http.StatusForbidden, "forbidden")
		return
	}
	if !s.checkCSRF(w, r, actor) {
		return
	}
	cfg := s.Runtime.Config()
	poolStr := strings.TrimSpace(cfg.Nebula.CIDR)
	if poolStr == "" {
		writeErr(w, http.StatusBadRequest, "nebula.cidr is not configured")
		return
	}
	pool, err := netip.ParsePrefix(poolStr)
	if err != nil || !pool.Addr().Is4() {
		writeErr(w, http.StatusBadRequest, "nebula.cidr must be an IPv4 prefix")
		return
	}
	var body struct {
		Name   string   `json:"name"`
		IP     string   `json:"ip"`
		Groups []string `json:"groups"`
		TTL    string   `json:"ttl"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	name := strings.TrimSpace(body.Name)
	if !nebulaNameRe.MatchString(name) {
		writeErr(w, http.StatusBadRequest, "invalid name")
		return
	}
	used, err := s.Store.NebulaUsedIPs()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	var network netip.Prefix
	if ipStr := strings.TrimSpace(body.IP); ipStr != "" {
		addr, aerr := netip.ParseAddr(ipStr)
		if aerr != nil || !addr.Is4() || !pool.Contains(addr) {
			writeErr(w, http.StatusBadRequest, "ip must be inside nebula.cidr")
			return
		}
		if _, taken := used[addr.String()]; taken {
			writeErr(w, http.StatusConflict, "ip already allocated")
			return
		}
		network = netip.PrefixFrom(addr, pool.Bits())
	} else {
		network, err = nebulapki.AllocateIP(pool, used)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	ca, err := s.loadNebulaCA()
	if err != nil {
		writeErr(w, http.StatusBadRequest, "nebula ca not available: create one first")
		return
	}
	ttl := cfg.Nebula.CertTTL.Duration
	if body.TTL != "" {
		if d, derr := time.ParseDuration(body.TTL); derr == nil && d > 0 {
			ttl = d
		}
	}
	groups := mergeGroups(cfg.Nebula.Groups, body.Groups)
	certPEM, keyPEM, fp, notAfter, err := ca.SignHost(name, network, groups, ttl, cfg.Nebula.CertVersion)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	host, err := s.Store.CreateNebulaHost(store.NebulaHost{
		Name:        name,
		IP:          network.Addr().String(),
		Fingerprint: fp,
		Groups:      groups,
		CertPEM:     string(certPEM),
		ExpiresAt:   notAfter,
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(actor, r, "nebula.host.issue", name, network.Addr().String())
	writeJSON(w, http.StatusOK, map[string]any{
		"id":          host.ID,
		"name":        name,
		"ip":          network.Addr().String(),
		"network":     network.String(),
		"fingerprint": fp,
		"groups":      groups,
		"cert_pem":    string(certPEM),
		"key_pem":     string(keyPEM),
		"ca_pem":      string(ca.CertPEM()),
		"expires_at":  notAfter,
		"config_yaml": nebulaHostConfigYAML(name, network.Addr().String(), cfg.Nebula),
	})
}

func (s *Server) handleNebulaHostID(w http.ResponseWriter, r *http.Request) {
	actor := actorFrom(r)
	if r.Method == http.MethodGet {
		if !rbac.CanRead(actor.User.Role) {
			writeErr(w, http.StatusForbidden, "forbidden")
			return
		}
	} else if !rbac.CanWriteOps(actor.User.Role) {
		writeErr(w, http.StatusForbidden, "forbidden")
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead && !s.checkCSRF(w, r, actor) {
		return
	}
	id := pathID(r, "hosts")
	if id == "" {
		writeErr(w, http.StatusBadRequest, "id required")
		return
	}
	switch r.Method {
	case http.MethodDelete:
		host, err := s.Store.GetNebulaHost(id)
		if err != nil {
			writeErr(w, http.StatusNotFound, "not found")
			return
		}
		if err := s.Store.RevokeNebulaHost(id); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		s.audit(actor, r, "nebula.host.revoke", host.Name, host.IP)
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	case http.MethodGet:
		host, err := s.Store.GetNebulaHost(id)
		if err != nil {
			writeErr(w, http.StatusNotFound, "not found")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"host": host, "cert_pem": host.CertPEM})
	default:
		writeErr(w, http.StatusMethodNotAllowed, "method")
	}
}

func (s *Server) handleNebulaBlocklist(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "method")
		return
	}
	actor := actorFrom(r)
	if !rbac.CanRead(actor.User.Role) {
		writeErr(w, http.StatusForbidden, "forbidden")
		return
	}
	fps, err := s.Store.NebulaBlocklist()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"fingerprints": fps})
}

func mergeGroups(base, extra []string) []string {
	seen := map[string]struct{}{}
	out := []string{}
	for _, g := range append(append([]string{}, base...), extra...) {
		g = strings.TrimSpace(g)
		if g == "" {
			continue
		}
		if _, ok := seen[g]; ok {
			continue
		}
		seen[g] = struct{}{}
		out = append(out, g)
	}
	return out
}

// nebulaHostConfigYAML renders a starter nebula config for a newly issued
// host. It is a hint, not a complete deployment file.
func nebulaHostConfigYAML(name, ip string, cfg config.NebulaConfig) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# nebula config for host %q (%s)\n", name, ip)
	b.WriteString("pki:\n  ca: /etc/nebula/ca.crt\n  cert: /etc/nebula/host.crt\n  key: /etc/nebula/host.key\n")
	b.WriteString("static_host_map:\n")
	if len(cfg.StaticHostMap) == 0 {
		b.WriteString("  # \"<lighthouse overlay ip>\": [\"<public ip or dns>:4242\"]\n")
	}
	for k, v := range cfg.StaticHostMap {
		fmt.Fprintf(&b, "  %s: [%s]\n", yamlQuote(k), yamlQuoteList(v))
	}
	b.WriteString("lighthouse:\n  am_lighthouse: false\n  interval: 60\n  hosts:\n")
	if len(cfg.LighthouseIPs) == 0 {
		b.WriteString("    # - \"<lighthouse overlay ip>\"\n")
	}
	for _, ip := range cfg.LighthouseIPs {
		fmt.Fprintf(&b, "    - %s\n", yamlQuote(ip))
	}
	b.WriteString("listen:\n  host: 0.0.0.0\n  port: 0\n")
	b.WriteString("punchy:\n  punch: true\n")
	b.WriteString("tun:\n  dev: nebula1\n")
	b.WriteString("firewall:\n  outbound:\n    - port: any\n      proto: any\n      host: any\n  inbound:\n    # tighten to the ports this host serves, per group\n    - port: any\n      proto: icmp\n      host: any\n")
	return b.String()
}

func yamlQuote(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}

func yamlQuoteList(list []string) string {
	out := make([]string, 0, len(list))
	for _, v := range list {
		out = append(out, yamlQuote(v))
	}
	return strings.Join(out, ", ")
}
