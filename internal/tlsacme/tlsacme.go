// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

// Package tlsacme wraps certmagic for automatic Let's Encrypt certificates.
package tlsacme

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/mholt/acmez/v3"
)

// Host certificate state values returned by Status.
const (
	StatePending   = "pending"
	StateActive    = "active"
	StateRenewing  = "renewing"
	StateFailed    = "failed"
	StateUnmanaged = "unmanaged"
)

// defaultLELifetime is used to map RenewWindow onto certmagic's RenewalWindowRatio.
const defaultLELifetime = 90 * 24 * time.Hour

// Config configures automatic ACME certificate management.
type Config struct {
	Email       string
	Staging     bool
	StorageDir  string
	Hosts       []string
	HTTP01      bool
	TLSALPN01   bool
	AgreeTOS    bool
	Directory   string
	RenewWindow time.Duration
}

// HostCertStatus reports certificate state for one hostname.
type HostCertStatus struct {
	Hostname          string    `json:"hostname"`
	State             string    `json:"state"`
	NotBefore         time.Time `json:"not_before,omitempty"`
	NotAfter          time.Time `json:"not_after,omitempty"`
	DaysLeft          int       `json:"days_left,omitempty"`
	Issuer            string    `json:"issuer,omitempty"`
	Subject           string    `json:"subject,omitempty"`
	Serial            string    `json:"serial,omitempty"`
	FingerprintSHA256 string    `json:"fingerprint_sha256,omitempty"`
	DNSNames          []string  `json:"dns_names,omitempty"`
	LastError         string    `json:"last_error,omitempty"`
	Managed           bool      `json:"managed"`
	Source            string    `json:"source"`
}

// Manager manages ACME certificates via certmagic.
type Manager struct {
	cfg    Config
	magic  *certmagic.Config
	cache  *certmagic.Cache
	issuer *certmagic.ACMEIssuer

	mu       sync.Mutex
	hosts    map[string]struct{}
	states   map[string]string
	issuers  map[string]string
	lastErrs map[string]string
}

// New creates a Manager from cfg.
func New(cfg Config) (*Manager, error) {
	if !cfg.AgreeTOS {
		return nil, errors.New("tlsacme: AgreeTOS must be true")
	}
	if cfg.Email == "" {
		return nil, errors.New("tlsacme: Email is required")
	}
	if cfg.StorageDir == "" {
		return nil, errors.New("tlsacme: StorageDir is required")
	}
	if err := os.MkdirAll(cfg.StorageDir, 0o700); err != nil {
		return nil, fmt.Errorf("tlsacme: create StorageDir: %w", err)
	}

	m := &Manager{
		cfg:      cfg,
		hosts:    make(map[string]struct{}),
		states:   make(map[string]string),
		issuers:  make(map[string]string),
		lastErrs: make(map[string]string),
	}

	var magic *certmagic.Config
	cache := certmagic.NewCache(certmagic.CacheOptions{
		GetConfigForCert: func(certmagic.Certificate) (*certmagic.Config, error) {
			return magic, nil
		},
	})

	cmCfg := certmagic.Config{
		Storage: &certmagic.FileStorage{Path: cfg.StorageDir},
		OnEvent: m.onEvent,
	}
	if cfg.RenewWindow > 0 {
		ratio := float64(cfg.RenewWindow) / float64(defaultLELifetime)
		if ratio > 1 {
			ratio = 1
		}
		if ratio < 0.01 {
			ratio = 0.01
		}
		cmCfg.RenewalWindowRatio = ratio
	}

	magic = certmagic.New(cache, cmCfg)

	ca := certmagic.LetsEncryptProductionCA
	if cfg.Staging {
		ca = certmagic.LetsEncryptStagingCA
	}
	if cfg.Directory != "" {
		ca = cfg.Directory
	}

	issuer := certmagic.NewACMEIssuer(magic, certmagic.ACMEIssuer{
		CA:                      ca,
		Email:                   cfg.Email,
		Agreed:                  cfg.AgreeTOS,
		DisableHTTPChallenge:    !cfg.HTTP01,
		DisableTLSALPNChallenge: !cfg.TLSALPN01,
	})
	magic.Issuers = []certmagic.Issuer{issuer}

	m.magic = magic
	m.cache = cache
	m.issuer = issuer

	for _, h := range cfg.Hosts {
		if h == "" {
			continue
		}
		m.hosts[h] = struct{}{}
		m.states[h] = StatePending
	}

	return m, nil
}

// TLSConfig returns a tls.Config that serves managed certificates.
func (m *Manager) TLSConfig() *tls.Config {
	next := []string{"h2", "http/1.1"}
	if m.cfg.TLSALPN01 {
		next = append(next, acmez.ACMETLS1Protocol)
	}
	return &tls.Config{
		MinVersion:     tls.VersionTLS12,
		GetCertificate: m.GetCertificate,
		NextProtos:     next,
	}
}

// GetCertificate exposes certmagic certificate selection for composite TLS configs.
func (m *Manager) GetCertificate(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if m == nil || m.magic == nil {
		return nil, nil
	}
	return m.magic.GetCertificate(chi)
}

// HTTPHandler returns an HTTP handler that solves ACME HTTP-01 challenges.
func (m *Manager) HTTPHandler() http.Handler {
	fallback := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})
	if m.issuer == nil || !m.cfg.HTTP01 {
		return fallback
	}
	return m.issuer.HTTPChallengeHandler(fallback)
}

// Manage obtains and keeps certificates for hosts.
func (m *Manager) Manage(ctx context.Context, hosts []string) error {
	cleaned := make([]string, 0, len(hosts))
	m.mu.Lock()
	for _, h := range hosts {
		if h == "" {
			continue
		}
		cleaned = append(cleaned, h)
		m.hosts[h] = struct{}{}
		if m.states[h] == "" || m.states[h] == StateUnmanaged {
			m.states[h] = StatePending
		}
	}
	m.mu.Unlock()

	if len(cleaned) == 0 {
		return nil
	}

	err := m.magic.ManageSync(ctx, cleaned)
	if err != nil {
		m.mu.Lock()
		for _, h := range cleaned {
			m.lastErrs[h] = err.Error()
			m.states[h] = StateFailed
		}
		m.mu.Unlock()
		return err
	}

	m.mu.Lock()
	for _, h := range cleaned {
		delete(m.lastErrs, h)
		m.states[h] = StateActive
	}
	m.mu.Unlock()
	return nil
}

// Unmanage stops tracking hosts for automatic management.
func (m *Manager) Unmanage(hosts []string) {
	sis := make([]certmagic.SubjectIssuer, 0, len(hosts))
	m.mu.Lock()
	for _, h := range hosts {
		if h == "" {
			continue
		}
		delete(m.hosts, h)
		delete(m.lastErrs, h)
		delete(m.issuers, h)
		m.states[h] = StateUnmanaged
		sis = append(sis, certmagic.SubjectIssuer{Subject: h})
	}
	m.mu.Unlock()
	if m.cache != nil && len(sis) > 0 {
		m.cache.RemoveManaged(sis)
	}
}

// Status returns certificate status for managed hosts.
func (m *Manager) Status() []HostCertStatus {
	m.mu.Lock()
	hosts := make([]string, 0, len(m.hosts))
	for h := range m.hosts {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	out := make([]HostCertStatus, 0, len(hosts))
	for _, h := range hosts {
		st := HostCertStatus{
			Hostname:  h,
			State:     m.states[h],
			LastError: m.lastErrs[h],
			Issuer:    m.issuers[h],
			Managed:   true,
			Source:    "acme",
		}
		if st.State == "" {
			st.State = StatePending
		}
		out = append(out, st)
	}
	m.mu.Unlock()

	ctx := context.Background()
	for i := range out {
		h := out[i].Hostname
		cert, err := m.magic.CacheManagedCertificate(ctx, h)
		if err != nil {
			continue
		}
		if cert.Leaf != nil {
			fillHostCertFromLeaf(&out[i], cert.Leaf)
			if out[i].State != StateFailed && out[i].State != StateRenewing {
				if cert.NeedsRenewal(m.magic) {
					out[i].State = StateRenewing
				} else {
					out[i].State = StateActive
				}
			}
		}
	}
	return out
}

// Detail returns status for one hostname, or an error when unmanaged and unknown.
func (m *Manager) Detail(hostname string) (HostCertStatus, error) {
	host := strings.ToLower(strings.TrimSpace(hostname))
	if host == "" {
		return HostCertStatus{}, errors.New("tlsacme: host is required")
	}
	all := m.Status()
	for _, st := range all {
		if strings.EqualFold(st.Hostname, host) {
			return st, nil
		}
	}
	m.mu.Lock()
	_, managed := m.hosts[host]
	m.mu.Unlock()
	if !managed {
		return HostCertStatus{}, fmt.Errorf("tlsacme: not found: %s", host)
	}
	return HostCertStatus{
		Hostname: host,
		State:    StatePending,
		Managed:  true,
		Source:   "acme",
	}, nil
}

func fillHostCertFromLeaf(st *HostCertStatus, leaf *x509.Certificate) {
	if st == nil || leaf == nil {
		return
	}
	st.NotBefore = leaf.NotBefore
	st.NotAfter = leaf.NotAfter
	days := int(time.Until(leaf.NotAfter).Hours() / 24)
	if days < 0 {
		days = 0
	}
	st.DaysLeft = days
	st.Subject = leaf.Subject.String()
	if leaf.SerialNumber != nil {
		st.Serial = leaf.SerialNumber.String()
	}
	sum := sha256.Sum256(leaf.Raw)
	st.FingerprintSHA256 = hex.EncodeToString(sum[:])
	if len(leaf.DNSNames) > 0 {
		st.DNSNames = append([]string(nil), leaf.DNSNames...)
	}
	if st.Issuer == "" {
		st.Issuer = leaf.Issuer.String()
	}
	st.Source = "acme"
}

// Renew forces renewal of the certificate for host.
func (m *Manager) Renew(ctx context.Context, host string) error {
	if host == "" {
		return errors.New("tlsacme: host is required")
	}
	m.mu.Lock()
	m.states[host] = StateRenewing
	m.mu.Unlock()

	err := m.magic.RenewCertSync(ctx, host, true)
	if err != nil {
		m.mu.Lock()
		m.lastErrs[host] = err.Error()
		m.states[host] = StateFailed
		m.mu.Unlock()
		return err
	}

	m.mu.Lock()
	delete(m.lastErrs, host)
	m.states[host] = StateActive
	m.hosts[host] = struct{}{}
	m.mu.Unlock()
	return nil
}

// Close stops background certificate maintenance.
func (m *Manager) Close() error {
	if m.cache != nil {
		m.cache.Stop()
	}
	return nil
}

// ManagedHosts returns the list of currently managed hostnames.
func (m *Manager) ManagedHosts() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, 0, len(m.hosts))
	for h := range m.hosts {
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}

func (m *Manager) onEvent(_ context.Context, event string, data map[string]any) error {
	host, _ := data["identifier"].(string)
	if host == "" {
		return nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	switch event {
	case "cert_obtaining":
		m.hosts[host] = struct{}{}
		if renewal, _ := data["renewal"].(bool); renewal {
			m.states[host] = StateRenewing
		} else {
			m.states[host] = StatePending
		}
	case "cert_obtained":
		m.hosts[host] = struct{}{}
		m.states[host] = StateActive
		delete(m.lastErrs, host)
		if issuer, ok := data["issuer"].(string); ok && issuer != "" {
			m.issuers[host] = issuer
		}
	case "cert_failed":
		m.hosts[host] = struct{}{}
		m.states[host] = StateFailed
		switch e := data["error"].(type) {
		case error:
			m.lastErrs[host] = e.Error()
		case string:
			m.lastErrs[host] = e
		default:
			if e != nil {
				m.lastErrs[host] = fmt.Sprint(e)
			}
		}
	}
	return nil
}
