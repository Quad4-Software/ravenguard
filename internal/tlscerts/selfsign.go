// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package tlscerts

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	SourceSelfSigned = "selfsigned"

	defaultSelfSignedValidity = 365 * 24 * time.Hour
	selfSignedRenewSkew       = 24 * time.Hour
)

// GenerateOptions configures self-signed certificate creation.
type GenerateOptions struct {
	// Hosts are DNS SANs. The first becomes the subject CommonName.
	Hosts []string
	// IPs are IP SANs.
	IPs []net.IP
	// Validity is how long the certificate is valid. Zero means 365 days.
	Validity time.Duration
	// NotBefore offsets the start time. Zero means now minus one hour.
	NotBefore time.Time
}

// Generate creates an ECDSA P-256 self-signed certificate and private key as PEM.
func Generate(opts GenerateOptions) (certPEM, keyPEM []byte, err error) {
	hosts, ips, err := normalizeGenerateNames(opts.Hosts, opts.IPs)
	if err != nil {
		return nil, nil, err
	}
	validity := opts.Validity
	if validity <= 0 {
		validity = defaultSelfSignedValidity
	}
	notBefore := opts.NotBefore
	if notBefore.IsZero() {
		notBefore = time.Now().Add(-time.Hour)
	}
	notAfter := notBefore.Add(validity)
	if !notAfter.After(notBefore) {
		return nil, nil, errors.New("tlscerts: validity must be positive")
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("tlscerts: generate key: %w", err)
	}

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, nil, fmt.Errorf("tlscerts: serial: %w", err)
	}

	cn := "localhost"
	if len(hosts) > 0 {
		cn = hosts[0]
	} else if len(ips) > 0 {
		cn = ips[0].String()
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     hosts,
		IPAddresses:  ips,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("tlscerts: create certificate: %w", err)
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("tlscerts: marshal key: %w", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	return certPEM, keyPEM, nil
}

// EnsureFiles loads an existing self-signed pair from dir or generates a new one.
// Files are fullchain.pem and privkey.pem. Existing material is reused when it
// is still valid for the requested names and not within the renewal skew window.
func EnsureFiles(dir string, opts GenerateOptions) (certPEM, keyPEM []byte, err error) {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return nil, nil, errors.New("tlscerts: storage dir is required")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, nil, fmt.Errorf("tlscerts: mkdir: %w", err)
	}

	hosts, ips, err := normalizeGenerateNames(opts.Hosts, opts.IPs)
	if err != nil {
		return nil, nil, err
	}
	if len(hosts) == 0 && len(ips) == 0 {
		hosts = []string{"localhost"}
	}
	opts.Hosts = hosts
	opts.IPs = ips

	certPath := filepath.Join(dir, "fullchain.pem")
	keyPath := filepath.Join(dir, "privkey.pem")
	existingCert, err1 := os.ReadFile(certPath)
	existingKey, err2 := os.ReadFile(keyPath)
	if err1 == nil && err2 == nil {
		if usableSelfSigned(existingCert, existingKey, hosts, ips) {
			return existingCert, existingKey, nil
		}
	}

	certPEM, keyPEM, err = Generate(opts)
	if err != nil {
		return nil, nil, err
	}
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		return nil, nil, fmt.Errorf("tlscerts: write cert: %w", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return nil, nil, fmt.Errorf("tlscerts: write key: %w", err)
	}
	return certPEM, keyPEM, nil
}

// WriteFiles writes cert and key PEM to the given paths.
// Existing files cause an error unless force is true.
func WriteFiles(certPath, keyPath string, certPEM, keyPEM []byte, force bool) error {
	certPath = strings.TrimSpace(certPath)
	keyPath = strings.TrimSpace(keyPath)
	if certPath == "" || keyPath == "" {
		return errors.New("tlscerts: cert and key paths are required")
	}
	if !force {
		if _, err := os.Stat(certPath); err == nil {
			return fmt.Errorf("tlscerts: cert file exists: %s", certPath)
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("tlscerts: stat cert: %w", err)
		}
		if _, err := os.Stat(keyPath); err == nil {
			return fmt.Errorf("tlscerts: key file exists: %s", keyPath)
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("tlscerts: stat key: %w", err)
		}
	}
	if err := os.MkdirAll(filepath.Dir(certPath), 0o700); err != nil {
		return fmt.Errorf("tlscerts: mkdir cert dir: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o700); err != nil {
		return fmt.Errorf("tlscerts: mkdir key dir: %w", err)
	}
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		return fmt.Errorf("tlscerts: write cert: %w", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return fmt.Errorf("tlscerts: write key: %w", err)
	}
	return nil
}

// ParseValidity parses a Go duration or a day count with a trailing "d" suffix.
func ParseValidity(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return defaultSelfSignedValidity, nil
	}
	if d, err := time.ParseDuration(s); err == nil {
		if d <= 0 {
			return 0, errors.New("tlscerts: validity must be positive")
		}
		return d, nil
	}
	if before, ok := strings.CutSuffix(s, "d"); ok {
		daysStr := before
		var days float64
		if _, err := fmt.Sscanf(daysStr, "%f", &days); err == nil && days > 0 {
			return time.Duration(days * float64(24*time.Hour)), nil
		}
	}
	return 0, fmt.Errorf("tlscerts: invalid validity %q", s)
}

// IsSelfSigned reports whether leaf is a self-signed certificate.
func IsSelfSigned(leaf *x509.Certificate) bool {
	if leaf == nil {
		return false
	}
	return leaf.Issuer.String() == leaf.Subject.String()
}

// SourceForLeaf returns SourceSelfSigned when the leaf is self-signed, else fallback.
func SourceForLeaf(leaf *x509.Certificate, fallback string) string {
	if IsSelfSigned(leaf) {
		return SourceSelfSigned
	}
	if fallback == "" {
		return SourceManual
	}
	return fallback
}

func usableSelfSigned(certPEM, keyPEM []byte, hosts []string, ips []net.IP) bool {
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return false
	}
	if err := ensureLeaf(&cert); err != nil || cert.Leaf == nil {
		return false
	}
	leaf := cert.Leaf
	if !IsSelfSigned(leaf) {
		return false
	}
	now := time.Now()
	if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter.Add(-selfSignedRenewSkew)) {
		return false
	}
	for _, h := range hosts {
		if err := leaf.VerifyHostname(h); err != nil {
			return false
		}
	}
	for _, ip := range ips {
		if err := leaf.VerifyHostname(ip.String()); err != nil {
			return false
		}
	}
	return true
}

func normalizeGenerateNames(hosts []string, ips []net.IP) ([]string, []net.IP, error) {
	seenHost := make(map[string]struct{})
	outHosts := make([]string, 0, len(hosts))
	for _, h := range hosts {
		h = strings.ToLower(strings.TrimSpace(h))
		if h == "" {
			continue
		}
		if strings.ContainsAny(h, `/\`) || strings.Contains(h, "..") {
			return nil, nil, fmt.Errorf("tlscerts: invalid hostname %q", h)
		}
		if ip := net.ParseIP(h); ip != nil {
			ips = append(ips, ip)
			continue
		}
		if _, ok := seenHost[h]; ok {
			continue
		}
		seenHost[h] = struct{}{}
		outHosts = append(outHosts, h)
	}

	seenIP := make(map[string]struct{})
	outIPs := make([]net.IP, 0, len(ips))
	for _, ip := range ips {
		if ip == nil {
			continue
		}
		key := ip.String()
		if _, ok := seenIP[key]; ok {
			continue
		}
		seenIP[key] = struct{}{}
		outIPs = append(outIPs, ip)
	}
	return outHosts, outIPs, nil
}
