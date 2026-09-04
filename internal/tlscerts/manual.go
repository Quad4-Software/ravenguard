// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

// Package tlscerts stores and inspects TLS certificates for admin and listeners.
package tlscerts

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	SourceACME   = "acme"
	SourceManual = "manual"
	SourceFiles  = "files"

	StateActive = "active"
	StateFailed = "failed"
)

// Detail describes one hostname certificate for the admin API.
type Detail struct {
	Hostname          string    `json:"hostname"`
	Source            string    `json:"source"`
	State             string    `json:"state"`
	NotBefore         time.Time `json:"not_before"`
	NotAfter          time.Time `json:"not_after"`
	DaysLeft          int       `json:"days_left,omitempty"`
	Issuer            string    `json:"issuer,omitempty"`
	Subject           string    `json:"subject,omitempty"`
	Serial            string    `json:"serial,omitempty"`
	FingerprintSHA256 string    `json:"fingerprint_sha256,omitempty"`
	DNSNames          []string  `json:"dns_names,omitempty"`
	LastError         string    `json:"last_error,omitempty"`
	Managed           bool      `json:"managed"`
}

// ManualStore keeps PEM certificate pairs on disk and in memory.
type ManualStore struct {
	dir   string
	mu    sync.RWMutex
	cache map[string]*tls.Certificate
}

// NewManualStore creates dir (0700) and loads existing host certificates.
func NewManualStore(dir string) (*ManualStore, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, errors.New("tlscerts: dir is required")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("tlscerts: mkdir: %w", err)
	}
	s := &ManualStore{
		dir:   dir,
		cache: make(map[string]*tls.Certificate),
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("tlscerts: readdir: %w", err)
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		host := strings.ToLower(e.Name())
		certPath := filepath.Join(dir, host, "fullchain.pem")
		keyPath := filepath.Join(dir, host, "privkey.pem")
		certPEM, err1 := os.ReadFile(certPath)
		keyPEM, err2 := os.ReadFile(keyPath)
		if err1 != nil || err2 != nil {
			continue
		}
		cert, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			continue
		}
		if err := ensureLeaf(&cert); err != nil {
			continue
		}
		s.cache[host] = &cert
	}
	return s, nil
}

// Dir returns the on-disk root directory.
func (s *ManualStore) Dir() string {
	return s.dir
}

// Put validates and stores a certificate/key PEM pair for hostname.
func (s *ManualStore) Put(hostname, certPEM, keyPEM string) error {
	host, err := normalizeHost(hostname)
	if err != nil {
		return err
	}
	cert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		return fmt.Errorf("tlscerts: invalid key pair: %w", err)
	}
	if err := ensureLeaf(&cert); err != nil {
		return err
	}
	hostDir := filepath.Join(s.dir, host)
	if err := os.MkdirAll(hostDir, 0o700); err != nil {
		return fmt.Errorf("tlscerts: mkdir host: %w", err)
	}
	certPath := filepath.Join(hostDir, "fullchain.pem")
	keyPath := filepath.Join(hostDir, "privkey.pem")
	if err := os.WriteFile(certPath, []byte(certPEM), 0o600); err != nil {
		return fmt.Errorf("tlscerts: write cert: %w", err)
	}
	if err := os.WriteFile(keyPath, []byte(keyPEM), 0o600); err != nil {
		return fmt.Errorf("tlscerts: write key: %w", err)
	}
	s.mu.Lock()
	s.cache[host] = &cert
	s.mu.Unlock()
	return nil
}

// Delete removes a manual certificate for hostname.
func (s *ManualStore) Delete(hostname string) error {
	host, err := normalizeHost(hostname)
	if err != nil {
		return err
	}
	s.mu.Lock()
	delete(s.cache, host)
	s.mu.Unlock()
	hostDir := filepath.Join(s.dir, host)
	if err := os.RemoveAll(hostDir); err != nil {
		return fmt.Errorf("tlscerts: delete: %w", err)
	}
	return nil
}

// GetCertificate returns a cached cert for the ClientHello ServerName, or nil,nil on miss.
func (s *ManualStore) GetCertificate(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if chi == nil {
		return nil, nil
	}
	host := strings.ToLower(strings.TrimSpace(chi.ServerName))
	if host == "" {
		return nil, nil
	}
	s.mu.RLock()
	cert := s.cache[host]
	s.mu.RUnlock()
	if cert == nil {
		return nil, nil
	}
	return cert, nil
}

// List returns details for all cached manual certificates, sorted by hostname.
func (s *ManualStore) List() []Detail {
	s.mu.RLock()
	hosts := make([]string, 0, len(s.cache))
	for h := range s.cache {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	out := make([]Detail, 0, len(hosts))
	for _, h := range hosts {
		cert := s.cache[h]
		src := SourceManual
		if cert != nil && cert.Leaf != nil {
			src = SourceForLeaf(cert.Leaf, SourceManual)
		}
		out = append(out, detailFromCert(h, src, false, cert, ""))
	}
	s.mu.RUnlock()
	return out
}

// Detail returns certificate details for one hostname.
func (s *ManualStore) Detail(hostname string) (Detail, error) {
	host, err := normalizeHost(hostname)
	if err != nil {
		return Detail{}, err
	}
	s.mu.RLock()
	cert := s.cache[host]
	s.mu.RUnlock()
	if cert == nil {
		return Detail{}, fmt.Errorf("tlscerts: not found: %s", host)
	}
	src := SourceManual
	if cert.Leaf != nil {
		src = SourceForLeaf(cert.Leaf, SourceManual)
	}
	return detailFromCert(host, src, false, cert, ""), nil
}

// Export returns PEM material for migration over the authenticated agent channel.
func (s *ManualStore) Export(hostname string) (certPEM, keyPEM string, err error) {
	host, err := normalizeHost(hostname)
	if err != nil {
		return "", "", err
	}
	s.mu.RLock()
	_, ok := s.cache[host]
	s.mu.RUnlock()
	if !ok {
		return "", "", fmt.Errorf("tlscerts: not found: %s", host)
	}
	certPath := filepath.Join(s.dir, host, "fullchain.pem")
	keyPath := filepath.Join(s.dir, host, "privkey.pem")
	certBytes, err1 := os.ReadFile(certPath)
	keyBytes, err2 := os.ReadFile(keyPath)
	if err1 != nil || err2 != nil {
		return "", "", fmt.Errorf("tlscerts: export read failed")
	}
	return string(certBytes), string(keyBytes), nil
}

// DetailFromLeaf fills a Detail from an x509 certificate leaf.
func DetailFromLeaf(hostname, source string, managed bool, leaf *x509.Certificate, state, lastErr string) Detail {
	d := Detail{
		Hostname:  hostname,
		Source:    source,
		State:     state,
		LastError: lastErr,
		Managed:   managed,
	}
	if leaf == nil {
		if d.State == "" {
			d.State = StateFailed
		}
		return d
	}
	d.NotBefore = leaf.NotBefore
	d.NotAfter = leaf.NotAfter
	d.DaysLeft = daysLeft(leaf.NotAfter)
	d.Issuer = leaf.Issuer.String()
	d.Subject = leaf.Subject.String()
	if leaf.SerialNumber != nil {
		d.Serial = leaf.SerialNumber.String()
	}
	sum := sha256.Sum256(leaf.Raw)
	d.FingerprintSHA256 = hex.EncodeToString(sum[:])
	if len(leaf.DNSNames) > 0 {
		d.DNSNames = append([]string(nil), leaf.DNSNames...)
	}
	if d.State == "" {
		if time.Now().After(leaf.NotAfter) {
			d.State = StateFailed
		} else {
			d.State = StateActive
		}
	}
	return d
}

func detailFromCert(hostname, source string, managed bool, cert *tls.Certificate, lastErr string) Detail {
	var leaf *x509.Certificate
	if cert != nil {
		leaf = cert.Leaf
	}
	return DetailFromLeaf(hostname, source, managed, leaf, "", lastErr)
}

func daysLeft(notAfter time.Time) int {
	if notAfter.IsZero() {
		return 0
	}
	d := int(time.Until(notAfter).Hours() / 24)
	if d < 0 {
		return 0
	}
	return d
}

func ensureLeaf(cert *tls.Certificate) error {
	if cert.Leaf != nil {
		return nil
	}
	if len(cert.Certificate) == 0 {
		return errors.New("tlscerts: empty certificate")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return fmt.Errorf("tlscerts: parse leaf: %w", err)
	}
	cert.Leaf = leaf
	return nil
}

func normalizeHost(hostname string) (string, error) {
	h := strings.ToLower(strings.TrimSpace(hostname))
	if h == "" || strings.ContainsAny(h, `/\`) || strings.Contains(h, "..") {
		return "", errors.New("tlscerts: invalid hostname")
	}
	return h, nil
}
