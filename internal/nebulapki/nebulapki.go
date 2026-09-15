// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

// Package nebulapki wraps Nebula certificate operations for the hub admin
// API: CA bootstrap and host certificate signing. The Nebula daemon itself
// runs outside ravenguard; this package only produces the PEM material each
// host needs.
package nebulapki

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net/netip"
	"os"
	"time"

	"github.com/slackhq/nebula/cert"
	"golang.org/x/crypto/curve25519"
)

const defaultCATTL = 10 * 365 * 24 * time.Hour

// CA holds overlay CA material used to sign host certificates.
type CA struct {
	cert    cert.Certificate
	key     []byte
	curve   cert.Curve
	certPEM []byte
}

// GenerateCA creates a fresh CA keypair and self-signed CA certificate.
// The returned key PEM is Ed25519 (NEBULA ED25519 PRIVATE KEY banner).
func GenerateCA(name string, ttl time.Duration) (certPEM, keyPEM []byte, fingerprint string, err error) {
	if name == "" {
		name = "ravenguard"
	}
	if ttl <= 0 {
		ttl = defaultCATTL
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, "", err
	}
	now := time.Now()
	tbs := &cert.TBSCertificate{
		Version:   cert.Version2,
		Name:      name,
		IsCA:      true,
		NotBefore: now.Add(-time.Minute),
		NotAfter:  now.Add(ttl),
		PublicKey: pub,
		Curve:     cert.Curve_CURVE25519,
	}
	nc, err := tbs.Sign(nil, cert.Curve_CURVE25519, priv)
	if err != nil {
		return nil, nil, "", fmt.Errorf("sign ca: %w", err)
	}
	pemBytes, err := nc.MarshalPEM()
	if err != nil {
		return nil, nil, "", err
	}
	fp, err := nc.Fingerprint()
	if err != nil {
		return nil, nil, "", err
	}
	return pemBytes, cert.MarshalSigningPrivateKeyToPEM(cert.Curve_CURVE25519, priv), fp, nil
}

// LoadCA reads a CA certificate and Ed25519 signing key from PEM files.
func LoadCA(certPath, keyPath string) (*CA, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("ca cert: %w", err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("ca key: %w", err)
	}
	return ParseCA(certPEM, keyPEM)
}

// ParseCA loads a CA certificate and signing key from PEM bytes.
func ParseCA(certPEM, keyPEM []byte) (*CA, error) {
	c, _, err := cert.UnmarshalCertificateFromPEM(certPEM)
	if err != nil {
		return nil, fmt.Errorf("ca cert: %w", err)
	}
	if !c.IsCA() {
		return nil, fmt.Errorf("ca cert: certificate is not a CA")
	}
	key, _, curve, err := cert.UnmarshalSigningPrivateKeyFromPEM(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("ca key: %w", err)
	}
	if curve != c.Curve() {
		return nil, fmt.Errorf("ca key curve %s does not match ca cert curve %s", curve, c.Curve())
	}
	if c.Expired(time.Now()) {
		return nil, fmt.Errorf("ca cert expired")
	}
	return &CA{cert: c, key: key, curve: curve, certPEM: certPEM}, nil
}

// Fingerprint returns the CA certificate SHA-256 fingerprint.
func (c *CA) Fingerprint() string {
	fp, _ := c.cert.Fingerprint()
	return fp
}

// Name returns the CA certificate subject name.
func (c *CA) Name() string { return c.cert.Name() }

// NotAfter returns when the CA certificate expires.
func (c *CA) NotAfter() time.Time { return c.cert.NotAfter() }

// CertPEM returns the CA certificate PEM for distribution to hosts.
func (c *CA) CertPEM() []byte { return c.certPEM }

// SignHost generates a fresh X25519 host keypair and signs a host
// certificate for network (an overlay IP with the pool prefix length, e.g.
// 10.42.0.5/16). It returns the cert PEM and X25519 private key PEM, which
// must only be transmitted to the host once.
func (c *CA) SignHost(name string, network netip.Prefix, groups []string, ttl time.Duration, version int) (certPEM, keyPEM []byte, fingerprint string, notAfter time.Time, err error) {
	if name == "" {
		return nil, nil, "", time.Time{}, fmt.Errorf("name required")
	}
	if !network.IsValid() || !network.Addr().Is4() {
		return nil, nil, "", time.Time{}, fmt.Errorf("invalid host network")
	}
	priv := make([]byte, 32)
	if _, err := rand.Read(priv); err != nil {
		return nil, nil, "", time.Time{}, err
	}
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		return nil, nil, "", time.Time{}, err
	}
	now := time.Now()
	if ttl <= 0 {
		ttl = 365 * 24 * time.Hour
	}
	notAfter = now.Add(ttl)
	if caEnd := c.cert.NotAfter(); notAfter.After(caEnd) {
		notAfter = caEnd
	}
	v := cert.Version(version)
	if v != cert.Version1 && v != cert.Version2 {
		v = cert.Version2
	}
	tbs := &cert.TBSCertificate{
		Version:   v,
		Name:      name,
		Networks:  []netip.Prefix{network},
		Groups:    groups,
		NotBefore: now.Add(-time.Minute),
		NotAfter:  notAfter,
		PublicKey: pub,
		Curve:     cert.Curve_CURVE25519,
	}
	nc, err := tbs.Sign(c.cert, c.curve, c.key)
	if err != nil {
		return nil, nil, "", time.Time{}, fmt.Errorf("sign host: %w", err)
	}
	pemBytes, err := nc.MarshalPEM()
	if err != nil {
		return nil, nil, "", time.Time{}, err
	}
	fp, err := nc.Fingerprint()
	if err != nil {
		return nil, nil, "", time.Time{}, err
	}
	return pemBytes, cert.MarshalPrivateKeyToPEM(cert.Curve_CURVE25519, priv), fp, notAfter, nil
}

// AllocateIP picks the lowest unused host address in pool. used holds
// already assigned overlay IPs (as strings). The network and broadcast
// addresses are skipped. Pools larger than maxScan are rejected.
func AllocateIP(pool netip.Prefix, used map[string]struct{}) (netip.Prefix, error) {
	const maxScan = 1 << 20
	if !pool.IsValid() || !pool.Addr().Is4() {
		return netip.Prefix{}, fmt.Errorf("pool must be an IPv4 prefix")
	}
	bits := pool.Bits()
	if bits < 0 || bits > 30 {
		return netip.Prefix{}, fmt.Errorf("pool must be at least a /30")
	}
	addr := pool.Masked().Addr().Next() // skip network address
	last := lastAddr(pool)
	for i := 0; i < maxScan; i++ {
		if !addr.IsValid() || addr == last || !pool.Contains(addr) {
			return netip.Prefix{}, fmt.Errorf("pool %s exhausted", pool)
		}
		if _, taken := used[addr.String()]; !taken {
			return netip.PrefixFrom(addr, pool.Bits()), nil
		}
		addr = addr.Next()
	}
	return netip.Prefix{}, fmt.Errorf("pool %s too large to scan", pool)
}

func lastAddr(p netip.Prefix) netip.Addr {
	addr := p.Masked().Addr()
	b := addr.As4()
	ones := p.Bits()
	hostBits := 32 - ones
	for i := 0; i < hostBits && i < 32; i++ {
		b[3-i/8] |= 1 << (uint(i) % 8)
	}
	return netip.AddrFrom4(b)
}
