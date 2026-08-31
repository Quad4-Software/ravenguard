// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package blocklist_test

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/Quad4-Software/ravenguard/internal/blocklist"
)

func TestLoadAndMatch(t *testing.T) {
	dir := t.TempDir()
	ipFile := filepath.Join(dir, "ips.txt")
	dnsFile := filepath.Join(dir, "dns.txt")
	uaFile := filepath.Join(dir, "ua.txt")
	_ = os.WriteFile(ipFile, []byte("203.0.113.10\n2001:db8::/64\n"), 0o600)
	_ = os.WriteFile(dnsFile, []byte("evil.example\n"), 0o600)
	_ = os.WriteFile(uaFile, []byte("sqlmap\n"), 0o600)

	s := blocklist.New()
	if err := s.Load([]string{ipFile}, []string{dnsFile}, []string{uaFile}); err != nil {
		t.Fatal(err)
	}
	if !s.IPBlocked(net.ParseIP("203.0.113.10")) {
		t.Fatal("ip")
	}
	if !s.IPBlocked(net.ParseIP("2001:db8::5")) {
		t.Fatal("cidr v6")
	}
	if !s.DNSBlocked("a.evil.example") {
		t.Fatal("dns suffix")
	}
	if !s.UABlocked("Mozilla sqlmap/1.0") {
		t.Fatal("ua")
	}
}

func TestParseIPOrCIDR(t *testing.T) {
	n, err := blocklist.ParseIPOrCIDR("10.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if !n.Contains(net.ParseIP("10.0.0.1")) {
		t.Fatal("single ip")
	}
}

func FuzzParseIPOrCIDR(f *testing.F) {
	f.Add("1.2.3.4")
	f.Add("1.2.3.0/24")
	f.Add("::1")
	f.Add("garbage")
	f.Fuzz(func(t *testing.T, s string) {
		_, _ = blocklist.ParseIPOrCIDR(s)
	})
}

func FuzzNormalizeHost(f *testing.F) {
	f.Add("Example.COM")
	f.Add("*.evil.test")
	f.Add("host:443")
	f.Fuzz(func(t *testing.T, s string) {
		_ = blocklist.NormalizeHost(s)
	})
}
