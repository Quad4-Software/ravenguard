// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package allowlist_test

import (
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/Quad4-Software/ravenguard/internal/allowlist"
)

func TestLoadAndMatch(t *testing.T) {
	dir := t.TempDir()
	ipFile := filepath.Join(dir, "ips.txt")
	uaFile := filepath.Join(dir, "ua.txt")
	hdrFile := filepath.Join(dir, "headers.txt")
	_ = os.WriteFile(ipFile, []byte("203.0.113.10\n2001:db8::/64\n"), 0o600)
	_ = os.WriteFile(uaFile, []byte("HealthCheckBot\n"), 0o600)
	_ = os.WriteFile(hdrFile, []byte("X-RG-Allow: trusted\nX-Internal-Token: s3cret\n"), 0o600)

	s := allowlist.New()
	if err := s.Load([]string{ipFile}, []string{uaFile}, []string{hdrFile}); err != nil {
		t.Fatal(err)
	}

	if !s.Match(net.ParseIP("203.0.113.10"), "", nil) {
		t.Fatal("ip")
	}
	if !s.Match(net.ParseIP("2001:db8::5"), "", nil) {
		t.Fatal("cidr v6")
	}
	if s.Match(net.ParseIP("198.51.100.1"), "", nil) {
		t.Fatal("unlisted ip")
	}
	if !s.Match(nil, "Mozilla HealthCheckBot/1.0", nil) {
		t.Fatal("ua")
	}
	if s.Match(nil, "Mozilla/5.0", nil) {
		t.Fatal("unlisted ua")
	}

	hdr := make(http.Header)
	hdr.Set("X-RG-Allow", "trusted")
	if !s.Match(nil, "", hdr) {
		t.Fatal("header")
	}
	hdr.Set("X-RG-Allow", "nope")
	if s.Match(nil, "", hdr) {
		t.Fatal("wrong header value")
	}
	hdr.Del("X-RG-Allow")
	hdr.Set("X-Internal-Token", "s3cret")
	if !s.Match(nil, "", hdr) {
		t.Fatal("second header")
	}
}

func TestEmptyNeverMatches(t *testing.T) {
	s := allowlist.New()
	if !s.Empty() {
		t.Fatal("expected empty")
	}
	if s.Match(net.ParseIP("127.0.0.1"), "bot", http.Header{"X": []string{"y"}}) {
		t.Fatal("empty must not match")
	}
}

func TestHeaderLineRequiresColon(t *testing.T) {
	dir := t.TempDir()
	hdrFile := filepath.Join(dir, "headers.txt")
	_ = os.WriteFile(hdrFile, []byte("not-a-header\n:missing-name\nX-Ok: yes\n"), 0o600)
	s := allowlist.New()
	if err := s.Load(nil, nil, []string{hdrFile}); err != nil {
		t.Fatal(err)
	}
	st := s.Stats()
	if st.HeaderCount != 1 {
		t.Fatalf("header count: %d", st.HeaderCount)
	}
	hdr := make(http.Header)
	hdr.Set("X-Ok", "yes")
	if !s.Match(nil, "", hdr) {
		t.Fatal("valid header")
	}
}
