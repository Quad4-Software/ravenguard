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

func TestSampleUABlocklist(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "..", "testdata", "blocklists", "ua.txt"))
	if err != nil {
		t.Fatal(err)
	}
	s := blocklist.New()
	if err := s.Load(nil, nil, []string{root}); err != nil {
		t.Fatal(err)
	}
	blocked := []string{
		"Mozilla/5.0 (compatible; GPTBot/1.2)",
		"Claude-SearchBot/1.0",
		"Perplexity-User",
		"Google-Agent",
		"Applebot-Extended",
		"MistralAI-User",
		"Bytespider",
		"HeadlessChrome/120.0.0.0",
		"python-requests/2.31.0",
		"playwright",
		"crawl4ai",
		"xrumer",
		"ChatGPT-Atlas/1.0",
		"DeepSeekBot/1.0",
		"Claude-Code/2.1.0",
	}
	for _, ua := range blocked {
		if !s.UABlocked(ua) {
			t.Fatalf("expected blocked: %q", ua)
		}
	}
	allowed := []string{
		"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
		"Mozilla/5.0 (compatible; Applebot/0.1; +http://www.apple.com/go/applebot)",
	}
	for _, ua := range allowed {
		if s.UABlocked(ua) {
			t.Fatalf("must not block: %q", ua)
		}
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
