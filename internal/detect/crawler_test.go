// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package detect

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

type fakeResolver struct {
	addrs     map[string][]string
	ips       map[string][]net.IP
	addrErr   error
	ipErr     error
	addrCalls atomic.Int64
	ipCalls   atomic.Int64
}

func (f *fakeResolver) LookupAddr(ctx context.Context, addr string) ([]string, error) {
	f.addrCalls.Add(1)
	if f.addrErr != nil {
		return nil, f.addrErr
	}
	return f.addrs[addr], nil
}

func (f *fakeResolver) LookupIP(ctx context.Context, host string) ([]net.IP, error) {
	f.ipCalls.Add(1)
	if f.ipErr != nil {
		return nil, f.ipErr
	}
	return f.ips[host], nil
}

func newTestVerifier(res *fakeResolver) *CrawlerVerifier {
	v := NewCrawlerVerifier(50*time.Millisecond, time.Hour, time.Hour)
	v.resolver = res
	return v
}

func TestCrawlerNotClaimed(t *testing.T) {
	v := newTestVerifier(&fakeResolver{})
	got := v.Check(context.Background(), net.ParseIP("1.2.3.4"), "Mozilla/5.0 (Windows NT 10.0) Chrome/120")
	if got != CrawlerNotClaimed {
		t.Fatalf("got %v", got)
	}
}

func TestCrawlerVerified(t *testing.T) {
	ip := net.ParseIP("66.249.66.1")
	res := &fakeResolver{
		addrs: map[string][]string{"66.249.66.1": {"crawl-66-249-66-1.googlebot.com."}},
		ips:   map[string][]net.IP{"crawl-66-249-66-1.googlebot.com": {ip}},
	}
	v := newTestVerifier(res)
	got := v.Check(context.Background(), ip, "Mozilla/5.0 (compatible; Googlebot/2.1)")
	if got != CrawlerVerified {
		t.Fatalf("got %v", got)
	}
	// Cached: a second check must not hit the resolver again.
	got = v.Check(context.Background(), ip, "Mozilla/5.0 (compatible; Googlebot/2.1)")
	if got != CrawlerVerified {
		t.Fatalf("cached got %v", got)
	}
	if res.addrCalls.Load() != 1 {
		t.Fatalf("resolver called %d times, want 1", res.addrCalls.Load())
	}
}

func TestCrawlerSpoofedForeignPTR(t *testing.T) {
	res := &fakeResolver{
		addrs: map[string][]string{"203.0.113.9": {"vps.attacker.example."}},
		ips:   map[string][]net.IP{},
	}
	v := newTestVerifier(res)
	got := v.Check(context.Background(), net.ParseIP("203.0.113.9"), "Googlebot/2.1")
	if got != CrawlerSpoofed {
		t.Fatalf("got %v", got)
	}
}

func TestCrawlerSpoofedForwardMismatch(t *testing.T) {
	// PTR name ends in the right suffix but resolves to a different IP.
	res := &fakeResolver{
		addrs: map[string][]string{"198.51.100.7": {"crawl-1-2-3-4.googlebot.com."}},
		ips:   map[string][]net.IP{"crawl-1-2-3-4.googlebot.com": {net.ParseIP("66.249.66.1")}},
	}
	v := newTestVerifier(res)
	got := v.Check(context.Background(), net.ParseIP("198.51.100.7"), "Googlebot/2.1")
	if got != CrawlerSpoofed {
		t.Fatalf("got %v", got)
	}
}

func TestCrawlerUnknownOnReverseError(t *testing.T) {
	res := &fakeResolver{addrErr: errors.New("NXDOMAIN")}
	v := newTestVerifier(res)
	got := v.Check(context.Background(), net.ParseIP("192.0.2.1"), "Googlebot/2.1")
	if got != CrawlerUnknown {
		t.Fatalf("reverse error must be inconclusive, got %v", got)
	}
}

func TestCrawlerUnknownOnForwardError(t *testing.T) {
	res := &fakeResolver{
		addrs: map[string][]string{"66.249.66.2": {"crawl-66-249-66-2.googlebot.com."}},
		ipErr: errors.New("resolver failure"),
	}
	v := newTestVerifier(res)
	got := v.Check(context.Background(), net.ParseIP("66.249.66.2"), "Googlebot/2.1")
	if got != CrawlerUnknown {
		t.Fatalf("forward error must be inconclusive, got %v", got)
	}
}

func TestCrawlerSuffixTrickRejected(t *testing.T) {
	// evilgooglebot.com contains googlebot.com as a substring but is not a
	// subdomain of it.
	res := &fakeResolver{
		addrs: map[string][]string{"203.0.113.5": {"x.evilgooglebot.com."}},
		ips:   map[string][]net.IP{"x.evilgooglebot.com": {net.ParseIP("203.0.113.5")}},
	}
	v := newTestVerifier(res)
	got := v.Check(context.Background(), net.ParseIP("203.0.113.5"), "Googlebot/2.1")
	if got != CrawlerSpoofed {
		t.Fatalf("got %v", got)
	}
}

func TestCrawlerRealBrowserNotFlagged(t *testing.T) {
	// Yandex Browser and Sogou browser UAs contain operator tokens but are
	// real user browsers; they must not trigger verification at all.
	for _, ua := range []string{
		"Mozilla/5.0 (Windows NT 10.0) YaBrowser/24.1 Chrome/120 Safari/537.36",
		"Mozilla/5.0 (Linux; Android 13) SogouMobileBrowser/12.0",
		"Mozilla/5.0 (iPhone) DuckDuckGo/7 Safari/604.1",
	} {
		if MatchCrawler(ua) {
			t.Fatalf("real browser UA must not claim crawler: %q", ua)
		}
	}
}

func TestCrawlerKnownClaimsMatch(t *testing.T) {
	for _, ua := range []string{
		"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
		"Mozilla/5.0 (compatible; bingbot/2.0)",
		"Mozilla/5.0 (compatible; DuckDuckBot/1.1)",
		"Mozilla/5.0 AppleWebKit/605.1.15 (compatible; Applebot/0.1)",
		"Mozilla/5.0 (compatible; Baiduspider/2.0)",
		"Mozilla/5.0 (compatible; YandexBot/3.0)",
		"Sogou web spider/4.0",
	} {
		if !MatchCrawler(ua) {
			t.Fatalf("crawler UA must match: %q", ua)
		}
	}
}

func TestCrawlerVerdictCachePerClaim(t *testing.T) {
	ip := net.ParseIP("66.249.66.1")
	res := &fakeResolver{
		addrs: map[string][]string{"66.249.66.1": {"crawl-66-249-66-1.googlebot.com."}},
		ips:   map[string][]net.IP{"crawl-66-249-66-1.googlebot.com": {ip}},
	}
	v := newTestVerifier(res)
	if got := v.Check(context.Background(), ip, "Googlebot/2.1"); got != CrawlerVerified {
		t.Fatalf("got %v", got)
	}
	// A different claim for the same IP is verified independently and is
	// spoofed because the PTR is not under search.msn.com.
	if got := v.Check(context.Background(), ip, "bingbot/2.0"); got != CrawlerSpoofed {
		t.Fatalf("got %v", got)
	}
	if res.addrCalls.Load() != 2 {
		t.Fatalf("resolver called %d times, want 2", res.addrCalls.Load())
	}
}

func TestCrawlerExpiredEntryReverifies(t *testing.T) {
	ip := net.ParseIP("66.249.66.1")
	res := &fakeResolver{
		addrs: map[string][]string{"66.249.66.1": {"crawl-66-249-66-1.googlebot.com."}},
		ips:   map[string][]net.IP{"crawl-66-249-66-1.googlebot.com": {ip}},
	}
	v := newTestVerifier(res)
	now := time.Now()
	v.now = func() time.Time { return now }
	if got := v.Check(context.Background(), ip, "Googlebot/2.1"); got != CrawlerVerified {
		t.Fatalf("got %v", got)
	}
	now = now.Add(2 * time.Hour)
	if got := v.Check(context.Background(), ip, "Googlebot/2.1"); got != CrawlerVerified {
		t.Fatalf("got %v", got)
	}
	if res.addrCalls.Load() != 2 {
		t.Fatalf("expired entry must reverify, calls=%d", res.addrCalls.Load())
	}
}

func TestCrawlerNilAndNilIP(t *testing.T) {
	var v *CrawlerVerifier
	if got := v.Check(context.Background(), net.ParseIP("1.1.1.1"), "Googlebot"); got != CrawlerUnknown {
		t.Fatalf("nil verifier got %v", got)
	}
	v = newTestVerifier(&fakeResolver{})
	if got := v.Check(context.Background(), nil, "Googlebot"); got != CrawlerUnknown {
		t.Fatalf("nil ip got %v", got)
	}
}

func TestCrawlerSweepBoundsCache(t *testing.T) {
	v := newTestVerifier(&fakeResolver{addrErr: errors.New("no ptr")})
	now := time.Now()
	v.now = func() time.Time { return now }
	for i := 0; i < 10; i++ {
		ip := net.ParseIP("10.0.0." + string(rune('0'+i)))
		v.Check(context.Background(), ip, "Googlebot/2.1")
	}
	if v.size.Load() != 10 {
		t.Fatalf("size=%d", v.size.Load())
	}
	// Expire everything, push the counter past the bound, and confirm the
	// sweep removes the dead entries.
	now = now.Add(2 * time.Hour)
	v.size.Store(maxCrawlerCache + 1)
	v.sweep()
	if v.size.Load() > maxCrawlerCache {
		t.Fatalf("sweep left size=%d", v.size.Load())
	}
}
