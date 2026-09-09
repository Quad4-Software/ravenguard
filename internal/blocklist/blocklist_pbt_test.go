// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package blocklist_test

import (
	"math/rand"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode"

	"github.com/Quad4-Software/ravenguard/internal/blocklist"
)

// --- helpers duplicated from the iputil tests to keep packages independent ---

func randomV6BL(r *rand.Rand) netip.Addr {
	var b [16]byte
	for i := range b {
		b[i] = byte(r.Intn(256))
	}
	mapped := true
	for i := range 10 {
		if b[i] != 0 {
			mapped = false
			break
		}
	}
	if mapped && b[10] == 0xff && b[11] == 0xff {
		b[0] = 0x01
	}
	return netip.AddrFrom16(b)
}

func randomNonMappedNoZoneAddrBL(r *rand.Rand) netip.Addr {
	if r.Intn(2) == 0 {
		var b [4]byte
		for i := range b {
			b[i] = byte(r.Intn(256))
		}
		return netip.AddrFrom4(b)
	}
	return randomV6BL(r)
}

func randomCIDRStringBL(r *rand.Rand, canonical bool) string {
	if r.Intn(2) == 0 {
		var b [4]byte
		for i := range b {
			b[i] = byte(r.Intn(256))
		}
		a := netip.AddrFrom4(b)
		bits := r.Intn(33)
		p := netip.PrefixFrom(a, bits)
		if canonical {
			p = p.Masked()
		}
		return p.String()
	}
	a := randomV6BL(r)
	bits := r.Intn(129)
	p := netip.PrefixFrom(a, bits)
	if canonical {
		p = p.Masked()
	}
	return p.String()
}

// netipRefForCIDR returns the canonical netip.Prefix for a CIDR or IP string
// after trimming whitespace. IPv4-mapped CIDRs are skipped.
func netipRefForCIDRBL(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, err
		}
		if p.Masked().Addr().Is4In6() {
			return netip.Prefix{}, nil
		}
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	if a.Is4In6() {
		a = a.Unmap()
	}
	bits := 32
	if !a.Is4() {
		bits = 128
	}
	return a.Prefix(bits)
}

func writeIPFile(t *testing.T, dir, name string, cidrs []string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	var b strings.Builder
	for _, c := range cidrs {
		b.WriteString(c)
		b.WriteByte('\n')
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// --- property tests ---

func TestParseIPOrCIDRDiffAndMetamorphic(t *testing.T) {
	r := rand.New(rand.NewSource(4))

	for range 200 {
		// Mostly CIDRs, sometimes plain IPs.
		var s string
		if r.Intn(5) == 0 {
			s = randomNonMappedNoZoneAddrBL(r).String()
		} else {
			s = randomCIDRStringBL(r, r.Intn(2) == 0)
		}

		n, err := blocklist.ParseIPOrCIDR(s)
		ref, refErr := netipRefForCIDRBL(s)

		if refErr != nil {
			if err == nil {
				t.Fatalf("ParseIPOrCIDR(%q)=%q, but netip rejects it", s, n.String())
			}
			continue
		}
		if !ref.IsValid() {
			// IPv4-mapped CIDR: just verify no panic and basic invariants.
			if err == nil && !n.Contains(n.IP) {
				t.Fatalf("ParseIPOrCIDR(%q) network does not contain itself", s)
			}
			continue
		}

		if err != nil {
			t.Fatalf("ParseIPOrCIDR(%q): %v", s, err)
		}

		if n.String() != ref.String() {
			t.Fatalf("ParseIPOrCIDR(%q)=%q, want %q", s, n.String(), ref.String())
		}

		if !n.Contains(n.IP) {
			t.Fatalf("ParseIPOrCIDR(%q) network %s does not contain %v", s, n.String(), n.IP)
		}

		ones, bits := n.Mask.Size()
		if ones < 0 || ones > bits || (bits != 32 && bits != 128) {
			t.Fatalf("ParseIPOrCIDR(%q) network %s has bad mask size %d/%d", s, n.String(), ones, bits)
		}

		// Metamorphic: the canonical string reparses to the same network.
		n2, err2 := blocklist.ParseIPOrCIDR(n.String())
		if err2 != nil || n2.String() != n.String() {
			t.Fatalf("ParseIPOrCIDR(%q) idempotence failed", s)
		}

		// Differential containment for random addresses.
		for range 5 {
			a := randomNonMappedNoZoneAddrBL(r)
			got := n.Contains(net.ParseIP(a.String()))
			want := ref.Contains(a)
			if got != want {
				t.Fatalf("contains %s in %s: got %v, want %v", a.String(), n.String(), got, want)
			}
		}
	}
}

func TestIPBlockedDiff(t *testing.T) {
	r := rand.New(rand.NewSource(5))

	dir := t.TempDir()
	cidrs := make([]string, 0, 8)
	for range 8 {
		cidrs = append(cidrs, randomCIDRStringBL(r, true))
	}
	file := writeIPFile(t, dir, "ips.txt", cidrs)

	s := blocklist.New()
	if err := s.Load([]string{file}, nil, nil); err != nil {
		t.Fatal(err)
	}

	for range 200 {
		a := randomNonMappedNoZoneAddrBL(r)

		want := false
		for _, c := range cidrs {
			ref, err := netipRefForCIDRBL(c)
			if err != nil || !ref.IsValid() {
				continue
			}
			if ref.Contains(a) {
				want = true
				break
			}
		}

		got := s.IPBlocked(net.ParseIP(a.String()))
		if got != want {
			t.Fatalf("IPBlocked(%s) with %v: got %v, want %v", a.String(), cidrs, got, want)
		}
	}
}

func TestIPBlockedCIDRNonCanonical(t *testing.T) {
	dir := t.TempDir()
	file := writeIPFile(t, dir, "ips.txt", []string{"1.2.3.4/24"})

	s := blocklist.New()
	if err := s.Load([]string{file}, nil, nil); err != nil {
		t.Fatal(err)
	}

	if !s.IPBlocked(net.ParseIP("1.2.3.99")) {
		t.Fatal("expected 1.2.3.99 to be blocked by 1.2.3.4/24")
	}
	if s.IPBlocked(net.ParseIP("1.2.4.1")) {
		t.Fatal("expected 1.2.4.1 not to be blocked by 1.2.3.4/24")
	}
}

func TestCIDRListUnion(t *testing.T) {
	r := rand.New(rand.NewSource(6))

	dir := t.TempDir()
	cidrs := make([]string, 0, 6)
	for range 6 {
		cidrs = append(cidrs, randomCIDRStringBL(r, true))
	}

	// Split the CIDRs into two files.
	mid := len(cidrs) / 2
	allFile := writeIPFile(t, dir, "all.txt", cidrs)
	fileA := writeIPFile(t, dir, "a.txt", cidrs[:mid])
	fileB := writeIPFile(t, dir, "b.txt", cidrs[mid:])

	sAll := blocklist.New()
	if err := sAll.Load([]string{allFile}, nil, nil); err != nil {
		t.Fatal(err)
	}

	sSplit := blocklist.New()
	if err := sSplit.Load([]string{fileA, fileB}, nil, nil); err != nil {
		t.Fatal(err)
	}

	for range 100 {
		a := randomNonMappedNoZoneAddrBL(r)
		gotAll := sAll.IPBlocked(net.ParseIP(a.String()))
		gotSplit := sSplit.IPBlocked(net.ParseIP(a.String()))
		if gotAll != gotSplit {
			t.Fatalf("union mismatch for %s: all=%v split=%v", a.String(), gotAll, gotSplit)
		}
	}
}

func TestNormalizeHostDiffAndMetamorphic(t *testing.T) {
	r := rand.New(rand.NewSource(7))

	fixed := []string{
		"Example.COM",
		"*.evil.test",
		"host:443",
		"localhost",
		"localhost.",
		".localhost",
		"*.localhost",
		"LocalHost:8080",
		"xn--bcher-kva.example",
		"path.com/segment",
		" spaces \t around ",
		"::1",
		"[::1]:443",
		"127.0.0.1:8080",
		"127.0.0.1",
		"fe80::1%eth0",
		"invalid\x80utf8",
		"host\x00null",
	}

	chars := []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.*:-/ ")

	testOne := func(s string) {
		out := blocklist.NormalizeHost(s)

		// The result must be lowercase and idempotent.
		if out != strings.ToLower(out) {
			t.Fatalf("NormalizeHost(%q)=%q is not lowercase", s, out)
		}

		out2 := blocklist.NormalizeHost(out)
		if out != out2 {
			t.Fatalf("NormalizeHost not idempotent: %q -> %q -> %q", s, out, out2)
		}

		// No Unicode whitespace remains and the value is not wrapped in dots.
		if strings.IndexFunc(out, unicode.IsSpace) != -1 {
			t.Fatalf("NormalizeHost(%q)=%q contains whitespace", s, out)
		}
		if strings.HasPrefix(out, ".") || strings.HasSuffix(out, ".") {
			t.Fatalf("NormalizeHost(%q)=%q is wrapped in dots", s, out)
		}
	}

	for _, s := range fixed {
		testOne(s)
	}

	for range 200 {
		n := r.Intn(20) + 1
		var b strings.Builder
		for range n {
			b.WriteRune(chars[r.Intn(len(chars))])
		}
		testOne(b.String())
	}
}

func TestAddHostAliasMetamorphic(t *testing.T) {
	dir := t.TempDir()
	s := blocklist.New()
	if err := s.SetOverlayDir(dir); err != nil {
		t.Fatal(err)
	}

	// Adding the same DNS alias twice must be a no-op.
	if err := s.AddEntry(blocklist.KindDNS, "Example.COM"); err != nil {
		t.Fatal(err)
	}
	if err := s.AddEntry(blocklist.KindDNS, "example.com"); err != nil {
		t.Fatal(err)
	}

	entries := s.ListEntries(blocklist.KindDNS)
	if len(entries) != 1 || entries[0] != "example.com" {
		t.Fatalf("expected one example.com entry, got %v", entries)
	}

	if !s.DNSBlocked("Example.COM") {
		t.Fatal("expected Example.COM to be blocked")
	}
	if !s.DNSBlocked("sub.Example.COM") {
		t.Fatal("expected sub.Example.COM to be blocked")
	}
	if s.DNSBlocked("other.test") {
		t.Fatal("expected other.test not to be blocked")
	}
}

func TestAddIPCIDRMetamorphic(t *testing.T) {
	dir := t.TempDir()
	s := blocklist.New()
	if err := s.SetOverlayDir(dir); err != nil {
		t.Fatal(err)
	}

	// Adding the same CIDR twice must be a no-op.
	if err := s.AddEntry(blocklist.KindIP, "1.2.3.0/24"); err != nil {
		t.Fatal(err)
	}
	if err := s.AddEntry(blocklist.KindIP, "1.2.3.0/24"); err != nil {
		t.Fatal(err)
	}

	entries := s.ListEntries(blocklist.KindIP)
	if len(entries) != 1 || entries[0] != "1.2.3.0/24" {
		t.Fatalf("expected one 1.2.3.0/24 entry, got %v", entries)
	}

	if !s.IPBlocked(net.ParseIP("1.2.3.99")) {
		t.Fatal("expected 1.2.3.99 to be blocked")
	}
}

func TestDNSBlockedAdversarial(t *testing.T) {
	dir := t.TempDir()
	s := blocklist.New()
	if err := s.SetOverlayDir(dir); err != nil {
		t.Fatal(err)
	}

	if err := s.AddEntry(blocklist.KindDNS, "LocalHost"); err != nil {
		t.Fatal(err)
	}
	if err := s.AddEntry(blocklist.KindDNS, "xn--bcher-kva.example"); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		host  string
		block bool
	}{
		{"localhost", true},
		{"LocalHost", true},
		{"localhost.", true},
		{".localhost", true},
		{"*.localhost", true},
		{"sub.localhost", true},
		{"localhost:8080", true},
		{"127.0.0.1", false},
		{"127.0.0.1:8080", false},
		{"xn--bcher-kva.example", true},
		{"XN--bcher-kva.Example", true},
		{"bücher.example", false},
		{"other.test", false},
	}

	for _, tc := range cases {
		got := s.DNSBlocked(tc.host)
		if got != tc.block {
			t.Fatalf("DNSBlocked(%q): got %v, want %v", tc.host, got, tc.block)
		}
	}
}

func TestParseIPOrCIDRAdversarial(t *testing.T) {
	cases := []string{
		"",
		"not-an-ip",
		"\xff\xfe",
		"\x80\x81",
		"\x001.2.3.4",
		"1.2.3.4/33",
		"::/129",
		"1.2.3.4/",
		"/24",
		"1.2.3.4:80",
		"[::1]:443",
		"fe80::1%eth0",
		strings.Repeat("x", 1<<20),
	}

	for _, s := range cases {
		func(s string) {
			defer func() {
				if recover() != nil {
					t.Fatalf("ParseIPOrCIDR(%q) panicked", s)
				}
			}()

			if _, err := blocklist.ParseIPOrCIDR(s); err == nil {
				t.Fatalf("ParseIPOrCIDR(%q) accepted invalid input", s)
			}
		}(s)
	}
}
