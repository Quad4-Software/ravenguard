// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package iputil_test

import (
	"math/rand"
	"net"
	"net/netip"
	"strings"
	"testing"

	"github.com/Quad4-Software/ravenguard/internal/iputil"
)

// randomAddr returns a pseudorandom netip.Addr. It may be IPv4, IPv6, or
// IPv6 with a zone. IPv4-mapped IPv6 addresses are avoided because Go's net
// package collapses them to IPv4 while netip keeps them distinct.
func randomAddr(r *rand.Rand) netip.Addr {
	switch r.Intn(10) {
	case 0, 1, 2, 3, 4, 5, 6:
		var b [4]byte
		for i := range b {
			b[i] = byte(r.Intn(256))
		}
		return netip.AddrFrom4(b)
	case 7, 8:
		return randomV6(r)
	default:
		return randomV6(r).WithZone(randomZone(r))
	}
}

// randomNonMappedNoZoneAddr returns a random address that is not IPv4-mapped
// and has no zone, suitable for CIDR containment tests.
func randomNonMappedNoZoneAddr(r *rand.Rand) netip.Addr {
	if r.Intn(2) == 0 {
		var b [4]byte
		for i := range b {
			b[i] = byte(r.Intn(256))
		}
		return netip.AddrFrom4(b)
	}
	return randomV6(r)
}

func randomV6(r *rand.Rand) netip.Addr {
	var b [16]byte
	for i := range b {
		b[i] = byte(r.Intn(256))
	}
	// Avoid the IPv4-mapped prefix ::ffff:0:0/96.
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

func randomZone(r *rand.Rand) string {
	zones := []string{"eth0", "lo", "1", "docker0"}
	return zones[r.Intn(len(zones))]
}

// wrapIP turns a canonical address into a string that iputil.ParseIP may see in
// real traffic. IPv6 with ports must be bracketed, otherwise ParseIP returns nil.
func wrapIP(r *rand.Rand, addr netip.Addr) string {
	base := addr.String()
	choices := []string{base, " " + base + " ", "[" + base + "]:443", "[" + base + "]"}
	if addr.Is4() || addr.Is4In6() {
		choices = append(choices, base+":80", base+":443")
	}
	return choices[r.Intn(len(choices))]
}

// netipRefForCIDR returns the canonical netip.Prefix for a single CIDR or IP
// string. It trims leading and trailing whitespace to match ParseCIDRs behavior.
func netipRefForCIDR(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, err
		}
		if p.Masked().Addr().Is4In6() {
			// IPv4-mapped CIDRs are treated specially by net.ParseCIDR. Skip
			// them in differential checks; invariants are still tested.
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

// randomCIDRString returns either a canonical or non-canonical CIDR string.
func randomCIDRString(r *rand.Rand, canonical bool) string {
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
	a := randomV6(r)
	bits := r.Intn(129)
	p := netip.PrefixFrom(a, bits)
	if canonical {
		p = p.Masked()
	}
	return p.String()
}

func TestParseIPDiffAndMetamorphic(t *testing.T) {
	r := rand.New(rand.NewSource(1))

	for range 200 {
		addr := randomAddr(r)
		s := wrapIP(r, addr)

		got := iputil.ParseIP(s)
		wantNet := net.ParseIP(addr.String())
		wantAddr, refErr := netip.ParseAddr(addr.String())

		if wantNet == nil {
			if got != nil {
				t.Fatalf("ParseIP(%q)=%q, want nil", s, got.String())
			}
			continue
		}

		if got == nil {
			t.Fatalf("ParseIP(%q)=nil, want %q", s, wantNet.String())
		}

		if got.String() != wantNet.String() {
			t.Fatalf("ParseIP(%q)=%q, want %q from net.ParseIP", s, got.String(), wantNet.String())
		}

		if refErr == nil && wantAddr.Zone() == "" {
			want := wantAddr.Unmap().String()
			if got.String() != want {
				t.Fatalf("ParseIP(%q)=%q, want %q from netip.ParseAddr", s, got.String(), want)
			}
		}

		// Metamorphic: parsing the canonical string again gives the same IP.
		got2 := iputil.ParseIP(got.String())
		if got2 == nil || got2.String() != got.String() {
			t.Fatalf("round-trip ParseIP(%q) -> %q -> %v", s, got.String(), got2)
		}

		// Metamorphic: parsing the same input twice is stable.
		got3 := iputil.ParseIP(s)
		if got3 == nil || got3.String() != got.String() {
			t.Fatalf("ParseIP is not stable for %q: got %v then %v", s, got, got3)
		}
	}
}

func TestParseCIDRsDiffAndMetamorphic(t *testing.T) {
	r := rand.New(rand.NewSource(2))

	for range 80 {
		n := r.Intn(5) + 1
		list := make([]string, 0, n)
		for range n {
			// Mix canonical and non-canonical CIDRs.
			list = append(list, randomCIDRString(r, r.Intn(2) == 0))
		}

		nets, err := iputil.ParseCIDRs(list)
		if err != nil {
			t.Fatalf("ParseCIDRs(%v): %v", list, err)
		}

		if len(nets) != len(list) {
			t.Fatalf("ParseCIDRs returned %d nets for %d inputs", len(nets), len(list))
		}

		var canon []string
		for i, s := range list {
			n := nets[i]

			// Invariants: the network contains its own address and the mask is
			// well-formed.
			if !n.Contains(n.IP) {
				t.Fatalf("network %s does not contain %v", n.String(), n.IP)
			}
			ones, bits := n.Mask.Size()
			if ones < 0 || ones > bits || (bits != 32 && bits != 128) {
				t.Fatalf("network %s has invalid mask size %d/%d", n.String(), ones, bits)
			}

			// Differential against netip.Prefix.
			ref, refErr := netipRefForCIDR(s)
			if refErr != nil {
				t.Fatalf("ParseCIDRs accepted %q but netip rejects it: %v", s, refErr)
			}
			if ref.IsValid() && n.String() != ref.String() {
				t.Fatalf("ParseCIDRs(%q)=%q, want %q", s, n.String(), ref.String())
			}

			// Differential containment for a few random addresses.
			for range 5 {
				a := randomNonMappedNoZoneAddr(r)
				if !ref.IsValid() {
					continue
				}
				got := n.Contains(net.ParseIP(a.String()))
				want := ref.Contains(a)
				if got != want {
					t.Fatalf("Contains for %s and %s: got %v, want %v", n.String(), a.String(), got, want)
				}
			}

			canon = append(canon, n.String())
		}

		// Metamorphic: reparsing the canonical string list is idempotent.
		nets2, err2 := iputil.ParseCIDRs(canon)
		if err2 != nil {
			t.Fatalf("re-ParseCIDRs(%v): %v", canon, err2)
		}
		if len(nets2) != len(nets) {
			t.Fatalf("re-ParseCIDRs returned %d nets, want %d", len(nets2), len(nets))
		}
		for i := range nets {
			if nets2[i].String() != nets[i].String() {
				t.Fatalf("ParseCIDRs is not idempotent: got %q then %q", nets[i].String(), nets2[i].String())
			}
		}
	}
}

func TestContainsIPDiff(t *testing.T) {
	r := rand.New(rand.NewSource(3))

	for range 80 {
		n := r.Intn(5) + 1
		list := make([]string, 0, n)
		for range n {
			list = append(list, randomCIDRString(r, true))
		}

		nets, err := iputil.ParseCIDRs(list)
		if err != nil {
			t.Fatalf("ParseCIDRs(%v): %v", list, err)
		}

		for range 50 {
			addr := randomNonMappedNoZoneAddr(r)

			// Compute the expected result using the independent netip oracle.
			want := false
			for _, s := range list {
				ref, err := netipRefForCIDR(s)
				if err != nil || !ref.IsValid() {
					continue
				}
				if ref.Contains(addr) {
					want = true
					break
				}
			}

			ip := net.ParseIP(addr.String())
			got := iputil.ContainsIP(nets, ip)
			if got != want {
				t.Fatalf("ContainsIP(%v, %s): got %v, want %v", list, addr.String(), got, want)
			}
		}
	}
}

func TestParseIPAdversarial(t *testing.T) {
	cases := []string{
		"",
		"not-an-ip",
		"\xff\xfe",
		"\x80\x81",
		"1.2.\x003.4",
		"1.2.3.4\x005.6",
		"\x00::1",
		strings.Repeat("x", 1<<20),
		strings.Repeat(" ", 1<<20) + "1.2.3.4" + strings.Repeat(" ", 1<<20),
		"fe80::1%eth0",
		"[fe80::1%eth0]:80",
		"\u00a0 1.2.3.4",
		"::/129",
	}

	for _, s := range cases {
		func(s string) {
			defer func() {
				if recover() != nil {
					t.Fatalf("ParseIP(%q) panicked", s)
				}
			}()

			_ = iputil.ParseIP(s)
		}(s)
	}
}

func TestParseCIDRsAdversarial(t *testing.T) {
	cases := [][]string{
		{},
		{""},
		{"  "},
		{"# comment"},
		{"1.2.3.4/33"},
		{"::/129"},
		{"1.2.3.4/"},
		{"/24"},
		{"not-an-ip"},
		{"1.2.3.4:80"},
		{"[::1]:443"},
		{"fe80::1%eth0"},
		{"\xff\xfe"},
		{"\x001.2.3.4"},
		{strings.Repeat("x", 1<<20)},
		{"1.2.3.0/24", "invalid", "2001:db8::/32"},
	}

	for _, list := range cases {
		func(list []string) {
			defer func() {
				if recover() != nil {
					t.Fatalf("ParseCIDRs(%v) panicked", list)
				}
			}()

			_, err := iputil.ParseCIDRs(list)
			// Empty and all-whitespace entries are silently skipped, but any
			// non-empty invalid input must produce an error.
			hasNonEmpty := false
			for _, s := range list {
				if strings.TrimSpace(s) != "" {
					hasNonEmpty = true
					break
				}
			}
			if hasNonEmpty && err == nil {
				t.Fatalf("ParseCIDRs(%v) accepted invalid input", list)
			}
		}(list)
	}
}

func TestContainsIPAdversarial(t *testing.T) {
	nets, err := iputil.ParseCIDRs([]string{"1.2.3.0/24", "2001:db8::/32"})
	if err != nil {
		t.Fatal(err)
	}

	testCases := []struct {
		nets []net.IPNet
		ip   net.IP
	}{
		{nil, nil},
		{nil, net.ParseIP("1.2.3.4")},
		{nets, nil},
		{nets, net.ParseIP("invalid")},
		{[]net.IPNet{}, net.ParseIP("1.2.3.4")},
	}

	for _, tc := range testCases {
		func(nets []net.IPNet, ip net.IP) {
			defer func() {
				if recover() != nil {
					t.Fatalf("ContainsIP(%v, %v) panicked", nets, ip)
				}
			}()

			if iputil.ContainsIP(nets, ip) {
				t.Fatalf("ContainsIP(%v, %v) returned true", nets, ip)
			}
		}(tc.nets, tc.ip)
	}
}
