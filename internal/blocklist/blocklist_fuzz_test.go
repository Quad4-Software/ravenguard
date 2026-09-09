// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package blocklist_test

import (
	"net"
	"net/netip"
	"strings"
	"testing"
	"unicode"

	"github.com/Quad4-Software/ravenguard/internal/blocklist"
)

func FuzzParseIPOrCIDR(f *testing.F) {
	f.Add("")
	f.Add("1.2.3.4")
	f.Add("1.2.3.0/24")
	f.Add("1.2.3.4/24")
	f.Add("2001:db8::/32")
	f.Add("1.2.3.4/33")
	f.Add("::/129")
	f.Add("not-a-cidr")
	f.Add("[::1]:443")
	f.Add("\xff\xfe")

	f.Fuzz(func(t *testing.T, s string) {
		n, err := blocklist.ParseIPOrCIDR(s)
		if err != nil {
			return
		}

		ones, bits := n.Mask.Size()
		if ones < 0 || ones > bits || (bits != 32 && bits != 128) {
			t.Fatalf("ParseIPOrCIDR(%q) network %s has bad mask size %d/%d", s, n.String(), ones, bits)
		}

		if !n.Contains(n.IP) {
			t.Fatalf("ParseIPOrCIDR(%q) network %s does not contain %v", s, n.String(), n.IP)
		}

		n2, err2 := blocklist.ParseIPOrCIDR(n.String())
		if err2 != nil || n2.String() != n.String() {
			t.Fatalf("ParseIPOrCIDR(%q) idempotence failed", s)
		}

		ref, refErr := netipRefForCIDRBL(s)
		if refErr != nil || !ref.IsValid() {
			return
		}
		if n.String() != ref.String() {
			t.Fatalf("ParseIPOrCIDR(%q)=%q, want %q", s, n.String(), ref.String())
		}
	})
}

func FuzzIPBlocked(f *testing.F) {
	f.Add("1.2.3.0/24", "1.2.3.4")
	f.Add("1.2.3.4", "1.2.3.4")
	f.Add("2001:db8::/32", "2001:db8::1")
	f.Add("1.2.3.0/24", "invalid")
	f.Add("invalid", "1.2.3.4")
	f.Add("1.2.3.0/24", "1.2.4.1")
	f.Add("2001:db8::/32", "2001:db9::1")

	f.Fuzz(func(t *testing.T, cidr, ip string) {
		n, err := blocklist.ParseIPOrCIDR(cidr)
		if err != nil {
			return
		}

		parsed := net.ParseIP(ip)
		got := n.Contains(parsed)

		ipAddr, ipErr := netip.ParseAddr(ip)
		if ipErr != nil || ipAddr.Zone() != "" {
			// The blocklist cannot parse invalid or zoned addresses, so
			// containment must be false.
			if got {
				t.Fatalf("Contains(%q, %q) returned true for unparseable IP", cidr, ip)
			}
			return
		}

		ref, refErr := netipRefForCIDRBL(cidr)
		if refErr != nil || !ref.IsValid() {
			return
		}
		if ref.Masked().Addr().Is4In6() {
			// IPv4-mapped CIDRs are treated differently by net and netip.
			return
		}

		if ipAddr.Is4In6() {
			if !ref.Masked().Addr().Is4() {
				return
			}
			ipAddr = ipAddr.Unmap()
		}

		want := ref.Contains(ipAddr)
		if got != want {
			t.Fatalf("Contains(%q, %q): got %v, want %v", cidr, ip, got, want)
		}
	})
}

func FuzzNormalizeHost(f *testing.F) {
	f.Add("")
	f.Add("Example.COM")
	f.Add("*.evil.test")
	f.Add("host:443")
	f.Add(" spaces ")
	f.Add("xn--bcher-kva.example")
	f.Add("\xff\xfe")
	f.Add("host\x00null")

	f.Fuzz(func(t *testing.T, s string) {
		out := blocklist.NormalizeHost(s)

		if out != strings.ToLower(out) {
			t.Fatalf("NormalizeHost(%q)=%q is not lowercase", s, out)
		}

		out2 := blocklist.NormalizeHost(out)
		if out != out2 {
			t.Fatalf("NormalizeHost(%q) not idempotent: %q -> %q", s, out, out2)
		}

		if strings.IndexFunc(out, unicode.IsSpace) != -1 {
			t.Fatalf("NormalizeHost(%q)=%q contains whitespace", s, out)
		}

		if strings.HasPrefix(out, ".") || strings.HasSuffix(out, ".") {
			t.Fatalf("NormalizeHost(%q)=%q is wrapped in dots", s, out)
		}
	})
}
