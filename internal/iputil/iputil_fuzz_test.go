// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package iputil_test

import (
	"net"
	"net/netip"
	"testing"

	"github.com/Quad4-Software/ravenguard/internal/iputil"
)

func FuzzParseIP(f *testing.F) {
	f.Add("")
	f.Add("1.2.3.4")
	f.Add("  1.2.3.4  ")
	f.Add("1.2.3.4:80")
	f.Add("[::1]:443")
	f.Add("::1")
	f.Add("::ffff:1.2.3.4")
	f.Add("[::ffff:1.2.3.4]:80")
	f.Add("fe80::1%eth0")
	f.Add("[fe80::1%eth0]:80")
	f.Add("not-an-ip")
	f.Add("1.2.3.4/33")

	f.Fuzz(func(t *testing.T, s string) {
		ip := iputil.ParseIP(s)

		if ip != nil {
			// Implicit oracle: the canonical string must reparse to the same IP.
			ip2 := iputil.ParseIP(ip.String())
			if ip2 == nil || ip2.String() != ip.String() {
				t.Fatalf("ParseIP(%q) round-trip: got %q then %v", s, ip.String(), ip2)
			}

			// Implicit oracle: the canonical form must be a valid IP address.
			if a, err := netip.ParseAddr(ip.String()); err != nil || a.Unmap().String() != ip.String() {
				t.Fatalf("ParseIP(%q) produced invalid string %q", s, ip.String())
			}
		}

		// Differential against netip.ParseAddr when the input is a plain address.
		if a, err := netip.ParseAddr(s); err == nil {
			if a.Zone() == "" {
				want := a.Unmap().String()
				if ip == nil || ip.String() != want {
					t.Fatalf("ParseIP(%q)=%v, want %q", s, ip, want)
				}
			} else if ip != nil {
				t.Fatalf("ParseIP(%q)=%v, want nil for zoned address", s, ip)
			}
		}
	})
}

func FuzzParseCIDRs(f *testing.F) {
	f.Add("")
	f.Add("1.2.3.4")
	f.Add("  1.2.3.4  ")
	f.Add("1.2.3.0/24")
	f.Add("1.2.3.4/24")
	f.Add("2001:db8::/32")
	f.Add("2001:db8::1/128")
	f.Add("1.2.3.4/33")
	f.Add("::/129")
	f.Add("not-a-cidr")

	f.Fuzz(func(t *testing.T, s string) {
		nets, err := iputil.ParseCIDRs([]string{s})
		if err != nil {
			return
		}

		for i := range nets {
			n := &nets[i]

			ones, bits := n.Mask.Size()
			if ones < 0 || ones > bits || (bits != 32 && bits != 128) {
				t.Fatalf("ParseCIDRs(%q) network %s has bad mask size %d/%d", s, n.String(), ones, bits)
			}

			if !n.Contains(n.IP) {
				t.Fatalf("ParseCIDRs(%q) network %s does not contain %v", s, n.String(), n.IP)
			}

			nets2, err2 := iputil.ParseCIDRs([]string{n.String()})
			if err2 != nil || len(nets2) != 1 || nets2[0].String() != n.String() {
				t.Fatalf("ParseCIDRs(%q) idempotence failed on %s", s, n.String())
			}

			ref, refErr := netipRefForCIDR(s)
			if refErr != nil || !ref.IsValid() {
				continue
			}
			if n.String() != ref.String() {
				t.Fatalf("ParseCIDRs(%q)=%q, want %q", s, n.String(), ref.String())
			}
		}
	})
}

func FuzzContainsIP(f *testing.F) {
	f.Add("1.2.3.0/24", "1.2.3.4")
	f.Add("1.2.3.4", "1.2.3.4")
	f.Add("2001:db8::/32", "2001:db8::1")
	f.Add("invalid", "1.2.3.4")
	f.Add("1.2.3.0/24", "invalid")
	f.Add("1.2.3.0/24", "1.2.4.1")
	f.Add("2001:db8::/32", "2001:db9::1")

	f.Fuzz(func(t *testing.T, cidr, ip string) {
		nets, err := iputil.ParseCIDRs([]string{cidr})
		if err != nil {
			return
		}

		for i := range nets {
			if !nets[i].Contains(nets[i].IP) {
				t.Fatalf("ParseCIDRs(%q) produced network %s that does not contain itself", cidr, nets[i].String())
			}
		}

		parsed := net.ParseIP(ip)
		got := iputil.ContainsIP(nets, parsed)

		ipAddr, ipErr := netip.ParseAddr(ip)
		if ipErr != nil || ipAddr.Zone() != "" {
			// iputil cannot parse invalid or zoned addresses, so ContainsIP must
			// return false.
			if got {
				t.Fatalf("ContainsIP(%q, %q) returned true for unparseable IP", cidr, ip)
			}
			return
		}

		ref, refErr := netipRefForCIDR(cidr)
		if refErr != nil || !ref.IsValid() {
			return
		}

		if ref.Masked().Addr().Is4In6() {
			// IPv4-mapped CIDRs have different semantics between net and netip.
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
			t.Fatalf("ContainsIP(%q, %q): got %v, want %v", cidr, ip, got, want)
		}
	})
}
