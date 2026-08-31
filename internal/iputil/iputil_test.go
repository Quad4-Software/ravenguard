// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package iputil_test

import (
	"crypto/tls"
	"net"
	"net/http"
	"testing"

	"github.com/Quad4-Software/ravenguard/internal/iputil"
)

func TestParseIP(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"1.2.3.4:80", "1.2.3.4"},
		{"[2001:db8::1]:443", "2001:db8::1"},
		{"2001:db8::1", "2001:db8::1"},
		{"", ""},
	}
	for _, tc := range cases {
		got := iputil.ParseIP(tc.in)
		if tc.want == "" {
			if got != nil {
				t.Fatalf("%q: got %v", tc.in, got)
			}
			continue
		}
		if got == nil || got.String() != tc.want {
			t.Fatalf("%q: got %v want %s", tc.in, got, tc.want)
		}
	}
}

func TestClientIPTrustedXFF(t *testing.T) {
	trusted, err := iputil.ParseCIDRs([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	r := &http.Request{
		RemoteAddr: "10.0.0.5:1234",
		Header:     http.Header{"X-Forwarded-For": []string{"203.0.113.9, 10.0.0.5"}},
	}
	ip := iputil.ClientIP(r, trusted, "X-Forwarded-For")
	if ip == nil || ip.String() != "203.0.113.9" {
		t.Fatalf("got %v", ip)
	}
}

func TestClientIPSpoofedLeftIgnored(t *testing.T) {
	trusted, err := iputil.ParseCIDRs([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	r := &http.Request{
		RemoteAddr: "10.0.0.5:1234",
		Header:     http.Header{"X-Forwarded-For": []string{"198.51.100.1, 203.0.113.9, 10.0.0.5"}},
	}
	ip := iputil.ClientIP(r, trusted, "X-Forwarded-For")
	if ip == nil || ip.String() != "203.0.113.9" {
		t.Fatalf("got %v want 203.0.113.9", ip)
	}
}

func TestClientIPUntrustedRemoteIgnoresHeader(t *testing.T) {
	trusted, err := iputil.ParseCIDRs([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	r := &http.Request{RemoteAddr: "198.51.100.20:1234", Header: make(http.Header)}
	r.Header.Set("X-Real-IP", "203.0.113.9")
	ip := iputil.ClientIP(r, trusted, "X-Real-IP")
	if ip == nil || ip.String() != "198.51.100.20" {
		t.Fatalf("got %v", ip)
	}
}

func TestClientIPRealIP(t *testing.T) {
	trusted, err := iputil.ParseCIDRs([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	r := &http.Request{RemoteAddr: "10.0.0.5:1234", Header: make(http.Header)}
	r.Header.Set("X-Real-IP", "203.0.113.44")
	ip := iputil.ClientIP(r, trusted, "X-Real-IP")
	if ip == nil || ip.String() != "203.0.113.44" {
		t.Fatalf("got %v", ip)
	}
}

func TestRequestHTTPS(t *testing.T) {
	r := &http.Request{Header: http.Header{"X-Forwarded-Proto": []string{"https"}}}
	if !iputil.RequestHTTPS(r, "X-Forwarded-Proto") {
		t.Fatal("expected https from proto header")
	}
	r2 := &http.Request{Header: http.Header{"X-Forwarded-Proto": []string{"http"}}}
	if iputil.RequestHTTPS(r2, "X-Forwarded-Proto") {
		t.Fatal("expected http")
	}
	r3 := &http.Request{TLS: &tls.ConnectionState{}}
	if !iputil.RequestHTTPS(r3, "X-Forwarded-Proto") {
		t.Fatal("expected tls")
	}
	r4 := &http.Request{Header: http.Header{"Forwarded": []string{"for=1.2.3.4;proto=https"}}}
	if !iputil.RequestHTTPS(r4, "") {
		t.Fatal("expected forwarded proto")
	}
}

func TestSetClientForwardHeaders(t *testing.T) {
	r := &http.Request{Header: http.Header{"X-Forwarded-For": []string{"1.1.1.1, 2.2.2.2"}}}
	iputil.SetClientForwardHeaders(r, net.ParseIP("203.0.113.9"), "https")
	if r.Header.Get("X-Real-IP") != "203.0.113.9" {
		t.Fatalf("xri=%q", r.Header.Get("X-Real-IP"))
	}
	if r.Header.Get("X-Forwarded-For") != "203.0.113.9" {
		t.Fatalf("xff=%q", r.Header.Get("X-Forwarded-For"))
	}
	if r.Header.Get("X-Forwarded-Proto") != "https" {
		t.Fatalf("proto=%q", r.Header.Get("X-Forwarded-Proto"))
	}
}

func TestContainsCIDR(t *testing.T) {
	nets, err := iputil.ParseCIDRs([]string{"2001:db8::/32", "198.51.100.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	if !iputil.ContainsIP(nets, net.ParseIP("198.51.100.10")) {
		t.Fatal("expected v4 hit")
	}
	if !iputil.ContainsIP(nets, net.ParseIP("2001:db8::abcd")) {
		t.Fatal("expected v6 hit")
	}
}

func FuzzParseIP(f *testing.F) {
	f.Add("1.2.3.4")
	f.Add("[::1]:80")
	f.Add("not-an-ip")
	f.Fuzz(func(t *testing.T, s string) {
		_ = iputil.ParseIP(s)
	})
}
