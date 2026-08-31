// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package iputil

import (
	"net"
	"net/http"

	"github.com/Quad4-Software/ravenguard/internal/faststr"
)

func ParseIP(s string) net.IP {
	s = faststr.TrimSpace(s)
	if s == "" {
		return nil
	}
	if host, _, err := net.SplitHostPort(s); err == nil {
		s = host
	}
	if len(s) >= 2 && s[0] == '[' {
		if i := len(s) - 1; s[i] == ']' {
			s = s[1:i]
		}
	}
	return net.ParseIP(s)
}

func ClientIP(r *http.Request, trusted []net.IPNet, header string) net.IP {
	remote := ParseIP(r.RemoteAddr)
	if remote == nil {
		return nil
	}
	if !isTrusted(remote, trusted) || header == "" {
		return remote
	}
	raw := r.Header.Get(header)
	if raw == "" {
		return remote
	}
	if !equalFoldASCII(header, "X-Forwarded-For") && !containsByte(raw, ',') {
		ip := ParseIP(raw)
		if ip != nil {
			return ip
		}
		return remote
	}
	for i := len(raw); i > 0; {
		j := i - 1
		for j >= 0 && raw[j] != ',' {
			j--
		}
		part := faststr.TrimSpace(raw[j+1 : i])
		i = j
		if part == "" {
			continue
		}
		ip := ParseIP(part)
		if ip == nil {
			continue
		}
		if isTrusted(ip, trusted) {
			continue
		}
		return ip
	}
	return remote
}

func RequestHTTPS(r *http.Request, protoHeader string) bool {
	if r == nil {
		return false
	}
	if r.TLS != nil {
		return true
	}
	if protoHeader != "" {
		p := faststr.TrimSpace(r.Header.Get(protoHeader))
		if equalFoldASCII(p, "https") {
			return true
		}
		if equalFoldASCII(p, "http") {
			return false
		}
	}
	if fwd := r.Header.Get("Forwarded"); fwd != "" {
		if faststr.ContainsFold(fwd, "proto=https") {
			return true
		}
		if faststr.ContainsFold(fwd, "proto=http") {
			return false
		}
	}
	return false
}

func SetClientForwardHeaders(r *http.Request, clientIP net.IP, proto string) {
	if r == nil || clientIP == nil {
		return
	}
	SetClientForwardHeadersIP(r, clientIP.String(), proto)
}

func SetClientForwardHeadersIP(r *http.Request, ip, proto string) {
	if r == nil || ip == "" {
		return
	}
	r.Header.Set("X-Real-IP", ip)
	r.Header.Set("X-Forwarded-For", ip)
	if proto != "" {
		r.Header.Set("X-Forwarded-Proto", proto)
	}
}

func ParseCIDRs(list []string) ([]net.IPNet, error) {
	out := make([]net.IPNet, 0, len(list))
	for _, s := range list {
		s = faststr.TrimSpace(s)
		if s == "" {
			continue
		}
		if !containsByte(s, '/') {
			ip := net.ParseIP(s)
			if ip == nil {
				return nil, &net.ParseError{Type: "IP address", Text: s}
			}
			if ip4 := ip.To4(); ip4 != nil {
				out = append(out, net.IPNet{IP: ip4, Mask: net.CIDRMask(32, 32)})
			} else {
				out = append(out, net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)})
			}
			continue
		}
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			return nil, err
		}
		out = append(out, *n)
	}
	return out, nil
}

func isTrusted(ip net.IP, nets []net.IPNet) bool {
	for i := range nets {
		if nets[i].Contains(ip) {
			return true
		}
	}
	return false
}

func ContainsIP(nets []net.IPNet, ip net.IP) bool {
	return isTrusted(ip, nets)
}

func containsByte(s string, c byte) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return true
		}
	}
	return false
}

func equalFoldASCII(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if ca == cb {
			continue
		}
		if ca >= 'A' && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}
