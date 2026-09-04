// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package blocklist

import (
	"bufio"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"
	"unicode"

	"github.com/Quad4-Software/ravenguard/internal/faststr"
)

type Sets struct {
	ips        atomic.Pointer[[]net.IPNet]
	dns        atomic.Pointer[map[string]struct{}]
	uas        atomic.Pointer[[]string]
	stop       chan struct{}
	lastReload atomic.Int64
	ipFiles    []string
	dnsFiles   []string
	uaFiles    []string
	overlayDir string
}

func New() *Sets {
	s := &Sets{stop: make(chan struct{})}
	emptyNets := []net.IPNet{}
	emptyDNS := map[string]struct{}{}
	emptyUA := []string{}
	s.ips.Store(&emptyNets)
	s.dns.Store(&emptyDNS)
	s.uas.Store(&emptyUA)
	return s
}

func (s *Sets) Load(ipFiles, dnsFiles, uaFiles []string) error {
	ips, err := loadIPFiles(ipFiles)
	if err != nil {
		return err
	}
	dns, err := loadStringFiles(dnsFiles, true)
	if err != nil {
		return err
	}
	uas, err := loadStringList(uaFiles)
	if err != nil {
		return err
	}
	s.ips.Store(&ips)
	s.dns.Store(&dns)
	s.uas.Store(&uas)
	s.ipFiles = append([]string(nil), ipFiles...)
	s.dnsFiles = append([]string(nil), dnsFiles...)
	s.uaFiles = append([]string(nil), uaFiles...)
	s.attachOverlayFiles()
	s.lastReload.Store(time.Now().UnixNano())
	return nil
}

func (s *Sets) StartReload(ipFiles, dnsFiles, uaFiles []string, every time.Duration) {
	if every <= 0 {
		return
	}
	s.ipFiles = append([]string(nil), ipFiles...)
	s.dnsFiles = append([]string(nil), dnsFiles...)
	s.uaFiles = append([]string(nil), uaFiles...)
	s.attachOverlayFiles()
	go func() {
		t := time.NewTicker(every)
		defer t.Stop()
		for {
			select {
			case <-s.stop:
				return
			case <-t.C:
				_ = s.Load(s.ipFiles, s.dnsFiles, s.uaFiles)
			}
		}
	}()
}

func (s *Sets) ReloadNow() error {
	s.attachOverlayFiles()
	return s.Load(s.ipFiles, s.dnsFiles, s.uaFiles)
}

type Stats struct {
	IPCount    int       `json:"ip_count"`
	DNSCount   int       `json:"dns_count"`
	UACount    int       `json:"ua_count"`
	LastReload time.Time `json:"last_reload"`
}

func (s *Sets) Stats() Stats {
	var st Stats
	if s == nil {
		return st
	}
	if ips := s.ips.Load(); ips != nil {
		st.IPCount = len(*ips)
	}
	if dns := s.dns.Load(); dns != nil {
		st.DNSCount = len(*dns)
	}
	if uas := s.uas.Load(); uas != nil {
		st.UACount = len(*uas)
	}
	if n := s.lastReload.Load(); n > 0 {
		st.LastReload = time.Unix(0, n)
	}
	return st
}

func (s *Sets) Stop() {
	select {
	case <-s.stop:
	default:
		close(s.stop)
	}
}

func (s *Sets) IPBlocked(ip net.IP) bool {
	if ip == nil {
		return false
	}
	nets := s.ips.Load()
	if nets == nil {
		return false
	}
	for i := range *nets {
		if (*nets)[i].Contains(ip) {
			return true
		}
	}
	return false
}

func (s *Sets) DNSBlocked(host string) bool {
	host = normalizeHost(host)
	if host == "" {
		return false
	}
	m := s.dns.Load()
	if m == nil {
		return false
	}
	if _, ok := (*m)[host]; ok {
		return true
	}
	for h := host; ; {
		i := strings.IndexByte(h, '.')
		if i < 0 {
			return false
		}
		h = h[i+1:]
		if _, ok := (*m)[h]; ok {
			return true
		}
	}
}

func (s *Sets) UABlocked(ua string) bool {
	list := s.uas.Load()
	if list == nil {
		return false
	}
	for _, p := range *list {
		if p != "" && faststr.ContainsFold(ua, p) {
			return true
		}
	}
	return false
}

func loadIPFiles(files []string) ([]net.IPNet, error) {
	var out []net.IPNet
	for _, f := range files {
		lines, err := readLines(f)
		if err != nil {
			return nil, err
		}
		for _, line := range lines {
			n, err := parseIPOrCIDR(line)
			if err != nil {
				continue
			}
			out = append(out, n)
		}
	}
	return out, nil
}

func loadStringFiles(files []string, asHost bool) (map[string]struct{}, error) {
	out := make(map[string]struct{})
	for _, f := range files {
		lines, err := readLines(f)
		if err != nil {
			return nil, err
		}
		for _, line := range lines {
			if asHost {
				line = normalizeHost(line)
			}
			if line == "" {
				continue
			}
			out[line] = struct{}{}
		}
	}
	return out, nil
}

func loadStringList(files []string) ([]string, error) {
	var out []string
	for _, f := range files {
		lines, err := readLines(f)
		if err != nil {
			return nil, err
		}
		for _, line := range lines {
			line = strings.ToLower(strings.TrimSpace(line))
			if line == "" {
				continue
			}
			out = append(out, line)
		}
	}
	return out, nil
}

func readLines(path string) ([]string, error) {
	f, err := os.Open(filepath.Clean(path)) // #nosec G304
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	var lines []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" {
			continue
		}
		lines = append(lines, line)
	}
	return lines, sc.Err()
}

func parseIPOrCIDR(s string) (net.IPNet, error) {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "/") {
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			return net.IPNet{}, err
		}
		return *n, nil
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return net.IPNet{}, &net.ParseError{Type: "IP address", Text: s}
	}
	if ip4 := ip.To4(); ip4 != nil {
		return net.IPNet{IP: ip4, Mask: net.CIDRMask(32, 32)}, nil
	}
	return net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}, nil
}

func normalizeHost(h string) string {
	h = strings.TrimSpace(h)
	h = strings.ToLower(h)
	h = strings.TrimPrefix(h, "*.")
	h = strings.Trim(h, ".")
	h = strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, h)
	if i := strings.IndexByte(h, '/'); i >= 0 {
		h = h[:i]
	}
	if i := strings.IndexByte(h, ':'); i >= 0 && !strings.Contains(h, "]") {
		if net.ParseIP(h) == nil {
			h = h[:i]
		}
	}
	return h
}

func ParseIPOrCIDR(s string) (net.IPNet, error) {
	return parseIPOrCIDR(s)
}

func NormalizeHost(h string) string {
	return normalizeHost(h)
}
