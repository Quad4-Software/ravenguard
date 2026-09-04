// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package allowlist

import (
	"bufio"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Quad4-Software/ravenguard/internal/blocklist"
	"github.com/Quad4-Software/ravenguard/internal/faststr"
)

// headerRule is an exact header name and value pair.
// Header name lookup uses http.Header.Get (case-insensitive).
type headerRule struct {
	name  string
	value string
}

// Sets holds IP, User-Agent, and header allowlists that skip detect and challenge.
type Sets struct {
	ips         atomic.Pointer[[]net.IPNet]
	uas         atomic.Pointer[[]string]
	headers     atomic.Pointer[[]headerRule]
	stop        chan struct{}
	lastReload  atomic.Int64
	ipFiles     []string
	uaFiles     []string
	headerFiles []string
}

// New returns empty allowlist sets.
func New() *Sets {
	s := &Sets{stop: make(chan struct{})}
	emptyNets := []net.IPNet{}
	emptyUA := []string{}
	emptyHdr := []headerRule{}
	s.ips.Store(&emptyNets)
	s.uas.Store(&emptyUA)
	s.headers.Store(&emptyHdr)
	return s
}

// Load replaces allowlist contents from the given files.
func (s *Sets) Load(ipFiles, uaFiles, headerFiles []string) error {
	ips, err := loadIPFiles(ipFiles)
	if err != nil {
		return err
	}
	uas, err := loadUAFiles(uaFiles)
	if err != nil {
		return err
	}
	hdrs, err := loadHeaderFiles(headerFiles)
	if err != nil {
		return err
	}
	s.ips.Store(&ips)
	s.uas.Store(&uas)
	s.headers.Store(&hdrs)
	s.ipFiles = append([]string(nil), ipFiles...)
	s.uaFiles = append([]string(nil), uaFiles...)
	s.headerFiles = append([]string(nil), headerFiles...)
	s.lastReload.Store(time.Now().UnixNano())
	return nil
}

// StartReload periodically reloads the configured files.
func (s *Sets) StartReload(ipFiles, uaFiles, headerFiles []string, every time.Duration) {
	if every <= 0 {
		return
	}
	s.ipFiles = append([]string(nil), ipFiles...)
	s.uaFiles = append([]string(nil), uaFiles...)
	s.headerFiles = append([]string(nil), headerFiles...)
	go func() {
		t := time.NewTicker(every)
		defer t.Stop()
		for {
			select {
			case <-s.stop:
				return
			case <-t.C:
				_ = s.Load(s.ipFiles, s.uaFiles, s.headerFiles)
			}
		}
	}()
}

// ReloadNow reloads from the last configured file paths.
func (s *Sets) ReloadNow() error {
	return s.Load(s.ipFiles, s.uaFiles, s.headerFiles)
}

// Stats summarizes loaded entry counts.
type Stats struct {
	IPCount     int       `json:"ip_count"`
	UACount     int       `json:"ua_count"`
	HeaderCount int       `json:"header_count"`
	LastReload  time.Time `json:"last_reload"`
}

// Stats returns current sizes and last reload time.
func (s *Sets) Stats() Stats {
	var st Stats
	if s == nil {
		return st
	}
	if ips := s.ips.Load(); ips != nil {
		st.IPCount = len(*ips)
	}
	if uas := s.uas.Load(); uas != nil {
		st.UACount = len(*uas)
	}
	if hdrs := s.headers.Load(); hdrs != nil {
		st.HeaderCount = len(*hdrs)
	}
	if n := s.lastReload.Load(); n > 0 {
		st.LastReload = time.Unix(0, n)
	}
	return st
}

// Stop ends the reload goroutine.
func (s *Sets) Stop() {
	select {
	case <-s.stop:
	default:
		close(s.stop)
	}
}

// Empty reports whether no allowlist entries are loaded.
func (s *Sets) Empty() bool {
	if s == nil {
		return true
	}
	st := s.Stats()
	return st.IPCount == 0 && st.UACount == 0 && st.HeaderCount == 0
}

// Match reports whether the client IP, User-Agent, or headers match any allowlist entry.
// Any single match is enough. Empty sets never match.
func (s *Sets) Match(ip net.IP, ua string, hdr http.Header) bool {
	if s == nil {
		return false
	}
	if s.matchIP(ip) {
		return true
	}
	if s.matchUA(ua) {
		return true
	}
	return s.matchHeaders(hdr)
}

func (s *Sets) matchIP(ip net.IP) bool {
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

func (s *Sets) matchUA(ua string) bool {
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

func (s *Sets) matchHeaders(hdr http.Header) bool {
	if hdr == nil {
		return false
	}
	rules := s.headers.Load()
	if rules == nil {
		return false
	}
	for _, rule := range *rules {
		if rule.name == "" {
			continue
		}
		if hdr.Get(rule.name) == rule.value {
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
			n, err := blocklist.ParseIPOrCIDR(line)
			if err != nil {
				continue
			}
			out = append(out, n)
		}
	}
	return out, nil
}

func loadUAFiles(files []string) ([]string, error) {
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

func loadHeaderFiles(files []string) ([]headerRule, error) {
	var out []headerRule
	for _, f := range files {
		lines, err := readLines(f)
		if err != nil {
			return nil, err
		}
		for _, line := range lines {
			name, value, ok := parseHeaderLine(line)
			if !ok {
				continue
			}
			out = append(out, headerRule{name: name, value: value})
		}
	}
	return out, nil
}

func parseHeaderLine(line string) (name, value string, ok bool) {
	line = strings.TrimSpace(line)
	if line == "" {
		return "", "", false
	}
	i := strings.IndexByte(line, ':')
	if i <= 0 {
		return "", "", false
	}
	name = strings.TrimSpace(line[:i])
	value = strings.TrimSpace(line[i+1:])
	if name == "" {
		return "", "", false
	}
	return name, value, true
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
