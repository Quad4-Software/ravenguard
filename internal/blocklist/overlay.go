// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package blocklist

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
)

const (
	KindIP  = "ip"
	KindDNS = "dns"
	KindUA  = "ua"
)

// SetOverlayDir configures writable overlay files under dir that are merged into loads.
func (s *Sets) SetOverlayDir(dir string) error {
	if s == nil || strings.TrimSpace(dir) == "" {
		return nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	for _, name := range []string{"ips.txt", "dns.txt", "ua.txt"} {
		p := filepath.Join(dir, name)
		if _, err := os.Stat(p); os.IsNotExist(err) {
			if err := os.WriteFile(p, []byte("# RavenGuard admin overlay\n"), 0o600); err != nil {
				return err
			}
		}
	}
	s.overlayDir = dir
	s.attachOverlayFiles()
	return s.ReloadNow()
}

func (s *Sets) attachOverlayFiles() {
	if s.overlayDir == "" {
		return
	}
	ip := filepath.Join(s.overlayDir, "ips.txt")
	dns := filepath.Join(s.overlayDir, "dns.txt")
	ua := filepath.Join(s.overlayDir, "ua.txt")
	s.ipFiles = prependUnique(s.ipFiles, ip)
	s.dnsFiles = prependUnique(s.dnsFiles, dns)
	s.uaFiles = prependUnique(s.uaFiles, ua)
}

func prependUnique(files []string, path string) []string {
	if slices.Contains(files, path) {
		return files
	}
	return append([]string{path}, files...)
}

func (s *Sets) OverlayDir() string {
	if s == nil {
		return ""
	}
	return s.overlayDir
}

func (s *Sets) Files() (ip, dns, ua []string) {
	if s == nil {
		return nil, nil, nil
	}
	return append([]string(nil), s.ipFiles...), append([]string(nil), s.dnsFiles...), append([]string(nil), s.uaFiles...)
}

func (s *Sets) ListEntries(kind string) []string {
	if s == nil {
		return nil
	}
	switch kind {
	case KindIP:
		nets := s.ips.Load()
		if nets == nil {
			return nil
		}
		out := make([]string, 0, len(*nets))
		for i := range *nets {
			out = append(out, (*nets)[i].String())
		}
		sort.Strings(out)
		return out
	case KindDNS:
		m := s.dns.Load()
		if m == nil {
			return nil
		}
		out := make([]string, 0, len(*m))
		for k := range *m {
			out = append(out, k)
		}
		sort.Strings(out)
		return out
	case KindUA:
		list := s.uas.Load()
		if list == nil {
			return nil
		}
		out := append([]string(nil), (*list)...)
		sort.Strings(out)
		return out
	default:
		return nil
	}
}

func (s *Sets) AddEntry(kind, value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return fmt.Errorf("empty entry")
	}
	path, err := s.overlayPath(kind)
	if err != nil {
		return err
	}
	switch kind {
	case KindIP:
		if _, err := parseIPOrCIDR(value); err != nil {
			return fmt.Errorf("invalid ip/cidr: %w", err)
		}
	case KindDNS:
		value = normalizeHost(value)
		if value == "" {
			return fmt.Errorf("invalid domain")
		}
	case KindUA:
		value = strings.ToLower(value)
	default:
		return fmt.Errorf("unknown kind %q", kind)
	}
	for _, e := range s.ListEntries(kind) {
		if strings.EqualFold(e, value) {
			return nil
		}
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600) // #nosec G304
	if err != nil {
		return err
	}
	_, werr := fmt.Fprintln(f, value)
	_ = f.Close()
	if werr != nil {
		return werr
	}
	return s.ReloadNow()
}

func (s *Sets) RemoveEntry(kind, value string) error {
	value = strings.TrimSpace(value)
	path, err := s.overlayPath(kind)
	if err != nil {
		return err
	}
	if kind == KindDNS {
		value = normalizeHost(value)
	}
	if kind == KindUA {
		value = strings.ToLower(value)
	}
	lines, err := readLines(path)
	if err != nil {
		return err
	}
	var kept []string
	removed := false
	for _, line := range lines {
		cmp := line
		if kind == KindDNS {
			cmp = normalizeHost(line)
		}
		if kind == KindUA {
			cmp = strings.ToLower(strings.TrimSpace(line))
		}
		if strings.EqualFold(cmp, value) {
			removed = true
			continue
		}
		kept = append(kept, line)
	}
	if !removed {
		// Also try removing from first non-overlay source file when present.
		return s.removeFromSources(kind, value)
	}
	var b strings.Builder
	b.WriteString("# RavenGuard admin overlay\n")
	for _, line := range kept {
		b.WriteString(line)
		b.WriteByte('\n')
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		return err
	}
	return s.ReloadNow()
}

func (s *Sets) removeFromSources(kind, value string) error {
	files := s.sourceFiles(kind)
	changed := false
	for _, path := range files {
		if s.overlayDir != "" && strings.HasPrefix(path, s.overlayDir) {
			continue
		}
		lines, err := readLines(path)
		if err != nil {
			continue
		}
		var kept []string
		local := false
		for _, line := range lines {
			cmp := line
			if kind == KindDNS {
				cmp = normalizeHost(line)
			}
			if kind == KindUA {
				cmp = strings.ToLower(strings.TrimSpace(line))
			}
			if kind == KindIP {
				if n, err := parseIPOrCIDR(line); err == nil {
					cmp = n.String()
				}
			}
			if strings.EqualFold(cmp, value) {
				local = true
				continue
			}
			kept = append(kept, line)
		}
		if !local {
			continue
		}
		var b strings.Builder
		for _, line := range kept {
			b.WriteString(line)
			b.WriteByte('\n')
		}
		if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
			return fmt.Errorf("write %s: %w (blocklist files may be read-only; use overlay)", path, err)
		}
		changed = true
	}
	if !changed {
		return fmt.Errorf("entry not found in writable lists")
	}
	return s.ReloadNow()
}

func (s *Sets) sourceFiles(kind string) []string {
	switch kind {
	case KindIP:
		return s.ipFiles
	case KindDNS:
		return s.dnsFiles
	case KindUA:
		return s.uaFiles
	default:
		return nil
	}
}

func (s *Sets) overlayPath(kind string) (string, error) {
	if s == nil || s.overlayDir == "" {
		return "", fmt.Errorf("blocklist overlay not configured")
	}
	switch kind {
	case KindIP:
		return filepath.Join(s.overlayDir, "ips.txt"), nil
	case KindDNS:
		return filepath.Join(s.overlayDir, "dns.txt"), nil
	case KindUA:
		return filepath.Join(s.overlayDir, "ua.txt"), nil
	default:
		return "", fmt.Errorf("unknown kind %q", kind)
	}
}
