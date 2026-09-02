// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package sandbox

import (
	"net"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
)

// DerivePaths fills filesystem and network allowances from process paths and
// listen/upstream settings. Caller-supplied paths in cfg are preserved.
func DerivePaths(cfg *Config, configPath string, listenHTTP, listenHTTPS, listenQUIC, upstreamURL string, tlsCert, tlsKey, acmeStorageDir string, blocklistFiles []string, adminListen, adminHTTPS, adminDataDir string) {
	addUnique := func(dst *[]string, paths ...string) {
		seen := make(map[string]struct{}, len(*dst))
		for _, p := range *dst {
			seen[p] = struct{}{}
		}
		for _, p := range paths {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			if _, ok := seen[p]; ok {
				continue
			}
			seen[p] = struct{}{}
			*dst = append(*dst, p)
		}
	}

	addUnique(&cfg.Landlock.RODirs,
		"/etc/ssl/certs",
		"/etc/ca-certificates",
		"/usr/share/ca-certificates",
		"/etc",
		"/lib",
		"/lib64",
		"/usr/lib",
		"/usr/lib64",
		"/proc/sys/net",
		"/sys/kernel/mm/transparent_hugepage",
	)
	addUnique(&cfg.Landlock.ROFiles,
		"/etc/resolv.conf",
		"/etc/hosts",
		"/etc/nsswitch.conf",
		"/etc/protocols",
		"/etc/services",
		"/etc/localtime",
		"/etc/timezone",
		"/dev/null",
		"/dev/urandom",
		"/dev/random",
		"/proc/self/exe",
		"/proc/self/maps",
		"/proc/self/status",
		"/proc/sys/kernel/random/uuid",
	)
	addUnique(&cfg.Landlock.RWDirs, "/tmp", "/dev/shm")

	if configPath != "" {
		addUnique(&cfg.Landlock.ROFiles, configPath)
		if dir := filepath.Dir(configPath); dir != "" && dir != "." {
			addUnique(&cfg.Landlock.RODirs, dir)
		}
	}
	for _, f := range blocklistFiles {
		if f == "" {
			continue
		}
		addUnique(&cfg.Landlock.ROFiles, f)
		if dir := filepath.Dir(f); dir != "" && dir != "." {
			addUnique(&cfg.Landlock.RODirs, dir)
		}
	}
	if tlsCert != "" {
		addUnique(&cfg.Landlock.ROFiles, tlsCert)
		addUnique(&cfg.Landlock.RODirs, filepath.Dir(tlsCert))
	}
	if tlsKey != "" {
		addUnique(&cfg.Landlock.ROFiles, tlsKey)
		addUnique(&cfg.Landlock.RODirs, filepath.Dir(tlsKey))
	}
	if acmeStorageDir != "" {
		addUnique(&cfg.Landlock.RWDirs, acmeStorageDir)
	}
	if adminDataDir != "" {
		addUnique(&cfg.Landlock.RWDirs, adminDataDir)
	}

	if u, err := url.Parse(upstreamURL); err == nil {
		switch strings.ToLower(u.Scheme) {
		case "unix":
			sock := u.Path
			if sock == "" {
				sock = u.Host
			}
			if sock != "" {
				addUnique(&cfg.Landlock.RWFiles, sock)
				addUnique(&cfg.Landlock.RODirs, filepath.Dir(sock))
			}
		case "http", "https", "ws", "wss":
			port := u.Port()
			if port == "" {
				switch strings.ToLower(u.Scheme) {
				case "https", "wss":
					port = "443"
				default:
					port = "80"
				}
			}
			if p, err := strconv.ParseUint(port, 10, 16); err == nil {
				addUnique16(&cfg.Landlock.ConnectTCP, uint16(p))
			}
		}
	}

	for _, addr := range []string{listenHTTP, listenHTTPS, adminListen, adminHTTPS} {
		if p, ok := tcpPort(addr); ok {
			addUnique16(&cfg.Landlock.BindTCP, p)
		}
	}
	if p, ok := udpPort(listenQUIC); ok {
		addUnique16(&cfg.Landlock.BindUDP, p)
	}

	addUnique16(&cfg.Landlock.ConnectTCP, 53, 80, 443)
	addUnique16(&cfg.Landlock.ConnectUDP, 53)
	addUnique16(&cfg.Landlock.BindUDP, 0)
}

func addUnique16(dst *[]uint16, ports ...uint16) {
	seen := make(map[uint16]struct{}, len(*dst))
	for _, p := range *dst {
		seen[p] = struct{}{}
	}
	for _, p := range ports {
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		*dst = append(*dst, p)
	}
}

func tcpPort(addr string) (uint16, bool) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return 0, false
	}
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		if after, ok := strings.CutPrefix(addr, ":"); ok {
			port = after
		} else {
			return 0, false
		}
	}
	n, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return 0, false
	}
	return uint16(n), true
}

func udpPort(addr string) (uint16, bool) {
	return tcpPort(addr)
}
