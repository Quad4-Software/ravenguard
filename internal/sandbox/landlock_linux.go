// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

//go:build linux

package sandbox

import (
	"fmt"
	"os"
	"strings"

	"github.com/landlock-lsm/go-landlock/landlock"
)

func applyLandlock(cfg LandlockConfig, mode Mode) (string, error) {
	pathRules, netRules := splitLandlockRules(cfg)
	if len(pathRules) == 0 && len(netRules) == 0 && !cfg.RestrictScoped {
		return "noop", nil
	}

	base := landlock.V10
	switch mode {
	case ModeBestEffort, ModeTry:
		base = base.BestEffort()
	}

	parts := []string{"v10"}
	if mode == ModeBestEffort || mode == ModeTry {
		parts = append(parts, "best_effort")
	}

	if len(pathRules) > 0 {
		if err := base.RestrictPaths(pathRules...); err != nil {
			return "", fmt.Errorf("restrict paths: %w", err)
		}
		parts = append(parts, "paths")
	}

	if cfg.RestrictNet {
		if err := base.RestrictNet(netRules...); err != nil {
			return "", fmt.Errorf("restrict net: %w", err)
		}
		parts = append(parts, "net")
	}

	if cfg.RestrictScoped {
		if err := base.RestrictScoped(); err != nil {
			return "", fmt.Errorf("restrict scoped: %w", err)
		}
		parts = append(parts, "scoped")
	}

	return strings.Join(parts, "+"), nil
}

func splitLandlockRules(cfg LandlockConfig) (paths []landlock.Rule, nets []landlock.Rule) {
	keep := func(list []string) []string {
		if !cfg.IgnoreMissing {
			return list
		}
		out := make([]string, 0, len(list))
		for _, p := range list {
			if _, err := os.Stat(p); err == nil {
				out = append(out, p)
			}
		}
		return out
	}

	if dirs := keep(cfg.RODirs); len(dirs) > 0 {
		r := landlock.RODirs(dirs...)
		if cfg.IgnoreMissing {
			r = r.IgnoreIfMissing()
		}
		paths = append(paths, r)
	}
	if dirs := keep(cfg.RWDirs); len(dirs) > 0 {
		r := landlock.RWDirs(dirs...)
		if cfg.IgnoreMissing {
			r = r.IgnoreIfMissing()
		}
		paths = append(paths, r)
	}
	if files := keep(cfg.ROFiles); len(files) > 0 {
		r := landlock.ROFiles(files...)
		if cfg.IgnoreMissing {
			r = r.IgnoreIfMissing()
		}
		paths = append(paths, r)
	}
	if files := keep(cfg.RWFiles); len(files) > 0 {
		for _, f := range files {
			r := landlock.RWFiles(f).WithResolveUnix()
			if cfg.IgnoreMissing {
				r = r.IgnoreIfMissing()
			}
			paths = append(paths, r)
		}
	}

	if cfg.RestrictNet {
		for _, p := range cfg.BindTCP {
			nets = append(nets, landlock.BindTCP(p))
		}
		for _, p := range cfg.BindUDP {
			nets = append(nets, landlock.BindUDP(p))
		}
		for _, p := range cfg.ConnectTCP {
			nets = append(nets, landlock.ConnectTCP(p))
		}
		for _, p := range cfg.ConnectUDP {
			nets = append(nets, landlock.ConnectSendUDP(p))
		}
	}
	return paths, nets
}

// AvailableLandlock reports a short description of the Landlock config probe.
func AvailableLandlock() string {
	return landlock.V10.BestEffort().String()
}
