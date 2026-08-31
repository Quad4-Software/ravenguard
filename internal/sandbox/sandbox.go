// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package sandbox

import (
	"fmt"
	"log/slog"
)

// Result summarizes what was applied.
type Result struct {
	Landlock string
	Seccomp  string
}

// Apply installs Landlock and seccomp according to cfg and mode semantics.
func Apply(cfg Config, log *slog.Logger) (Result, error) {
	if log == nil {
		log = slog.Default()
	}
	var res Result

	llMode := cfg.landlockMode()
	if llMode.Enabled() {
		status, err := applyLandlock(cfg.Landlock, llMode)
		res.Landlock = status
		if err != nil {
			if llMode.SoftFail() {
				log.Warn("landlock unavailable or failed, continuing", "mode", string(llMode), "err", err)
				res.Landlock = "skipped: " + err.Error()
			} else {
				return res, fmt.Errorf("landlock: %w", err)
			}
		} else {
			log.Info("landlock applied", "mode", string(llMode), "status", status)
		}
	} else {
		res.Landlock = "off"
	}

	scMode := cfg.seccompMode()
	if scMode.Enabled() {
		status, err := applySeccomp(cfg.Seccomp, scMode)
		res.Seccomp = status
		if err != nil {
			if scMode.SoftFail() {
				log.Warn("seccomp unavailable or failed, continuing", "mode", string(scMode), "err", err)
				res.Seccomp = "skipped: " + err.Error()
			} else {
				return res, fmt.Errorf("seccomp: %w", err)
			}
		} else {
			log.Info("seccomp applied", "mode", string(scMode), "status", status)
		}
	} else {
		res.Seccomp = "off"
	}

	return res, nil
}
