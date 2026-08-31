// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package sandbox

import (
	"fmt"
	"strings"
)

// Mode controls how sandbox failures are handled.
//
// off: do not apply the sandbox.
// try: attempt to apply; any error is logged and ignored.
// best_effort: degrade gracefully when the kernel lacks features
// (Landlock BestEffort, soft-fail when seccomp is unsupported).
// enforce: require a successful apply or return an error.
type Mode string

const (
	ModeOff        Mode = "off"
	ModeTry        Mode = "try"
	ModeBestEffort Mode = "best_effort"
	ModeEnforce    Mode = "enforce"
)

func ParseMode(s string) (Mode, error) {
	raw := strings.ToLower(strings.TrimSpace(s))
	if raw == "" {
		return "", nil
	}
	m := Mode(raw)
	switch m {
	case ModeOff, ModeTry, ModeBestEffort, ModeEnforce:
		return m, nil
	default:
		return "", fmt.Errorf("sandbox mode %q is invalid (use off, try, best_effort, or enforce)", s)
	}
}

func (m Mode) Enabled() bool {
	return m != "" && m != ModeOff
}

func (m Mode) SoftFail() bool {
	return m == ModeTry || m == ModeBestEffort
}
