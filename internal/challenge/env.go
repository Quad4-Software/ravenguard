// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package challenge

import (
	"errors"
	"fmt"
	"strings"
)

var ErrAutomation = errors.New("automation environment detected")

// EnvReport is a compact browser environment probe from the challenge page.
type EnvReport struct {
	Webdriver    bool `json:"webdriver"`
	Playwright   bool `json:"playwright"`
	Selenium     bool `json:"selenium"`
	Headless     bool `json:"headless"`
	NoPlugins    bool `json:"no_plugins"`
	ZeroViewport bool `json:"zero_viewport"`
	SoftWebGL    bool `json:"soft_webgl"`
	WDDeleted    bool `json:"wd_deleted"`
	PermMismatch bool `json:"perm_mismatch"`
	Interacted   bool `json:"interacted"`
	SolveMs      int  `json:"solve_ms"`
}

type EnvVerdict struct {
	Refuse  bool
	Reasons []string
}

// softRefuseThreshold is the number of soft automation signals that together
// justify a refusal. Each alone has real-browser edge cases; two or more is a
// reliable automation fingerprint.
const softRefuseThreshold = 2

func (m *Manager) EvaluateEnv(rep EnvReport, difficulty int, gate string) EnvVerdict {
	var v EnvVerdict
	if rep.Webdriver {
		v.Refuse = true
		v.Reasons = append(v.Reasons, "webdriver")
	}
	if rep.Playwright {
		v.Refuse = true
		v.Reasons = append(v.Reasons, "playwright")
	}
	if rep.Selenium {
		v.Refuse = true
		v.Reasons = append(v.Reasons, "selenium")
	}
	if rep.Headless {
		v.Refuse = true
		v.Reasons = append(v.Reasons, "headless")
	}
	var soft []string
	if rep.NoPlugins {
		soft = append(soft, "no_plugins")
	}
	if rep.ZeroViewport {
		soft = append(soft, "zero_viewport")
	}
	if rep.SoftWebGL {
		soft = append(soft, "soft_webgl")
	}
	if rep.WDDeleted {
		soft = append(soft, "wd_deleted")
	}
	if rep.PermMismatch {
		soft = append(soft, "perm_mismatch")
	}
	if v.Refuse || len(soft) >= softRefuseThreshold {
		v.Refuse = true
		v.Reasons = append(v.Reasons, soft...)
	}
	if NormalizeGate(gate) == GateInteractive && !rep.Interacted {
		v.Refuse = true
		v.Reasons = append(v.Reasons, "no_interaction")
	}
	if difficulty >= 12 && rep.SolveMs > 0 && rep.SolveMs < minSolveMs(difficulty) {
		v.Refuse = true
		v.Reasons = append(v.Reasons, "solve_too_fast")
	}
	return v
}

func minSolveMs(difficulty int) int {
	if difficulty <= 8 {
		return 1
	}
	if difficulty <= 12 {
		return 20
	}
	if difficulty <= 16 {
		return 40
	}
	return 80
}

func FormatEnvReasons(reasons []string) string {
	if len(reasons) == 0 {
		return "automation"
	}
	return fmt.Sprintf("automation: %s", strings.Join(reasons, ","))
}
