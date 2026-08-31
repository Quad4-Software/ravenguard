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
	Webdriver  bool `json:"webdriver"`
	Playwright bool `json:"playwright"`
	Headless   bool `json:"headless"`
	NoPlugins  bool `json:"no_plugins"`
	Interacted bool `json:"interacted"`
	SolveMs    int  `json:"solve_ms"`
}

type EnvVerdict struct {
	Refuse  bool
	Reasons []string
}

func (m *Manager) EvaluateEnv(rep EnvReport, difficulty int) EnvVerdict {
	var v EnvVerdict
	if rep.Webdriver {
		v.Refuse = true
		v.Reasons = append(v.Reasons, "webdriver")
	}
	if rep.Playwright {
		v.Refuse = true
		v.Reasons = append(v.Reasons, "playwright")
	}
	if rep.Headless {
		v.Refuse = true
		v.Reasons = append(v.Reasons, "headless")
	}
	if rep.NoPlugins && (rep.Webdriver || rep.Headless || rep.Playwright) {
		v.Reasons = append(v.Reasons, "no_plugins")
	}
	if !rep.Interacted {
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
