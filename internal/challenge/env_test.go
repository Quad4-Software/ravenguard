// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package challenge_test

import (
	"strings"
	"testing"

	"github.com/Quad4-Software/ravenguard/internal/challenge"
)

func TestEvaluateEnvClean(t *testing.T) {
	m := &challenge.Manager{Secret: []byte("test-secret-16chars"), Difficulty: 8}
	v := m.EvaluateEnv(challenge.EnvReport{
		Interacted: true,
		SolveMs:    100,
	}, 8)
	if v.Refuse {
		t.Fatalf("unexpected refuse %v", v.Reasons)
	}
}

func TestEvaluateEnvWebdriver(t *testing.T) {
	m := &challenge.Manager{Secret: []byte("test-secret-16chars"), Difficulty: 16}
	v := m.EvaluateEnv(challenge.EnvReport{
		Webdriver:  true,
		Interacted: true,
		SolveMs:    500,
	}, 16)
	if !v.Refuse {
		t.Fatal("expected refuse")
	}
}

func TestEvaluateEnvSelenium(t *testing.T) {
	m := &challenge.Manager{Secret: []byte("test-secret-16chars"), Difficulty: 8}
	v := m.EvaluateEnv(challenge.EnvReport{
		Selenium:   true,
		Interacted: true,
		SolveMs:    200,
	}, 8)
	if !v.Refuse {
		t.Fatal("expected selenium refuse")
	}
	if len(v.Reasons) == 0 || v.Reasons[0] != "selenium" {
		t.Fatalf("reasons=%v", v.Reasons)
	}
}

func TestEvaluateEnvPlaywright(t *testing.T) {
	m := &challenge.Manager{Secret: []byte("test-secret-16chars"), Difficulty: 8}
	v := m.EvaluateEnv(challenge.EnvReport{
		Playwright: true,
		NoPlugins:  true,
		Interacted: true,
		SolveMs:    200,
	}, 8)
	if !v.Refuse {
		t.Fatal("expected playwright refuse")
	}
	joined := strings.Join(v.Reasons, ",")
	if !strings.Contains(joined, "playwright") || !strings.Contains(joined, "no_plugins") {
		t.Fatalf("reasons=%v", v.Reasons)
	}
}

func TestEvaluateEnvHeadless(t *testing.T) {
	m := &challenge.Manager{Secret: []byte("test-secret-16chars"), Difficulty: 8}
	v := m.EvaluateEnv(challenge.EnvReport{
		Headless:   true,
		Interacted: true,
		SolveMs:    200,
	}, 8)
	if !v.Refuse {
		t.Fatal("expected headless refuse")
	}
}

func TestEvaluateEnvTooFast(t *testing.T) {
	m := &challenge.Manager{Secret: []byte("test-secret-16chars"), Difficulty: 16}
	v := m.EvaluateEnv(challenge.EnvReport{
		Interacted: true,
		SolveMs:    5,
	}, 16)
	if !v.Refuse {
		t.Fatal("expected solve_too_fast")
	}
}
