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
	}, 8, challenge.GateInteractive)
	if v.Refuse {
		t.Fatalf("unexpected refuse %v", v.Reasons)
	}
}

func TestEvaluateEnvInvisibleNoInteraction(t *testing.T) {
	m := &challenge.Manager{Secret: []byte("test-secret-16chars"), Difficulty: 8}
	v := m.EvaluateEnv(challenge.EnvReport{
		Interacted: false,
		SolveMs:    100,
	}, 8, challenge.GateInvisible)
	if v.Refuse {
		t.Fatalf("invisible should allow no interaction %v", v.Reasons)
	}
}

func TestEvaluateEnvInteractiveNoInteraction(t *testing.T) {
	m := &challenge.Manager{Secret: []byte("test-secret-16chars"), Difficulty: 8}
	v := m.EvaluateEnv(challenge.EnvReport{
		Interacted: false,
		SolveMs:    100,
	}, 8, challenge.GateInteractive)
	if !v.Refuse {
		t.Fatal("expected no_interaction refuse")
	}
}

func TestEvaluateEnvWebdriver(t *testing.T) {
	m := &challenge.Manager{Secret: []byte("test-secret-16chars"), Difficulty: 16}
	v := m.EvaluateEnv(challenge.EnvReport{
		Webdriver:  true,
		Interacted: true,
		SolveMs:    500,
	}, 16, challenge.GateInteractive)
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
	}, 8, challenge.GateInteractive)
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
	}, 8, challenge.GateInteractive)
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
	}, 8, challenge.GateInvisible)
	if !v.Refuse {
		t.Fatal("expected headless refuse")
	}
}

func TestEvaluateEnvTooFast(t *testing.T) {
	m := &challenge.Manager{Secret: []byte("test-secret-16chars"), Difficulty: 16}
	v := m.EvaluateEnv(challenge.EnvReport{
		Interacted: true,
		SolveMs:    5,
	}, 16, challenge.GateInteractive)
	if !v.Refuse {
		t.Fatal("expected solve_too_fast")
	}
}

func TestEvaluateEnvSingleSoftSignalPasses(t *testing.T) {
	m := &challenge.Manager{Secret: []byte("test-secret-16chars"), Difficulty: 8}
	for name, rep := range map[string]challenge.EnvReport{
		"no_plugins":    {NoPlugins: true},
		"zero_viewport": {ZeroViewport: true},
		"soft_webgl":    {SoftWebGL: true},
		"wd_deleted":    {WDDeleted: true},
		"perm_mismatch": {PermMismatch: true},
	} {
		rep.Interacted = true
		rep.SolveMs = 100
		v := m.EvaluateEnv(rep, 8, challenge.GateInteractive)
		if v.Refuse {
			t.Fatalf("%s alone must not refuse %v", name, v.Reasons)
		}
	}
}

func TestEvaluateEnvTwoSoftSignalsRefuse(t *testing.T) {
	m := &challenge.Manager{Secret: []byte("test-secret-16chars"), Difficulty: 8}
	v := m.EvaluateEnv(challenge.EnvReport{
		ZeroViewport: true,
		SoftWebGL:    true,
		Interacted:   true,
		SolveMs:      100,
	}, 8, challenge.GateInteractive)
	if !v.Refuse {
		t.Fatal("two soft signals must refuse")
	}
	joined := strings.Join(v.Reasons, ",")
	if !strings.Contains(joined, "zero_viewport") || !strings.Contains(joined, "soft_webgl") {
		t.Fatalf("reasons=%v", v.Reasons)
	}
}

func TestEvaluateEnvHardSignalIncludesSoftReasons(t *testing.T) {
	m := &challenge.Manager{Secret: []byte("test-secret-16chars"), Difficulty: 16}
	v := m.EvaluateEnv(challenge.EnvReport{
		Webdriver:  true,
		NoPlugins:  true,
		SoftWebGL:  true,
		Interacted: true,
		SolveMs:    500,
	}, 16, challenge.GateInteractive)
	if !v.Refuse {
		t.Fatal("expected refuse")
	}
	joined := strings.Join(v.Reasons, ",")
	for _, want := range []string{"webdriver", "no_plugins", "soft_webgl"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing %s in reasons=%v", want, v.Reasons)
		}
	}
}
