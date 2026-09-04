// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package sandbox_test

import (
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"

	"github.com/Quad4-Software/ravenguard/internal/sandbox"
)

func TestParseMode(t *testing.T) {
	cases := []struct {
		in      string
		want    sandbox.Mode
		wantErr bool
	}{
		{"", "", false},
		{"off", sandbox.ModeOff, false},
		{"try", sandbox.ModeTry, false},
		{"best_effort", sandbox.ModeBestEffort, false},
		{"enforce", sandbox.ModeEnforce, false},
		{"TRY", sandbox.ModeTry, false},
		{"nope", "", true},
	}
	for _, tc := range cases {
		got, err := sandbox.ParseMode(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Fatalf("ParseMode(%q) expected error", tc.in)
			}
			continue
		}
		if err != nil {
			t.Fatalf("ParseMode(%q): %v", tc.in, err)
		}
		if got != tc.want {
			t.Fatalf("ParseMode(%q)=%q want %q", tc.in, got, tc.want)
		}
	}
}

func TestDerivePaths(t *testing.T) {
	cfg := sandbox.Config{
		Mode: sandbox.ModeBestEffort,
		Landlock: sandbox.LandlockConfig{
			RestrictNet: true,
			ConnectTCP:  []uint16{8443},
		},
	}
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "ravenguard.toml")
	bl := filepath.Join(dir, "ips.txt")
	if err := os.WriteFile(cfgPath, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bl, []byte("1.1.1.1\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	sandbox.DerivePaths(&cfg, cfgPath, ":8080", ":8443", ":8443", "http://10.0.0.5:9000", "", "", "", "", []string{bl}, "", "", "")

	if !contains16(cfg.Landlock.BindTCP, 8080) || !contains16(cfg.Landlock.BindTCP, 8443) {
		t.Fatalf("bind_tcp=%v", cfg.Landlock.BindTCP)
	}
	if !contains16(cfg.Landlock.BindUDP, 8443) || !contains16(cfg.Landlock.BindUDP, 0) {
		t.Fatalf("bind_udp=%v", cfg.Landlock.BindUDP)
	}
	if !contains16(cfg.Landlock.ConnectTCP, 9000) || !contains16(cfg.Landlock.ConnectTCP, 443) {
		t.Fatalf("connect_tcp=%v", cfg.Landlock.ConnectTCP)
	}
	if !contains16(cfg.Landlock.ConnectTCP, 8443) {
		t.Fatalf("expected preserved connect 8443 in %v", cfg.Landlock.ConnectTCP)
	}
	if !containsStr(cfg.Landlock.ROFiles, cfgPath) || !containsStr(cfg.Landlock.ROFiles, bl) {
		t.Fatalf("ro_files=%v", cfg.Landlock.ROFiles)
	}
}

func TestDeriveUnixUpstream(t *testing.T) {
	cfg := sandbox.Config{Mode: sandbox.ModeTry, Landlock: sandbox.LandlockConfig{RestrictNet: true}}
	sandbox.DerivePaths(&cfg, "", ":8080", "", "", "unix:///var/run/app.sock", "", "", "", "", nil, "", "", "")
	if !containsStr(cfg.Landlock.RWFiles, "/var/run/app.sock") {
		t.Fatalf("rw_files=%v", cfg.Landlock.RWFiles)
	}
}

func TestDeriveWSSUpstream(t *testing.T) {
	cfg := sandbox.Config{Mode: sandbox.ModeTry, Landlock: sandbox.LandlockConfig{RestrictNet: true}}
	sandbox.DerivePaths(&cfg, "", ":8080", "", "", "wss://origin.example:9443", "", "", "", "", nil, "", "", "")
	if !contains16(cfg.Landlock.ConnectTCP, 9443) {
		t.Fatalf("connect_tcp=%v want 9443", cfg.Landlock.ConnectTCP)
	}
}

func TestDeriveWSDefaultPort(t *testing.T) {
	cfg := sandbox.Config{Mode: sandbox.ModeTry, Landlock: sandbox.LandlockConfig{RestrictNet: true}}
	sandbox.DerivePaths(&cfg, "", ":8080", "", "", "ws://origin.example", "", "", "", "", nil, "", "", "")
	if !contains16(cfg.Landlock.ConnectTCP, 80) {
		t.Fatalf("connect_tcp=%v want 80", cfg.Landlock.ConnectTCP)
	}
}

func TestApplyOff(t *testing.T) {
	res, err := sandbox.Apply(sandbox.Config{Mode: sandbox.ModeOff}, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	if res.Landlock != "off" || res.Seccomp != "off" {
		t.Fatalf("result=%+v", res)
	}
}

func TestApplyTryDoesNotFail(t *testing.T) {
	if os.Getenv("RG_SANDBOX_SELFTEST") == "1" {
		cfg := sandbox.Config{
			Mode: sandbox.ModeTry,
			Landlock: sandbox.LandlockConfig{
				RODirs:         []string{"/usr"},
				RWDirs:         []string{"/tmp"},
				RestrictNet:    true,
				RestrictScoped: true,
				BindTCP:        []uint16{0},
				ConnectTCP:     []uint16{53, 80, 443},
				ConnectUDP:     []uint16{53},
				BindUDP:        []uint16{0},
				IgnoreMissing:  true,
			},
			Seccomp: sandbox.SeccompConfig{DenyAction: "errno"},
		}
		if _, err := sandbox.Apply(cfg, slog.Default()); err != nil {
			t.Fatalf("try mode should soft-fail: %v", err)
		}
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestApplyTryDoesNotFail$", "-test.v")
	cmd.Env = append(os.Environ(), "RG_SANDBOX_SELFTEST=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("subprocess apply failed: %v\n%s", err, out)
	}
}

func TestNeedsClassicTCP(t *testing.T) {
	cfg := sandbox.Config{
		Mode:     sandbox.ModeBestEffort,
		Landlock: sandbox.LandlockConfig{RestrictNet: true},
	}
	if !cfg.NeedsClassicTCP() {
		t.Fatal("expected classic TCP")
	}
	cfg.Landlock.RestrictNet = false
	if cfg.NeedsClassicTCP() {
		t.Fatal("expected no classic TCP requirement")
	}
}

func contains16(list []uint16, want uint16) bool {
	return slices.Contains(list, want)
}

func containsStr(list []string, want string) bool {
	return slices.Contains(list, want)
}
