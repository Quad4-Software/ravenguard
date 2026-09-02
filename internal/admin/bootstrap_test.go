// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package admin_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Quad4-Software/ravenguard/internal/admin"
	"github.com/Quad4-Software/ravenguard/internal/admin/ops"
	"github.com/Quad4-Software/ravenguard/internal/blocklist"
	"github.com/Quad4-Software/ravenguard/internal/config"
	"github.com/Quad4-Software/ravenguard/internal/protect"
)

func TestAutoBootstrapPassword(t *testing.T) {
	dir := t.TempDir()
	rt := ops.NewRuntime(config.Default(), protect.New(protect.Config{Enabled: true}), blocklist.New(), nil, nil, nil, nil)
	srv, err := admin.New(admin.Options{
		Config: config.AdminConfig{
			Enabled:       true,
			Listen:        "127.0.0.1:0",
			BasePath:      "/",
			DataDir:       dir,
			BootstrapUser: "owner",
			SessionTTL:    config.Duration{},
			CookieSecure:  "false",
		},
		Runtime: rt,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srv.Close() }()

	b, err := os.ReadFile(filepath.Join(dir, "initial_admin_password"))
	if err != nil {
		t.Fatal(err)
	}
	pass := strings.TrimSpace(string(b))
	if len(pass) < 12 {
		t.Fatalf("password too short: %q", pass)
	}
}
