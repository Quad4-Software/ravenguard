// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/Quad4-Software/ravenguard/internal/config"
	"github.com/Quad4-Software/ravenguard/internal/sandbox"
	"github.com/Quad4-Software/ravenguard/internal/tunnel"
)

func runConnector(cfg config.Config) {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	sbCfg, err := sandbox.FromFileConfig(
		cfg.Sandbox.Mode,
		cfg.Sandbox.Landlock.Mode,
		cfg.Sandbox.Seccomp.Mode,
		cfg.Sandbox.Landlock.RODirs,
		cfg.Sandbox.Landlock.RWDirs,
		cfg.Sandbox.Landlock.ROFiles,
		cfg.Sandbox.Landlock.RWFiles,
		cfg.Sandbox.Landlock.RestrictNet != nil && *cfg.Sandbox.Landlock.RestrictNet,
		cfg.Sandbox.Landlock.RestrictScoped != nil && *cfg.Sandbox.Landlock.RestrictScoped,
		cfg.Sandbox.Landlock.IgnoreMissing == nil || *cfg.Sandbox.Landlock.IgnoreMissing,
		cfg.Sandbox.Landlock.BindTCP,
		cfg.Sandbox.Landlock.BindUDP,
		cfg.Sandbox.Landlock.ConnectTCP,
		cfg.Sandbox.Landlock.ConnectUDP,
		cfg.Sandbox.Seccomp.DenyAction,
	)
	if err != nil {
		slog.Error("sandbox config", "err", err)
		os.Exit(1)
	}
	sandbox.DerivePaths(&sbCfg, "", "", "", "", cfg.Tunnel.EdgeURL, "", "", "", "", nil, "", "", "")
	for _, origin := range cfg.Tunnel.Origins {
		sandbox.DerivePaths(&sbCfg, "", "", "", "", origin, "", "", "", "", nil, "", "", "")
	}
	if _, err := sandbox.Apply(sbCfg, slog.Default()); err != nil {
		slog.Error("sandbox", "err", err)
		os.Exit(1)
	}

	allow := tunnel.NewAllowlist(cfg.Tunnel.Origins)
	d := &tunnel.ConnectorDialer{
		EdgeURL:   cfg.Tunnel.EdgeURL,
		Ticket:    cfg.Tunnel.Ticket,
		Allowlist: allow,
	}
	slog.Info("ravenguard connector starting", "edge", cfg.Tunnel.EdgeURL, "origins", len(cfg.Tunnel.Origins))
	if err := d.Run(ctx); err != nil && ctx.Err() == nil {
		slog.Error("connector", "err", err)
		os.Exit(1)
	}
}
