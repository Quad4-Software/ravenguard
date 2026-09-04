// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/Quad4-Software/ravenguard/internal/access"
	"github.com/Quad4-Software/ravenguard/internal/admin"
	"github.com/Quad4-Software/ravenguard/internal/admin/ops"
	"github.com/Quad4-Software/ravenguard/internal/agentprotocol"
	"github.com/Quad4-Software/ravenguard/internal/config"
	"github.com/Quad4-Software/ravenguard/internal/logging"
	"github.com/Quad4-Software/ravenguard/internal/router"
	"github.com/Quad4-Software/ravenguard/internal/sandbox"
)

func runHub(cfg config.Config) {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	keys, err := agentprotocol.LoadOrCreateKeyPair(cfg.Admin.DataDir)
	if err != nil {
		slog.Error("hub keys", "err", err)
		os.Exit(1)
	}
	reg := agentprotocol.NewRegistry()
	hubURL := cfg.Hub.PublicURL
	if hubURL == "" {
		if cfg.Admin.HTTPS != "" {
			hubURL = "https://" + stripHostPortListen(cfg.Admin.HTTPS)
		} else {
			hubURL = "http://" + stripHostPortListen(cfg.Admin.Listen)
		}
	}

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
	sandbox.DerivePaths(&sbCfg, "", "", "", "", "",
		cfg.TLS.CertFile, cfg.TLS.KeyFile, "", nil,
		cfg.Admin.Listen, cfg.Admin.HTTPS, cfg.Admin.DataDir)
	if _, err := sandbox.Apply(sbCfg, slog.Default()); err != nil {
		slog.Error("sandbox", "err", err)
		os.Exit(1)
	}

	secureCookie := admin.CookieSecure(cfg.Admin.CookieSecure, cfg.Admin.HTTPS != "")
	adminSrv, err := admin.New(admin.Options{
		Config:            cfg.Admin,
		TLSCertFile:       cfg.TLS.CertFile,
		TLSKeyFile:        cfg.TLS.KeyFile,
		Runtime:           ops.NewRuntime(cfg, nil, nil, nil, nil, nil, nil),
		SecureCookie:      secureCookie,
		AgentRegistry:     reg,
		HubKeys:           &keys,
		HubPublicURL:      hubURL,
		MountAgentConnect: true,
		LogSnapshot: func(limit int, level string) any {
			ring := logging.DefaultRing()
			if ring == nil {
				return []logging.Entry{}
			}
			return ring.Snapshot(limit, level)
		},
	})
	if err != nil {
		slog.Error("admin", "err", err)
		os.Exit(1)
	}
	slog.Info("ravenguard hub starting", "listen", cfg.Admin.Listen, "https", cfg.Admin.HTTPS, "hub_pubkey", keys.PublicKeyBase64())
	var wg sync.WaitGroup
	wg.Go(func() {
		if err := adminSrv.Run(ctx); err != nil {
			slog.Error("hub server", "err", err)
			cancel()
		}
	})
	<-ctx.Done()
	wg.Wait()
	_ = adminSrv.Close()
}

func stripHostPortListen(addr string) string {
	if addr == "" {
		return "127.0.0.1:9090"
	}
	if addr[0] == ':' {
		return "127.0.0.1" + addr
	}
	return addr
}

func applyRoutingSnapshot(routeTable *router.Table, accessMgr *access.Manager, raw json.RawMessage) error {
	if len(raw) == 0 || routeTable == nil {
		return nil
	}
	var snap agentprotocol.RoutingSnapshot
	if err := json.Unmarshal(raw, &snap); err != nil {
		return err
	}
	var ups []router.Upstream
	var rts []struct {
		ID             string   `json:"id"`
		Name           string   `json:"name"`
		Enabled        bool     `json:"enabled"`
		Hosts          []string `json:"hosts"`
		PathPrefix     string   `json:"path_prefix"`
		UpstreamID     string   `json:"upstream_id"`
		StripPrefix    bool     `json:"strip_prefix"`
		Priority       int      `json:"priority"`
		AccessPolicyID *string  `json:"access_policy_id"`
	}
	var polRows []struct {
		ID        string        `json:"id"`
		Name      string        `json:"name"`
		Mode      string        `json:"mode"`
		Rules     []access.Rule `json:"rules"`
		CookieTTL string        `json:"cookie_ttl"`
	}
	_ = json.Unmarshal(snap.Upstreams, &ups)
	_ = json.Unmarshal(snap.Routes, &rts)
	_ = json.Unmarshal(snap.AccessPolicies, &polRows)

	rr := make([]router.Route, 0, len(rts))
	for _, rt := range rts {
		policyID := ""
		if rt.AccessPolicyID != nil {
			policyID = *rt.AccessPolicyID
		}
		rr = append(rr, router.Route{
			ID: rt.ID, Name: rt.Name, Enabled: rt.Enabled, Hosts: rt.Hosts,
			PathPrefix: rt.PathPrefix, UpstreamID: rt.UpstreamID,
			StripPrefix: rt.StripPrefix, Priority: rt.Priority,
			AccessPolicyID: policyID,
		})
	}
	if err := routeTable.Replace(ups, rr); err != nil {
		return err
	}
	if accessMgr != nil {
		ap := make([]access.Policy, 0, len(polRows))
		for _, p := range polRows {
			ttl := 24 * time.Hour
			if d, err := time.ParseDuration(p.CookieTTL); err == nil && d > 0 {
				ttl = d
			}
			ap = append(ap, access.Policy{
				ID: p.ID, Name: p.Name, Mode: p.Mode, Rules: p.Rules, CookieTTL: ttl,
			})
		}
		accessMgr.Replace(ap)
	}
	return nil
}
