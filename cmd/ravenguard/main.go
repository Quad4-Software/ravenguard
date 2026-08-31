// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Quad4-Software/ravenguard/internal/blocklist"
	"github.com/Quad4-Software/ravenguard/internal/challenge"
	"github.com/Quad4-Software/ravenguard/internal/config"
	"github.com/Quad4-Software/ravenguard/internal/detect"
	"github.com/Quad4-Software/ravenguard/internal/health"
	"github.com/Quad4-Software/ravenguard/internal/iputil"
	"github.com/Quad4-Software/ravenguard/internal/listener"
	"github.com/Quad4-Software/ravenguard/internal/logging"
	"github.com/Quad4-Software/ravenguard/internal/pipeline"
	"github.com/Quad4-Software/ravenguard/internal/privacy"
	"github.com/Quad4-Software/ravenguard/internal/protect"
	"github.com/Quad4-Software/ravenguard/internal/proxy"
	"github.com/Quad4-Software/ravenguard/internal/qfeeds"
	"github.com/Quad4-Software/ravenguard/internal/ratelimit"
	rgsentry "github.com/Quad4-Software/ravenguard/internal/sentry"
	"github.com/Quad4-Software/ravenguard/internal/sandbox"
	"github.com/Quad4-Software/ravenguard/internal/ui"
)

func main() {
	flags, err := config.ParseFlags(os.Args[1:])
	if err != nil {
		os.Exit(2)
	}

	cfg, err := config.LoadWithFlags(flags)
	if err != nil {
		slog.Error("config", "err", err)
		os.Exit(1)
	}
	baseLog := logging.Setup(cfg.Logging.Level, cfg.Logging.Format)

	sentryRep, err := rgsentry.Init(cfg.Sentry)
	if err != nil {
		slog.Error("sentry", "err", err)
		os.Exit(1)
	}
	defer sentryRep.Flush()
	if sentryRep.Enabled() {
		slog.SetDefault(slog.New(rgsentry.WrapHandler(baseLog.Handler(), sentryRep)))
	}

	target, err := proxy.ParseUpstreamURL(cfg.Upstream.URL)
	if err != nil {
		slog.Error("upstream url", "err", err)
		os.Exit(1)
	}

	trusted, err := iputil.ParseCIDRs(cfg.Trust.TrustedProxies)
	if err != nil {
		slog.Error("trust.trusted_proxies", "err", err)
		os.Exit(1)
	}

	lists := blocklist.New()
	if err = lists.Load(cfg.Blocklists.IPFiles, cfg.Blocklists.DNSFiles, cfg.Blocklists.UAFiles); err != nil {
		slog.Error("blocklists", "err", err)
		os.Exit(1)
	}
	lists.StartReload(cfg.Blocklists.IPFiles, cfg.Blocklists.DNSFiles, cfg.Blocklists.UAFiles, cfg.Blocklists.ReloadInterval.Duration)

	var feeds *qfeeds.Cache
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if cfg.QFeeds.Enabled {
		feeds = qfeeds.New(qfeeds.Config{
			APIToken: cfg.QFeeds.APIToken,
			BaseURL:  cfg.QFeeds.BaseURL,
			Feeds:    cfg.QFeeds.Feeds,
			Refresh:  cfg.QFeeds.Refresh.Duration,
			OnError:  cfg.QFeeds.OnError,
			Limit:    cfg.QFeeds.Limit,
		})
		feeds.Start(ctx)
	}

	retention := cfg.Privacy.Retention.Duration
	if retention <= 0 {
		retention = 30 * time.Minute
	}

	var limiter *ratelimit.Limiter
	if cfg.RateLimit.Enabled {
		limiter = ratelimit.New(cfg.RateLimit.Requests, cfg.RateLimit.Burst, cfg.RateLimit.Window.Duration, cfg.RateLimit.PerPath)
		pipeline.StartSweeper(limiter, 5*time.Minute, retention)
	}

	var nf *detect.NotFoundTracker
	if cfg.Detect.Enabled && cfg.Detect.High404Action != "off" {
		nf = detect.NewNotFoundTracker(cfg.Detect.High404Threshold, cfg.Detect.High404Window.Duration)
		pipeline.StartNotFoundSweeper(nf, time.Minute, retention)
	}

	var beh *detect.BehaviorTracker
	if cfg.Detect.Enabled {
		beh = detect.NewBehaviorTracker(detect.BehaviorConfig{
			Window:          cfg.Detect.BehaviorWindow.Duration,
			BurstLimit:      cfg.Detect.BehaviorBurstLimit,
			BurstScore:      cfg.Detect.BehaviorBurstScore,
			PathFanout:      cfg.Detect.BehaviorPathFanout,
			PathFanoutScore: cfg.Detect.BehaviorPathFanoutScore,
			StrikeLimit:     cfg.Detect.BehaviorStrikeLimit,
			StrikeScore:     cfg.Detect.BehaviorStrikeScore,
		})
		pipeline.StartBehaviorSweeper(beh, time.Minute, retention)
	}

	var prot *protect.Guard
	if cfg.Protect.Enabled {
		prot = protect.New(protect.Config{
			Enabled:             true,
			MaxBodyBytes:        cfg.Protect.MaxBodyBytes,
			MaxHeaderBytes:      cfg.Protect.MaxHeaderBytes,
			MaxURLBytes:         cfg.Protect.MaxURLBytes,
			MaxConcurrentGlobal: cfg.Protect.MaxConcurrentGlobal,
			MaxConcurrentClient: cfg.Protect.MaxConcurrentClient,
			BanAfterStrikes:     cfg.Protect.BanAfterStrikes,
			BanTTL:              cfg.Protect.BanTTL.Duration,
			AttackBlock:         cfg.Protect.AttackBlock,
			AttackScore:         cfg.Protect.AttackScore,
			WriteMethodCost:     cfg.Protect.WriteMethodCost,
		})
		pipeline.StartProtectSweeper(prot, time.Minute, retention)
	}

	var hc *health.Checker
	if cfg.Upstream.Health.Enabled {
		hc = health.New(health.Config{
			Enabled:  true,
			URL:      target,
			Path:     cfg.Upstream.Health.Path,
			Interval: cfg.Upstream.Health.Interval.Duration,
			Timeout:  cfg.Upstream.Health.Timeout.Duration,
			Dial:     proxy.DialFunc(target, cfg.Upstream.ConnectTimeout.Duration),
		})
		hc.Start(ctx)
	}

	hashSecret := cfg.Privacy.IPHashSecret
	if hashSecret == "" {
		hashSecret = cfg.Challenge.Secret
	}
	priv := privacy.New(privacy.Config{
		HashClientIP: cfg.Privacy.HashClientIP,
		Secret:       []byte(hashSecret),
		LogIP:        cfg.Privacy.LogIP,
	})

	secure := cfg.Listen.HTTPS != "" || cfg.Listen.QUIC != ""
	var chal *challenge.Manager
	if cfg.Challenge.Enabled {
		chal = &challenge.Manager{
			Secret:     []byte(cfg.Challenge.Secret),
			Difficulty: cfg.Challenge.Difficulty,
			CookieName: cfg.Challenge.CookieName,
			CookieTTL:  cfg.Challenge.CookieTTL.Duration,
			Secure:     secure,
		}
		if cfg.Challenge.Captcha.Enabled {
			v, cerr := challenge.NewCaptcha(cfg.Challenge.Captcha.Provider, cfg.Challenge.Captcha.Token)
			if cerr != nil {
				slog.Error("captcha", "err", cerr)
				os.Exit(1)
			}
			chal.Captcha = v
		}
		pipeline.StartNonceSweeper(chal, time.Minute)
	}

	pages, err := ui.New(ui.Site{
		Brand:            cfg.UI.Brand,
		StatusText:       cfg.UI.StatusText,
		Description:      cfg.Site.Description,
		PublicURL:        cfg.Site.PublicURL,
		OGImage:          cfg.Site.OGImage,
		ThemeColor:       cfg.Site.ThemeColor,
		Robots:           cfg.Site.Robots,
		Lang:             cfg.Site.Lang,
		Prefix:           cfg.Challenge.PathPrefix,
		PrivacyNoticeURL: cfg.Privacy.PrivacyNoticeURL,
	})
	if err != nil {
		slog.Error("ui", "err", err)
		os.Exit(1)
	}

	flush := cfg.Upstream.FlushInterval.Duration
	up := proxy.New(proxy.Config{
		Target:                target,
		ConnectTimeout:        cfg.Upstream.ConnectTimeout.Duration,
		ResponseHeaderTimeout: cfg.Upstream.ResponseHeader.Duration,
		IdleConnTimeout:       cfg.Upstream.IdleConnTimeout.Duration,
		MaxIdleConns:          cfg.Upstream.MaxIdleConns,
		MaxIdleConnsPerHost:   cfg.Upstream.MaxIdleConnsPerHost,
		MaxConnsPerHost:       cfg.Upstream.MaxConnsPerHost,
		FlushInterval:         flush,
		SetHeaders:            proxy.ParseSetHeaders(cfg.Upstream.SetHeaders),
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			ray := r.Header.Get("X-RavenGuard-Ray")
			if ray == "" {
				ray = "unknown"
			}
			slog.Debug("upstream error", "err", err, "ray", ray)
			sentryRep.CaptureUpstreamError(err, ray)
			pages.RenderUpstream(w, ray)
		},
	})

	handler := sentryRep.Wrap(pipeline.New(cfg, lists, feeds, limiter, chal, pages, up, trusted, nf, hc, priv, beh, prot))

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
	blocklistPaths := append([]string{}, cfg.Blocklists.IPFiles...)
	blocklistPaths = append(blocklistPaths, cfg.Blocklists.DNSFiles...)
	blocklistPaths = append(blocklistPaths, cfg.Blocklists.UAFiles...)
	sandbox.DerivePaths(&sbCfg, flags.ConfigPath, cfg.Listen.HTTP, cfg.Listen.HTTPS, cfg.Listen.QUIC, cfg.Upstream.URL, cfg.TLS.CertFile, cfg.TLS.KeyFile, blocklistPaths)
	if _, err = sandbox.Apply(sbCfg, slog.Default()); err != nil {
		slog.Error("sandbox", "err", err)
		sentryRep.CaptureException(err)
		sentryRep.Flush()
		os.Exit(1)
	}

	maxHeader := 1 << 14
	if prot != nil {
		maxHeader = prot.MaxHeaderBytes()
	}
	srv := listener.New(listener.Config{
		HTTP:             cfg.Listen.HTTP,
		HTTPS:            cfg.Listen.HTTPS,
		QUIC:             cfg.Listen.QUIC,
		CertFile:         cfg.TLS.CertFile,
		KeyFile:          cfg.TLS.KeyFile,
		Handler:          handler,
		ProxyProtocol:    cfg.Trust.ProxyProtocol,
		MaxHeaderBytes:   maxHeader,
		DisableMultipath: sbCfg.NeedsClassicTCP(),
	})

	slog.Info("ravenguard starting", "upstream", cfg.Upstream.URL, "trust_mode", cfg.Trust.Mode)
	err = srv.Run(ctx)
	lists.Stop()
	if feeds != nil {
		feeds.Stop()
	}
	if hc != nil {
		hc.Stop()
	}
	if err != nil {
		slog.Error("server", "err", err)
		sentryRep.CaptureException(err)
		sentryRep.Flush()
		os.Exit(1)
	}
}
