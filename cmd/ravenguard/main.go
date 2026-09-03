// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package main

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Quad4-Software/ravenguard/internal/access"
	"github.com/Quad4-Software/ravenguard/internal/admin"
	"github.com/Quad4-Software/ravenguard/internal/admin/ops"
	"github.com/Quad4-Software/ravenguard/internal/admin/store"
	"github.com/Quad4-Software/ravenguard/internal/allowlist"
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
	"github.com/Quad4-Software/ravenguard/internal/router"
	"github.com/Quad4-Software/ravenguard/internal/sandbox"
	rgsentry "github.com/Quad4-Software/ravenguard/internal/sentry"
	"github.com/Quad4-Software/ravenguard/internal/tlsacme"
	"github.com/Quad4-Software/ravenguard/internal/tlscerts"
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

	allows := allowlist.New()
	if err = allows.Load(cfg.Allowlists.IPFiles, cfg.Allowlists.UAFiles, cfg.Allowlists.HeaderFiles); err != nil {
		slog.Error("allowlists", "err", err)
		os.Exit(1)
	}
	allows.StartReload(cfg.Allowlists.IPFiles, cfg.Allowlists.UAFiles, cfg.Allowlists.HeaderFiles, cfg.Allowlists.ReloadInterval.Duration)

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
		pipeline.StartSweeper(ctx, limiter, 5*time.Minute, retention)
	}

	var nf *detect.NotFoundTracker
	if cfg.Detect.Enabled && cfg.Detect.High404Action != "off" {
		nf = detect.NewNotFoundTracker(cfg.Detect.High404Threshold, cfg.Detect.High404Window.Duration)
		pipeline.StartNotFoundSweeper(ctx, nf, time.Minute, retention)
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
		pipeline.StartBehaviorSweeper(ctx, beh, time.Minute, retention)
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
		pipeline.StartProtectSweeper(ctx, prot, time.Minute, retention)
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
			Algorithm:  cfg.Challenge.Algorithm,
			CookieName: cfg.Challenge.CookieName,
			CookieTTL:  cfg.Challenge.CookieTTL.Duration,
			Secure:     secure,
		}
		if cfg.Challenge.Captcha.Enabled {
			switch strings.ToLower(strings.TrimSpace(cfg.Challenge.Captcha.Provider)) {
			case "ravenguard":
				chal.Captcha = challenge.NewRavenCaptcha(chal)
			default:
				v, cerr := challenge.NewCaptcha(cfg.Challenge.Captcha.Provider, cfg.Challenge.Captcha.Token)
				if cerr != nil {
					slog.Error("captcha", "err", cerr)
					os.Exit(1)
				}
				chal.Captcha = v
			}
		}
		pipeline.StartNonceSweeper(ctx, chal, time.Minute)
	}

	pages, err := ui.New(ui.SiteFromConfig(cfg))
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

	routeTable := router.New(ctx)
	routeTable.SetErrorHandler(func(w http.ResponseWriter, r *http.Request, err error) {
		ray := r.Header.Get("X-RavenGuard-Ray")
		if ray == "" {
			ray = "unknown"
		}
		slog.Debug("upstream error", "err", err, "ray", ray)
		sentryRep.CaptureUpstreamError(err, ray)
		pages.RenderUpstream(w, ray)
	})
	routeTable.SetFallback(up, hc)
	defer routeTable.Close()

	accessSecret := []byte(cfg.Challenge.Secret)
	if len(accessSecret) == 0 {
		accessSecret = []byte(hashSecret)
	}
	accessMgr := access.NewManager(accessSecret)
	accessMgr.Brand = cfg.UI.Brand
	if cfg.Stealth.AccessCookieName != "" {
		accessMgr.CookieName = cfg.Stealth.AccessCookieName
	}

	pipe := pipeline.New(cfg, lists, feeds, limiter, chal, pages, up, trusted, nf, hc, priv, beh, prot)
	pipe.SetRouter(routeTable)
	pipe.SetAccess(accessMgr)
	pipe.SetAllowlists(allows)

	var acmeMgr *tlsacme.Manager
	acmeStorage := ""
	if strings.EqualFold(cfg.TLS.Mode, "acme") {
		http01 := cfg.TLS.ACME.HTTP01 == nil || *cfg.TLS.ACME.HTTP01
		tlsALPN := cfg.TLS.ACME.TLSALPN01 == nil || *cfg.TLS.ACME.TLSALPN01
		acmeStorage = cfg.TLS.ACME.StorageDir
		if abs, aerr := filepath.Abs(acmeStorage); aerr == nil {
			acmeStorage = abs
			cfg.TLS.ACME.StorageDir = abs
		}
		acmeMgr, err = tlsacme.New(tlsacme.Config{
			Email:       cfg.TLS.ACME.Email,
			Staging:     cfg.TLS.ACME.Staging,
			StorageDir:  acmeStorage,
			Hosts:       cfg.TLS.ACME.Hosts,
			HTTP01:      http01,
			TLSALPN01:   tlsALPN,
			AgreeTOS:    cfg.TLS.ACME.AgreeTOS,
			Directory:   cfg.TLS.ACME.Directory,
			RenewWindow: cfg.TLS.ACME.RenewWindow.Duration,
		})
		if err != nil {
			slog.Error("acme", "err", err)
			os.Exit(1)
		}
		defer func() { _ = acmeMgr.Close() }()
		pipe.SetACMEHandler(acmeMgr.HTTPHandler())
		if cfg.TLS.ACME.RedirectHTTP == nil || *cfg.TLS.ACME.RedirectHTTP {
			if cfg.Listen.HTTPS != "" {
				pipe.SetRedirectHTTP(true)
			}
		}
	}

	handler := sentryRep.Wrap(pipe)

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
	blocklistPaths = append(blocklistPaths, cfg.Allowlists.IPFiles...)
	blocklistPaths = append(blocklistPaths, cfg.Allowlists.UAFiles...)
	blocklistPaths = append(blocklistPaths, cfg.Allowlists.HeaderFiles...)
	adminListen, adminHTTPS, adminDataDir := "", "", ""
	if cfg.Admin.Enabled {
		adminListen = cfg.Admin.Listen
		adminHTTPS = cfg.Admin.HTTPS
		adminDataDir = cfg.Admin.DataDir
		if abs, aerr := filepath.Abs(adminDataDir); aerr == nil {
			adminDataDir = abs
			cfg.Admin.DataDir = abs
		}
		if err = os.MkdirAll(adminDataDir, 0o700); err != nil {
			slog.Error("admin data_dir", "err", err, "path", adminDataDir)
			os.Exit(1)
		}
		overlayDir := filepath.Join(adminDataDir, "blocklist-overlay")
		if err = lists.SetOverlayDir(overlayDir); err != nil {
			slog.Error("blocklist overlay", "err", err, "path", overlayDir)
			os.Exit(1)
		}
	}
	if acmeStorage != "" {
		if err = os.MkdirAll(acmeStorage, 0o700); err != nil {
			slog.Error("acme storage_dir", "err", err, "path", acmeStorage)
			os.Exit(1)
		}
	}

	manualDir := ""
	switch {
	case acmeStorage != "":
		manualDir = filepath.Join(acmeStorage, "manual")
	case adminDataDir != "":
		manualDir = filepath.Join(adminDataDir, "manual-certs")
	default:
		manualDir = "./data/manual-certs"
		if abs, aerr := filepath.Abs(manualDir); aerr == nil {
			manualDir = abs
		}
	}
	manualStore, err := tlscerts.NewManualStore(manualDir)
	if err != nil {
		slog.Error("manual certs", "err", err, "path", manualDir)
		os.Exit(1)
	}

	sandbox.DerivePaths(&sbCfg, flags.ConfigPath, cfg.Listen.HTTP, cfg.Listen.HTTPS, cfg.Listen.QUIC, cfg.Upstream.URL, cfg.TLS.CertFile, cfg.TLS.KeyFile, acmeStorage, blocklistPaths, adminListen, adminHTTPS, adminDataDir)
	if acmeStorage == "" && adminDataDir == "" && manualDir != "" {
		sbCfg.Landlock.RWDirs = append(sbCfg.Landlock.RWDirs, manualDir)
	}
	if _, err = sandbox.Apply(sbCfg, slog.Default()); err != nil {
		slog.Error("sandbox", "err", err)
		sentryRep.CaptureException(err)
		sentryRep.Flush()
		os.Exit(1)
	}

	reloadRouting := func(st *store.Store) error {
		if st == nil {
			return nil
		}
		ups, err := st.ListUpstreams()
		if err != nil {
			return err
		}
		rts, err := st.ListRoutes()
		if err != nil {
			return err
		}
		pols, err := st.ListAccessPolicies()
		if err != nil {
			return err
		}
		ru := make([]router.Upstream, 0, len(ups))
		for _, u := range ups {
			ru = append(ru, router.Upstream{
				ID: u.ID, Name: u.Name, URL: u.URL,
				ConnectTimeout: u.ConnectTimeout, ResponseHeader: u.ResponseHeader,
				IdleConnTimeout: u.IdleConnTimeout, MaxIdleConns: u.MaxIdleConns,
				MaxIdleConnsPerHost: u.MaxIdleConnsPerHost, MaxConnsPerHost: u.MaxConnsPerHost,
				FlushInterval: u.FlushInterval, SetHeaders: u.SetHeaders,
				HealthEnabled: u.HealthEnabled, HealthPath: u.HealthPath,
				HealthInterval: u.HealthInterval, HealthTimeout: u.HealthTimeout,
			})
		}
		rr := make([]router.Route, 0, len(rts))
		hosts := make([]string, 0)
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
			hosts = append(hosts, rt.Hosts...)
		}
		if err := routeTable.Replace(ru, rr); err != nil {
			return err
		}
		ap := make([]access.Policy, 0, len(pols))
		for _, p := range pols {
			ttl := 24 * time.Hour
			if d, err := time.ParseDuration(p.CookieTTL); err == nil && d > 0 {
				ttl = d
			}
			ap = append(ap, access.Policy{
				ID: p.ID, Name: p.Name, Mode: p.Mode, Rules: p.Rules, CookieTTL: ttl,
			})
		}
		accessMgr.Replace(ap)
		if acmeMgr != nil {
			managed := append([]string{}, cfg.TLS.ACME.Hosts...)
			managed = append(managed, hosts...)
			managed = uniqueHosts(managed)
			if len(managed) > 0 {
				if err := acmeMgr.Manage(ctx, managed); err != nil {
					slog.Warn("acme manage", "err", err)
				}
			}
		}
		return nil
	}

	var adminSrv *admin.Server
	var rt *ops.Runtime
	if cfg.Admin.Enabled {
		rt = ops.NewRuntime(cfg, prot, lists, limiter, hc, feeds, chal)
		rt.RootCtx = ctx
		rt.SetPipeline(pipe)
		rt.StartSampler(ctx)
		secureCookie := admin.CookieSecure(cfg.Admin.CookieSecure, cfg.Admin.HTTPS != "" || cfg.Listen.HTTPS != "" || cfg.Listen.QUIC != "")
		reloadFn := func() error {
			if adminSrv == nil {
				return nil
			}
			return reloadRouting(adminSrv.Store())
		}
		adminSrv, err = admin.New(admin.Options{
			Config:               cfg.Admin,
			TLSCertFile:          cfg.TLS.CertFile,
			TLSKeyFile:           cfg.TLS.KeyFile,
			Runtime:              rt,
			SecureCookie:         secureCookie,
			BootstrapUpstreamURL: cfg.Upstream.URL,
			ReloadRoutes:         reloadFn,
			LogSnapshot: func(limit int, level string) any {
				ring := logging.DefaultRing()
				if ring == nil {
					return []logging.Entry{}
				}
				return ring.Snapshot(limit, level)
			},
			CertStatus: func() any {
				return mergeCertDetails(manualStore, acmeMgr)
			},
			CertDetail: func(host string) (any, error) {
				if manualStore != nil {
					if d, derr := manualStore.Detail(host); derr == nil {
						return d, nil
					}
				}
				if acmeMgr != nil {
					return acmeMgr.Detail(host)
				}
				return nil, ops.ErrManualCertUnavailable
			},
			CertRenew: func(c context.Context, host string) error {
				if acmeMgr == nil {
					return ops.ErrCertRenewUnavailable
				}
				return acmeMgr.Renew(c, host)
			},
			ManualCertPut: func(host, certPEM, keyPEM string) error {
				if manualStore == nil {
					return ops.ErrManualCertUnavailable
				}
				return manualStore.Put(host, certPEM, keyPEM)
			},
			ManualCertDelete: func(host string) error {
				if manualStore == nil {
					return ops.ErrManualCertUnavailable
				}
				return manualStore.Delete(host)
			},
			ACMEManage: func(c context.Context, hosts []string) error {
				if acmeMgr == nil {
					return ops.ErrACMEManageUnavailable
				}
				return acmeMgr.Manage(c, hosts)
			},
		})
		if err != nil {
			slog.Error("admin", "err", err)
			os.Exit(1)
		}
		if err := reloadRouting(adminSrv.Store()); err != nil {
			slog.Error("load routes", "err", err)
			os.Exit(1)
		}
		var adminWG sync.WaitGroup
		adminWG.Go(func() {
			if aerr := adminSrv.Run(ctx); aerr != nil {
				slog.Error("admin server", "err", aerr)
				cancel()
			}
		})
		defer func() {
			adminWG.Wait()
			if cerr := adminSrv.Close(); cerr != nil {
				slog.Warn("admin close", "err", cerr)
			}
		}()
	} else if acmeMgr != nil && len(cfg.TLS.ACME.Hosts) > 0 {
		if err := acmeMgr.Manage(ctx, cfg.TLS.ACME.Hosts); err != nil {
			slog.Warn("acme manage", "err", err)
		}
	}

	var tlsCfg *tls.Config
	switch strings.ToLower(cfg.TLS.Mode) {
	case "acme":
		if acmeMgr != nil {
			tlsCfg = acmeMgr.TLSConfig()
			acmeGet := tlsCfg.GetCertificate
			tlsCfg.GetCertificate = func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
				if manualStore != nil {
					if c, cerr := manualStore.GetCertificate(chi); cerr != nil {
						return nil, cerr
					} else if c != nil {
						return c, nil
					}
				}
				if acmeGet != nil {
					return acmeGet(chi)
				}
				return nil, nil
			}
		}
	case "files":
		// listener loads from cert/key files
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
		TLSConfig:        tlsCfg,
		Handler:          handler,
		ProxyProtocol:    cfg.Trust.ProxyProtocol,
		MaxHeaderBytes:   maxHeader,
		DisableMultipath: sbCfg.NeedsClassicTCP(),
	})

	slog.Info("ravenguard starting", "upstream", cfg.Upstream.URL, "trust_mode", cfg.Trust.Mode, "tls_mode", cfg.TLS.Mode, "admin", cfg.Admin.Enabled)
	go func() {
		<-ctx.Done()
		slog.Info("shutting down")
	}()
	err = srv.Run(ctx)
	slog.Info("cleaning up")
	lists.Stop()
	allows.Stop()
	if feeds != nil {
		feeds.Stop()
	}
	if hc != nil {
		hc.Stop()
	}
	up.CloseIdleConnections()
	if err != nil {
		slog.Error("server", "err", err)
		sentryRep.CaptureException(err)
		sentryRep.Flush()
		os.Exit(1)
	}
}

func mergeCertDetails(manual *tlscerts.ManualStore, acme *tlsacme.Manager) []tlscerts.Detail {
	out := make([]tlscerts.Detail, 0)
	if manual != nil {
		out = append(out, manual.List()...)
	}
	if acme != nil {
		for _, st := range acme.Status() {
			out = append(out, tlscerts.Detail{
				Hostname:          st.Hostname,
				Source:            "acme",
				State:             st.State,
				NotBefore:         st.NotBefore,
				NotAfter:          st.NotAfter,
				DaysLeft:          st.DaysLeft,
				Issuer:            st.Issuer,
				Subject:           st.Subject,
				Serial:            st.Serial,
				FingerprintSHA256: st.FingerprintSHA256,
				DNSNames:          append([]string(nil), st.DNSNames...),
				LastError:         st.LastError,
				Managed:           st.Managed,
			})
		}
	}
	return out
}

func uniqueHosts(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, h := range in {
		h = strings.ToLower(strings.TrimSpace(h))
		if h == "" {
			continue
		}
		if u, err := url.Parse(h); err == nil && u.Host != "" {
			h = strings.ToLower(u.Hostname())
		}
		if _, ok := seen[h]; ok {
			continue
		}
		seen[h] = struct{}{}
		out = append(out, h)
	}
	return out
}
