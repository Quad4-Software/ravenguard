// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package ops

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Quad4-Software/ravenguard/internal/blocklist"
	"github.com/Quad4-Software/ravenguard/internal/challenge"
	"github.com/Quad4-Software/ravenguard/internal/config"
	"github.com/Quad4-Software/ravenguard/internal/health"
	"github.com/Quad4-Software/ravenguard/internal/protect"
	"github.com/Quad4-Software/ravenguard/internal/qfeeds"
	"github.com/Quad4-Software/ravenguard/internal/ratelimit"
)

// Runtime is a façade over live guard subsystems for the admin API.
type Runtime struct {
	StartedAt time.Time
	RootCtx   context.Context

	mu      sync.RWMutex
	cfg     config.Config
	Protect *protect.Guard
	Lists   *blocklist.Sets
	Limiter *ratelimit.Limiter
	Health  *health.Checker
	Feeds   *qfeeds.Cache
	Chal    *challenge.Manager

	Pipeline interface {
		ApplyConfig(cfg config.Config)
	}

	ReloadRoutes     func() error
	CertStatus       func() any
	CertRenew        func(ctx context.Context, host string) error
	LogSnapshot      func(limit int, level string) any
	ManualCertPut    func(hostname, certPEM, keyPEM string) error
	ManualCertDelete func(hostname string) error
	CertDetail       func(hostname string) (any, error)
	ACMEManage       func(ctx context.Context, hosts []string) error

	challengeEnabled atomic.Bool

	cpu cpuTracker

	procMu   sync.RWMutex
	lastProc ProcessStats

	histMu  sync.Mutex
	history []Sample
}

const historyLimit = 120

type Sample struct {
	At                 time.Time `json:"at"`
	BanCount           int       `json:"ban_count"`
	ConcurrencyGlobal  int64     `json:"concurrency_global"`
	ConcurrencyClients int       `json:"concurrency_clients"`
	RateLimitBuckets   int       `json:"ratelimit_buckets"`
	UpstreamHealthy    *bool     `json:"upstream_healthy"`
	CPUPercent         float64   `json:"cpu_percent"`
	RSSBytes           uint64    `json:"rss_bytes"`
	HeapAllocBytes     uint64    `json:"heap_alloc_bytes"`
	Goroutines         int       `json:"goroutines"`
}

func NewRuntime(cfg config.Config, prot *protect.Guard, lists *blocklist.Sets, lim *ratelimit.Limiter, hc *health.Checker, feeds *qfeeds.Cache, chal *challenge.Manager) *Runtime {
	r := &Runtime{
		StartedAt: time.Now().UTC(),
		cfg:       cfg,
		Protect:   prot,
		Lists:     lists,
		Limiter:   lim,
		Health:    hc,
		Feeds:     feeds,
		Chal:      chal,
		history:   make([]Sample, 0, historyLimit),
	}
	r.challengeEnabled.Store(cfg.Challenge.Enabled)
	return r
}

// SetPipeline wires the request pipeline for live ApplyConfig updates.
func (r *Runtime) SetPipeline(p interface{ ApplyConfig(cfg config.Config) }) {
	if r == nil {
		return
	}
	r.Pipeline = p
}

func (r *Runtime) Config() config.Config {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.cfg
}

func (r *Runtime) ReplaceConfig(cfg config.Config) {
	r.mu.Lock()
	r.cfg = cfg
	r.mu.Unlock()
	r.challengeEnabled.Store(cfg.Challenge.Enabled)
}

type Status struct {
	UptimeSeconds      int64           `json:"uptime_seconds"`
	UpstreamHealthy    *bool           `json:"upstream_healthy"`
	BanCount           int             `json:"ban_count"`
	ConcurrencyGlobal  int64           `json:"concurrency_global"`
	ConcurrencyClients int             `json:"concurrency_clients"`
	RateLimitBuckets   int             `json:"ratelimit_buckets"`
	Blocklists         blocklist.Stats `json:"blocklists"`
	ChallengeEnabled   bool            `json:"challenge_enabled"`
	QFeedsEnabled      bool            `json:"qfeeds_enabled"`
	QFeeds             qfeeds.Status   `json:"qfeeds"`
	ProtectEnabled     bool            `json:"protect_enabled"`
	RateLimitEnabled   bool            `json:"ratelimit_enabled"`
	DetectEnabled      bool            `json:"detect_enabled"`
	Process            ProcessStats    `json:"process"`
}

func (r *Runtime) Status() Status {
	cfg := r.Config()
	st := Status{
		UptimeSeconds:    int64(time.Since(r.StartedAt).Seconds()),
		ChallengeEnabled: r.challengeEnabled.Load(),
		QFeedsEnabled:    cfg.QFeeds.Enabled && r.Feeds != nil,
		QFeeds:           r.Feeds.Status(cfg.QFeeds.Enabled),
		ProtectEnabled:   cfg.Protect.Enabled,
		RateLimitEnabled: cfg.RateLimit.Enabled,
		DetectEnabled:    cfg.Detect.Enabled,
		Process:          r.processView(),
	}
	if r.Lists != nil {
		st.Blocklists = r.Lists.Stats()
	}
	if r.Protect != nil {
		st.BanCount = r.Protect.BanCount()
		st.ConcurrencyGlobal, st.ConcurrencyClients = r.Protect.Concurrency()
	}
	if r.Limiter != nil {
		st.RateLimitBuckets = r.Limiter.ActiveBuckets()
	}
	if r.Health != nil {
		h := r.Health.Healthy()
		st.UpstreamHealthy = &h
	}
	return st
}

func (r *Runtime) processView() ProcessStats {
	r.procMu.RLock()
	cached := r.lastProc
	r.procMu.RUnlock()
	proc := collectProcessStats(r.cpu.lastPercent())
	if cached.NumCPU == 0 && cached.Goroutines == 0 {
		return proc
	}
	proc.CPUPercent = cached.CPUPercent
	return proc
}

func (r *Runtime) RecordSample() {
	proc := collectProcessStats(r.cpu.samplePercent())
	r.procMu.Lock()
	r.lastProc = proc
	r.procMu.Unlock()

	st := r.Status()
	sample := Sample{
		At:                 time.Now().UTC(),
		BanCount:           st.BanCount,
		ConcurrencyGlobal:  st.ConcurrencyGlobal,
		ConcurrencyClients: st.ConcurrencyClients,
		RateLimitBuckets:   st.RateLimitBuckets,
		UpstreamHealthy:    st.UpstreamHealthy,
		CPUPercent:         proc.CPUPercent,
		RSSBytes:           proc.RSSBytes,
		HeapAllocBytes:     proc.HeapAllocBytes,
		Goroutines:         proc.Goroutines,
	}
	r.histMu.Lock()
	r.history = append(r.history, sample)
	if len(r.history) > historyLimit {
		r.history = append([]Sample(nil), r.history[len(r.history)-historyLimit:]...)
	}
	r.histMu.Unlock()
}

func (r *Runtime) History() []Sample {
	r.histMu.Lock()
	defer r.histMu.Unlock()
	out := make([]Sample, len(r.history))
	copy(out, r.history)
	return out
}

func (r *Runtime) StartSampler(ctx context.Context) {
	if ctx == nil {
		ctx = context.Background()
	}
	r.RecordSample()
	go func() {
		t := time.NewTicker(5 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				r.RecordSample()
			}
		}
	}()
}

// QFeedsSafe is the editable Q-Feeds subset for the admin UI.
type QFeedsSafe struct {
	Enabled  bool     `json:"enabled"`
	Feeds    []string `json:"feeds"`
	Refresh  string   `json:"refresh"`
	OnError  string   `json:"on_error"`
	BaseURL  string   `json:"base_url"`
	Limit    int      `json:"limit"`
	APIToken string   `json:"api_token"`
}

func (r *Runtime) QFeedsView() QFeedsSafe {
	return qfeedsSafeFrom(r.Config())
}

func (r *Runtime) ApplyQFeeds(safe QFeedsSafe) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	cfg := r.cfg
	applyQFeedsSettings(&cfg, safe)
	r.cfg = cfg
	r.syncQFeedsLocked(cfg)
	return nil
}

func applyQFeedsSettings(cfg *config.Config, safe QFeedsSafe) {
	cfg.QFeeds.Enabled = safe.Enabled
	if len(safe.Feeds) > 0 {
		cfg.QFeeds.Feeds = append([]string(nil), safe.Feeds...)
	}
	if d, err := time.ParseDuration(safe.Refresh); err == nil && d > 0 {
		cfg.QFeeds.Refresh = config.Duration{Duration: d}
	}
	if safe.OnError == "fail_open" || safe.OnError == "fail_closed" {
		cfg.QFeeds.OnError = safe.OnError
	}
	if strings.TrimSpace(safe.BaseURL) != "" {
		cfg.QFeeds.BaseURL = strings.TrimSpace(safe.BaseURL)
	}
	if safe.Limit >= 0 {
		cfg.QFeeds.Limit = safe.Limit
	}
	if strings.TrimSpace(safe.APIToken) != "" {
		cfg.QFeeds.APIToken = strings.TrimSpace(safe.APIToken)
	}
}

func (r *Runtime) syncQFeedsLocked(cfg config.Config) {
	if r.Feeds != nil {
		r.Feeds.UpdateSettings(cfg.QFeeds.Feeds, cfg.QFeeds.Refresh.Duration, cfg.QFeeds.OnError, cfg.QFeeds.BaseURL, cfg.QFeeds.Limit, cfg.QFeeds.APIToken)
		if cfg.QFeeds.Enabled {
			ctx := r.RootCtx
			if ctx == nil {
				ctx = context.Background()
			}
			r.Feeds.RefreshNow(ctx)
		}
		return
	}
	if cfg.QFeeds.Enabled && cfg.QFeeds.APIToken != "" {
		feeds := qfeeds.New(qfeeds.Config{
			APIToken: cfg.QFeeds.APIToken,
			BaseURL:  cfg.QFeeds.BaseURL,
			Feeds:    cfg.QFeeds.Feeds,
			Refresh:  cfg.QFeeds.Refresh.Duration,
			OnError:  cfg.QFeeds.OnError,
			Limit:    cfg.QFeeds.Limit,
		})
		ctx := r.RootCtx
		if ctx == nil {
			ctx = context.Background()
		}
		feeds.Start(ctx)
		r.Feeds = feeds
	}
}

func qfeedsSafeFrom(cfg config.Config) QFeedsSafe {
	return QFeedsSafe{
		Enabled: cfg.QFeeds.Enabled,
		Feeds:   append([]string(nil), cfg.QFeeds.Feeds...),
		Refresh: cfg.QFeeds.Refresh.String(),
		OnError: cfg.QFeeds.OnError,
		BaseURL: cfg.QFeeds.BaseURL,
		Limit:   cfg.QFeeds.Limit,
	}
}

// SafeConfig is the editable subset returned to the UI.
type SafeConfig struct {
	RateLimit RateLimitSafe `json:"ratelimit"`
	Protect   ProtectSafe   `json:"protect"`
	Detect    DetectSafe    `json:"detect"`
	Challenge ChallengeSafe `json:"challenge"`
	UI        UISafe        `json:"ui"`
	Trust     TrustSafe     `json:"trust"`
	Stealth   StealthSafe   `json:"stealth"`
	Privacy   PrivacySafe   `json:"privacy"`
	Logging   LoggingSafe   `json:"logging"`
	QFeeds    *QFeedsSafe   `json:"qfeeds,omitempty"`
}

type RateLimitSafe struct {
	Enabled       bool   `json:"enabled"`
	Requests      int    `json:"requests"`
	Window        string `json:"window"`
	Burst         int    `json:"burst"`
	PerPath       bool   `json:"per_path"`
	ChallengeOver bool   `json:"challenge_over"`
}

type ProtectSafe struct {
	Enabled             bool   `json:"enabled"`
	MaxBodyBytes        int64  `json:"max_body_bytes"`
	MaxHeaderBytes      int    `json:"max_header_bytes"`
	MaxURLBytes         int    `json:"max_url_bytes"`
	MaxConcurrentGlobal int64  `json:"max_concurrent_global"`
	MaxConcurrentClient int    `json:"max_concurrent_per_client"`
	BanAfterStrikes     int    `json:"ban_after_strikes"`
	BanTTL              string `json:"ban_ttl"`
	AttackBlock         bool   `json:"attack_block"`
	AttackScore         int    `json:"attack_score"`
	WriteMethodCost     int    `json:"write_method_cost"`
}

type DetectSafe struct {
	Enabled                  bool             `json:"enabled"`
	ChallengeScore           int              `json:"challenge_score"`
	BlockScore               int              `json:"block_score"`
	MissingUAScore           int              `json:"missing_ua_score"`
	ScannerUAScore           int              `json:"scanner_ua_score"`
	AIUAScore                int              `json:"ai_ua_score"`
	ProbePathScore           int              `json:"probe_path_score"`
	OddMethodScore           int              `json:"odd_method_score"`
	MissingAcceptScore       int              `json:"missing_accept_score"`
	MissingAcceptLangScore   int              `json:"missing_accept_lang_score"`
	MissingSecFetchScore     int              `json:"missing_sec_fetch_score"`
	SecCHUAMismatchScore     int              `json:"sec_ch_ua_mismatch_score"`
	StarAcceptBrowserScore   int              `json:"star_accept_browser_score"`
	High404Threshold         int              `json:"high_404_threshold"`
	High404Window            string           `json:"high_404_window"`
	High404Action            string           `json:"high_404_action"`
	BehaviorWindow           string           `json:"behavior_window"`
	BehaviorBurstLimit       int              `json:"behavior_burst_limit"`
	BehaviorBurstScore       int              `json:"behavior_burst_score"`
	BehaviorPathFanout       int              `json:"behavior_path_fanout"`
	BehaviorPathFanoutScore  int              `json:"behavior_path_fanout_score"`
	BehaviorStrikeLimit      int              `json:"behavior_strike_limit"`
	BehaviorStrikeScore      int              `json:"behavior_strike_score"`
	BehaviorWriteBurstLimit  int              `json:"behavior_write_burst_limit"`
	BehaviorWriteBurstScore  int              `json:"behavior_write_burst_score"`
	BehaviorWriteRepeatLimit int              `json:"behavior_write_repeat_limit"`
	BehaviorWriteRepeatScore int              `json:"behavior_write_repeat_score"`
	EmptyFormContextScore    int              `json:"empty_form_context_score"`
	ForumWritePathScore      int              `json:"forum_write_path_score"`
	ProxySignals             ProxySignalsSafe `json:"proxy_signals"`
}

type ProxySignalsSafe struct {
	BotScoreHeader  string `json:"bot_score_header"`
	BotScoreHeader2 string `json:"bot_score_header_2"`
	JA4Header       string `json:"ja4_header"`
	LowScorePoints  int    `json:"low_score_points"`
}

type ChallengeSafe struct {
	Enabled         bool   `json:"enabled"`
	Mode            string `json:"mode"`
	Difficulty      int    `json:"difficulty"`
	Algorithm       string `json:"algorithm"`
	CookieName      string `json:"cookie_name"`
	CookieTTL       string `json:"cookie_ttl"`
	PathPrefix      string `json:"path_prefix"`
	CaptchaEnabled  bool   `json:"captcha_enabled"`
	CaptchaProvider string `json:"captcha_provider"`
}

type TrustSafe struct {
	Mode           string   `json:"mode"`
	TrustedProxies []string `json:"trusted_proxies"`
	RealIPHeader   string   `json:"real_ip_header"`
	ProtoHeader    string   `json:"proto_header"`
	ProxyProtocol  bool     `json:"proxy_protocol"`
}

type UISafe struct {
	Brand             string `json:"brand"`
	StatusText        string `json:"status_text"`
	LogoURL           string `json:"logo_url"`
	FaviconURL        string `json:"favicon_url"`
	ThemeColor        string `json:"theme_color"`
	Background        string `json:"background"`
	Foreground        string `json:"foreground"`
	Accent            string `json:"accent"`
	FontSans          string `json:"font_sans"`
	FontMono          string `json:"font_mono"`
	ChallengeTitle    string `json:"challenge_title"`
	ChallengeSubtitle string `json:"challenge_subtitle"`
	BlockTitle        string `json:"block_title"`
	RateLimitTitle    string `json:"rate_limit_title"`
	UpstreamTitle     string `json:"upstream_title"`
	ErrorTitle        string `json:"error_title"`
	FooterText        string `json:"footer_text"`
	Contact           string `json:"contact"`
	CustomCSS         string `json:"custom_css"`
	Description       string `json:"description"`
	Lang              string `json:"lang"`
	Robots            string `json:"robots"`
	PrivacyNoticeURL  string `json:"privacy_notice_url"`
	OGImage           string `json:"og_image"`
	RayLabel          string `json:"ray_label"`
}

type StealthSafe struct {
	RayHeader        string `json:"ray_header"`
	ElementName      string `json:"element_name"`
	BootstrapGlobal  string `json:"bootstrap_global"`
	AccessCookieName string `json:"access_cookie_name"`
	HideBrandMark    bool   `json:"hide_brand_mark"`
	GenericCopy      bool   `json:"generic_copy"`
	ServeManifest    bool   `json:"serve_manifest"`
	ServeRootIcons   bool   `json:"serve_root_icons"`
	WidgetInputName  string `json:"widget_input_name"`
}

type PrivacySafe struct {
	HashClientIP     bool   `json:"hash_client_ip"`
	LogIP            string `json:"log_ip"`
	Retention        string `json:"retention"`
	PrivacyNoticeURL string `json:"privacy_notice_url"`
}

type LoggingSafe struct {
	Level  string `json:"level"`
	Format string `json:"format"`
}

type ConfigView struct {
	Live            SafeConfig     `json:"live"`
	RestartRequired map[string]any `json:"restart_required"`
}

func (r *Runtime) ConfigView() ConfigView {
	cfg := r.Config()
	qf := qfeedsSafeFrom(cfg)
	return ConfigView{
		Live: SafeConfig{
			RateLimit: RateLimitSafe{
				Enabled: cfg.RateLimit.Enabled, Requests: cfg.RateLimit.Requests,
				Window: cfg.RateLimit.Window.String(), Burst: cfg.RateLimit.Burst,
				PerPath: cfg.RateLimit.PerPath, ChallengeOver: cfg.RateLimit.ChallengeOver,
			},
			Protect: ProtectSafe{
				Enabled: cfg.Protect.Enabled, MaxBodyBytes: cfg.Protect.MaxBodyBytes,
				MaxHeaderBytes: cfg.Protect.MaxHeaderBytes, MaxURLBytes: cfg.Protect.MaxURLBytes,
				MaxConcurrentGlobal: cfg.Protect.MaxConcurrentGlobal, MaxConcurrentClient: cfg.Protect.MaxConcurrentClient,
				BanAfterStrikes: cfg.Protect.BanAfterStrikes, BanTTL: cfg.Protect.BanTTL.String(),
				AttackBlock: cfg.Protect.AttackBlock, AttackScore: cfg.Protect.AttackScore,
				WriteMethodCost: cfg.Protect.WriteMethodCost,
			},
			Detect: DetectSafe{
				Enabled: cfg.Detect.Enabled, ChallengeScore: cfg.Detect.ChallengeScore, BlockScore: cfg.Detect.BlockScore,
				MissingUAScore: cfg.Detect.MissingUAScore, ScannerUAScore: cfg.Detect.ScannerUAScore,
				AIUAScore: cfg.Detect.AIUAScore, ProbePathScore: cfg.Detect.ProbePathScore,
				OddMethodScore: cfg.Detect.OddMethodScore, MissingAcceptScore: cfg.Detect.MissingAcceptScore,
				MissingAcceptLangScore: cfg.Detect.MissingAcceptLangScore, MissingSecFetchScore: cfg.Detect.MissingSecFetchScore,
				SecCHUAMismatchScore: cfg.Detect.SecCHUAMismatchScore, StarAcceptBrowserScore: cfg.Detect.StarAcceptBrowserScore,
				High404Threshold: cfg.Detect.High404Threshold, High404Window: cfg.Detect.High404Window.String(),
				High404Action: cfg.Detect.High404Action, BehaviorWindow: cfg.Detect.BehaviorWindow.String(),
				BehaviorBurstLimit: cfg.Detect.BehaviorBurstLimit, BehaviorBurstScore: cfg.Detect.BehaviorBurstScore,
				BehaviorPathFanout: cfg.Detect.BehaviorPathFanout, BehaviorPathFanoutScore: cfg.Detect.BehaviorPathFanoutScore,
				BehaviorStrikeLimit: cfg.Detect.BehaviorStrikeLimit, BehaviorStrikeScore: cfg.Detect.BehaviorStrikeScore,
				BehaviorWriteBurstLimit: cfg.Detect.BehaviorWriteBurstLimit, BehaviorWriteBurstScore: cfg.Detect.BehaviorWriteBurstScore,
				BehaviorWriteRepeatLimit: cfg.Detect.BehaviorWriteRepeatLimit, BehaviorWriteRepeatScore: cfg.Detect.BehaviorWriteRepeatScore,
				EmptyFormContextScore: cfg.Detect.EmptyFormContextScore, ForumWritePathScore: cfg.Detect.ForumWritePathScore,
				ProxySignals: ProxySignalsSafe{
					BotScoreHeader: cfg.Detect.ProxySignals.BotScoreHeader, BotScoreHeader2: cfg.Detect.ProxySignals.BotScoreHeader2,
					JA4Header: cfg.Detect.ProxySignals.JA4Header, LowScorePoints: cfg.Detect.ProxySignals.LowScorePoints,
				},
			},
			Challenge: ChallengeSafe{
				Enabled: cfg.Challenge.Enabled, Mode: cfg.Challenge.Mode,
				Difficulty: cfg.Challenge.Difficulty, Algorithm: cfg.Challenge.Algorithm,
				CookieName: cfg.Challenge.CookieName, CookieTTL: cfg.Challenge.CookieTTL.String(),
				PathPrefix: cfg.Challenge.PathPrefix, CaptchaEnabled: cfg.Challenge.Captcha.Enabled,
				CaptchaProvider: cfg.Challenge.Captcha.Provider,
			},
			UI: UISafe{
				Brand: cfg.UI.Brand, StatusText: cfg.UI.StatusText,
				LogoURL: cfg.UI.LogoURL, FaviconURL: cfg.UI.FaviconURL,
				ThemeColor: cfg.Site.ThemeColor, Background: cfg.UI.Background,
				Foreground: cfg.UI.Foreground, Accent: cfg.UI.Accent,
				FontSans: cfg.UI.FontSans, FontMono: cfg.UI.FontMono,
				ChallengeTitle: cfg.UI.ChallengeTitle, ChallengeSubtitle: cfg.UI.ChallengeSubtitle,
				BlockTitle: cfg.UI.BlockTitle, RateLimitTitle: cfg.UI.RateLimitTitle,
				UpstreamTitle: cfg.UI.UpstreamTitle, ErrorTitle: cfg.UI.ErrorTitle,
				FooterText: cfg.UI.FooterText, Contact: cfg.UI.Contact, CustomCSS: cfg.UI.CustomCSS,
				Description: cfg.Site.Description, Lang: cfg.Site.Lang, Robots: cfg.Site.Robots,
				PrivacyNoticeURL: cfg.Privacy.PrivacyNoticeURL, OGImage: cfg.Site.OGImage,
				RayLabel: cfg.UI.RayLabel,
			},
			Trust: TrustSafe{
				Mode: cfg.Trust.Mode, TrustedProxies: append([]string(nil), cfg.Trust.TrustedProxies...),
				RealIPHeader: cfg.Trust.RealIPHeader, ProtoHeader: cfg.Trust.ProtoHeader,
				ProxyProtocol: cfg.Trust.ProxyProtocol,
			},
			Stealth: StealthSafe{
				RayHeader: cfg.Stealth.RayHeader, ElementName: cfg.Stealth.ElementName,
				BootstrapGlobal: cfg.Stealth.BootstrapGlobal, AccessCookieName: cfg.Stealth.AccessCookieName,
				HideBrandMark: cfg.Stealth.HideBrandMark, GenericCopy: cfg.Stealth.GenericCopy,
				ServeManifest: cfg.Stealth.ServeManifest, ServeRootIcons: cfg.Stealth.ServeRootIcons,
				WidgetInputName: cfg.Stealth.WidgetInputName,
			},
			Privacy: PrivacySafe{
				HashClientIP: cfg.Privacy.HashClientIP, LogIP: cfg.Privacy.LogIP,
				Retention: cfg.Privacy.Retention.String(), PrivacyNoticeURL: cfg.Privacy.PrivacyNoticeURL,
			},
			Logging: LoggingSafe{Level: cfg.Logging.Level, Format: cfg.Logging.Format},
			QFeeds:  &qf,
		},
		RestartRequired: map[string]any{
			"listen": map[string]string{
				"http":  cfg.Listen.HTTP,
				"https": cfg.Listen.HTTPS,
				"quic":  cfg.Listen.QUIC,
			},
			"tls": map[string]string{
				"mode":      cfg.TLS.Mode,
				"cert_file": redactNonEmpty(cfg.TLS.CertFile),
				"key_file":  redactNonEmpty(cfg.TLS.KeyFile),
			},
			"upstream": map[string]any{"url": cfg.Upstream.URL, "health_enabled": cfg.Upstream.Health.Enabled},
			"trust": map[string]any{
				"mode":            cfg.Trust.Mode,
				"trusted_proxies": cfg.Trust.TrustedProxies,
				"real_ip_header":  cfg.Trust.RealIPHeader,
				"proto_header":    cfg.Trust.ProtoHeader,
				"proxy_protocol":  cfg.Trust.ProxyProtocol,
			},
			"challenge": map[string]any{"path_prefix": cfg.Challenge.PathPrefix},
			"admin":     map[string]any{"listen": cfg.Admin.Listen, "https": cfg.Admin.HTTPS, "base_path": cfg.Admin.BasePath, "data_dir": cfg.Admin.DataDir},
			"sandbox":   map[string]string{"mode": cfg.Sandbox.Mode},
			"secrets":   map[string]string{"challenge_secret": "[redacted]", "qfeeds_api_token": redactSecret(cfg.QFeeds.APIToken), "sentry_dsn": redactSecret(cfg.Sentry.DSN)},
		},
	}
}

func redactSecret(s string) string {
	if s == "" {
		return ""
	}
	return "[redacted]"
}

func redactNonEmpty(s string) string {
	if s == "" {
		return ""
	}
	return "[set]"
}

func (r *Runtime) ApplySafeConfig(safe SafeConfig) error {
	if err := validateSafeConfig(safe); err != nil {
		return err
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	cfg := r.cfg

	cfg.RateLimit.Enabled = safe.RateLimit.Enabled
	if safe.RateLimit.Requests > 0 {
		cfg.RateLimit.Requests = safe.RateLimit.Requests
	}
	if safe.RateLimit.Burst > 0 {
		cfg.RateLimit.Burst = safe.RateLimit.Burst
	}
	if d, err := time.ParseDuration(safe.RateLimit.Window); err == nil && d > 0 {
		cfg.RateLimit.Window = config.Duration{Duration: d}
	}
	cfg.RateLimit.PerPath = safe.RateLimit.PerPath
	cfg.RateLimit.ChallengeOver = safe.RateLimit.ChallengeOver

	cfg.Protect.Enabled = safe.Protect.Enabled
	if safe.Protect.MaxBodyBytes > 0 {
		cfg.Protect.MaxBodyBytes = safe.Protect.MaxBodyBytes
	}
	if safe.Protect.MaxHeaderBytes > 0 {
		cfg.Protect.MaxHeaderBytes = safe.Protect.MaxHeaderBytes
	}
	if safe.Protect.MaxURLBytes > 0 {
		cfg.Protect.MaxURLBytes = safe.Protect.MaxURLBytes
	}
	if safe.Protect.MaxConcurrentGlobal > 0 {
		cfg.Protect.MaxConcurrentGlobal = safe.Protect.MaxConcurrentGlobal
	}
	if safe.Protect.MaxConcurrentClient > 0 {
		cfg.Protect.MaxConcurrentClient = safe.Protect.MaxConcurrentClient
	}
	if safe.Protect.BanAfterStrikes > 0 {
		cfg.Protect.BanAfterStrikes = safe.Protect.BanAfterStrikes
	}
	if d, err := time.ParseDuration(safe.Protect.BanTTL); err == nil && d > 0 {
		cfg.Protect.BanTTL = config.Duration{Duration: d}
	}
	cfg.Protect.AttackBlock = safe.Protect.AttackBlock
	if safe.Protect.AttackScore > 0 {
		cfg.Protect.AttackScore = safe.Protect.AttackScore
	}
	if safe.Protect.WriteMethodCost > 0 {
		cfg.Protect.WriteMethodCost = safe.Protect.WriteMethodCost
	}

	applyDetectSafe(&cfg, safe.Detect)
	applyChallengeSafe(&cfg, safe.Challenge)
	applyUISafe(&cfg, safe.UI)
	applyTrustSafe(&cfg, safe.Trust)
	applyStealthSafe(&cfg, safe.Stealth)
	applyPrivacySafe(&cfg, safe.Privacy)
	applyLoggingSafe(&cfg, safe.Logging)
	if safe.QFeeds != nil {
		applyQFeedsSettings(&cfg, *safe.QFeeds)
	}

	r.cfg = cfg
	r.challengeEnabled.Store(cfg.Challenge.Enabled)
	if safe.QFeeds != nil {
		r.syncQFeedsLocked(cfg)
	}

	if r.Protect != nil {
		r.Protect.UpdateConfig(protect.Config{
			Enabled:             cfg.Protect.Enabled,
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
	}
	if r.Limiter != nil && cfg.RateLimit.Enabled {
		r.Limiter.Update(cfg.RateLimit.Requests, cfg.RateLimit.Burst, cfg.RateLimit.Window.Duration, cfg.RateLimit.PerPath)
	}
	if r.Chal != nil {
		r.Chal.Difficulty = cfg.Challenge.Difficulty
		r.Chal.CookieTTL = cfg.Challenge.CookieTTL.Duration
		if cfg.Challenge.CookieName != "" {
			r.Chal.CookieName = cfg.Challenge.CookieName
		}
		if cfg.Challenge.Algorithm != "" {
			r.Chal.Algorithm = cfg.Challenge.Algorithm
		}
	}
	if r.Pipeline != nil {
		r.Pipeline.ApplyConfig(cfg)
	}
	return nil
}

func validateSafeConfig(safe SafeConfig) error {
	if mode := strings.TrimSpace(safe.Trust.Mode); mode != "" {
		m := strings.ToLower(mode)
		if m != "edge" && m != "behind_proxy" {
			return fmt.Errorf("trust.mode must be edge or behind_proxy")
		}
		if m == "behind_proxy" && !hasTrustedProxy(safe.Trust.TrustedProxies) {
			return fmt.Errorf("trust.trusted_proxies is required when trust.mode is behind_proxy")
		}
	}
	if safe.Privacy.LogIP != "" {
		switch strings.ToLower(strings.TrimSpace(safe.Privacy.LogIP)) {
		case "off", "hash", "full":
		default:
			return fmt.Errorf("privacy.log_ip must be off, hash, or full")
		}
	}
	if safe.Logging.Level != "" {
		switch strings.ToLower(strings.TrimSpace(safe.Logging.Level)) {
		case "debug", "info", "warn", "warning", "error":
		default:
			return fmt.Errorf("logging.level must be debug, info, warn, or error")
		}
	}
	if safe.Logging.Format != "" {
		switch strings.ToLower(strings.TrimSpace(safe.Logging.Format)) {
		case "text", "json":
		default:
			return fmt.Errorf("logging.format must be text or json")
		}
	}
	return nil
}

func hasTrustedProxy(proxies []string) bool {
	for _, p := range proxies {
		if strings.TrimSpace(p) != "" {
			return true
		}
	}
	return false
}

func applyDetectSafe(cfg *config.Config, safe DetectSafe) {
	cfg.Detect.Enabled = safe.Enabled
	if safe.ChallengeScore > 0 {
		cfg.Detect.ChallengeScore = safe.ChallengeScore
	}
	if safe.BlockScore > 0 {
		cfg.Detect.BlockScore = safe.BlockScore
	}
	if safe.MissingUAScore > 0 {
		cfg.Detect.MissingUAScore = safe.MissingUAScore
	}
	if safe.ScannerUAScore > 0 {
		cfg.Detect.ScannerUAScore = safe.ScannerUAScore
	}
	if safe.AIUAScore > 0 {
		cfg.Detect.AIUAScore = safe.AIUAScore
	}
	if safe.ProbePathScore > 0 {
		cfg.Detect.ProbePathScore = safe.ProbePathScore
	}
	if safe.OddMethodScore > 0 {
		cfg.Detect.OddMethodScore = safe.OddMethodScore
	}
	if safe.MissingAcceptScore > 0 {
		cfg.Detect.MissingAcceptScore = safe.MissingAcceptScore
	}
	if safe.MissingAcceptLangScore > 0 {
		cfg.Detect.MissingAcceptLangScore = safe.MissingAcceptLangScore
	}
	if safe.MissingSecFetchScore > 0 {
		cfg.Detect.MissingSecFetchScore = safe.MissingSecFetchScore
	}
	if safe.SecCHUAMismatchScore > 0 {
		cfg.Detect.SecCHUAMismatchScore = safe.SecCHUAMismatchScore
	}
	if safe.StarAcceptBrowserScore > 0 {
		cfg.Detect.StarAcceptBrowserScore = safe.StarAcceptBrowserScore
	}
	if safe.High404Threshold > 0 {
		cfg.Detect.High404Threshold = safe.High404Threshold
	}
	if d, err := time.ParseDuration(safe.High404Window); err == nil && d > 0 {
		cfg.Detect.High404Window = config.Duration{Duration: d}
	}
	if safe.High404Action != "" {
		cfg.Detect.High404Action = safe.High404Action
	}
	if d, err := time.ParseDuration(safe.BehaviorWindow); err == nil && d > 0 {
		cfg.Detect.BehaviorWindow = config.Duration{Duration: d}
	}
	if safe.BehaviorBurstLimit > 0 {
		cfg.Detect.BehaviorBurstLimit = safe.BehaviorBurstLimit
	}
	if safe.BehaviorBurstScore > 0 {
		cfg.Detect.BehaviorBurstScore = safe.BehaviorBurstScore
	}
	if safe.BehaviorPathFanout > 0 {
		cfg.Detect.BehaviorPathFanout = safe.BehaviorPathFanout
	}
	if safe.BehaviorPathFanoutScore > 0 {
		cfg.Detect.BehaviorPathFanoutScore = safe.BehaviorPathFanoutScore
	}
	if safe.BehaviorStrikeLimit > 0 {
		cfg.Detect.BehaviorStrikeLimit = safe.BehaviorStrikeLimit
	}
	if safe.BehaviorStrikeScore > 0 {
		cfg.Detect.BehaviorStrikeScore = safe.BehaviorStrikeScore
	}
	if safe.BehaviorWriteBurstLimit > 0 {
		cfg.Detect.BehaviorWriteBurstLimit = safe.BehaviorWriteBurstLimit
	}
	if safe.BehaviorWriteBurstScore > 0 {
		cfg.Detect.BehaviorWriteBurstScore = safe.BehaviorWriteBurstScore
	}
	if safe.BehaviorWriteRepeatLimit > 0 {
		cfg.Detect.BehaviorWriteRepeatLimit = safe.BehaviorWriteRepeatLimit
	}
	if safe.BehaviorWriteRepeatScore > 0 {
		cfg.Detect.BehaviorWriteRepeatScore = safe.BehaviorWriteRepeatScore
	}
	if safe.EmptyFormContextScore > 0 {
		cfg.Detect.EmptyFormContextScore = safe.EmptyFormContextScore
	}
	if safe.ForumWritePathScore > 0 {
		cfg.Detect.ForumWritePathScore = safe.ForumWritePathScore
	}
	setNonEmpty(&cfg.Detect.ProxySignals.BotScoreHeader, safe.ProxySignals.BotScoreHeader)
	setNonEmpty(&cfg.Detect.ProxySignals.BotScoreHeader2, safe.ProxySignals.BotScoreHeader2)
	setNonEmpty(&cfg.Detect.ProxySignals.JA4Header, safe.ProxySignals.JA4Header)
	if safe.ProxySignals.LowScorePoints > 0 {
		cfg.Detect.ProxySignals.LowScorePoints = safe.ProxySignals.LowScorePoints
	}
}

func applyChallengeSafe(cfg *config.Config, safe ChallengeSafe) {
	cfg.Challenge.Enabled = safe.Enabled
	if safe.Mode != "" {
		cfg.Challenge.Mode = safe.Mode
	}
	if safe.Difficulty >= 0 && safe.Difficulty <= 28 {
		cfg.Challenge.Difficulty = safe.Difficulty
	}
	setNonEmpty(&cfg.Challenge.Algorithm, safe.Algorithm)
	setNonEmpty(&cfg.Challenge.CookieName, safe.CookieName)
	if d, err := time.ParseDuration(safe.CookieTTL); err == nil && d > 0 {
		cfg.Challenge.CookieTTL = config.Duration{Duration: d}
	}
	setNonEmpty(&cfg.Challenge.PathPrefix, safe.PathPrefix)
	if safe.CaptchaProvider != "" || safe.CaptchaEnabled {
		cfg.Challenge.Captcha.Enabled = safe.CaptchaEnabled
		setNonEmpty(&cfg.Challenge.Captcha.Provider, safe.CaptchaProvider)
	}
}

func applyUISafe(cfg *config.Config, ui UISafe) {
	setNonEmpty(&cfg.UI.Brand, ui.Brand)
	setNonEmpty(&cfg.UI.StatusText, ui.StatusText)
	setNonEmpty(&cfg.UI.LogoURL, ui.LogoURL)
	setNonEmpty(&cfg.UI.FaviconURL, ui.FaviconURL)
	setNonEmpty(&cfg.UI.Background, ui.Background)
	setNonEmpty(&cfg.UI.Foreground, ui.Foreground)
	setNonEmpty(&cfg.UI.Accent, ui.Accent)
	setNonEmpty(&cfg.UI.FontSans, ui.FontSans)
	setNonEmpty(&cfg.UI.FontMono, ui.FontMono)
	setNonEmpty(&cfg.UI.ChallengeTitle, ui.ChallengeTitle)
	setNonEmpty(&cfg.UI.ChallengeSubtitle, ui.ChallengeSubtitle)
	setNonEmpty(&cfg.UI.BlockTitle, ui.BlockTitle)
	setNonEmpty(&cfg.UI.RateLimitTitle, ui.RateLimitTitle)
	setNonEmpty(&cfg.UI.UpstreamTitle, ui.UpstreamTitle)
	setNonEmpty(&cfg.UI.ErrorTitle, ui.ErrorTitle)
	setNonEmpty(&cfg.UI.FooterText, ui.FooterText)
	setNonEmpty(&cfg.UI.Contact, ui.Contact)
	setNonEmpty(&cfg.UI.CustomCSS, ui.CustomCSS)
	setNonEmpty(&cfg.UI.RayLabel, ui.RayLabel)
	setNonEmpty(&cfg.Site.Description, ui.Description)
	setNonEmpty(&cfg.Site.Lang, ui.Lang)
	setNonEmpty(&cfg.Site.Robots, ui.Robots)
	setNonEmpty(&cfg.Site.OGImage, ui.OGImage)
	setNonEmpty(&cfg.Site.ThemeColor, ui.ThemeColor)
	setNonEmpty(&cfg.Privacy.PrivacyNoticeURL, ui.PrivacyNoticeURL)
}

func applyTrustSafe(cfg *config.Config, safe TrustSafe) {
	mode := strings.ToLower(strings.TrimSpace(safe.Mode))
	if mode == "" {
		return
	}
	cfg.Trust.Mode = mode
	cfg.Trust.TrustedProxies = append([]string(nil), safe.TrustedProxies...)
	setNonEmpty(&cfg.Trust.RealIPHeader, safe.RealIPHeader)
	setNonEmpty(&cfg.Trust.ProtoHeader, safe.ProtoHeader)
	cfg.Trust.ProxyProtocol = safe.ProxyProtocol
}

func applyStealthSafe(cfg *config.Config, safe StealthSafe) {
	if safe.RayHeader == "" && safe.ElementName == "" && safe.BootstrapGlobal == "" &&
		safe.AccessCookieName == "" && safe.WidgetInputName == "" {
		return
	}
	setNonEmpty(&cfg.Stealth.RayHeader, safe.RayHeader)
	setNonEmpty(&cfg.Stealth.ElementName, safe.ElementName)
	setNonEmpty(&cfg.Stealth.BootstrapGlobal, safe.BootstrapGlobal)
	setNonEmpty(&cfg.Stealth.AccessCookieName, safe.AccessCookieName)
	setNonEmpty(&cfg.Stealth.WidgetInputName, safe.WidgetInputName)
	cfg.Stealth.HideBrandMark = safe.HideBrandMark
	cfg.Stealth.GenericCopy = safe.GenericCopy
	cfg.Stealth.ServeManifest = safe.ServeManifest
	cfg.Stealth.ServeRootIcons = safe.ServeRootIcons
}

func applyPrivacySafe(cfg *config.Config, safe PrivacySafe) {
	if safe.LogIP == "" && safe.Retention == "" && safe.PrivacyNoticeURL == "" {
		return
	}
	cfg.Privacy.HashClientIP = safe.HashClientIP
	setNonEmpty(&cfg.Privacy.LogIP, safe.LogIP)
	if d, err := time.ParseDuration(safe.Retention); err == nil && d > 0 {
		cfg.Privacy.Retention = config.Duration{Duration: d}
	}
	setNonEmpty(&cfg.Privacy.PrivacyNoticeURL, safe.PrivacyNoticeURL)
}

func applyLoggingSafe(cfg *config.Config, safe LoggingSafe) {
	setNonEmpty(&cfg.Logging.Level, safe.Level)
	setNonEmpty(&cfg.Logging.Format, safe.Format)
}

func setNonEmpty(dst *string, v string) {
	v = strings.TrimSpace(v)
	if v != "" {
		*dst = v
	}
}

// OverlaySafe copies cfg and applies the editable subset without touching live subsystems.
func OverlaySafe(cfg config.Config, safe SafeConfig) config.Config {
	applyDetectSafe(&cfg, safe.Detect)
	applyChallengeSafe(&cfg, safe.Challenge)
	applyUISafe(&cfg, safe.UI)
	applyTrustSafe(&cfg, safe.Trust)
	applyStealthSafe(&cfg, safe.Stealth)
	applyPrivacySafe(&cfg, safe.Privacy)
	applyLoggingSafe(&cfg, safe.Logging)
	if safe.QFeeds != nil {
		applyQFeedsSettings(&cfg, *safe.QFeeds)
	}
	return cfg
}

func EncodeSafeConfig(safe SafeConfig) (string, error) {
	b, err := json.Marshal(safe)
	return string(b), err
}

func DecodeSafeConfig(payload string) (SafeConfig, error) {
	var safe SafeConfig
	if payload == "" || payload == "{}" {
		return safe, nil
	}
	err := json.Unmarshal([]byte(payload), &safe)
	return safe, err
}

// MergeAndEncode overlays fn onto decoded existing SafeConfig JSON and encodes the result.
// Handlers should persist the merged blob with SetConfigOverrides so QFeeds updates
// share one overrides payload with other live fields instead of replacing them.
func MergeAndEncode(existing string, fn func(*SafeConfig)) (string, error) {
	safe, err := DecodeSafeConfig(existing)
	if err != nil {
		return "", err
	}
	if fn != nil {
		fn(&safe)
	}
	return EncodeSafeConfig(safe)
}
