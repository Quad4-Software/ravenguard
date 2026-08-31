// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package config

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
)

type Config struct {
	Listen     ListenConfig     `toml:"listen"`
	TLS        TLSConfig        `toml:"tls"`
	Upstream   UpstreamConfig   `toml:"upstream"`
	Trust      TrustConfig      `toml:"trust"`
	Blocklists BlocklistsConfig `toml:"blocklists"`
	QFeeds     QFeedsConfig     `toml:"qfeeds"`
	RateLimit  RateLimitConfig  `toml:"ratelimit"`
	Protect    ProtectConfig    `toml:"protect"`
	Detect     DetectConfig     `toml:"detect"`
	Challenge  ChallengeConfig  `toml:"challenge"`
	Privacy    PrivacyConfig    `toml:"privacy"`
	UI         UIConfig         `toml:"ui"`
	Site       SiteConfig       `toml:"site"`
	Logging    LoggingConfig    `toml:"logging"`
	Sentry     SentryConfig     `toml:"sentry"`
	Sandbox    SandboxConfig    `toml:"sandbox"`
}

// SandboxConfig controls Linux Landlock and seccomp-bpf hardening.
// Modes: off, try, best_effort, enforce.
type SandboxConfig struct {
	Mode     string               `toml:"mode"`
	Landlock SandboxLandlockConfig `toml:"landlock"`
	Seccomp  SandboxSeccompConfig  `toml:"seccomp"`
}

type SandboxLandlockConfig struct {
	Mode           string   `toml:"mode"`
	RODirs         []string `toml:"ro_dirs"`
	RWDirs         []string `toml:"rw_dirs"`
	ROFiles        []string `toml:"ro_files"`
	RWFiles        []string `toml:"rw_files"`
	RestrictNet    *bool    `toml:"restrict_net"`
	RestrictScoped *bool    `toml:"restrict_scoped"`
	BindTCP        []uint16 `toml:"bind_tcp"`
	BindUDP        []uint16 `toml:"bind_udp"`
	ConnectTCP     []uint16 `toml:"connect_tcp"`
	ConnectUDP     []uint16 `toml:"connect_udp"`
	IgnoreMissing  *bool    `toml:"ignore_missing"`
}

type SandboxSeccompConfig struct {
	Mode       string `toml:"mode"`
	DenyAction string `toml:"deny_action"`
}

type ListenConfig struct {
	HTTP  string `toml:"http"`
	HTTPS string `toml:"https"`
	QUIC  string `toml:"quic"`
}

type TLSConfig struct {
	CertFile string `toml:"cert_file"`
	KeyFile  string `toml:"key_file"`
}

type UpstreamConfig struct {
	URL                 string               `toml:"url"`
	ConnectTimeout      Duration             `toml:"connect_timeout"`
	ResponseHeader      Duration             `toml:"response_header_timeout"`
	IdleConnTimeout     Duration             `toml:"idle_conn_timeout"`
	MaxIdleConns        int                  `toml:"max_idle_conns"`
	MaxIdleConnsPerHost int                  `toml:"max_idle_conns_per_host"`
	MaxConnsPerHost     int                  `toml:"max_conns_per_host"`
	FlushInterval       Duration             `toml:"flush_interval"`
	SetHeaders          []string             `toml:"set_headers"`
	Health              UpstreamHealthConfig `toml:"health"`
}

type UpstreamHealthConfig struct {
	Enabled  bool     `toml:"enabled"`
	Path     string   `toml:"path"`
	Interval Duration `toml:"interval"`
	Timeout  Duration `toml:"timeout"`
}

type TrustConfig struct {
	Mode           string   `toml:"mode"`
	TrustedProxies []string `toml:"trusted_proxies"`
	RealIPHeader   string   `toml:"real_ip_header"`
	ProtoHeader    string   `toml:"proto_header"`
	ProxyProtocol  bool     `toml:"proxy_protocol"`
}

type PrivacyConfig struct {
	HashClientIP     bool     `toml:"hash_client_ip"`
	IPHashSecret     string   `toml:"ip_hash_secret"`
	LogIP            string   `toml:"log_ip"`
	Retention        Duration `toml:"retention"`
	PrivacyNoticeURL string   `toml:"privacy_notice_url"`
}

type BlocklistsConfig struct {
	IPFiles        []string `toml:"ip_files"`
	DNSFiles       []string `toml:"dns_files"`
	UAFiles        []string `toml:"ua_files"`
	ReloadInterval Duration `toml:"reload_interval"`
}

type QFeedsConfig struct {
	Enabled  bool     `toml:"enabled"`
	APIToken string   `toml:"api_token"`
	BaseURL  string   `toml:"base_url"`
	Feeds    []string `toml:"feeds"`
	Refresh  Duration `toml:"refresh"`
	OnError  string   `toml:"on_error"`
	Limit    int      `toml:"limit"`
}

type RateLimitConfig struct {
	Enabled       bool     `toml:"enabled"`
	Requests      int      `toml:"requests"`
	Window        Duration `toml:"window"`
	Burst         int      `toml:"burst"`
	PerPath       bool     `toml:"per_path"`
	ChallengeOver bool     `toml:"challenge_over"`
}

type ProtectConfig struct {
	Enabled             bool     `toml:"enabled"`
	MaxBodyBytes        int64    `toml:"max_body_bytes"`
	MaxHeaderBytes      int      `toml:"max_header_bytes"`
	MaxURLBytes         int      `toml:"max_url_bytes"`
	MaxConcurrentGlobal int64    `toml:"max_concurrent_global"`
	MaxConcurrentClient int      `toml:"max_concurrent_per_client"`
	BanAfterStrikes     int      `toml:"ban_after_strikes"`
	BanTTL              Duration `toml:"ban_ttl"`
	AttackBlock         bool     `toml:"attack_block"`
	AttackScore         int      `toml:"attack_score"`
	WriteMethodCost     int      `toml:"write_method_cost"`
}

type DetectConfig struct {
	Enabled                 bool               `toml:"enabled"`
	ChallengeScore          int                `toml:"challenge_score"`
	BlockScore              int                `toml:"block_score"`
	MissingUAScore          int                `toml:"missing_ua_score"`
	ScannerUAScore          int                `toml:"scanner_ua_score"`
	AIUAScore               int                `toml:"ai_ua_score"`
	ProbePathScore          int                `toml:"probe_path_score"`
	OddMethodScore          int                `toml:"odd_method_score"`
	MissingAcceptScore      int                `toml:"missing_accept_score"`
	MissingAcceptLangScore  int                `toml:"missing_accept_lang_score"`
	MissingSecFetchScore    int                `toml:"missing_sec_fetch_score"`
	SecCHUAMismatchScore    int                `toml:"sec_ch_ua_mismatch_score"`
	StarAcceptBrowserScore  int                `toml:"star_accept_browser_score"`
	High404Threshold        int                `toml:"high_404_threshold"`
	High404Window           Duration           `toml:"high_404_window"`
	High404Action           string             `toml:"high_404_action"`
	BehaviorWindow          Duration           `toml:"behavior_window"`
	BehaviorBurstLimit      int                `toml:"behavior_burst_limit"`
	BehaviorBurstScore      int                `toml:"behavior_burst_score"`
	BehaviorPathFanout      int                `toml:"behavior_path_fanout"`
	BehaviorPathFanoutScore int                `toml:"behavior_path_fanout_score"`
	BehaviorStrikeLimit     int                `toml:"behavior_strike_limit"`
	BehaviorStrikeScore     int                `toml:"behavior_strike_score"`
	ProxySignals            DetectProxySignals `toml:"proxy_signals"`
}

type DetectProxySignals struct {
	BotScoreHeader  string `toml:"bot_score_header"`
	BotScoreHeader2 string `toml:"bot_score_header_2"`
	JA4Header       string `toml:"ja4_header"`
	LowScorePoints  int    `toml:"low_score_points"`
}

type ChallengeConfig struct {
	Enabled    bool          `toml:"enabled"`
	Mode       string        `toml:"mode"`
	Difficulty int           `toml:"difficulty"`
	CookieName string        `toml:"cookie_name"`
	CookieTTL  Duration      `toml:"cookie_ttl"`
	Secret     string        `toml:"secret"`
	PathPrefix string        `toml:"path_prefix"`
	Captcha    CaptchaConfig `toml:"captcha"`
}

type CaptchaConfig struct {
	Enabled  bool   `toml:"enabled"`
	Provider string `toml:"provider"`
	Token    string `toml:"token"`
}

type UIConfig struct {
	Brand      string `toml:"brand"`
	StatusText string `toml:"status_text"`
	TestMode   bool   `toml:"test_mode"`
}

type SiteConfig struct {
	PublicURL   string `toml:"public_url"`
	Description string `toml:"description"`
	OGImage     string `toml:"og_image"`
	ThemeColor  string `toml:"theme_color"`
	Robots      string `toml:"robots"`
	Lang        string `toml:"lang"`
}

type LoggingConfig struct {
	Level  string `toml:"level"`
	Format string `toml:"format"`
}

// SentryConfig configures Sentry or GlitchTip error reporting.
// GlitchTip accepts the same DSN and SDK protocol as Sentry for errors.
type SentryConfig struct {
	Enabled          bool     `toml:"enabled"`
	DSN              string   `toml:"dsn"`
	Environment      string   `toml:"environment"`
	Release          string   `toml:"release"`
	ServerName       string   `toml:"server_name"`
	SampleRate       float64  `toml:"sample_rate"`
	TracesSampleRate float64  `toml:"traces_sample_rate"`
	Debug            bool     `toml:"debug"`
	AttachStacktrace bool     `toml:"attach_stacktrace"`
	SendDefaultPII   bool     `toml:"send_default_pii"`
	CaptureUpstream  bool     `toml:"capture_upstream_errors"`
	FlushTimeout     Duration `toml:"flush_timeout"`
}

type Duration struct {
	time.Duration
}

func (d *Duration) UnmarshalText(text []byte) error {
	if len(text) == 0 {
		d.Duration = 0
		return nil
	}
	parsed, err := time.ParseDuration(string(text))
	if err != nil {
		return err
	}
	d.Duration = parsed
	return nil
}

func (d Duration) MarshalText() ([]byte, error) {
	return []byte(d.Duration.String()), nil
}

func Default() Config {
	return Config{
		Listen: ListenConfig{HTTP: ":8080"},
		Upstream: UpstreamConfig{
			URL:                 "http://127.0.0.1:8000",
			ConnectTimeout:      Duration{5 * time.Second},
			ResponseHeader:      Duration{30 * time.Second},
			IdleConnTimeout:     Duration{90 * time.Second},
			MaxIdleConns:        1024,
			MaxIdleConnsPerHost: 256,
			MaxConnsPerHost:     0,
			FlushInterval:       Duration{-1},
			Health: UpstreamHealthConfig{
				Path:     "/healthz",
				Interval: Duration{10 * time.Second},
				Timeout:  Duration{3 * time.Second},
			},
		},
		Trust: TrustConfig{
			Mode:         "edge",
			RealIPHeader: "X-Real-IP",
			ProtoHeader:  "X-Forwarded-Proto",
		},
		Blocklists: BlocklistsConfig{
			ReloadInterval: Duration{30 * time.Second},
		},
		QFeeds: QFeedsConfig{
			BaseURL: "https://api.qfeeds.com",
			Feeds:   []string{"malware_ip", "malware_domains"},
			Refresh: Duration{1 * time.Hour},
			OnError: "fail_open",
		},
		RateLimit: RateLimitConfig{
			Enabled: true, Requests: 120, Window: Duration{time.Minute}, Burst: 60, ChallengeOver: true,
		},
		Protect: ProtectConfig{
			Enabled:             true,
			MaxBodyBytes:        1 << 20,
			MaxHeaderBytes:      1 << 14,
			MaxURLBytes:         8192,
			MaxConcurrentGlobal: 8192,
			MaxConcurrentClient: 32,
			BanAfterStrikes:     5,
			BanTTL:              Duration{10 * time.Minute},
			AttackBlock:         true,
			AttackScore:         90,
			WriteMethodCost:     3,
		},
		Detect: DetectConfig{
			Enabled: true, ChallengeScore: 40, BlockScore: 90,
			MissingUAScore: 25, ScannerUAScore: 50, AIUAScore: 55,
			ProbePathScore: 40, OddMethodScore: 30, MissingAcceptScore: 10,
			MissingAcceptLangScore: 15, MissingSecFetchScore: 20,
			SecCHUAMismatchScore: 25, StarAcceptBrowserScore: 15,
			High404Threshold: 20, High404Window: Duration{time.Minute}, High404Action: "challenge",
			BehaviorWindow:     Duration{time.Minute},
			BehaviorBurstLimit: 60, BehaviorBurstScore: 35,
			BehaviorPathFanout: 40, BehaviorPathFanoutScore: 30,
			BehaviorStrikeLimit: 3, BehaviorStrikeScore: 25,
			ProxySignals: DetectProxySignals{
				BotScoreHeader:  "CF-Bot-Score",
				BotScoreHeader2: "X-Bot-Score",
				JA4Header:       "X-JA4",
				LowScorePoints:  40,
			},
		},
		Challenge: ChallengeConfig{
			Enabled: true, Mode: "detect", Difficulty: 16,
			CookieName: "rg_clear", CookieTTL: Duration{24 * time.Hour}, PathPrefix: "/_rg",
		},
		Privacy: PrivacyConfig{
			HashClientIP: true,
			LogIP:        "hash",
			Retention:    Duration{30 * time.Minute},
		},
		UI: UIConfig{
			Brand: "RavenGuard", StatusText: "Checking your browser before accessing this site.",
		},
		Site: SiteConfig{
			Description: "RavenGuard application guard",
			ThemeColor:  "#050505",
			Robots:      "noindex, nofollow",
			Lang:        "en",
		},
		Logging: LoggingConfig{Level: "info", Format: "text"},
		Sentry: SentryConfig{
			SampleRate:       1.0,
			AttachStacktrace: true,
			FlushTimeout:     Duration{2 * time.Second},
		},
		Sandbox: SandboxConfig{
			Mode: "best_effort",
			Landlock: SandboxLandlockConfig{
				RestrictNet:    boolPtr(true),
				RestrictScoped: boolPtr(true),
				IgnoreMissing:  boolPtr(true),
			},
			Seccomp: SandboxSeccompConfig{
				DenyAction: "errno",
			},
		},
	}
}

func boolPtr(v bool) *bool { return &v }

type Flags struct {
	ConfigPath  string
	ListenHTTP  string
	ListenHTTPS string
	ListenQUIC  string
	Upstream    string
	Secret      string
	TestMode    bool
	TestModeSet bool
	PublicURL   string
	LogLevel    string
	LogFormat   string
}

func ParseFlags(args []string) (Flags, error) {
	fs := flag.NewFlagSet("ravenguard", flag.ContinueOnError)
	var f Flags
	fs.StringVar(&f.ConfigPath, "config", envOr("RG_CONFIG", "configs/ravenguard.toml"), "path to TOML config")
	fs.StringVar(&f.ListenHTTP, "listen-http", "", "HTTP listen address (overrides config/env)")
	fs.StringVar(&f.ListenHTTPS, "listen-https", "", "HTTPS listen address")
	fs.StringVar(&f.ListenQUIC, "listen-quic", "", "QUIC/HTTP3 listen address")
	fs.StringVar(&f.Upstream, "upstream", "", "upstream URL (http://, https://, or unix://)")
	fs.StringVar(&f.Secret, "challenge-secret", "", "challenge HMAC secret")
	fs.StringVar(&f.PublicURL, "public-url", "", "public site URL for SEO canonical/OG")
	fs.StringVar(&f.LogLevel, "log-level", "", "debug|info|warn|error")
	fs.StringVar(&f.LogFormat, "log-format", "", "text|json")
	test := fs.Bool("test-mode", false, "enable UI test routes under /_rg/test")
	if err := fs.Parse(args); err != nil {
		return Flags{}, err
	}
	f.TestMode = *test
	fs.Visit(func(fl *flag.Flag) {
		if fl.Name == "test-mode" {
			f.TestModeSet = true
		}
	})
	return f, nil
}

func Load(path string) (Config, error) {
	cfg := Default()
	if path != "" {
		if _, err := toml.DecodeFile(path, &cfg); err != nil {
			return Config{}, fmt.Errorf("load config: %w", err)
		}
	}
	applyEnv(&cfg)
	normalize(&cfg)
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func LoadWithFlags(f Flags) (Config, error) {
	path := f.ConfigPath
	if path == "" {
		path = envOr("RG_CONFIG", "configs/ravenguard.toml")
	}
	cfg, err := Load(path)
	if err != nil {
		return Config{}, err
	}
	applyFlags(&cfg, f)
	normalize(&cfg)
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func applyEnv(c *Config) {
	setStr(&c.Listen.HTTP, "RG_LISTEN_HTTP")
	setStr(&c.Listen.HTTPS, "RG_LISTEN_HTTPS")
	setStr(&c.Listen.QUIC, "RG_LISTEN_QUIC")
	setStr(&c.TLS.CertFile, "RG_TLS_CERT_FILE")
	setStr(&c.TLS.KeyFile, "RG_TLS_KEY_FILE")
	setStr(&c.Upstream.URL, "RG_UPSTREAM_URL")
	setStr(&c.Trust.Mode, "RG_TRUST_MODE")
	setStr(&c.Trust.RealIPHeader, "RG_REAL_IP_HEADER")
	setStr(&c.Trust.ProtoHeader, "RG_PROTO_HEADER")
	setBool(&c.Trust.ProxyProtocol, "RG_PROXY_PROTOCOL")
	setStr(&c.QFeeds.APIToken, "RG_QFEEDS_API_TOKEN")
	if c.QFeeds.APIToken == "" {
		setStr(&c.QFeeds.APIToken, "QFEEDS_API_TOKEN")
	}
	setBool(&c.QFeeds.Enabled, "RG_QFEEDS_ENABLED")
	setStr(&c.Challenge.Secret, "RG_CHALLENGE_SECRET")
	setStr(&c.Challenge.Mode, "RG_CHALLENGE_MODE")
	setStr(&c.Challenge.PathPrefix, "RG_CHALLENGE_PATH_PREFIX")
	setInt(&c.Challenge.Difficulty, "RG_CHALLENGE_DIFFICULTY")
	setBool(&c.Challenge.Enabled, "RG_CHALLENGE_ENABLED")
	setBool(&c.Challenge.Captcha.Enabled, "RG_CAPTCHA_ENABLED")
	setStr(&c.Challenge.Captcha.Provider, "RG_CAPTCHA_PROVIDER")
	setStr(&c.Challenge.Captcha.Token, "RG_CAPTCHA_TOKEN")
	setBool(&c.Privacy.HashClientIP, "RG_PRIVACY_HASH_CLIENT_IP")
	setStr(&c.Privacy.IPHashSecret, "RG_PRIVACY_IP_HASH_SECRET")
	setStr(&c.Privacy.LogIP, "RG_PRIVACY_LOG_IP")
	setStr(&c.Privacy.PrivacyNoticeURL, "RG_PRIVACY_NOTICE_URL")
	setStr(&c.UI.Brand, "RG_UI_BRAND")
	setStr(&c.UI.StatusText, "RG_UI_STATUS_TEXT")
	setBool(&c.UI.TestMode, "RG_UI_TEST_MODE")
	setStr(&c.Site.PublicURL, "RG_SITE_PUBLIC_URL")
	setStr(&c.Site.Description, "RG_SITE_DESCRIPTION")
	setStr(&c.Site.OGImage, "RG_SITE_OG_IMAGE")
	setStr(&c.Site.ThemeColor, "RG_SITE_THEME_COLOR")
	setStr(&c.Site.Robots, "RG_SITE_ROBOTS")
	setStr(&c.Site.Lang, "RG_SITE_LANG")
	setStr(&c.Logging.Level, "RG_LOG_LEVEL")
	setStr(&c.Logging.Format, "RG_LOG_FORMAT")
	setBool(&c.Upstream.Health.Enabled, "RG_UPSTREAM_HEALTH_ENABLED")
	setStr(&c.Upstream.Health.Path, "RG_UPSTREAM_HEALTH_PATH")
	setBool(&c.Sentry.Enabled, "RG_SENTRY_ENABLED")
	setStr(&c.Sentry.DSN, "RG_SENTRY_DSN")
	if c.Sentry.DSN == "" {
		setStr(&c.Sentry.DSN, "SENTRY_DSN")
	}
	setStr(&c.Sentry.Environment, "RG_SENTRY_ENVIRONMENT")
	if c.Sentry.Environment == "" {
		setStr(&c.Sentry.Environment, "SENTRY_ENVIRONMENT")
	}
	setStr(&c.Sentry.Release, "RG_SENTRY_RELEASE")
	if c.Sentry.Release == "" {
		setStr(&c.Sentry.Release, "SENTRY_RELEASE")
	}
	setStr(&c.Sentry.ServerName, "RG_SENTRY_SERVER_NAME")
	setFloat(&c.Sentry.SampleRate, "RG_SENTRY_SAMPLE_RATE")
	setFloat(&c.Sentry.TracesSampleRate, "RG_SENTRY_TRACES_SAMPLE_RATE")
	setBool(&c.Sentry.Debug, "RG_SENTRY_DEBUG")
	setBool(&c.Sentry.AttachStacktrace, "RG_SENTRY_ATTACH_STACKTRACE")
	setBool(&c.Sentry.SendDefaultPII, "RG_SENTRY_SEND_DEFAULT_PII")
	setBool(&c.Sentry.CaptureUpstream, "RG_SENTRY_CAPTURE_UPSTREAM_ERRORS")
	if v := os.Getenv("RG_SENTRY_FLUSH_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			c.Sentry.FlushTimeout = Duration{d}
		}
	}
	setStr(&c.Sandbox.Mode, "RG_SANDBOX_MODE")
	setStr(&c.Sandbox.Landlock.Mode, "RG_SANDBOX_LANDLOCK_MODE")
	setStr(&c.Sandbox.Seccomp.Mode, "RG_SANDBOX_SECCOMP_MODE")
	setStr(&c.Sandbox.Seccomp.DenyAction, "RG_SANDBOX_SECCOMP_DENY_ACTION")
	setBoolPtr(&c.Sandbox.Landlock.RestrictNet, "RG_SANDBOX_LANDLOCK_RESTRICT_NET")
	setBoolPtr(&c.Sandbox.Landlock.RestrictScoped, "RG_SANDBOX_LANDLOCK_RESTRICT_SCOPED")
	setBoolPtr(&c.Sandbox.Landlock.IgnoreMissing, "RG_SANDBOX_LANDLOCK_IGNORE_MISSING")
}

func applyFlags(c *Config, f Flags) {
	if f.ListenHTTP != "" {
		c.Listen.HTTP = f.ListenHTTP
	}
	if f.ListenHTTPS != "" {
		c.Listen.HTTPS = f.ListenHTTPS
	}
	if f.ListenQUIC != "" {
		c.Listen.QUIC = f.ListenQUIC
	}
	if f.Upstream != "" {
		c.Upstream.URL = f.Upstream
	}
	if f.Secret != "" {
		c.Challenge.Secret = f.Secret
	}
	if f.PublicURL != "" {
		c.Site.PublicURL = f.PublicURL
	}
	if f.LogLevel != "" {
		c.Logging.Level = f.LogLevel
	}
	if f.LogFormat != "" {
		c.Logging.Format = f.LogFormat
	}
	if f.TestModeSet {
		c.UI.TestMode = f.TestMode
	}
}

func normalize(c *Config) {
	if c.Trust.Mode == "" {
		c.Trust.Mode = "edge"
	}
	if c.Trust.RealIPHeader == "" {
		c.Trust.RealIPHeader = "X-Real-IP"
	}
	if c.Trust.ProtoHeader == "" {
		c.Trust.ProtoHeader = "X-Forwarded-Proto"
	}
	if c.QFeeds.OnError == "" {
		c.QFeeds.OnError = "fail_open"
	}
	if c.Challenge.PathPrefix == "" {
		c.Challenge.PathPrefix = "/_rg"
	}
	if c.Challenge.Mode == "" {
		c.Challenge.Mode = "detect"
	}
	if c.Detect.High404Action == "" {
		c.Detect.High404Action = "challenge"
	}
	if c.Upstream.Health.Path == "" {
		c.Upstream.Health.Path = "/healthz"
	}
	if c.Privacy.LogIP == "" {
		c.Privacy.LogIP = "hash"
	}
	if c.Privacy.Retention.Duration <= 0 {
		c.Privacy.Retention = Duration{30 * time.Minute}
	}
	if c.Site.Robots == "" {
		c.Site.Robots = "noindex, nofollow"
	}
	if c.Site.ThemeColor == "" {
		c.Site.ThemeColor = "#050505"
	}
	if c.Site.Lang == "" {
		c.Site.Lang = "en"
	}
	if c.Site.Description == "" {
		c.Site.Description = c.UI.Brand + " application guard"
	}
	if c.UI.Brand == "" {
		c.UI.Brand = "RavenGuard"
	}
	if c.Sentry.FlushTimeout.Duration <= 0 {
		c.Sentry.FlushTimeout = Duration{2 * time.Second}
	}
	if c.Sentry.DSN != "" && !c.Sentry.Enabled {
		c.Sentry.Enabled = true
	}
	if c.Sandbox.Mode == "" {
		c.Sandbox.Mode = "best_effort"
	}
	if c.Sandbox.Landlock.RestrictNet == nil {
		c.Sandbox.Landlock.RestrictNet = boolPtr(true)
	}
	if c.Sandbox.Landlock.RestrictScoped == nil {
		c.Sandbox.Landlock.RestrictScoped = boolPtr(true)
	}
	if c.Sandbox.Landlock.IgnoreMissing == nil {
		c.Sandbox.Landlock.IgnoreMissing = boolPtr(true)
	}
	if c.Sandbox.Seccomp.DenyAction == "" {
		c.Sandbox.Seccomp.DenyAction = "errno"
	}
}

func weakChallengeSecret(secret string) bool {
	s := strings.TrimSpace(secret)
	if s == "" {
		return true
	}
	low := strings.ToLower(s)
	if strings.HasPrefix(low, "change-me") {
		return true
	}
	return len(s) < 16
}

func (c Config) Validate() error {
	if c.Upstream.URL == "" {
		return fmt.Errorf("upstream.url is required")
	}
	if c.Listen.HTTP == "" && c.Listen.HTTPS == "" && c.Listen.QUIC == "" {
		return fmt.Errorf("at least one of listen.http, listen.https, listen.quic is required")
	}
	if (c.Listen.HTTPS != "" || c.Listen.QUIC != "") && (c.TLS.CertFile == "" || c.TLS.KeyFile == "") {
		return fmt.Errorf("tls.cert_file and tls.key_file required when https or quic is enabled")
	}
	switch strings.ToLower(strings.TrimSpace(c.Trust.Mode)) {
	case "edge", "behind_proxy":
	default:
		return fmt.Errorf("trust.mode must be edge or behind_proxy")
	}
	if strings.EqualFold(strings.TrimSpace(c.Trust.Mode), "behind_proxy") {
		hasProxy := false
		for _, p := range c.Trust.TrustedProxies {
			if strings.TrimSpace(p) != "" {
				hasProxy = true
				break
			}
		}
		if !hasProxy {
			return fmt.Errorf("trust.trusted_proxies is required when trust.mode is behind_proxy")
		}
	}
	switch strings.ToLower(strings.TrimSpace(c.Privacy.LogIP)) {
	case "off", "hash", "full":
	default:
		return fmt.Errorf("privacy.log_ip must be off, hash, or full")
	}
	if c.Challenge.Enabled {
		if weakChallengeSecret(c.Challenge.Secret) {
			return fmt.Errorf("challenge.secret must be at least 16 characters and must not use a change-me placeholder")
		}
		if c.Challenge.Difficulty < 0 || c.Challenge.Difficulty > 28 {
			return fmt.Errorf("challenge.difficulty must be between 0 and 28")
		}
		if c.Challenge.CookieName == "" {
			return fmt.Errorf("challenge.cookie_name is required")
		}
		switch strings.ToLower(c.Challenge.Mode) {
		case "detect", "always":
		default:
			return fmt.Errorf("challenge.mode must be detect or always")
		}
	}
	if c.Challenge.Captcha.Enabled {
		provider := strings.ToLower(strings.TrimSpace(c.Challenge.Captcha.Provider))
		if provider == "" {
			return fmt.Errorf("challenge.captcha.provider is required when captcha is enabled")
		}
		if provider != "stub" {
			return fmt.Errorf("challenge.captcha.provider %q is not supported (use stub)", c.Challenge.Captcha.Provider)
		}
	}
	if c.QFeeds.Enabled {
		if c.QFeeds.APIToken == "" {
			return fmt.Errorf("qfeeds.api_token is required when qfeeds is enabled")
		}
		switch c.QFeeds.OnError {
		case "fail_open", "fail_closed":
		default:
			return fmt.Errorf("qfeeds.on_error must be fail_open or fail_closed")
		}
	}
	if c.RateLimit.Enabled {
		if c.RateLimit.Requests <= 0 {
			return fmt.Errorf("ratelimit.requests must be > 0")
		}
		if c.RateLimit.Window.Duration <= 0 {
			return fmt.Errorf("ratelimit.window must be > 0")
		}
	}
	if c.Detect.Enabled {
		if c.Detect.BlockScore < c.Detect.ChallengeScore {
			return fmt.Errorf("detect.block_score must be >= detect.challenge_score")
		}
		switch strings.ToLower(c.Detect.High404Action) {
		case "challenge", "block", "off", "":
		default:
			return fmt.Errorf("detect.high_404_action must be challenge, block, or off")
		}
	}
	switch strings.ToLower(c.Logging.Level) {
	case "", "debug", "info", "warn", "warning", "error":
	default:
		return fmt.Errorf("logging.level must be debug, info, warn, or error")
	}
	switch strings.ToLower(c.Logging.Format) {
	case "", "text", "json":
	default:
		return fmt.Errorf("logging.format must be text or json")
	}
	if c.Sentry.Enabled {
		if strings.TrimSpace(c.Sentry.DSN) == "" {
			return fmt.Errorf("sentry.dsn is required when sentry is enabled")
		}
		if c.Sentry.SampleRate < 0 || c.Sentry.SampleRate > 1 {
			return fmt.Errorf("sentry.sample_rate must be between 0 and 1")
		}
		if c.Sentry.TracesSampleRate < 0 || c.Sentry.TracesSampleRate > 1 {
			return fmt.Errorf("sentry.traces_sample_rate must be between 0 and 1")
		}
	}
	if err := validateSandboxMode("sandbox.mode", c.Sandbox.Mode); err != nil {
		return err
	}
	if err := validateSandboxMode("sandbox.landlock.mode", c.Sandbox.Landlock.Mode); err != nil {
		return err
	}
	if err := validateSandboxMode("sandbox.seccomp.mode", c.Sandbox.Seccomp.Mode); err != nil {
		return err
	}
	switch strings.ToLower(strings.TrimSpace(c.Sandbox.Seccomp.DenyAction)) {
	case "", "errno", "kill", "kill_thread", "kill_process", "trap", "log":
	default:
		return fmt.Errorf("sandbox.seccomp.deny_action must be errno, kill_thread, kill_process, trap, or log")
	}
	return nil
}

func validateSandboxMode(field, value string) error {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "off", "try", "best_effort", "enforce":
		return nil
	default:
		return fmt.Errorf("%s must be off, try, best_effort, or enforce", field)
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func setStr(dst *string, key string) {
	if v := os.Getenv(key); v != "" {
		*dst = v
	}
}

func setBool(dst *bool, key string) {
	v := os.Getenv(key)
	if v == "" {
		return
	}
	b, err := strconv.ParseBool(v)
	if err == nil {
		*dst = b
	}
}

func setInt(dst *int, key string) {
	v := os.Getenv(key)
	if v == "" {
		return
	}
	n, err := strconv.Atoi(v)
	if err == nil {
		*dst = n
	}
}

func setFloat(dst *float64, key string) {
	v := os.Getenv(key)
	if v == "" {
		return
	}
	n, err := strconv.ParseFloat(v, 64)
	if err == nil {
		*dst = n
	}
}

func setBoolPtr(dst **bool, key string) {
	v := os.Getenv(key)
	if v == "" {
		return
	}
	b, err := strconv.ParseBool(v)
	if err == nil {
		*dst = &b
	}
}
