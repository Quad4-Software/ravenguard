// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package config

import (
	"flag"
	"fmt"
	"net/url"
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
	Allowlists AllowlistsConfig `toml:"allowlists"`
	QFeeds     QFeedsConfig     `toml:"qfeeds"`
	RateLimit  RateLimitConfig  `toml:"ratelimit"`
	Protect    ProtectConfig    `toml:"protect"`
	Detect     DetectConfig     `toml:"detect"`
	Coraza     CorazaConfig     `toml:"coraza"`
	Semantic   SemanticConfig   `toml:"semantic"`
	ML         MLConfig         `toml:"ml"`
	Challenge  ChallengeConfig  `toml:"challenge"`
	Stealth    StealthConfig    `toml:"stealth"`
	Privacy    PrivacyConfig    `toml:"privacy"`
	UI         UIConfig         `toml:"ui"`
	Site       SiteConfig       `toml:"site"`
	Logging    LoggingConfig    `toml:"logging"`
	Sentry     SentryConfig     `toml:"sentry"`
	Sandbox    SandboxConfig    `toml:"sandbox"`
	Admin      AdminConfig      `toml:"admin"`
	Hub        HubConfig        `toml:"hub"`
	Agent      AgentConfig      `toml:"agent"`

	runMode string `toml:"-"`
}

// HubConfig is reserved for hub-specific options (keypair lives under admin.data_dir).
type HubConfig struct {
	// PublicURL is the URL agents should dial (shown in enrollment UI).
	PublicURL string `toml:"public_url"`
}

// AgentConfig configures outbound connection from a proxy process to the hub.
type AgentConfig struct {
	HubURL    string `toml:"hub_url"`
	Token     string `toml:"token"`
	HubPubKey string `toml:"hub_pubkey"`
	Name      string `toml:"name"`
	DataDir   string `toml:"data_dir"`
}

// AdminConfig configures the management plane (separate listen, users, SPA).
type AdminConfig struct {
	Enabled           bool     `toml:"enabled"`
	Listen            string   `toml:"listen"`
	HTTPS             string   `toml:"https"`
	CertFile          string   `toml:"cert_file"`
	KeyFile           string   `toml:"key_file"`
	BasePath          string   `toml:"base_path"`
	DataDir           string   `toml:"data_dir"`
	BootstrapUser     string   `toml:"bootstrap_user"`
	BootstrapPassword string   `toml:"bootstrap_password"`
	SessionTTL        Duration `toml:"session_ttl"`
	CookieSecure      string   `toml:"cookie_secure"`
}

// SandboxConfig controls Linux Landlock and seccomp-bpf hardening.
// Modes: off, try, best_effort, enforce.
type SandboxConfig struct {
	Mode     string                `toml:"mode"`
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
	HTTP  string `toml:"http" json:"http"`
	HTTPS string `toml:"https" json:"https"`
	QUIC  string `toml:"quic" json:"quic"`
}

type TLSConfig struct {
	Mode       string           `toml:"mode"` // off | files | acme | selfsigned
	CertFile   string           `toml:"cert_file"`
	KeyFile    string           `toml:"key_file"`
	ACME       ACMEConfig       `toml:"acme"`
	SelfSigned SelfSignedConfig `toml:"selfsigned"`
}

// ACMEConfig configures automatic Let's Encrypt certificate management.
type ACMEConfig struct {
	Email        string   `toml:"email"`
	Directory    string   `toml:"directory"`
	Staging      bool     `toml:"staging"`
	StorageDir   string   `toml:"storage_dir"`
	Hosts        []string `toml:"hosts"`
	HTTP01       *bool    `toml:"http01"`
	TLSALPN01    *bool    `toml:"tls_alpn01"`
	RedirectHTTP *bool    `toml:"redirect_http"`
	AgreeTOS     bool     `toml:"agree_tos"`
	RenewWindow  Duration `toml:"renew_window"`
	OnDemand     bool     `toml:"on_demand"`
}

// SelfSignedConfig configures automatic self-signed certificate generation.
type SelfSignedConfig struct {
	StorageDir string   `toml:"storage_dir"`
	Hosts      []string `toml:"hosts"`
	Validity   Duration `toml:"validity"`
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
	WAFEventsTTL     Duration `toml:"waf_events_ttl"`
	PrivacyNoticeURL string   `toml:"privacy_notice_url"`
}

type BlocklistsConfig struct {
	IPFiles        []string `toml:"ip_files"`
	DNSFiles       []string `toml:"dns_files"`
	UAFiles        []string `toml:"ua_files"`
	ReloadInterval Duration `toml:"reload_interval"`
}

// AllowlistsConfig loads trusted IP, User-Agent, and header lists that skip detect and challenge.
type AllowlistsConfig struct {
	IPFiles        []string `toml:"ip_files"`
	UAFiles        []string `toml:"ua_files"`
	HeaderFiles    []string `toml:"header_files"`
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

// CorazaConfig configures the optional Coraza / OWASP CRS engine.
type CorazaConfig struct {
	Enabled          bool     `toml:"enabled"`
	Mode             string   `toml:"mode"`
	CRS              bool     `toml:"crs"`
	Paranoia         int      `toml:"paranoia"`
	RulesDir         string   `toml:"rules_dir"`
	RulesFile        string   `toml:"rules_file"`
	Directives       string   `toml:"directives"`
	MaxBodyInspect   int64    `toml:"max_body_inspect"`
	SkipPathPrefixes []string `toml:"skip_path_prefixes"`
}

// SemanticConfig configures SafeLine-style payload semantic analysis.
type SemanticConfig struct {
	Enabled          bool     `toml:"enabled"`
	Mode             string   `toml:"mode"`
	MaxBodyInspect   int64    `toml:"max_body_inspect"`
	MaxDecodeDepth   int      `toml:"max_decode_depth"`
	MaxDecodeBytes   int      `toml:"max_decode_bytes"`
	MaxCPUNanos      int64    `toml:"max_cpu_ns"`
	StrictBudget     bool     `toml:"strict_budget"`
	Families         []string `toml:"families"`
	SkipPathPrefixes []string `toml:"skip_path_prefixes"`
}

// MLConfig configures the lightweight request scorer.
type MLConfig struct {
	Enabled          bool    `toml:"enabled"`
	Mode             string  `toml:"mode"`
	ModelPath        string  `toml:"model_path"`
	AdaptPath        string  `toml:"adapt_path"`
	AttestPath       string  `toml:"attest_path"`
	ChallengeProb    float64 `toml:"challenge_prob"`
	BlockProb        float64 `toml:"block_prob"`
	ConfidenceMin    float64 `toml:"confidence_min"`
	FPRGate          float64 `toml:"fpr_gate"`
	ShadowSampleRate float64 `toml:"shadow_sample_rate"`
	MaxPoints        int     `toml:"max_points"`
}

type DetectConfig struct {
	Enabled                  bool               `toml:"enabled"`
	ChallengeScore           int                `toml:"challenge_score"`
	BlockScore               int                `toml:"block_score"`
	MissingUAScore           int                `toml:"missing_ua_score"`
	ScannerUAScore           int                `toml:"scanner_ua_score"`
	AIUAScore                int                `toml:"ai_ua_score"`
	ProbePathScore           int                `toml:"probe_path_score"`
	OddMethodScore           int                `toml:"odd_method_score"`
	MissingAcceptScore       int                `toml:"missing_accept_score"`
	MissingAcceptLangScore   int                `toml:"missing_accept_lang_score"`
	MissingSecFetchScore     int                `toml:"missing_sec_fetch_score"`
	SecCHUAMismatchScore     int                `toml:"sec_ch_ua_mismatch_score"`
	StarAcceptBrowserScore   int                `toml:"star_accept_browser_score"`
	High404Threshold         int                `toml:"high_404_threshold"`
	High404Window            Duration           `toml:"high_404_window"`
	High404Action            string             `toml:"high_404_action"`
	BehaviorWindow           Duration           `toml:"behavior_window"`
	BehaviorBurstLimit       int                `toml:"behavior_burst_limit"`
	BehaviorBurstScore       int                `toml:"behavior_burst_score"`
	BehaviorPathFanout       int                `toml:"behavior_path_fanout"`
	BehaviorPathFanoutScore  int                `toml:"behavior_path_fanout_score"`
	BehaviorStrikeLimit      int                `toml:"behavior_strike_limit"`
	BehaviorStrikeScore      int                `toml:"behavior_strike_score"`
	BehaviorWriteBurstLimit  int                `toml:"behavior_write_burst_limit"`
	BehaviorWriteBurstScore  int                `toml:"behavior_write_burst_score"`
	BehaviorWriteRepeatLimit int                `toml:"behavior_write_repeat_limit"`
	BehaviorWriteRepeatScore int                `toml:"behavior_write_repeat_score"`
	EmptyFormContextScore    int                `toml:"empty_form_context_score"`
	ForumWritePathScore      int                `toml:"forum_write_path_score"`
	ProxySignals             DetectProxySignals `toml:"proxy_signals"`
}

type DetectProxySignals struct {
	BotScoreHeader  string `toml:"bot_score_header"`
	BotScoreHeader2 string `toml:"bot_score_header_2"`
	JA4Header       string `toml:"ja4_header"`
	LowScorePoints  int    `toml:"low_score_points"`
}

type ChallengeConfig struct {
	Enabled    bool   `toml:"enabled"`
	Mode       string `toml:"mode"`
	Difficulty int    `toml:"difficulty"`
	// Algorithm is sha256, pbkdf2, argon2id, or adaptive (default).
	Algorithm string `toml:"algorithm"`
	// EnvProbe is on (default) or off. off skips automation refusal for e2e harnesses.
	EnvProbe   string        `toml:"env_probe"`
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

// StealthConfig controls public fingerprints on the guard edge.
type StealthConfig struct {
	RayHeader        string `toml:"ray_header"`
	ElementName      string `toml:"element_name"`
	BootstrapGlobal  string `toml:"bootstrap_global"`
	AccessCookieName string `toml:"access_cookie_name"`
	HideBrandMark    bool   `toml:"hide_brand_mark"`
	GenericCopy      bool   `toml:"generic_copy"`
	ServeManifest    bool   `toml:"serve_manifest"`
	ServeRootIcons   bool   `toml:"serve_root_icons"`
	WidgetInputName  string `toml:"widget_input_name"`
}

type UIConfig struct {
	Brand             string `toml:"brand"`
	StatusText        string `toml:"status_text"`
	TestMode          bool   `toml:"test_mode"`
	LogoURL           string `toml:"logo_url"`
	FaviconURL        string `toml:"favicon_url"`
	Background        string `toml:"background"`
	Foreground        string `toml:"foreground"`
	Accent            string `toml:"accent"`
	FontSans          string `toml:"font_sans"`
	FontMono          string `toml:"font_mono"`
	ChallengeTitle    string `toml:"challenge_title"`
	ChallengeSubtitle string `toml:"challenge_subtitle"`
	BlockTitle        string `toml:"block_title"`
	RateLimitTitle    string `toml:"rate_limit_title"`
	UpstreamTitle     string `toml:"upstream_title"`
	ErrorTitle        string `toml:"error_title"`
	FooterText        string `toml:"footer_text"`
	Contact           string `toml:"contact"`
	CustomCSS         string `toml:"custom_css"`
	RayLabel          string `toml:"ray_label"`
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
	s := string(text)
	parsed, err := time.ParseDuration(s)
	if err != nil {
		if before, ok := strings.CutSuffix(s, "d"); ok {
			daysStr := before
			days, perr := strconv.ParseFloat(daysStr, 64)
			if perr == nil && days > 0 {
				d.Duration = time.Duration(days * float64(24*time.Hour))
				return nil
			}
		}
		return err
	}
	d.Duration = parsed
	return nil
}

func (d Duration) MarshalText() ([]byte, error) {
	return []byte(d.String()), nil
}

func Default() Config {
	http01 := true
	tlsALPN := true
	redir := true
	return Config{
		Listen: ListenConfig{HTTP: ":8080"},
		TLS: TLSConfig{
			Mode: "off",
			ACME: ACMEConfig{
				StorageDir:   "./data/certs",
				HTTP01:       &http01,
				TLSALPN01:    &tlsALPN,
				RedirectHTTP: &redir,
			},
			SelfSigned: SelfSignedConfig{
				StorageDir: "./data/selfsigned",
				Hosts:      []string{"localhost"},
				Validity:   Duration{365 * 24 * time.Hour},
			},
		},
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
		Allowlists: AllowlistsConfig{
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
		Coraza: CorazaConfig{
			Enabled:          false,
			Mode:             "block",
			CRS:              true,
			Paranoia:         1,
			MaxBodyInspect:   1 << 20,
			SkipPathPrefixes: []string{"/_rg"},
		},
		Semantic: SemanticConfig{
			Enabled:          false,
			Mode:             "shadow",
			MaxBodyInspect:   64 << 10,
			MaxDecodeDepth:   3,
			MaxDecodeBytes:   256 << 10,
			MaxCPUNanos:      2_000_000,
			Families:         []string{"sqli", "xss", "cmd", "path"},
			SkipPathPrefixes: []string{"/_rg"},
		},
		ML: MLConfig{
			Enabled:          false,
			Mode:             "shadow",
			ModelPath:        "assets/ml/base.bin",
			ChallengeProb:    0.75,
			BlockProb:        0.95,
			ConfidenceMin:    0.85,
			FPRGate:          0.001,
			ShadowSampleRate: 0.02,
			MaxPoints:        60,
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
			BehaviorWriteBurstLimit: 20, BehaviorWriteBurstScore: 35,
			BehaviorWriteRepeatLimit: 8, BehaviorWriteRepeatScore: 40,
			EmptyFormContextScore: 30, ForumWritePathScore: 25,
			ProxySignals: DetectProxySignals{
				BotScoreHeader:  "CF-Bot-Score",
				BotScoreHeader2: "X-Bot-Score",
				JA4Header:       "X-JA4",
				LowScorePoints:  40,
			},
		},
		Challenge: ChallengeConfig{
			Enabled: true, Mode: "detect", Difficulty: 16, Algorithm: "adaptive",
			EnvProbe: "on", CookieName: "rg_clear", CookieTTL: Duration{24 * time.Hour}, PathPrefix: "/_rg",
		},
		Stealth: StealthConfig{
			RayHeader:        "X-RavenGuard-Ray",
			ElementName:      "rg-check",
			BootstrapGlobal:  "__g__",
			AccessCookieName: "rg_access",
			ServeManifest:    true,
			ServeRootIcons:   true,
			WidgetInputName:  "rg",
		},
		Privacy: PrivacyConfig{
			HashClientIP: true,
			LogIP:        "hash",
			Retention:    Duration{30 * time.Minute},
			WAFEventsTTL: Duration{24 * time.Hour},
		},
		UI: UIConfig{
			Brand: "RavenGuard", StatusText: "Checking your browser before accessing this site.",
		},
		Site: SiteConfig{
			Description: "RavenGuard Web Application Firewall",
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
				RestrictNet:    new(true),
				RestrictScoped: new(true),
				IgnoreMissing:  new(true),
			},
			Seccomp: SandboxSeccompConfig{
				DenyAction: "errno",
			},
		},
		Admin: AdminConfig{
			Enabled:       false,
			Listen:        "127.0.0.1:9090",
			BasePath:      "/",
			DataDir:       "./data/admin",
			BootstrapUser: "admin",
			SessionTTL:    Duration{12 * time.Hour},
			CookieSecure:  "auto",
		},
		Agent: AgentConfig{
			DataDir: "./data/proxy",
		},
	}
}

type Flags struct {
	ConfigPath      string
	ListenHTTP      string
	ListenHTTPS     string
	ListenQUIC      string
	Upstream        string
	Secret          string
	TestMode        bool
	TestModeSet     bool
	PublicURL       string
	LogLevel        string
	LogFormat       string
	AdminListen     string
	AdminEnabled    bool
	AdminEnabledSet bool
	AdminDataDir    string
}

func ParseFlags(args []string) (Flags, error) {
	fs := flag.NewFlagSet("ravenguard", flag.ContinueOnError)
	var f Flags
	fs.StringVar(&f.ConfigPath, "config", envOr("RG_CONFIG", "configs/ravenguard.toml"), "path to TOML config")
	fs.StringVar(&f.ListenHTTP, "listen-http", "", "HTTP listen address (overrides config/env)")
	fs.StringVar(&f.ListenHTTPS, "listen-https", "", "HTTPS listen address")
	fs.StringVar(&f.ListenQUIC, "listen-quic", "", "QUIC/HTTP3 listen address")
	fs.StringVar(&f.Upstream, "upstream", "", "upstream URL (http://, https://, ws://, wss://, or unix://)")
	fs.StringVar(&f.Secret, "challenge-secret", "", "challenge HMAC secret")
	fs.StringVar(&f.PublicURL, "public-url", "", "public site URL for SEO canonical/OG")
	fs.StringVar(&f.LogLevel, "log-level", "", "debug|info|warn|error")
	fs.StringVar(&f.LogFormat, "log-format", "", "text|json")
	fs.StringVar(&f.AdminListen, "admin-listen", "", "admin HTTP listen address")
	fs.StringVar(&f.AdminDataDir, "admin-data-dir", "", "admin SQLite data directory")
	adminEnabled := fs.Bool("admin-enabled", false, "enable admin control plane")
	test := fs.Bool("test-mode", false, "enable UI test routes under /_rg/test")
	if err := fs.Parse(args); err != nil {
		return Flags{}, err
	}
	f.TestMode = *test
	f.AdminEnabled = *adminEnabled
	fs.Visit(func(fl *flag.Flag) {
		if fl.Name == "test-mode" {
			f.TestModeSet = true
		}
		if fl.Name == "admin-enabled" {
			f.AdminEnabledSet = true
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
	return LoadWithFlagsMode(f, "all")
}

func LoadWithFlagsMode(f Flags, mode string) (Config, error) {
	path := f.ConfigPath
	if path == "" {
		path = envOr("RG_CONFIG", "configs/ravenguard.toml")
	}
	cfg := Default()
	if path != "" {
		if _, err := toml.DecodeFile(path, &cfg); err != nil {
			return Config{}, fmt.Errorf("load config: %w", err)
		}
	}
	applyEnv(&cfg)
	applyFlags(&cfg, f)
	cfg.SetRunMode(mode)
	if mode == "hub" {
		cfg.Admin.Enabled = true
	}
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
	setStr(&c.TLS.Mode, "RG_TLS_MODE")
	setStr(&c.TLS.ACME.Email, "RG_ACME_EMAIL")
	setStr(&c.TLS.ACME.StorageDir, "RG_ACME_STORAGE_DIR")
	setStr(&c.TLS.ACME.Directory, "RG_ACME_DIRECTORY")
	setBool(&c.TLS.ACME.Staging, "RG_ACME_STAGING")
	setBool(&c.TLS.ACME.AgreeTOS, "RG_ACME_AGREE_TOS")
	if v := os.Getenv("RG_ACME_HOSTS"); v != "" {
		parts := strings.Split(v, ",")
		c.TLS.ACME.Hosts = c.TLS.ACME.Hosts[:0]
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p != "" {
				c.TLS.ACME.Hosts = append(c.TLS.ACME.Hosts, p)
			}
		}
	}
	setStr(&c.TLS.SelfSigned.StorageDir, "RG_SELFSIGNED_STORAGE_DIR")
	if v := os.Getenv("RG_SELFSIGNED_HOSTS"); v != "" {
		parts := strings.Split(v, ",")
		c.TLS.SelfSigned.Hosts = c.TLS.SelfSigned.Hosts[:0]
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p != "" {
				c.TLS.SelfSigned.Hosts = append(c.TLS.SelfSigned.Hosts, p)
			}
		}
	}
	setStr(&c.Upstream.URL, "RG_UPSTREAM_URL")
	setStr(&c.Trust.Mode, "RG_TRUST_MODE")
	setStr(&c.Trust.RealIPHeader, "RG_REAL_IP_HEADER")
	setStr(&c.Trust.ProtoHeader, "RG_PROTO_HEADER")
	setBool(&c.Trust.ProxyProtocol, "RG_PROXY_PROTOCOL")
	if v := os.Getenv("RG_TRUSTED_PROXIES"); v != "" {
		parts := strings.Split(v, ",")
		c.Trust.TrustedProxies = c.Trust.TrustedProxies[:0]
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p != "" {
				c.Trust.TrustedProxies = append(c.Trust.TrustedProxies, p)
			}
		}
	}
	setStr(&c.Challenge.CookieName, "RG_CHALLENGE_COOKIE_NAME")
	setStr(&c.Stealth.RayHeader, "RG_STEALTH_RAY_HEADER")
	setStr(&c.Stealth.ElementName, "RG_STEALTH_ELEMENT_NAME")
	setStr(&c.Stealth.BootstrapGlobal, "RG_STEALTH_BOOTSTRAP_GLOBAL")
	setStr(&c.Stealth.AccessCookieName, "RG_STEALTH_ACCESS_COOKIE_NAME")
	setBool(&c.Stealth.HideBrandMark, "RG_STEALTH_HIDE_BRAND_MARK")
	setBool(&c.Stealth.GenericCopy, "RG_STEALTH_GENERIC_COPY")
	setStr(&c.QFeeds.APIToken, "RG_QFEEDS_API_TOKEN")
	if c.QFeeds.APIToken == "" {
		setStr(&c.QFeeds.APIToken, "QFEEDS_API_TOKEN")
	}
	setBool(&c.QFeeds.Enabled, "RG_QFEEDS_ENABLED")
	setStr(&c.Challenge.Secret, "RG_CHALLENGE_SECRET")
	setStr(&c.Challenge.Mode, "RG_CHALLENGE_MODE")
	setStr(&c.Challenge.EnvProbe, "RG_CHALLENGE_ENV_PROBE")
	setStr(&c.Challenge.PathPrefix, "RG_CHALLENGE_PATH_PREFIX")
	setStr(&c.Challenge.Algorithm, "RG_CHALLENGE_ALGORITHM")
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
	setStr(&c.UI.Contact, "RG_UI_CONTACT")
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
	setBool(&c.Admin.Enabled, "RG_ADMIN_ENABLED")
	setStr(&c.Admin.Listen, "RG_ADMIN_LISTEN")
	setStr(&c.Admin.HTTPS, "RG_ADMIN_HTTPS")
	setStr(&c.Admin.BasePath, "RG_ADMIN_BASE_PATH")
	setStr(&c.Admin.DataDir, "RG_ADMIN_DATA_DIR")
	setStr(&c.Admin.BootstrapUser, "RG_ADMIN_BOOTSTRAP_USER")
	setStr(&c.Admin.BootstrapPassword, "RG_ADMIN_BOOTSTRAP_PASSWORD")
	setStr(&c.Admin.CookieSecure, "RG_ADMIN_COOKIE_SECURE")
	setStr(&c.Hub.PublicURL, "RG_HUB_PUBLIC_URL")
	setStr(&c.Agent.HubURL, "RG_AGENT_HUB_URL")
	setStr(&c.Agent.Token, "RG_AGENT_TOKEN")
	setStr(&c.Agent.HubPubKey, "RG_AGENT_HUB_PUBKEY")
	setStr(&c.Agent.Name, "RG_AGENT_NAME")
	setStr(&c.Agent.DataDir, "RG_AGENT_DATA_DIR")
	if v := os.Getenv("RG_ADMIN_SESSION_TTL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			c.Admin.SessionTTL = Duration{d}
		}
	}
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
	if f.AdminListen != "" {
		c.Admin.Listen = f.AdminListen
	}
	if f.AdminDataDir != "" {
		c.Admin.DataDir = f.AdminDataDir
	}
	if f.AdminEnabledSet {
		c.Admin.Enabled = f.AdminEnabled
	}
}

func normalize(c *Config) {
	if c.Trust.Mode == "" {
		c.Trust.Mode = "edge"
	}
	if c.TLS.Mode == "" {
		if c.TLS.CertFile != "" || c.TLS.KeyFile != "" {
			c.TLS.Mode = "files"
		} else {
			c.TLS.Mode = "off"
		}
	}
	c.TLS.Mode = strings.ToLower(strings.TrimSpace(c.TLS.Mode))
	if c.TLS.ACME.StorageDir == "" {
		c.TLS.ACME.StorageDir = "./data/certs"
	}
	if c.TLS.SelfSigned.StorageDir == "" {
		c.TLS.SelfSigned.StorageDir = "./data/selfsigned"
	}
	if len(c.TLS.SelfSigned.Hosts) == 0 {
		c.TLS.SelfSigned.Hosts = []string{"localhost"}
	}
	if c.TLS.SelfSigned.Validity.Duration <= 0 {
		c.TLS.SelfSigned.Validity = Duration{365 * 24 * time.Hour}
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
	if c.Challenge.EnvProbe == "" {
		c.Challenge.EnvProbe = "on"
	}
	if c.Challenge.CookieName == "" {
		c.Challenge.CookieName = "rg_clear"
	}
	if c.Stealth.ElementName == "" {
		c.Stealth.ElementName = "rg-check"
	}
	if c.Stealth.BootstrapGlobal == "" {
		c.Stealth.BootstrapGlobal = "__g__"
	}
	if c.Stealth.AccessCookieName == "" {
		c.Stealth.AccessCookieName = "rg_access"
	}
	if c.Stealth.WidgetInputName == "" {
		c.Stealth.WidgetInputName = "rg"
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
	if c.Privacy.WAFEventsTTL.Duration <= 0 {
		c.Privacy.WAFEventsTTL = Duration{24 * time.Hour}
	}
	if c.Coraza.Mode == "" {
		c.Coraza.Mode = "block"
	}
	if c.Coraza.Paranoia < 1 {
		c.Coraza.Paranoia = 1
	}
	if c.Coraza.MaxBodyInspect <= 0 {
		c.Coraza.MaxBodyInspect = 1 << 20
	}
	if c.Coraza.SkipPathPrefixes == nil {
		c.Coraza.SkipPathPrefixes = []string{"/_rg"}
	}
	if c.Semantic.Mode == "" {
		c.Semantic.Mode = "shadow"
	}
	if c.Semantic.MaxBodyInspect <= 0 {
		c.Semantic.MaxBodyInspect = 64 << 10
	}
	if c.Semantic.MaxDecodeDepth <= 0 {
		c.Semantic.MaxDecodeDepth = 3
	}
	if c.Semantic.MaxDecodeBytes <= 0 {
		c.Semantic.MaxDecodeBytes = 256 << 10
	}
	if c.Semantic.MaxCPUNanos <= 0 {
		c.Semantic.MaxCPUNanos = 2_000_000
	}
	if c.Semantic.Families == nil {
		c.Semantic.Families = []string{"sqli", "xss", "cmd", "path"}
	}
	if c.Semantic.SkipPathPrefixes == nil {
		c.Semantic.SkipPathPrefixes = []string{"/_rg"}
	}
	if c.ML.Mode == "" {
		c.ML.Mode = "shadow"
	}
	if c.ML.ModelPath == "" {
		c.ML.ModelPath = "assets/ml/base.bin"
	}
	if c.ML.ChallengeProb <= 0 {
		c.ML.ChallengeProb = 0.75
	}
	if c.ML.BlockProb <= 0 {
		c.ML.BlockProb = 0.95
	}
	if c.ML.ConfidenceMin <= 0 {
		c.ML.ConfidenceMin = 0.85
	}
	if c.ML.FPRGate <= 0 {
		c.ML.FPRGate = 0.001
	}
	if c.ML.ShadowSampleRate <= 0 {
		c.ML.ShadowSampleRate = 0.02
	}
	if c.ML.MaxPoints <= 0 {
		c.ML.MaxPoints = 60
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
		c.Site.Description = c.UI.Brand + " Web Application Firewall"
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
		c.Sandbox.Landlock.RestrictNet = new(true)
	}
	if c.Sandbox.Landlock.RestrictScoped == nil {
		c.Sandbox.Landlock.RestrictScoped = new(true)
	}
	if c.Sandbox.Landlock.IgnoreMissing == nil {
		c.Sandbox.Landlock.IgnoreMissing = new(true)
	}
	if c.Sandbox.Seccomp.DenyAction == "" {
		c.Sandbox.Seccomp.DenyAction = "errno"
	}
	if c.Admin.Listen == "" {
		c.Admin.Listen = "127.0.0.1:9090"
	}
	if c.Admin.BasePath == "" {
		c.Admin.BasePath = "/"
	}
	if c.Admin.DataDir == "" {
		c.Admin.DataDir = "./data/admin"
	}
	if c.Admin.BootstrapUser == "" {
		c.Admin.BootstrapUser = "admin"
	}
	if c.Admin.SessionTTL.Duration <= 0 {
		c.Admin.SessionTTL = Duration{12 * time.Hour}
	}
	if c.Admin.CookieSecure == "" {
		c.Admin.CookieSecure = "auto"
	}
	c.Admin.BasePath = normalizeBasePath(c.Admin.BasePath)
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

func validateUpstreamURL(raw string) error {
	raw = strings.TrimSpace(raw)
	if strings.HasPrefix(raw, "unix://") || strings.HasPrefix(raw, "unix:") {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("upstream.url: %w", err)
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https", "ws", "wss":
		if u.Host == "" {
			return fmt.Errorf("upstream.url must include a host")
		}
		return nil
	case "unix":
		return nil
	default:
		return fmt.Errorf("upstream.url scheme must be http, https, ws, wss, or unix")
	}
}

func (c *Config) SetRunMode(mode string) {
	if c == nil {
		return
	}
	c.runMode = strings.ToLower(strings.TrimSpace(mode))
}

// ResolveRunMode picks process mode for Coolify-style deploys that cannot set a custom command.
// Precedence: first CLI token (hub|proxy|all) then RG_MODE then all.
func ResolveRunMode(args []string) (mode string, rest []string, err error) {
	mode = "all"
	if v := strings.ToLower(strings.TrimSpace(os.Getenv("RG_MODE"))); v != "" {
		mode = v
	}
	rest = args
	if len(args) > 0 {
		switch args[0] {
		case "hub", "proxy", "all":
			mode = args[0]
			rest = args[1:]
		}
	}
	switch mode {
	case "hub", "proxy", "all":
		return mode, rest, nil
	default:
		return "", rest, fmt.Errorf("mode must be all, hub, or proxy (got %q)", mode)
	}
}

func (c Config) Validate() error {
	hubOnly := c.runMode == "hub"
	if !hubOnly {
		if c.Upstream.URL == "" {
			return fmt.Errorf("upstream.url is required")
		}
		if err := validateUpstreamURL(c.Upstream.URL); err != nil {
			return err
		}
		if c.Listen.HTTP == "" && c.Listen.HTTPS == "" && c.Listen.QUIC == "" {
			return fmt.Errorf("at least one of listen.http, listen.https, listen.quic is required")
		}
	} else if c.Upstream.URL != "" {
		if err := validateUpstreamURL(c.Upstream.URL); err != nil {
			return err
		}
	}
	tlsMode := strings.ToLower(strings.TrimSpace(c.TLS.Mode))
	if tlsMode == "" {
		tlsMode = "off"
	}
	switch tlsMode {
	case "off", "files", "acme", "selfsigned":
	default:
		return fmt.Errorf("tls.mode must be off, files, acme, or selfsigned")
	}
	needsTLS := !hubOnly && (c.Listen.HTTPS != "" || c.Listen.QUIC != "")
	switch tlsMode {
	case "files":
		if needsTLS && (c.TLS.CertFile == "" || c.TLS.KeyFile == "") {
			return fmt.Errorf("tls.cert_file and tls.key_file required when tls.mode is files and https or quic is enabled")
		}
	case "acme":
		if !hubOnly {
			if !c.TLS.ACME.AgreeTOS {
				return fmt.Errorf("tls.acme.agree_tos is required when tls.mode is acme")
			}
			if strings.TrimSpace(c.TLS.ACME.Email) == "" {
				return fmt.Errorf("tls.acme.email is required when tls.mode is acme")
			}
			if strings.TrimSpace(c.TLS.ACME.StorageDir) == "" {
				return fmt.Errorf("tls.acme.storage_dir is required when tls.mode is acme")
			}
			http01 := c.TLS.ACME.HTTP01 == nil || *c.TLS.ACME.HTTP01
			if http01 && c.Listen.HTTP == "" {
				return fmt.Errorf("listen.http is required when tls.acme.http01 is enabled")
			}
		}
	case "selfsigned":
		if needsTLS && strings.TrimSpace(c.TLS.SelfSigned.StorageDir) == "" {
			return fmt.Errorf("tls.selfsigned.storage_dir is required when tls.mode is selfsigned and https or quic is enabled")
		}
	case "off":
		if needsTLS {
			return fmt.Errorf("tls.mode must be files, acme, or selfsigned when listen.https or listen.quic is set")
		}
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
	if !hubOnly && c.Challenge.Enabled {
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
		case "detect", "always", "attack":
		default:
			return fmt.Errorf("challenge.mode must be detect, always, or attack")
		}
		switch strings.ToLower(strings.TrimSpace(c.Challenge.EnvProbe)) {
		case "on", "off", "":
		default:
			return fmt.Errorf("challenge.env_probe must be on or off")
		}
		algo := strings.ToLower(strings.TrimSpace(c.Challenge.Algorithm))
		if algo == "" {
			c.Challenge.Algorithm = "adaptive"
			algo = "adaptive"
		}
		switch algo {
		case "adaptive", "sha256", "sha-256", "pbkdf2", "pbkdf2-sha256", "argon2id":
		default:
			return fmt.Errorf("challenge.algorithm must be adaptive, sha256, pbkdf2, or argon2id")
		}
	}
	if !hubOnly && c.Challenge.Captcha.Enabled {
		provider := strings.ToLower(strings.TrimSpace(c.Challenge.Captcha.Provider))
		if provider == "" {
			return fmt.Errorf("challenge.captcha.provider is required when captcha is enabled")
		}
		if provider != "stub" && provider != "ravenguard" {
			return fmt.Errorf("challenge.captcha.provider %q is not supported (use stub or ravenguard)", c.Challenge.Captcha.Provider)
		}
	}
	if !hubOnly && c.QFeeds.Enabled {
		if c.QFeeds.APIToken == "" {
			return fmt.Errorf("qfeeds.api_token is required when qfeeds is enabled")
		}
		switch c.QFeeds.OnError {
		case "fail_open", "fail_closed":
		default:
			return fmt.Errorf("qfeeds.on_error must be fail_open or fail_closed")
		}
	}
	if !hubOnly && c.Coraza.Enabled {
		switch strings.ToLower(strings.TrimSpace(c.Coraza.Mode)) {
		case "block", "detect":
		default:
			return fmt.Errorf("coraza.mode must be block or detect")
		}
		if c.Coraza.Paranoia < 1 || c.Coraza.Paranoia > 4 {
			return fmt.Errorf("coraza.paranoia must be between 1 and 4")
		}
		if !c.Coraza.CRS && strings.TrimSpace(c.Coraza.RulesDir) == "" && strings.TrimSpace(c.Coraza.RulesFile) == "" && strings.TrimSpace(c.Coraza.Directives) == "" {
			return fmt.Errorf("coraza requires crs, rules_dir, rules_file, or directives when enabled")
		}
	}
	if !hubOnly && c.Semantic.Enabled {
		switch strings.ToLower(strings.TrimSpace(c.Semantic.Mode)) {
		case "shadow", "challenge", "block":
		default:
			return fmt.Errorf("semantic.mode must be shadow, challenge, or block")
		}
	}
	if !hubOnly && c.ML.Enabled {
		switch strings.ToLower(strings.TrimSpace(c.ML.Mode)) {
		case "off", "shadow", "challenge", "block":
		default:
			return fmt.Errorf("ml.mode must be off, shadow, challenge, or block")
		}
		if c.ML.BlockProb < c.ML.ChallengeProb {
			return fmt.Errorf("ml.block_prob must be >= ml.challenge_prob")
		}
	}
	if !hubOnly && c.RateLimit.Enabled {
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
	if c.Admin.Enabled || hubOnly {
		if hubOnly {
			if c.Admin.Listen == "" && c.Admin.HTTPS == "" {
				return fmt.Errorf("admin.listen or admin.https is required in hub mode")
			}
			if strings.TrimSpace(c.Admin.DataDir) == "" {
				return fmt.Errorf("admin.data_dir is required in hub mode")
			}
		}
		if c.Admin.Listen == "" && c.Admin.HTTPS == "" {
			return fmt.Errorf("admin.listen or admin.https is required when admin is enabled")
		}
		if c.Admin.HTTPS != "" {
			cert := c.Admin.CertFile
			key := c.Admin.KeyFile
			if cert == "" {
				cert = c.TLS.CertFile
			}
			if key == "" {
				key = c.TLS.KeyFile
			}
			if cert == "" || key == "" {
				return fmt.Errorf("admin TLS cert/key or tls.cert_file/tls.key_file required when admin.https is set")
			}
		}
		if strings.TrimSpace(c.Admin.DataDir) == "" {
			return fmt.Errorf("admin.data_dir is required when admin is enabled")
		}
		switch strings.ToLower(strings.TrimSpace(c.Admin.CookieSecure)) {
		case "auto", "true", "false", "1", "0", "yes", "no":
		default:
			return fmt.Errorf("admin.cookie_secure must be auto, true, or false")
		}
	}
	if c.runMode == "proxy" {
		if strings.TrimSpace(c.Agent.HubURL) == "" {
			return fmt.Errorf("agent.hub_url is required in proxy mode")
		}
		if strings.TrimSpace(c.Agent.Token) == "" {
			return fmt.Errorf("agent.token is required in proxy mode")
		}
		if strings.TrimSpace(c.Agent.HubPubKey) == "" {
			return fmt.Errorf("agent.hub_pubkey is required in proxy mode")
		}
		if strings.TrimSpace(c.Agent.DataDir) == "" {
			return fmt.Errorf("agent.data_dir is required in proxy mode")
		}
	}
	return nil
}

func normalizeBasePath(p string) string {
	p = strings.TrimSpace(p)
	if p == "" || p == "/" {
		return "/"
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return strings.TrimSuffix(p, "/")
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
