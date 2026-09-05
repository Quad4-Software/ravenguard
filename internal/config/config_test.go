// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package config_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Quad4-Software/ravenguard/internal/config"
)

func TestLoadExample(t *testing.T) {
	path := filepath.Join("..", "..", "configs", "ravenguard.toml")
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Upstream.URL == "" {
		t.Fatal("expected upstream url")
	}
	if cfg.Challenge.Secret == "" {
		t.Fatal("expected challenge secret")
	}
	if cfg.Trust.Mode != "behind_proxy" {
		t.Fatalf("trust.mode=%q", cfg.Trust.Mode)
	}
	if !cfg.Privacy.HashClientIP {
		t.Fatal("expected privacy.hash_client_ip")
	}
	if !cfg.Logging.Stats {
		t.Fatal("expected logging.stats enabled by default")
	}
}

func TestValidateCaptchaRejected(t *testing.T) {
	cfg := config.Default()
	cfg.Challenge.Secret = "test-secret-16chars"
	cfg.Challenge.Captcha.Enabled = true
	cfg.Challenge.Captcha.Provider = "hcaptcha"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected captcha validation error")
	}
}

func TestValidateCaptchaStubOK(t *testing.T) {
	cfg := config.Default()
	cfg.Challenge.Secret = "test-secret-16chars"
	cfg.Challenge.Captcha.Enabled = true
	cfg.Challenge.Captcha.Provider = "stub"
	cfg.Challenge.Captcha.Token = "ok"
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestValidateCaptchaRavenOK(t *testing.T) {
	cfg := config.Default()
	cfg.Challenge.Secret = "test-secret-16chars"
	cfg.Challenge.Captcha.Enabled = true
	cfg.Challenge.Captcha.Provider = "ravenguard"
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestValidateChallengeMode(t *testing.T) {
	cfg := config.Default()
	cfg.Challenge.Secret = "test-secret-16chars"
	cfg.Challenge.Mode = "nope"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected mode error")
	}
}

func TestValidateWeakSecret(t *testing.T) {
	cfg := config.Default()
	cfg.Challenge.Secret = "change-me-please-long"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected weak secret error")
	}
	cfg.Challenge.Secret = "short"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected short secret error")
	}
}

func TestValidateBehindProxyRequiresTrusted(t *testing.T) {
	cfg := config.Default()
	cfg.Challenge.Secret = "test-secret-16chars"
	cfg.Trust.Mode = "behind_proxy"
	cfg.Trust.TrustedProxies = nil
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected trusted_proxies error")
	}
	cfg.Trust.TrustedProxies = []string{"10.0.0.0/8"}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestValidateRequiresListen(t *testing.T) {
	cfg := config.Default()
	cfg.Listen.HTTP = ""
	cfg.Challenge.Secret = "test-secret-16chars"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected listen error")
	}
}

func TestValidateUpstreamSchemes(t *testing.T) {
	cfg := config.Default()
	cfg.Challenge.Secret = "test-secret-16chars"
	cfg.Trust.Mode = "edge"
	for _, url := range []string{
		"http://127.0.0.1:8000",
		"https://origin.example",
		"ws://127.0.0.1:8000/ws",
		"wss://origin.example/socket",
		"unix:///var/run/app.sock",
	} {
		cfg.Upstream.URL = url
		if err := cfg.Validate(); err != nil {
			t.Fatalf("%s: %v", url, err)
		}
	}
	cfg.Upstream.URL = "ftp://origin.example"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected scheme error for ftp")
	}
	cfg.Upstream.URL = "https://"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected host error")
	}
}

func TestEnvOverrides(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "c.toml")
	content := `
[listen]
http = ":8080"
[upstream]
url = "http://127.0.0.1:9"
[challenge]
enabled = true
secret = "file-secret-16chars"
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("RG_CHALLENGE_SECRET", "env-secret-16chars!")
	t.Setenv("RG_LISTEN_HTTP", ":9090")
	t.Setenv("RG_SITE_PUBLIC_URL", "https://edge.example")
	t.Setenv("RG_UI_CONTACT", "help@example.com")
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Challenge.Secret != "env-secret-16chars!" {
		t.Fatalf("secret=%q", cfg.Challenge.Secret)
	}
	if cfg.Listen.HTTP != ":9090" {
		t.Fatalf("http=%q", cfg.Listen.HTTP)
	}
	if cfg.Site.PublicURL != "https://edge.example" {
		t.Fatalf("public=%q", cfg.Site.PublicURL)
	}
	if cfg.UI.Contact != "help@example.com" {
		t.Fatalf("contact=%q", cfg.UI.Contact)
	}
}

func TestFlagsBeatEnv(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "c.toml")
	_ = os.WriteFile(path, []byte(`
[listen]
http = ":8080"
[upstream]
url = "http://127.0.0.1:9"
[challenge]
enabled = true
secret = "file-secret-16chars"
`), 0o600)
	t.Setenv("RG_UPSTREAM_URL", "http://env:9")
	f := config.Flags{ConfigPath: path, Upstream: "http://flag:9", Secret: "flag-secret-16char"}
	cfg, err := config.LoadWithFlags(f)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Upstream.URL != "http://flag:9" {
		t.Fatalf("upstream=%q", cfg.Upstream.URL)
	}
	if cfg.Challenge.Secret != "flag-secret-16char" {
		t.Fatalf("secret=%q", cfg.Challenge.Secret)
	}
}

func TestQFeedsTokenFromEnv(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "c.toml")
	content := `
[listen]
http = ":8080"
[upstream]
url = "http://127.0.0.1:9"
[challenge]
enabled = true
secret = "qfeeds-secret-16ch"
[qfeeds]
enabled = true
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("QFEEDS_API_TOKEN", "tok123")
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.QFeeds.APIToken != "tok123" {
		t.Fatalf("token=%q", cfg.QFeeds.APIToken)
	}
}

func TestSentryDSNEnables(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "c.toml")
	content := `
[listen]
http = ":8080"
[upstream]
url = "http://127.0.0.1:9"
[challenge]
enabled = true
secret = "sentry-secret-16ch"
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SENTRY_DSN", "https://key@localhost/1")
	t.Setenv("SENTRY_ENVIRONMENT", "staging")
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !cfg.Sentry.Enabled {
		t.Fatal("expected sentry enabled when DSN set")
	}
	if cfg.Sentry.DSN != "https://key@localhost/1" {
		t.Fatalf("dsn=%q", cfg.Sentry.DSN)
	}
	if cfg.Sentry.Environment != "staging" {
		t.Fatalf("env=%q", cfg.Sentry.Environment)
	}
}

func TestValidateSentry(t *testing.T) {
	cfg := config.Default()
	cfg.Challenge.Secret = "test-secret-16chars"
	cfg.Sentry.Enabled = true
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected dsn required")
	}
	cfg.Sentry.DSN = "https://key@localhost/1"
	cfg.Sentry.SampleRate = 2
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected sample_rate error")
	}
	cfg.Sentry.SampleRate = 1
	cfg.Sentry.TracesSampleRate = -0.1
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected traces_sample_rate error")
	}
	cfg.Sentry.TracesSampleRate = 0.1
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestValidateSandboxMode(t *testing.T) {
	cfg := config.Default()
	cfg.Challenge.Secret = "test-secret-16chars"
	cfg.Sandbox.Mode = "strict"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected sandbox.mode error")
	}
	cfg.Sandbox.Mode = "try"
	cfg.Sandbox.Seccomp.DenyAction = "explode"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected deny_action error")
	}
	cfg.Sandbox.Seccomp.DenyAction = "errno"
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if cfg.Sandbox.Mode != "try" {
		t.Fatalf("mode=%q", cfg.Sandbox.Mode)
	}
}

func TestEnvTrustedProxies(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cfg.toml")
	body := []byte(`
[upstream]
url = "http://127.0.0.1:8000"
[challenge]
secret = "test-secret-16chars"
[trust]
mode = "behind_proxy"
trusted_proxies = ["10.0.0.0/8"]
`)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("RG_TRUSTED_PROXIES", "192.168.0.0/16, 127.0.0.1")
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Trust.TrustedProxies) != 2 {
		t.Fatalf("trusted_proxies=%v", cfg.Trust.TrustedProxies)
	}
	if cfg.Trust.TrustedProxies[0] != "192.168.0.0/16" || cfg.Trust.TrustedProxies[1] != "127.0.0.1" {
		t.Fatalf("trusted_proxies=%v", cfg.Trust.TrustedProxies)
	}
}

func TestResolveRunMode(t *testing.T) {
	t.Setenv("RG_MODE", "")
	mode, rest, err := config.ResolveRunMode([]string{"-config", "x.toml"})
	if err != nil || mode != "all" || len(rest) != 2 {
		t.Fatalf("default mode=%q rest=%v err=%v", mode, rest, err)
	}

	t.Setenv("RG_MODE", "hub")
	mode, rest, err = config.ResolveRunMode([]string{"-config", "x.toml"})
	if err != nil || mode != "hub" || len(rest) != 2 {
		t.Fatalf("env mode=%q rest=%v err=%v", mode, rest, err)
	}

	mode, rest, err = config.ResolveRunMode([]string{"proxy", "-config", "x.toml"})
	if err != nil || mode != "proxy" || len(rest) != 2 || rest[0] != "-config" {
		t.Fatalf("cli beats env mode=%q rest=%v err=%v", mode, rest, err)
	}

	t.Setenv("RG_MODE", "nope")
	_, _, err = config.ResolveRunMode(nil)
	if err == nil {
		t.Fatal("expected invalid RG_MODE error")
	}
}

func TestLogStatsFlagAndEnv(t *testing.T) {
	t.Setenv("RG_LOG_STATS", "true")
	t.Setenv("RG_LOG_STATS_INTERVAL", "15s")
	f, err := config.ParseFlags([]string{
		"-config", filepath.Join("..", "..", "configs", "ravenguard.toml"),
		"-log-stats",
		"-log-stats-interval", "45s",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !f.LogStatsSet || !f.LogStats {
		t.Fatalf("flag stats=%v set=%v", f.LogStats, f.LogStatsSet)
	}
	cfg, err := config.LoadWithFlags(f)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Logging.Stats {
		t.Fatal("expected stats enabled")
	}
	if cfg.Logging.StatsInterval.Duration != 45*time.Second {
		t.Fatalf("interval=%s", cfg.Logging.StatsInterval)
	}
}

func TestValidateStatsInterval(t *testing.T) {
	cfg := config.Default()
	cfg.Challenge.Secret = "test-secret-16chars"
	cfg.Logging.Stats = true
	cfg.Logging.StatsInterval = config.Duration{Duration: 500 * time.Millisecond}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected stats_interval validation error")
	}
}

func TestValidateSelfSignedMode(t *testing.T) {
	cfg := config.Default()
	cfg.Challenge.Secret = "test-secret-16chars"
	cfg.TLS.Mode = "selfsigned"
	cfg.Listen.HTTPS = ":8443"
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}

	cfg.TLS.SelfSigned.StorageDir = ""
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected storage_dir error")
	}

	cfg = config.Default()
	cfg.Challenge.Secret = "test-secret-16chars"
	cfg.TLS.Mode = "off"
	cfg.Listen.HTTPS = ":8443"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected tls.mode error when https set")
	}
}

func TestSelfSignedEnvOverrides(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cfg.toml")
	if err := os.WriteFile(path, []byte(`
[listen]
http = ":8080"
[upstream]
url = "http://127.0.0.1:8000"
[challenge]
secret = "test-secret-16chars"
`), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("RG_TLS_MODE", "selfsigned")
	t.Setenv("RG_SELFSIGNED_STORAGE_DIR", "/tmp/rg-ss")
	t.Setenv("RG_SELFSIGNED_HOSTS", "dev.local, 127.0.0.1")
	t.Setenv("RG_LISTEN_HTTPS", ":8443")

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.TLS.Mode != "selfsigned" {
		t.Fatalf("mode=%q", cfg.TLS.Mode)
	}
	if cfg.TLS.SelfSigned.StorageDir != "/tmp/rg-ss" {
		t.Fatalf("storage_dir=%q", cfg.TLS.SelfSigned.StorageDir)
	}
	if len(cfg.TLS.SelfSigned.Hosts) != 2 || cfg.TLS.SelfSigned.Hosts[0] != "dev.local" || cfg.TLS.SelfSigned.Hosts[1] != "127.0.0.1" {
		t.Fatalf("hosts=%v", cfg.TLS.SelfSigned.Hosts)
	}
	if cfg.Listen.HTTPS != ":8443" {
		t.Fatalf("https=%q", cfg.Listen.HTTPS)
	}
}

func TestDefaultSelfSigned(t *testing.T) {
	cfg := config.Default()
	if cfg.TLS.SelfSigned.StorageDir != "./data/selfsigned" {
		t.Fatalf("storage_dir=%q", cfg.TLS.SelfSigned.StorageDir)
	}
	if len(cfg.TLS.SelfSigned.Hosts) != 1 || cfg.TLS.SelfSigned.Hosts[0] != "localhost" {
		t.Fatalf("hosts=%v", cfg.TLS.SelfSigned.Hosts)
	}
	if cfg.TLS.SelfSigned.Validity.Duration <= 0 {
		t.Fatal("expected default validity")
	}
}
