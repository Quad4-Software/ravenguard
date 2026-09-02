package ops_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Quad4-Software/ravenguard/internal/admin/ops"
	"github.com/Quad4-Software/ravenguard/internal/challenge"
	"github.com/Quad4-Software/ravenguard/internal/config"
)

type pipeStub struct {
	n   int
	cfg config.Config
}

func (p *pipeStub) ApplyConfig(cfg config.Config) {
	p.n++
	p.cfg = cfg
}

func TestConfigViewJSON(t *testing.T) {
	cfg := config.Default()
	cfg.Challenge.Secret = "rg-dev-secret-replace-me!!"
	cfg.Challenge.Captcha.Token = "captcha-secret-token"
	cfg.QFeeds.APIToken = "qfeeds-secret-token"
	rt := ops.NewRuntime(cfg, nil, nil, nil, nil, nil, nil)
	b, err := json.Marshal(rt.ConfigView())
	if err != nil {
		t.Fatal(err)
	}
	raw := string(b)
	if strings.Contains(raw, "captcha-secret-token") {
		t.Fatal("captcha token leaked in config view")
	}
	if strings.Contains(raw, "qfeeds-secret-token") {
		t.Fatal("qfeeds api token leaked in config view")
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	live, ok := m["live"].(map[string]any)
	if !ok || live == nil {
		t.Fatalf("missing live: %s", b)
	}
	for _, k := range []string{"ratelimit", "protect", "detect", "challenge", "ui", "trust", "stealth", "privacy", "logging", "qfeeds"} {
		if live[k] == nil {
			t.Fatalf("missing live.%s", k)
		}
	}
	ui, _ := live["ui"].(map[string]any)
	if ui["brand"] == nil || ui["status_text"] == nil || ui["theme_color"] == nil {
		t.Fatalf("ui missing appearance fields: %v", ui)
	}
	ch, _ := live["challenge"].(map[string]any)
	if _, ok := ch["token"]; ok {
		t.Fatal("challenge must not include captcha token")
	}
	if ch["path_prefix"] == nil || ch["algorithm"] == nil || ch["cookie_name"] == nil {
		t.Fatalf("challenge missing new fields: %v", ch)
	}
	dt, _ := live["detect"].(map[string]any)
	if dt["missing_ua_score"] == nil || dt["proxy_signals"] == nil {
		t.Fatalf("detect missing signal fields: %v", dt)
	}
	rr, _ := m["restart_required"].(map[string]any)
	trust, _ := rr["trust"].(map[string]any)
	for _, k := range []string{"mode", "trusted_proxies", "real_ip_header", "proto_header", "proxy_protocol"} {
		if _, ok := trust[k]; !ok {
			t.Fatalf("restart_required.trust missing %s", k)
		}
	}
	chalRR, _ := rr["challenge"].(map[string]any)
	if chalRR["path_prefix"] == nil {
		t.Fatal("restart_required.challenge.path_prefix missing")
	}
}

func TestEncodeDecodeSafeConfigRoundTrip(t *testing.T) {
	cfg := config.Default()
	rt := ops.NewRuntime(cfg, nil, nil, nil, nil, nil, nil)
	encoded, err := ops.EncodeSafeConfig(rt.ConfigView().Live)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := ops.DecodeSafeConfig(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.UI.Brand != cfg.UI.Brand || decoded.UI.StatusText != cfg.UI.StatusText {
		t.Fatalf("ui roundtrip: %+v", decoded.UI)
	}
	if decoded.Detect.MissingUAScore != cfg.Detect.MissingUAScore {
		t.Fatalf("detect roundtrip: %+v", decoded.Detect)
	}
	if decoded.QFeeds == nil || decoded.QFeeds.APIToken != "" {
		t.Fatalf("qfeeds view should omit token: %+v", decoded.QFeeds)
	}
}

func TestApplySafeConfigTrustValidation(t *testing.T) {
	rt := ops.NewRuntime(config.Default(), nil, nil, nil, nil, nil, nil)
	err := rt.ApplySafeConfig(ops.SafeConfig{Trust: ops.TrustSafe{Mode: "nope"}})
	if err == nil || !strings.Contains(err.Error(), "trust.mode") {
		t.Fatalf("expected trust.mode error, got %v", err)
	}
	err = rt.ApplySafeConfig(ops.SafeConfig{Trust: ops.TrustSafe{Mode: "behind_proxy"}})
	if err == nil || !strings.Contains(err.Error(), "trusted_proxies") {
		t.Fatalf("expected trusted_proxies error, got %v", err)
	}
	if rt.Config().Trust.Mode != "edge" {
		t.Fatal("invalid apply must not mutate trust")
	}
	if err := rt.ApplySafeConfig(ops.SafeConfig{
		Trust: ops.TrustSafe{Mode: "behind_proxy", TrustedProxies: []string{"10.0.0.1/32"}, RealIPHeader: "X-Real-IP", ProxyProtocol: true},
	}); err != nil {
		t.Fatal(err)
	}
	got := rt.Config().Trust
	if got.Mode != "behind_proxy" || len(got.TrustedProxies) != 1 || !got.ProxyProtocol {
		t.Fatalf("trust not applied: %+v", got)
	}
}

func TestApplySafeConfigAppearanceAndChallenge(t *testing.T) {
	cfg := config.Default()
	chal := &challenge.Manager{Difficulty: cfg.Challenge.Difficulty, CookieTTL: cfg.Challenge.CookieTTL.Duration, CookieName: cfg.Challenge.CookieName, Algorithm: cfg.Challenge.Algorithm}
	rt := ops.NewRuntime(cfg, nil, nil, nil, nil, nil, chal)
	pipe := &pipeStub{}
	rt.SetPipeline(pipe)
	safe := rt.ConfigView().Live
	safe.UI.Brand = "Acme"
	safe.UI.StatusText = "Please wait"
	safe.UI.Description = "Acme guard"
	safe.UI.Lang = "de"
	safe.UI.ThemeColor = "#111111"
	safe.UI.PrivacyNoticeURL = "https://example.com/privacy"
	safe.UI.OGImage = "https://example.com/og.png"
	safe.Challenge.CookieName = "acme_clear"
	safe.Challenge.Algorithm = "sha256"
	safe.Challenge.Difficulty = 18
	safe.Challenge.CookieTTL = "12h"
	if err := rt.ApplySafeConfig(safe); err != nil {
		t.Fatal(err)
	}
	got := rt.Config()
	if got.UI.Brand != "Acme" || got.Site.Description != "Acme guard" || got.Site.Lang != "de" {
		t.Fatalf("site/ui not applied: ui=%+v site=%+v", got.UI, got.Site)
	}
	if got.Site.ThemeColor != "#111111" || got.Privacy.PrivacyNoticeURL != "https://example.com/privacy" {
		t.Fatalf("appearance extras: site=%+v privacy=%+v", got.Site, got.Privacy)
	}
	if chal.CookieName != "acme_clear" || chal.Algorithm != "sha256" || chal.Difficulty != 18 || chal.CookieTTL != 12*time.Hour {
		t.Fatalf("chal not updated: %+v", chal)
	}
	if pipe.n != 1 {
		t.Fatalf("pipeline ApplyConfig calls: %d", pipe.n)
	}
	if pipe.cfg.UI.Brand != "Acme" {
		t.Fatal("pipeline did not receive updated cfg")
	}
}

func TestOverlaySafeDoesNotMutateRuntime(t *testing.T) {
	rt := ops.NewRuntime(config.Default(), nil, nil, nil, nil, nil, nil)
	before := rt.Config()
	out := ops.OverlaySafe(before, ops.SafeConfig{UI: ops.UISafe{Brand: "PreviewBrand", StatusText: before.UI.StatusText}})
	if out.UI.Brand != "PreviewBrand" {
		t.Fatalf("overlay brand: %s", out.UI.Brand)
	}
	if rt.Config().UI.Brand != before.UI.Brand {
		t.Fatal("overlay mutated runtime")
	}
}

func TestApplySafeConfigOldPayloadKeepsDefaults(t *testing.T) {
	cfg := config.Default()
	cfg.Challenge.Captcha.Enabled = true
	cfg.Challenge.Captcha.Provider = "stub"
	cfg.Stealth.ServeManifest = true
	cfg.Privacy.HashClientIP = true
	rt := ops.NewRuntime(cfg, nil, nil, nil, nil, nil, nil)
	old := `{"ratelimit":{"enabled":true,"requests":120,"window":"1m","burst":60,"per_path":false,"challenge_over":true},"protect":{"enabled":true,"max_body_bytes":1048576,"max_header_bytes":16384,"max_url_bytes":8192,"max_concurrent_global":8192,"max_concurrent_per_client":32,"ban_after_strikes":5,"ban_ttl":"10m","attack_block":true,"attack_score":90,"write_method_cost":3},"detect":{"enabled":true,"challenge_score":40,"block_score":90},"challenge":{"enabled":true,"mode":"detect","difficulty":16,"cookie_ttl":"24h"},"ui":{"brand":"RavenGuard","status_text":"Checking your browser before accessing this site."}}`
	safe, err := ops.DecodeSafeConfig(old)
	if err != nil {
		t.Fatal(err)
	}
	if err := rt.ApplySafeConfig(safe); err != nil {
		t.Fatal(err)
	}
	got := rt.Config()
	if !got.Privacy.HashClientIP {
		t.Fatal("old payload wiped hash_client_ip")
	}
	if !got.Stealth.ServeManifest {
		t.Fatal("old payload wiped serve_manifest")
	}
	if !got.Challenge.Captcha.Enabled || got.Challenge.Captcha.Provider != "stub" {
		t.Fatalf("old payload wiped captcha: %+v", got.Challenge.Captcha)
	}
}

func TestMergeAndEncodeQFeeds(t *testing.T) {
	cfg := config.Default()
	rt := ops.NewRuntime(cfg, nil, nil, nil, nil, nil, nil)
	base, err := ops.EncodeSafeConfig(rt.ConfigView().Live)
	if err != nil {
		t.Fatal(err)
	}
	merged, err := ops.MergeAndEncode(base, func(s *ops.SafeConfig) {
		s.QFeeds = &ops.QFeedsSafe{Enabled: true, Feeds: []string{"malware_ip"}, Refresh: "2h", OnError: "fail_closed", BaseURL: "https://api.example", Limit: 10, APIToken: "secret"}
	})
	if err != nil {
		t.Fatal(err)
	}
	out, err := ops.DecodeSafeConfig(merged)
	if err != nil {
		t.Fatal(err)
	}
	if out.UI.Brand != cfg.UI.Brand {
		t.Fatal("merge replaced unrelated live fields")
	}
	if out.QFeeds == nil || !out.QFeeds.Enabled || out.QFeeds.APIToken != "secret" {
		t.Fatalf("qfeeds not merged: %+v", out.QFeeds)
	}
}

func TestApplySafeConfigNestedQFeeds(t *testing.T) {
	cfg := config.Default()
	rt := ops.NewRuntime(cfg, nil, nil, nil, nil, nil, nil)
	safe := rt.ConfigView().Live
	safe.QFeeds = &ops.QFeedsSafe{Enabled: false, Feeds: []string{"malware_domains"}, Refresh: "30m", OnError: "fail_open", BaseURL: "https://feeds.example", Limit: 5}
	if err := rt.ApplySafeConfig(safe); err != nil {
		t.Fatal(err)
	}
	got := rt.Config().QFeeds
	if got.Enabled || got.BaseURL != "https://feeds.example" || got.Limit != 5 {
		t.Fatalf("nested qfeeds not applied: %+v", got)
	}
}
