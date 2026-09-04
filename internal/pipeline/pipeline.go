// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package pipeline

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Quad4-Software/ravenguard/internal/access"
	"github.com/Quad4-Software/ravenguard/internal/allowlist"
	"github.com/Quad4-Software/ravenguard/internal/blocklist"
	"github.com/Quad4-Software/ravenguard/internal/challenge"
	"github.com/Quad4-Software/ravenguard/internal/config"
	"github.com/Quad4-Software/ravenguard/internal/corazaeng"
	"github.com/Quad4-Software/ravenguard/internal/detect"
	"github.com/Quad4-Software/ravenguard/internal/health"
	"github.com/Quad4-Software/ravenguard/internal/iputil"
	"github.com/Quad4-Software/ravenguard/internal/privacy"
	"github.com/Quad4-Software/ravenguard/internal/protect"
	"github.com/Quad4-Software/ravenguard/internal/qfeeds"
	"github.com/Quad4-Software/ravenguard/internal/ratelimit"
	"github.com/Quad4-Software/ravenguard/internal/rayid"
	"github.com/Quad4-Software/ravenguard/internal/requestlog"
	"github.com/Quad4-Software/ravenguard/internal/router"
	"github.com/Quad4-Software/ravenguard/internal/schemagate"
	"github.com/Quad4-Software/ravenguard/internal/ui"
)

type Handler struct {
	mu              sync.RWMutex
	cfg             config.Config
	lists           *blocklist.Sets
	allows          *allowlist.Sets
	feeds           *qfeeds.Cache
	limiter         *ratelimit.Limiter
	chal            *challenge.Manager
	pages           *ui.Pages
	upstream        http.Handler
	routes          *router.Table
	access          *access.Manager
	acmeHTTP        http.Handler
	trusted         []net.IPNet
	priv            *privacy.Guard
	prot            *protect.Guard
	mux             *http.ServeMux
	nf              *detect.NotFoundTracker
	beh             *detect.BehaviorTracker
	health          *health.Checker
	detectCfg       detect.Config
	challengeAlways bool
	high404Action   uint8
	writeCost       int
	redirectHTTP    bool
	reqLog          *requestlog.Logger
	coraza          *corazaeng.Engine
	schemas         *schemagate.Manager
}

const (
	high404Challenge uint8 = 0
	high404Block     uint8 = 1
	high404Off       uint8 = 2
)

var bodyPool = sync.Pool{
	New: func() any {
		b := make([]byte, 0, 512)
		return &b
	},
}

var statusPool = sync.Pool{
	New: func() any {
		return &statusRecorder{status: 200}
	},
}

func New(
	cfg config.Config,
	lists *blocklist.Sets,
	feeds *qfeeds.Cache,
	limiter *ratelimit.Limiter,
	chal *challenge.Manager,
	pages *ui.Pages,
	upstream http.Handler,
	trusted []net.IPNet,
	nf *detect.NotFoundTracker,
	hc *health.Checker,
	priv *privacy.Guard,
	beh *detect.BehaviorTracker,
	prot *protect.Guard,
) *Handler {
	h := &Handler{
		cfg:      cfg,
		lists:    lists,
		feeds:    feeds,
		limiter:  limiter,
		chal:     chal,
		pages:    pages,
		upstream: upstream,
		trusted:  trusted,
		priv:     priv,
		prot:     prot,
		mux:      http.NewServeMux(),
		nf:       nf,
		beh:      beh,
		health:   hc,
		detectCfg: detect.Config{
			MissingUAScore:         cfg.Detect.MissingUAScore,
			ScannerUAScore:         cfg.Detect.ScannerUAScore,
			AIUAScore:              cfg.Detect.AIUAScore,
			ProbePathScore:         cfg.Detect.ProbePathScore,
			OddMethodScore:         cfg.Detect.OddMethodScore,
			MissingAcceptScore:     cfg.Detect.MissingAcceptScore,
			MissingAcceptLangScore: cfg.Detect.MissingAcceptLangScore,
			MissingSecFetchScore:   cfg.Detect.MissingSecFetchScore,
			SecCHUAMismatchScore:   cfg.Detect.SecCHUAMismatchScore,
			StarAcceptBrowserScore: cfg.Detect.StarAcceptBrowserScore,
			EmptyFormContextScore:  cfg.Detect.EmptyFormContextScore,
			ForumWritePathScore:    cfg.Detect.ForumWritePathScore,
			ProxyBotLowScore:       cfg.Detect.ProxySignals.LowScorePoints,
			ProxyBotHeader:         cfg.Detect.ProxySignals.BotScoreHeader,
			ProxyBotScoreHeader:    cfg.Detect.ProxySignals.BotScoreHeader2,
			ProxyJA4Header:         cfg.Detect.ProxySignals.JA4Header,
		},
		challengeAlways: strings.EqualFold(cfg.Challenge.Mode, "always") || strings.EqualFold(cfg.Challenge.Mode, "attack"),
		writeCost:       3,
	}
	if prot != nil {
		h.writeCost = prot.WriteCost()
	}
	switch strings.ToLower(cfg.Detect.High404Action) {
	case "block":
		h.high404Action = high404Block
	case "off":
		h.high404Action = high404Off
	default:
		h.high404Action = high404Challenge
	}
	testURL := ""
	if cfg.UI.TestMode {
		testURL = cfg.Challenge.PathPrefix + "/test"
	}
	pages.MountStaticTo(h.mux, testURL)
	h.mux.HandleFunc("/robots.txt", h.pages.ServeRobots)
	if cfg.Stealth.ServeManifest {
		h.mux.HandleFunc("/site.webmanifest", h.pages.ServeManifest)
		h.mux.HandleFunc(cfg.Challenge.PathPrefix+"/site.webmanifest", h.pages.ServeManifest)
	}
	h.mux.HandleFunc(cfg.Challenge.PathPrefix+"/challenge", h.handleChallengePOST)
	h.mux.HandleFunc(cfg.Challenge.PathPrefix+"/v1/challenge", h.handleChallengeV1GET)
	h.mux.HandleFunc(cfg.Challenge.PathPrefix+"/v1/verify", h.handleVerifyV1POST)
	h.mux.HandleFunc(cfg.Challenge.PathPrefix+"/access", h.handleAccessPOST)
	h.mux.HandleFunc(cfg.Challenge.PathPrefix+"/healthz", h.handleHealthz)
	h.mux.HandleFunc("/healthz", h.handleHealthz)
	if cfg.UI.TestMode {
		h.mountTestRoutes()
	}
	h.mux.HandleFunc("/", h.guard)
	return h
}

func (h *Handler) handleHealthz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	h.mu.RLock()
	hc := h.health
	h.mu.RUnlock()
	if hc != nil && !hc.Healthy() {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("upstream unhealthy\n"))
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

// ServeHTTP implements http.Handler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.acmeHTTP != nil && strings.HasPrefix(r.URL.Path, "/.well-known/acme-challenge/") {
		h.acmeHTTP.ServeHTTP(w, r)
		return
	}
	if h.redirectHTTP && r.TLS == nil && r.Method != http.MethodConnect {
		if !strings.HasPrefix(r.URL.Path, "/.well-known/acme-challenge/") {
			host := r.Host
			target := "https://" + host + r.URL.RequestURI()
			http.Redirect(w, r, target, http.StatusMovedPermanently) // #nosec G710 -- HTTP to HTTPS redirect using request host
			return
		}
	}
	h.mux.ServeHTTP(w, r)
}

// SetRouter attaches the multi-upstream route table.
func (h *Handler) SetRouter(t *router.Table) {
	h.mu.Lock()
	h.routes = t
	h.mu.Unlock()
}

// SetAccess attaches the access policy manager.
func (h *Handler) SetAccess(m *access.Manager) {
	h.mu.Lock()
	h.access = m
	h.mu.Unlock()
}

// SetAllowlists attaches IP, User-Agent, and header allowlists that skip detect and challenge.
func (h *Handler) SetAllowlists(a *allowlist.Sets) {
	h.mu.Lock()
	h.allows = a
	h.mu.Unlock()
}

// SetACMEHandler mounts the HTTP-01 challenge handler (bypasses WAF).
func (h *Handler) SetACMEHandler(handler http.Handler) {
	h.mu.Lock()
	h.acmeHTTP = handler
	h.mu.Unlock()
}

// SetRedirectHTTP enables HTTP to HTTPS redirect for non-ACME paths.
func (h *Handler) SetRedirectHTTP(enabled bool) {
	h.mu.Lock()
	h.redirectHTTP = enabled
	h.mu.Unlock()
}

// SetRequestLog attaches the WAF deny event logger.
func (h *Handler) SetRequestLog(l *requestlog.Logger) {
	h.mu.Lock()
	h.reqLog = l
	h.mu.Unlock()
}

// SetCoraza attaches the optional Coraza engine.
func (h *Handler) SetCoraza(e *corazaeng.Engine) {
	h.mu.Lock()
	h.coraza = e
	h.mu.Unlock()
}

// SetSchemaGate attaches the OpenAPI schema manager.
func (h *Handler) SetSchemaGate(m *schemagate.Manager) {
	h.mu.Lock()
	h.schemas = m
	h.mu.Unlock()
}

func (h *Handler) recordEvent(r *http.Request, ray, bindID, ipStr, host, ua, action, reason string, score int, details map[string]string) {
	h.mu.RLock()
	l := h.reqLog
	h.mu.RUnlock()
	if l == nil {
		return
	}
	method, path := "", ""
	if r != nil {
		method = r.Method
		if r.URL != nil {
			path = r.URL.Path
		}
	}
	l.Record(requestlog.Event{
		Ray:     ray,
		Action:  action,
		Reason:  reason,
		Method:  method,
		Path:    path,
		Host:    host,
		UA:      ua,
		IPHash:  h.logIP(ipStr),
		BindID:  bindID,
		Score:   score,
		Details: details,
	})
}

func (h *Handler) emitBlock(w http.ResponseWriter, r *http.Request, ray, bindID, ipStr, host, ua, reason string, score int, details map[string]string) {
	h.recordEvent(r, ray, bindID, ipStr, host, ua, requestlog.ActionBlock, reason, score, details)
	h.pages.RenderBlock(w, ray, reason)
}

func (h *Handler) emitRateLimit(w http.ResponseWriter, r *http.Request, ray, bindID, ipStr, host, ua string) {
	h.recordEvent(r, ray, bindID, ipStr, host, ua, requestlog.ActionRateLimit, "Rate limited", 0, nil)
	h.pages.RenderRateLimit(w, ray)
}

// ApplyConfig updates live-tunable config fields from the admin plane.
func (h *Handler) ApplyConfig(cfg config.Config) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.cfg = cfg
	h.challengeAlways = strings.EqualFold(cfg.Challenge.Mode, "always") || strings.EqualFold(cfg.Challenge.Mode, "attack")
	switch strings.ToLower(cfg.Detect.High404Action) {
	case "block":
		h.high404Action = high404Block
	case "off":
		h.high404Action = high404Off
	default:
		h.high404Action = high404Challenge
	}
	h.detectCfg = detect.Config{
		MissingUAScore:         cfg.Detect.MissingUAScore,
		ScannerUAScore:         cfg.Detect.ScannerUAScore,
		AIUAScore:              cfg.Detect.AIUAScore,
		ProbePathScore:         cfg.Detect.ProbePathScore,
		OddMethodScore:         cfg.Detect.OddMethodScore,
		MissingAcceptScore:     cfg.Detect.MissingAcceptScore,
		MissingAcceptLangScore: cfg.Detect.MissingAcceptLangScore,
		MissingSecFetchScore:   cfg.Detect.MissingSecFetchScore,
		SecCHUAMismatchScore:   cfg.Detect.SecCHUAMismatchScore,
		StarAcceptBrowserScore: cfg.Detect.StarAcceptBrowserScore,
		EmptyFormContextScore:  cfg.Detect.EmptyFormContextScore,
		ForumWritePathScore:    cfg.Detect.ForumWritePathScore,
		ProxyBotLowScore:       cfg.Detect.ProxySignals.LowScorePoints,
		ProxyBotHeader:         cfg.Detect.ProxySignals.BotScoreHeader,
		ProxyBotScoreHeader:    cfg.Detect.ProxySignals.BotScoreHeader2,
		ProxyJA4Header:         cfg.Detect.ProxySignals.JA4Header,
	}
	if nets, err := iputil.ParseCIDRs(cfg.Trust.TrustedProxies); err == nil {
		h.trusted = nets
	}
	if h.pages != nil {
		h.pages.UpdateSite(ui.SiteFromConfig(cfg))
	}
	if h.access != nil {
		h.access.Brand = cfg.UI.Brand
		if cfg.Stealth.AccessCookieName != "" {
			h.access.CookieName = cfg.Stealth.AccessCookieName
		}
	}
	if h.chal != nil {
		if cfg.Challenge.CookieName != "" {
			h.chal.CookieName = cfg.Challenge.CookieName
		}
		h.chal.Difficulty = cfg.Challenge.Difficulty
		h.chal.CookieTTL = cfg.Challenge.CookieTTL.Duration
		if cfg.Challenge.Algorithm != "" {
			h.chal.Algorithm = cfg.Challenge.Algorithm
		}
	}
}

func (h *Handler) resolveClientIP(r *http.Request) net.IP {
	cfg := h.config()
	h.mu.RLock()
	trusted := h.trusted
	h.mu.RUnlock()
	if !strings.EqualFold(cfg.Trust.Mode, "behind_proxy") {
		return iputil.ClientIP(r, nil, "")
	}
	return iputil.ClientIP(r, trusted, cfg.Trust.RealIPHeader)
}

func (h *Handler) setRayHeader(w http.ResponseWriter, ray string) {
	name := strings.TrimSpace(h.config().Stealth.RayHeader)
	if name == "" {
		return
	}
	w.Header().Set(name, ray)
}

func (h *Handler) config() config.Config {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.cfg
}

func (h *Handler) mountTestRoutes() {
	prefix := h.cfg.Challenge.PathPrefix
	base := prefix + "/test"
	redir := func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, base, http.StatusFound)
	}
	h.mux.HandleFunc(prefix, redir)
	h.mux.HandleFunc(prefix+"/", redir)
	h.mux.HandleFunc(base, h.handleTestIndex)
	h.mux.HandleFunc(base+"/", h.handleTestIndex)
	h.mux.HandleFunc(base+"/challenge", func(w http.ResponseWriter, r *http.Request) {
		ray := rayid.New()
		h.setRayHeader(w, ray)
		if h.chal != nil {
			h.serveChallenge(w, r, ray, "preview", challenge.RiskLow)
			return
		}
		h.pages.ServeChallenge(w, ui.Data{
			StatusText:     h.cfg.UI.StatusText,
			RayID:          ray,
			ChallengeURL:   h.cfg.Challenge.PathPrefix + "/v1/challenge",
			CaptchaEnabled: false,
		})
	})
	h.mux.HandleFunc(base+"/block", func(w http.ResponseWriter, r *http.Request) {
		ray := rayid.New()
		h.setRayHeader(w, ray)
		h.pages.RenderBlock(w, ray, "Test mode: sample block page")
	})
	h.mux.HandleFunc(base+"/ratelimit", func(w http.ResponseWriter, r *http.Request) {
		ray := rayid.New()
		h.setRayHeader(w, ray)
		h.pages.RenderRateLimit(w, ray)
	})
	h.mux.HandleFunc(base+"/upstream", func(w http.ResponseWriter, r *http.Request) {
		ray := rayid.New()
		h.setRayHeader(w, ray)
		h.pages.RenderUpstream(w, ray)
	})
	h.mux.HandleFunc(base+"/error", func(w http.ResponseWriter, r *http.Request) {
		ray := rayid.New()
		h.setRayHeader(w, ray)
		h.pages.RenderError(w, ray, "Internal error", "Test mode: sample error page for unexpected failures.", http.StatusInternalServerError)
	})
}

func (h *Handler) handleTestIndex(w http.ResponseWriter, r *http.Request) {
	ray := rayid.New()
	h.setRayHeader(w, ray)
	h.pages.RenderTestIndex(w, ray)
}

func (h *Handler) clientBind(ipStr string) string {
	if h.priv != nil {
		return h.priv.ClientKey(ipStr)
	}
	return ipStr
}

func (h *Handler) logIP(ipStr string) string {
	if h.priv != nil {
		return h.priv.LogIP(ipStr)
	}
	return ipStr
}

func (h *Handler) requestSecure(r *http.Request) bool {
	cfg := h.config()
	if cfg.Listen.HTTPS != "" || cfg.Listen.QUIC != "" {
		return true
	}
	if h.chal != nil && h.chal.SecureDefault() {
		return true
	}
	if !strings.EqualFold(cfg.Trust.Mode, "behind_proxy") {
		return r.TLS != nil
	}
	return iputil.RequestHTTPS(r, cfg.Trust.ProtoHeader)
}

func (h *Handler) guard(w http.ResponseWriter, r *http.Request) {
	cfg := h.config()
	ray := rayid.New()
	h.setRayHeader(w, ray)

	clientIP := h.resolveClientIP(r)
	ipStr := ""
	if clientIP != nil {
		ipStr = clientIP.String()
	}
	bindID := h.clientBind(ipStr)

	if h.prot != nil && h.prot.Enabled() {
		if reason := h.prot.CheckRequestSize(r); reason != "" {
			host := stripPort(r.Host)
			ua := r.Header.Get("User-Agent")
			h.emitBlock(w, r, ray, bindID, ipStr, host, ua, reason, 0, nil)
			return
		}
		h.prot.LimitBody(w, r)
		if h.prot.Banned(bindID) {
			host := stripPort(r.Host)
			ua := r.Header.Get("User-Agent")
			h.emitBlock(w, r, ray, bindID, ipStr, host, ua, "Temporarily banned", 0, nil)
			return
		}
		if !h.prot.Acquire(bindID) {
			host := stripPort(r.Host)
			ua := r.Header.Get("User-Agent")
			h.emitRateLimit(w, r, ray, bindID, ipStr, host, ua)
			return
		}
		defer h.prot.Release(bindID)
	}

	host := stripPort(r.Host)
	ua := r.Header.Get("User-Agent")
	allowed := h.allows != nil && h.allows.Match(clientIP, ua, r.Header)

	if h.lists != nil {
		if h.lists.IPBlocked(clientIP) {
			h.emitBlock(w, r, ray, bindID, ipStr, host, ua, "IP blocked", 0, nil)
			return
		}
		if h.lists.DNSBlocked(host) {
			h.emitBlock(w, r, ray, bindID, ipStr, host, ua, "Host blocked", 0, nil)
			return
		}
		if h.lists.UABlocked(ua) {
			h.emitBlock(w, r, ray, bindID, ipStr, host, ua, "Client blocked", 0, nil)
			return
		}
	}

	if h.feeds != nil {
		if h.feeds.IPBlocked(clientIP) {
			h.emitBlock(w, r, ray, bindID, ipStr, host, ua, "Threat feed match", 0, nil)
			return
		}
		if h.feeds.DomainBlocked(host) {
			h.emitBlock(w, r, ray, bindID, ipStr, host, ua, "Threat feed match", 0, nil)
			return
		}
	}

	if !h.upstreamHealthy(r) {
		h.pages.RenderUpstream(w, ray)
		return
	}

	skipAttack := false
	if h.coraza != nil && h.coraza.Enabled() {
		cr := h.coraza.Evaluate(r)
		if cr.Matched {
			details := map[string]string{
				"rule_id": strconv.Itoa(cr.RuleID),
				"action":  cr.Action,
				"data":    cr.Data,
			}
			if cr.ShouldBlock {
				if h.prot != nil && h.prot.Enabled() {
					h.prot.BanNow(bindID)
				}
				h.recordEvent(r, ray, bindID, ipStr, host, ua, requestlog.ActionCoraza, "Coraza rule matched", 0, details)
				h.pages.RenderBlock(w, ray, "Request blocked by WAF rules")
				return
			}
			h.recordEvent(r, ray, bindID, ipStr, host, ua, requestlog.ActionCoraza, "Coraza detect match", 0, details)
		}
		if strings.EqualFold(h.coraza.Mode(), "block") {
			skipAttack = true
		}
	}

	if !skipAttack {
		if attack := detect.AttackMatch(r); attack != "" {
			slog.Debug("attack signature", "ray", ray, "ip", h.logIP(ipStr), "reason", attack)
			if h.prot == nil || !h.prot.Enabled() || h.prot.AttackBlock() {
				if h.prot != nil && h.prot.Enabled() {
					h.prot.BanNow(bindID)
				}
				h.emitBlock(w, r, ray, bindID, ipStr, host, ua, "Attack pattern blocked", 0, map[string]string{"attack": attack})
				return
			}
			if h.prot != nil {
				h.prot.Strike(bindID)
			}
		}
	}

	if h.limiter != nil && cfg.RateLimit.Enabled {
		cost := 1
		if h.prot != nil && h.prot.Enabled() {
			cost = protect.MethodCost(r.Method, h.writeCost)
		}
		if !h.limiter.AllowN(bindID, r.URL.Path, cost) {
			if h.prot != nil && h.prot.Enabled() {
				h.prot.Strike(bindID)
			}
			if isWebSocketUpgrade(r) {
				h.recordEvent(r, ray, bindID, ipStr, host, ua, requestlog.ActionRateLimit, "Rate limited", 0, nil)
				http.Error(w, "rate limited", http.StatusTooManyRequests)
				return
			}
			if cfg.RateLimit.ChallengeOver && cfg.Challenge.Enabled && h.chal != nil {
				h.serveChallenge(w, r, ray, bindID, challenge.RiskElevated)
				return
			}
			h.emitRateLimit(w, r, ray, bindID, ipStr, host, ua)
			return
		}
	}

	if isWebSocketUpgrade(r) {
		if !allowed && cfg.Challenge.Enabled && h.chal != nil && !h.chal.HasClearance(r, bindID) {
			h.recordEvent(r, ray, bindID, ipStr, host, ua, requestlog.ActionChallenge, "clearance required", 0, nil)
			http.Error(w, "clearance required", http.StatusForbidden)
			return
		}
		if !h.checkAccess(w, r, ray, bindID, clientIP, true) {
			return
		}
		if !h.checkOpenAPI(w, r, ray, bindID, ipStr, host, ua) {
			return
		}
		h.proxy(w, r, ray, clientIP, ipStr, bindID)
		return
	}

	needChallenge := false
	detectScore := 0
	if !allowed && cfg.Detect.Enabled {
		if h.beh != nil {
			h.beh.Record(bindID, r.URL.Path, r.Method)
			if h.beh.StrikesExceeded(bindID) {
				if h.prot != nil && h.prot.Enabled() {
					h.prot.BanNow(bindID)
				}
				h.emitBlock(w, r, ray, bindID, ipStr, host, ua, "Too many failed challenges", 0, nil)
				return
			}
		}
		res := detect.ScoreDebug(r, h.detectCfg)
		if h.beh != nil {
			br := h.beh.Score(bindID)
			res.Score += br.Score
			res.Reasons = append(res.Reasons, br.Reasons...)
		}
		detectScore = res.Score
		if res.Score > 0 {
			slog.Debug("detect score", "ray", ray, "ip", h.logIP(ipStr), "score", res.Score)
		}
		if res.Score >= cfg.Detect.BlockScore {
			if h.prot != nil && h.prot.Enabled() {
				h.prot.Strike(bindID)
			}
			details := map[string]string{}
			if len(res.Reasons) > 0 {
				details["reasons"] = strings.Join(res.Reasons, ",")
			}
			h.emitBlock(w, r, ray, bindID, ipStr, host, ua, "Request blocked", res.Score, details)
			return
		}
		if res.Score >= cfg.Detect.ChallengeScore {
			needChallenge = true
		}
		if h.nf != nil && h.nf.Exceeded(bindID) {
			switch h.high404Action {
			case high404Block:
				if h.prot != nil && h.prot.Enabled() {
					h.prot.Strike(bindID)
				}
				h.emitBlock(w, r, ray, bindID, ipStr, host, ua, "Too many missing pages", 0, nil)
				return
			case high404Off:
			default:
				needChallenge = true
			}
		}
	}

	if !allowed && cfg.Challenge.Enabled && h.chal != nil {
		if h.chal.HasClearance(r, bindID) {
			if !h.checkAccess(w, r, ray, bindID, clientIP, false) {
				return
			}
			if !h.checkOpenAPI(w, r, ray, bindID, ipStr, host, ua) {
				return
			}
			h.proxy(w, r, ray, clientIP, ipStr, bindID)
			return
		}
		if h.challengeAlways || needChallenge {
			risk := challenge.RiskFromScore(detectScore, cfg.Detect.ChallengeScore, cfg.Detect.BlockScore)
			if h.challengeAlways && detectScore == 0 {
				risk = challenge.RiskLow
			}
			risk = challenge.FloorRiskForMode(cfg.Challenge.Mode, risk)
			h.serveChallenge(w, r, ray, bindID, risk)
			return
		}
	}

	if !h.checkAccess(w, r, ray, bindID, clientIP, false) {
		return
	}
	if !h.checkOpenAPI(w, r, ray, bindID, ipStr, host, ua) {
		return
	}
	h.proxy(w, r, ray, clientIP, ipStr, bindID)
}

func (h *Handler) checkOpenAPI(w http.ResponseWriter, r *http.Request, ray, bindID, ipStr, host, ua string) bool {
	h.mu.RLock()
	schemas := h.schemas
	routes := h.routes
	h.mu.RUnlock()
	if schemas == nil || routes == nil {
		return true
	}
	m, ok := routes.Lookup(r)
	if !ok || m.Route.OpenAPISchemaID == "" {
		return true
	}
	res := schemas.Validate(r, m.Route.OpenAPISchemaID)
	if res.OK {
		return true
	}
	details := map[string]string{"schema_id": res.SchemaID}
	if res.ShouldBlock {
		h.recordEvent(r, ray, bindID, ipStr, host, ua, requestlog.ActionOpenAPI, res.Reason, 0, details)
		if isWebSocketUpgrade(r) {
			http.Error(w, "openapi schema violation", http.StatusForbidden)
			return false
		}
		h.pages.RenderBlock(w, ray, "OpenAPI schema violation")
		return false
	}
	h.recordEvent(r, ray, bindID, ipStr, host, ua, requestlog.ActionOpenAPI, res.Reason, 0, details)
	return true
}

func (h *Handler) upstreamHealthy(r *http.Request) bool {
	h.mu.RLock()
	routes := h.routes
	hc := h.health
	h.mu.RUnlock()
	if routes != nil && (routes.HasRoutes() || true) {
		return routes.Healthy(r)
	}
	if hc != nil {
		return hc.Healthy()
	}
	return true
}

func (h *Handler) checkAccess(w http.ResponseWriter, r *http.Request, ray, bindID string, clientIP net.IP, websocket bool) bool {
	h.mu.RLock()
	am := h.access
	routes := h.routes
	h.mu.RUnlock()
	if am == nil {
		return true
	}
	policyID := ""
	if routes != nil {
		if m, ok := routes.Lookup(r); ok {
			policyID = m.Route.AccessPolicyID
		}
	}
	if policyID == "" {
		return true
	}
	res := am.Check(r, policyID, bindID, clientIP)
	if res.OK {
		return true
	}
	ipStr := ""
	if clientIP != nil {
		ipStr = clientIP.String()
	}
	host := stripPort(r.Host)
	ua := r.Header.Get("User-Agent")
	details := map[string]string{"policy_id": policyID}
	if websocket {
		h.recordEvent(r, ray, bindID, ipStr, host, ua, requestlog.ActionAccess, res.Reason, 0, details)
		http.Error(w, res.Reason, res.Status)
		return false
	}
	if res.NeedForm {
		h.recordEvent(r, ray, bindID, ipStr, host, ua, requestlog.ActionAccess, "access form required", 0, details)
		h.setRayHeader(w, ray)
		action := h.config().Challenge.PathPrefix + "/access"
		if h.pages != nil {
			kind := access.RulePassword
			if p, ok := am.Get(policyID); ok {
				for _, rule := range p.Rules {
					if rule.Type == access.RulePIN {
						kind = access.RulePIN
						break
					}
					if rule.Type == access.RulePassword {
						kind = access.RulePassword
					}
				}
			}
			h.pages.ServeAccessForm(w, kind, action)
		} else {
			am.WriteFormForPolicy(w, policyID, action)
		}
		return false
	}
	h.recordEvent(r, ray, bindID, ipStr, host, ua, requestlog.ActionAccess, res.Reason, 0, details)
	h.pages.RenderBlock(w, ray, res.Reason)
	return false
}

func (h *Handler) handleAccessPOST(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	h.mu.RLock()
	am := h.access
	routes := h.routes
	h.mu.RUnlock()
	if am == nil {
		http.Error(w, "access disabled", http.StatusNotFound)
		return
	}
	_ = r.ParseForm()
	secret := r.FormValue("secret")
	if secret == "" {
		secret = r.FormValue("password")
	}
	if secret == "" {
		secret = r.FormValue("pin")
	}
	clientIP := h.resolveClientIP(r)
	ipStr := ""
	if clientIP != nil {
		ipStr = clientIP.String()
	}
	bindID := h.clientBind(ipStr)
	policyID := ""
	if routes != nil {
		if m, ok := routes.Lookup(r); ok {
			policyID = m.Route.AccessPolicyID
		}
	}
	if policyID == "" {
		policyID = r.FormValue("policy_id")
	}
	if !am.VerifyForm(r, policyID, bindID, secret) {
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}
	am.IssueCookie(w, policyID, bindID, h.requestSecure(r))
	http.Redirect(w, r, "/", http.StatusFound)
}

func (h *Handler) proxy(w http.ResponseWriter, r *http.Request, ray string, clientIP net.IP, ipStr, bindID string) {
	cfg := h.config()
	if clientIP != nil {
		proto := "http"
		if h.requestSecure(r) {
			proto = "https"
		}
		iputil.SetClientForwardHeadersIP(r, ipStr, proto)
	}
	if name := strings.TrimSpace(h.config().Stealth.RayHeader); name != "" {
		r.Header.Set(name, ray)
	}

	h.mu.RLock()
	up := h.upstream
	routes := h.routes
	h.mu.RUnlock()
	if routes != nil {
		up = routes
	}

	if isWebSocketUpgrade(r) || h.nf == nil || !cfg.Detect.Enabled {
		up.ServeHTTP(w, r)
		return
	}

	rw := statusPool.Get().(*statusRecorder)
	rw.ResponseWriter = w
	rw.status = 200
	up.ServeHTTP(rw, r)
	h.nf.Record(bindID, rw.status)
	rw.ResponseWriter = nil
	statusPool.Put(rw)
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Unwrap() http.ResponseWriter {
	return s.ResponseWriter
}

func (s *statusRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h, ok := s.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("ResponseWriter does not support hijacking")
	}
	return h.Hijack()
}

func (s *statusRecorder) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func isWebSocketUpgrade(r *http.Request) bool {
	if r == nil {
		return false
	}
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		return false
	}
	for part := range strings.SplitSeq(r.Header.Get("Connection"), ",") {
		if strings.EqualFold(strings.TrimSpace(part), "upgrade") {
			return true
		}
	}
	return false
}

func (h *Handler) serveChallenge(w http.ResponseWriter, r *http.Request, ray, bindID string, risk challenge.RiskLevel) {
	if h.chal == nil {
		h.pages.RenderError(w, ray, "Challenge unavailable", "Browser challenge is not configured on this edge.", http.StatusInternalServerError)
		return
	}
	ipStr := ""
	if clientIP := h.resolveClientIP(r); clientIP != nil {
		ipStr = clientIP.String()
	}
	host := stripPort(r.Host)
	ua := r.Header.Get("User-Agent")
	mode := h.cfg.Challenge.Mode
	prevRisk, prevGate := h.chal.TakeChallenge(bindID)
	risk = max(prevRisk, challenge.FloorRiskForMode(mode, risk))
	gate := challenge.ResolveGate(mode, risk, prevGate, h.cfg.Challenge.Captcha.Enabled)
	h.chal.RememberChallenge(bindID, risk, gate)
	captchaOn := h.cfg.Challenge.Captcha.Enabled && gate == challenge.GateInteractive
	h.recordEvent(r, ray, bindID, ipStr, host, ua, requestlog.ActionChallenge, "Challenge required", 0, map[string]string{"gate": gate})
	h.pages.ServeChallenge(w, ui.Data{
		StatusText:       h.cfg.UI.StatusText,
		RayID:            ray,
		ChallengeURL:     h.cfg.Challenge.PathPrefix + "/v1/challenge",
		Gate:             gate,
		CaptchaEnabled:   captchaOn,
		PrivacyNoticeURL: h.cfg.Privacy.PrivacyNoticeURL,
	})
}

type challengeBody struct {
	Payload  string              `json:"payload"`
	Token    string              `json:"token"`
	Solution string              `json:"solution"`
	Ray      string              `json:"ray"`
	Captcha  string              `json:"captcha"`
	Env      challenge.EnvReport `json:"env"`
}

func (h *Handler) handleChallengeV1GET(w http.ResponseWriter, r *http.Request) {
	ray := rayid.New()
	h.setRayHeader(w, ray)
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if h.chal == nil {
		http.Error(w, "challenge disabled", http.StatusBadRequest)
		return
	}
	clientIP := h.resolveClientIP(r)
	ipStr := ""
	if clientIP != nil {
		ipStr = clientIP.String()
	}
	bindID := h.clientBind(ipStr)
	if h.limiter != nil && h.cfg.RateLimit.Enabled {
		if !h.limiter.AllowN(bindID, r.URL.Path, 1) {
			http.Error(w, "too many requests", http.StatusTooManyRequests)
			return
		}
	}
	risk, prevGate := h.chal.TakeChallenge(bindID)
	risk = challenge.FloorRiskForMode(h.cfg.Challenge.Mode, risk)
	gate := challenge.ResolveGate(h.cfg.Challenge.Mode, risk, prevGate, h.cfg.Challenge.Captcha.Enabled)
	ch, err := h.chal.IssueChallenge(bindID, risk, gate)
	if err != nil {
		http.Error(w, "issue failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(ch)
}

func (h *Handler) handleVerifyV1POST(w http.ResponseWriter, r *http.Request) {
	h.handleChallengePOST(w, r)
}

func (h *Handler) handleChallengePOST(w http.ResponseWriter, r *http.Request) {
	ray := rayid.New()
	h.setRayHeader(w, ray)
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if h.chal == nil {
		http.Error(w, "challenge disabled", http.StatusBadRequest)
		return
	}
	clientIP := h.resolveClientIP(r)
	ipStr := ""
	if clientIP != nil {
		ipStr = clientIP.String()
	}
	bindID := h.clientBind(ipStr)
	if h.limiter != nil && h.cfg.RateLimit.Enabled {
		if !h.limiter.AllowN(bindID, r.URL.Path, 1) {
			http.Error(w, "too many requests", http.StatusTooManyRequests)
			return
		}
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var body challengeBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if rayFromBody := strings.TrimSpace(body.Ray); rayFromBody != "" && rayFromBody != ray {
		// Allow challenge UI to continue the issued Ray, but refuse spoofing a Ray
		// already bound to a different client.
		if h.reqLog != nil {
			if existing, ok := h.reqLog.GetByRay(rayFromBody); ok && existing.BindID != "" && existing.BindID != bindID {
				slog.Debug("challenge ray spoof ignored", "ray", ray, "spoof", rayFromBody)
			} else {
				ray = rayFromBody
				h.setRayHeader(w, ray)
			}
		} else {
			ray = rayFromBody
			h.setRayHeader(w, ray)
		}
	}

	var (
		diff int
		gate string
		env  challenge.EnvReport
	)
	if body.Payload != "" {
		p, err := h.chal.VerifyPayload(body.Payload, bindID)
		if err != nil {
			if h.beh != nil {
				h.beh.Strike(bindID)
			}
			h.chal.RememberChallenge(bindID, challenge.RiskHigh, challenge.GateInteractive)
			http.Error(w, "invalid solution", http.StatusForbidden)
			return
		}
		diff = p.Difficulty
		gate = p.Gate
		env = p.Env.ToReport()
	} else {
		tok, err := h.chal.ParseToken(body.Token, bindID)
		if err != nil {
			http.Error(w, "invalid token", http.StatusBadRequest)
			return
		}
		if err := h.chal.VerifyPoW(tok, body.Solution); err != nil {
			if h.beh != nil {
				h.beh.Strike(bindID)
			}
			h.chal.RememberChallenge(bindID, challenge.RiskHigh, challenge.GateInteractive)
			http.Error(w, "invalid solution", http.StatusForbidden)
			return
		}
		if err := h.chal.ConsumeNonce(tok); err != nil {
			http.Error(w, "invalid solution", http.StatusForbidden)
			return
		}
		diff = tok.Difficulty
		gate = challenge.GateInteractive
		env = body.Env
	}

	probeOff := strings.EqualFold(strings.TrimSpace(h.cfg.Challenge.EnvProbe), "off")
	if !probeOff {
		verdict := h.chal.EvaluateEnv(env, diff, gate)
		if verdict.Refuse {
			if h.beh != nil {
				h.beh.Strike(bindID)
			}
			if h.prot != nil && h.prot.Enabled() {
				h.prot.Strike(bindID)
			}
			h.chal.RememberChallenge(bindID, challenge.RiskHigh, challenge.GateInteractive)
			slog.Debug("challenge env refuse", "ray", ray, "ip", h.logIP(ipStr), "reasons", verdict.Reasons)
			host := stripPort(r.Host)
			ua := r.Header.Get("User-Agent")
			if (h.beh != nil && h.beh.StrikesExceeded(bindID)) || (h.prot != nil && h.prot.Banned(bindID)) {
				h.emitBlock(w, r, ray, bindID, ipStr, host, ua, "Too many failed challenges", 0, map[string]string{
					"env": strings.Join(verdict.Reasons, ","),
				})
				return
			}
			h.recordEvent(r, ray, bindID, ipStr, host, ua, requestlog.ActionBlock, "challenge env refuse", 0, map[string]string{
				"env": strings.Join(verdict.Reasons, ","),
			})
			http.Error(w, challenge.FormatEnvReasons(verdict.Reasons), http.StatusForbidden)
			return
		}
	}
	if h.cfg.Challenge.Captcha.Enabled {
		provider := strings.ToLower(strings.TrimSpace(h.cfg.Challenge.Captcha.Provider))
		if body.Payload == "" || provider != "ravenguard" {
			if h.chal.Captcha == nil {
				http.Error(w, "captcha provider missing", http.StatusInternalServerError)
				return
			}
			token := body.Captcha
			if token == "" {
				token = body.Payload
			}
			if err := h.chal.Captcha.Verify(r, token); err != nil {
				if h.beh != nil {
					h.beh.Strike(bindID)
				}
				h.chal.RememberChallenge(bindID, challenge.RiskHigh, challenge.GateInteractive)
				http.Error(w, "captcha failed", http.StatusForbidden)
				return
			}
		}
	}
	http.SetCookie(w, h.chal.ClearanceCookie(bindID, ray, h.requestSecure(r)))
	w.Header().Set("Content-Type", "application/json")
	bp := bodyPool.Get().(*[]byte)
	buf := (*bp)[:0]
	buf = append(buf, `{"ok":true}`...)
	_, _ = w.Write(buf)
	*bp = buf[:0]
	bodyPool.Put(bp)
}

func stripPort(host string) string {
	if host == "" {
		return ""
	}
	if host[0] == '[' {
		if end := strings.IndexByte(host, ']'); end > 0 {
			return host[1:end]
		}
	}
	if i := strings.LastIndexByte(host, ':'); i >= 0 && strings.Count(host, ":") == 1 {
		return host[:i]
	}
	return host
}

func StartSweeper(ctx context.Context, l *ratelimit.Limiter, every, maxAge time.Duration) {
	if l == nil || every <= 0 {
		return
	}
	go runSweeper(ctx, every, func() { l.Sweep(maxAge) })
}

func StartNotFoundSweeper(ctx context.Context, nf *detect.NotFoundTracker, every, maxAge time.Duration) {
	if nf == nil || every <= 0 {
		return
	}
	go runSweeper(ctx, every, func() { nf.Sweep(maxAge) })
}

func StartNonceSweeper(ctx context.Context, chal *challenge.Manager, every time.Duration) {
	if chal == nil || every <= 0 {
		return
	}
	go runSweeper(ctx, every, func() { chal.SweepNonces(time.Now()) })
}

func StartBehaviorSweeper(ctx context.Context, beh *detect.BehaviorTracker, every, maxAge time.Duration) {
	if beh == nil || every <= 0 {
		return
	}
	go runSweeper(ctx, every, func() { beh.Sweep(maxAge) })
}

func StartProtectSweeper(ctx context.Context, g *protect.Guard, every, maxAge time.Duration) {
	if g == nil || every <= 0 {
		return
	}
	go runSweeper(ctx, every, func() { g.Sweep(maxAge) })
}

func runSweeper(ctx context.Context, every time.Duration, fn func()) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			fn()
		}
	}
}
