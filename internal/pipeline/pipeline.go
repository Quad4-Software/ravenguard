// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package pipeline

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Quad4-Software/ravenguard/internal/blocklist"
	"github.com/Quad4-Software/ravenguard/internal/challenge"
	"github.com/Quad4-Software/ravenguard/internal/config"
	"github.com/Quad4-Software/ravenguard/internal/detect"
	"github.com/Quad4-Software/ravenguard/internal/health"
	"github.com/Quad4-Software/ravenguard/internal/iputil"
	"github.com/Quad4-Software/ravenguard/internal/privacy"
	"github.com/Quad4-Software/ravenguard/internal/protect"
	"github.com/Quad4-Software/ravenguard/internal/qfeeds"
	"github.com/Quad4-Software/ravenguard/internal/ratelimit"
	"github.com/Quad4-Software/ravenguard/internal/rayid"
	"github.com/Quad4-Software/ravenguard/internal/ui"
)

type Handler struct {
	cfg             config.Config
	lists           *blocklist.Sets
	feeds           *qfeeds.Cache
	limiter         *ratelimit.Limiter
	chal            *challenge.Manager
	pages           *ui.Pages
	upstream        http.Handler
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
) http.Handler {
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
			ProxyBotLowScore:       cfg.Detect.ProxySignals.LowScorePoints,
			ProxyBotHeader:         cfg.Detect.ProxySignals.BotScoreHeader,
			ProxyBotScoreHeader:    cfg.Detect.ProxySignals.BotScoreHeader2,
			ProxyJA4Header:         cfg.Detect.ProxySignals.JA4Header,
		},
		challengeAlways: strings.EqualFold(cfg.Challenge.Mode, "always"),
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
	h.mux.HandleFunc("/site.webmanifest", h.pages.ServeManifest)
	h.mux.HandleFunc(cfg.Challenge.PathPrefix+"/site.webmanifest", h.pages.ServeManifest)
	h.mux.HandleFunc(cfg.Challenge.PathPrefix+"/challenge", h.handleChallengePOST)
	if cfg.UI.TestMode {
		h.mountTestRoutes()
	}
	h.mux.HandleFunc("/", h.guard)
	return h.mux
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
		w.Header().Set("X-RavenGuard-Ray", ray)
		if h.chal != nil {
			h.serveChallenge(w, r, ray, "preview")
			return
		}
		h.pages.ServeChallenge(w, ui.Data{
			StatusText: h.cfg.UI.StatusText,
			RayID:      ray,
			Token:      "preview.0.8.deadbeef",
			Difficulty: 8,
		})
	})
	h.mux.HandleFunc(base+"/block", func(w http.ResponseWriter, r *http.Request) {
		ray := rayid.New()
		w.Header().Set("X-RavenGuard-Ray", ray)
		h.pages.RenderBlock(w, ray, "Test mode: sample block page")
	})
	h.mux.HandleFunc(base+"/ratelimit", func(w http.ResponseWriter, r *http.Request) {
		ray := rayid.New()
		w.Header().Set("X-RavenGuard-Ray", ray)
		h.pages.RenderRateLimit(w, ray)
	})
	h.mux.HandleFunc(base+"/upstream", func(w http.ResponseWriter, r *http.Request) {
		ray := rayid.New()
		w.Header().Set("X-RavenGuard-Ray", ray)
		h.pages.RenderUpstream(w, ray)
	})
	h.mux.HandleFunc(base+"/error", func(w http.ResponseWriter, r *http.Request) {
		ray := rayid.New()
		w.Header().Set("X-RavenGuard-Ray", ray)
		h.pages.RenderError(w, ray, "Internal error", "Test mode: sample error page for unexpected failures.", http.StatusInternalServerError)
	})
}

func (h *Handler) handleTestIndex(w http.ResponseWriter, r *http.Request) {
	ray := rayid.New()
	w.Header().Set("X-RavenGuard-Ray", ray)
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
	if h.cfg.Listen.HTTPS != "" || h.cfg.Listen.QUIC != "" {
		return true
	}
	if h.chal != nil && h.chal.SecureDefault() {
		return true
	}
	return iputil.RequestHTTPS(r, h.cfg.Trust.ProtoHeader)
}

func (h *Handler) guard(w http.ResponseWriter, r *http.Request) {
	ray := rayid.New()
	w.Header().Set("X-RavenGuard-Ray", ray)

	clientIP := iputil.ClientIP(r, h.trusted, h.cfg.Trust.RealIPHeader)
	ipStr := ""
	if clientIP != nil {
		ipStr = clientIP.String()
	}
	bindID := h.clientBind(ipStr)

	if h.prot != nil && h.prot.Enabled() {
		if reason := h.prot.CheckRequestSize(r); reason != "" {
			h.pages.RenderBlock(w, ray, reason)
			return
		}
		h.prot.LimitBody(w, r)
		if h.prot.Banned(bindID) {
			h.pages.RenderBlock(w, ray, "Temporarily banned")
			return
		}
		if !h.prot.Acquire(bindID) {
			h.pages.RenderRateLimit(w, ray)
			return
		}
		defer h.prot.Release(bindID)
	}

	host := stripPort(r.Host)
	ua := r.Header.Get("User-Agent")

	if h.lists != nil {
		if h.lists.IPBlocked(clientIP) {
			h.pages.RenderBlock(w, ray, "IP blocked")
			return
		}
		if h.lists.DNSBlocked(host) {
			h.pages.RenderBlock(w, ray, "Host blocked")
			return
		}
		if h.lists.UABlocked(ua) {
			h.pages.RenderBlock(w, ray, "Client blocked")
			return
		}
	}

	if h.feeds != nil {
		if h.feeds.IPBlocked(clientIP) {
			h.pages.RenderBlock(w, ray, "Threat feed match")
			return
		}
		if h.feeds.DomainBlocked(host) {
			h.pages.RenderBlock(w, ray, "Threat feed match")
			return
		}
	}

	if h.health != nil && !h.health.Healthy() {
		h.pages.RenderUpstream(w, ray)
		return
	}

	if attack := detect.AttackMatch(r); attack != "" {
		slog.Debug("attack signature", "ray", ray, "ip", h.logIP(ipStr), "reason", attack)
		if h.prot == nil || !h.prot.Enabled() || h.prot.AttackBlock() {
			if h.prot != nil && h.prot.Enabled() {
				h.prot.BanNow(bindID)
			}
			h.pages.RenderBlock(w, ray, "Attack pattern blocked")
			return
		}
		if h.prot != nil {
			h.prot.Strike(bindID)
		}
	}

	if h.limiter != nil && h.cfg.RateLimit.Enabled {
		cost := 1
		if h.prot != nil && h.prot.Enabled() {
			cost = protect.MethodCost(r.Method, h.writeCost)
		}
		if !h.limiter.AllowN(bindID, r.URL.Path, cost) {
			if h.prot != nil && h.prot.Enabled() {
				h.prot.Strike(bindID)
			}
			if isWebSocketUpgrade(r) {
				http.Error(w, "rate limited", http.StatusTooManyRequests)
				return
			}
			if h.cfg.RateLimit.ChallengeOver && h.cfg.Challenge.Enabled && h.chal != nil {
				h.serveChallenge(w, r, ray, bindID)
				return
			}
			h.pages.RenderRateLimit(w, ray)
			return
		}
	}

	if isWebSocketUpgrade(r) {
		if h.cfg.Challenge.Enabled && h.chal != nil && !h.chal.HasClearance(r, bindID) {
			http.Error(w, "clearance required", http.StatusForbidden)
			return
		}
		h.proxy(w, r, ray, clientIP, ipStr, bindID)
		return
	}

	needChallenge := false
	if h.cfg.Detect.Enabled {
		if h.beh != nil {
			h.beh.Record(bindID, r.URL.Path)
			if h.beh.StrikesExceeded(bindID) {
				if h.prot != nil && h.prot.Enabled() {
					h.prot.BanNow(bindID)
				}
				h.pages.RenderBlock(w, ray, "Too many failed challenges")
				return
			}
		}
		res := detect.Score(r, h.detectCfg)
		if h.beh != nil {
			br := h.beh.Score(bindID)
			res.Score += br.Score
		}
		if res.Score > 0 {
			slog.Debug("detect score", "ray", ray, "ip", h.logIP(ipStr), "score", res.Score)
		}
		if res.Score >= h.cfg.Detect.BlockScore {
			if h.prot != nil && h.prot.Enabled() {
				h.prot.Strike(bindID)
			}
			h.pages.RenderBlock(w, ray, "Request blocked")
			return
		}
		if res.Score >= h.cfg.Detect.ChallengeScore {
			needChallenge = true
		}
		if h.nf != nil && h.nf.Exceeded(bindID) {
			switch h.high404Action {
			case high404Block:
				if h.prot != nil && h.prot.Enabled() {
					h.prot.Strike(bindID)
				}
				h.pages.RenderBlock(w, ray, "Too many missing pages")
				return
			case high404Off:
			default:
				needChallenge = true
			}
		}
	}

	if h.cfg.Challenge.Enabled && h.chal != nil {
		if h.chal.HasClearance(r, bindID) {
			h.proxy(w, r, ray, clientIP, ipStr, bindID)
			return
		}
		if h.challengeAlways || needChallenge {
			h.serveChallenge(w, r, ray, bindID)
			return
		}
	}

	h.proxy(w, r, ray, clientIP, ipStr, bindID)
}

func (h *Handler) proxy(w http.ResponseWriter, r *http.Request, ray string, clientIP net.IP, ipStr, bindID string) {
	if clientIP != nil {
		proto := "http"
		if h.requestSecure(r) {
			proto = "https"
		}
		iputil.SetClientForwardHeadersIP(r, ipStr, proto)
	}
	r.Header.Set("X-RavenGuard-Ray", ray)

	if isWebSocketUpgrade(r) || h.nf == nil || !h.cfg.Detect.Enabled {
		h.upstream.ServeHTTP(w, r)
		return
	}

	rw := statusPool.Get().(*statusRecorder)
	rw.ResponseWriter = w
	rw.status = 200
	h.upstream.ServeHTTP(rw, r)
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

func (h *Handler) serveChallenge(w http.ResponseWriter, r *http.Request, ray, bindID string) {
	if h.chal == nil {
		h.pages.RenderError(w, ray, "Challenge unavailable", "Browser challenge is not configured on this edge.", http.StatusInternalServerError)
		return
	}
	tok, payload, err := h.chal.Issue(bindID)
	if err != nil {
		h.pages.RenderError(w, ray, "Challenge unavailable", "Could not issue a verification challenge. Try again shortly.", http.StatusInternalServerError)
		return
	}
	h.pages.ServeChallenge(w, ui.Data{
		StatusText:       h.cfg.UI.StatusText,
		RayID:            ray,
		Token:            payload,
		Difficulty:       tok.Difficulty,
		CaptchaEnabled:   h.cfg.Challenge.Captcha.Enabled,
		PrivacyNoticeURL: h.cfg.Privacy.PrivacyNoticeURL,
	})
}

type challengeBody struct {
	Token    string              `json:"token"`
	Solution string              `json:"solution"`
	Ray      string              `json:"ray"`
	Captcha  string              `json:"captcha"`
	Env      challenge.EnvReport `json:"env"`
}

func (h *Handler) handleChallengePOST(w http.ResponseWriter, r *http.Request) {
	ray := rayid.New()
	w.Header().Set("X-RavenGuard-Ray", ray)
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if h.chal == nil {
		http.Error(w, "challenge disabled", http.StatusBadRequest)
		return
	}
	clientIP := iputil.ClientIP(r, h.trusted, h.cfg.Trust.RealIPHeader)
	ipStr := ""
	if clientIP != nil {
		ipStr = clientIP.String()
	}
	bindID := h.clientBind(ipStr)
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var body challengeBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	tok, err := h.chal.ParseToken(body.Token, bindID)
	if err != nil {
		http.Error(w, "invalid token", http.StatusBadRequest)
		return
	}
	if err := h.chal.VerifyPoW(tok, body.Solution); err != nil {
		if h.beh != nil {
			h.beh.Strike(bindID)
		}
		http.Error(w, "invalid solution", http.StatusForbidden)
		return
	}
	if err := h.chal.ConsumeNonce(tok); err != nil {
		http.Error(w, "invalid solution", http.StatusForbidden)
		return
	}
	verdict := h.chal.EvaluateEnv(body.Env, tok.Difficulty)
	if verdict.Refuse {
		if h.beh != nil {
			h.beh.Strike(bindID)
		}
		if h.prot != nil && h.prot.Enabled() {
			h.prot.Strike(bindID)
		}
		slog.Debug("challenge env refuse", "ray", ray, "ip", h.logIP(ipStr), "reasons", verdict.Reasons)
		if (h.beh != nil && h.beh.StrikesExceeded(bindID)) || (h.prot != nil && h.prot.Banned(bindID)) {
			h.pages.RenderBlock(w, ray, "Too many failed challenges")
			return
		}
		http.Error(w, challenge.FormatEnvReasons(verdict.Reasons), http.StatusForbidden)
		return
	}
	if h.cfg.Challenge.Captcha.Enabled {
		if h.chal.Captcha == nil {
			http.Error(w, "captcha provider missing", http.StatusInternalServerError)
			return
		}
		if err := h.chal.Captcha.Verify(r, body.Captcha); err != nil {
			if h.beh != nil {
				h.beh.Strike(bindID)
			}
			http.Error(w, "captcha failed", http.StatusForbidden)
			return
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

func StartSweeper(l *ratelimit.Limiter, every, maxAge time.Duration) {
	if l == nil || every <= 0 {
		return
	}
	go func() {
		t := time.NewTicker(every)
		defer t.Stop()
		for range t.C {
			l.Sweep(maxAge)
		}
	}()
}

func StartNotFoundSweeper(nf *detect.NotFoundTracker, every, maxAge time.Duration) {
	if nf == nil || every <= 0 {
		return
	}
	go func() {
		t := time.NewTicker(every)
		defer t.Stop()
		for range t.C {
			nf.Sweep(maxAge)
		}
	}()
}

func StartNonceSweeper(chal *challenge.Manager, every time.Duration) {
	if chal == nil || every <= 0 {
		return
	}
	go func() {
		t := time.NewTicker(every)
		defer t.Stop()
		for range t.C {
			chal.SweepNonces(time.Now())
		}
	}()
}

func StartBehaviorSweeper(beh *detect.BehaviorTracker, every, maxAge time.Duration) {
	if beh == nil || every <= 0 {
		return
	}
	go func() {
		t := time.NewTicker(every)
		defer t.Stop()
		for range t.C {
			beh.Sweep(maxAge)
		}
	}()
}

func StartProtectSweeper(g *protect.Guard, every, maxAge time.Duration) {
	if g == nil || every <= 0 {
		return
	}
	go func() {
		t := time.NewTicker(every)
		defer t.Stop()
		for range t.C {
			g.Sweep(maxAge)
		}
	}()
}
