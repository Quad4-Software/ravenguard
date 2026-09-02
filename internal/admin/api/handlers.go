// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package api

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Quad4-Software/ravenguard/internal/admin/auth"
	"github.com/Quad4-Software/ravenguard/internal/admin/ops"
	"github.com/Quad4-Software/ravenguard/internal/admin/rbac"
	"github.com/Quad4-Software/ravenguard/internal/admin/store"
	"github.com/Quad4-Software/ravenguard/internal/config"
	"github.com/Quad4-Software/ravenguard/internal/iputil"
	"github.com/Quad4-Software/ravenguard/internal/ui"
)

const sessionCookie = "rg_admin_session"
const csrfHeader = "X-CSRF-Token"

type Server struct {
	Store            *store.Store
	Runtime          *ops.Runtime
	Admin            config.AdminConfig
	Lockout          *auth.Lockout
	SecureCookie     bool
	ReloadRoutes     func() error
	CertStatus       func() any
	CertRenew        func(ctx context.Context, host string) error
	LogSnapshot      func(limit int, level string) any
	ManualCertPut    func(hostname, certPEM, keyPEM string) error
	ManualCertDelete func(hostname string) error
	CertDetail       func(hostname string) (any, error)
	ACMEManage       func(ctx context.Context, hosts []string) error
	Pages            *ui.Pages
}

type ctxKey int

const actorKey ctxKey = 1

type Actor struct {
	User      store.User
	Session   *store.Session
	TokenAuth bool
	CSRF      string
}

func (s *Server) Mount(mux *http.ServeMux, base string) {
	p := strings.TrimSuffix(base, "/")
	api := p + "/api/v1"
	mux.HandleFunc(api+"/auth/login", s.handleLogin)
	mux.HandleFunc(api+"/auth/logout", s.auth(s.handleLogout))
	mux.HandleFunc(api+"/auth/me", s.auth(s.handleMe))
	mux.HandleFunc(api+"/auth/password", s.auth(s.csrf(s.handlePassword)))
	mux.HandleFunc(api+"/auth/profile", s.auth(s.csrf(s.handleProfile)))
	mux.HandleFunc(api+"/users", s.auth(s.handleUsers))
	mux.HandleFunc(api+"/users/", s.auth(s.handleUserID))
	mux.HandleFunc(api+"/tokens", s.auth(s.handleTokens))
	mux.HandleFunc(api+"/tokens/", s.auth(s.handleTokenID))
	mux.HandleFunc(api+"/status", s.auth(s.handleStatus))
	mux.HandleFunc(api+"/status/history", s.auth(s.handleStatusHistory))
	mux.HandleFunc(api+"/bans", s.auth(s.handleBans))
	mux.HandleFunc(api+"/blocklists", s.auth(s.handleBlocklists))
	mux.HandleFunc(api+"/blocklists/reload", s.auth(s.csrf(s.handleBlocklistReload)))
	mux.HandleFunc(api+"/blocklists/entries", s.auth(s.handleBlocklistEntries))
	mux.HandleFunc(api+"/qfeeds", s.auth(s.handleQFeeds))
	mux.HandleFunc(api+"/qfeeds/refresh", s.auth(s.csrf(s.handleQFeedsRefresh)))
	mux.HandleFunc(api+"/config", s.auth(s.handleConfig))
	mux.HandleFunc(api+"/appearance/assets", s.auth(s.handleAppearanceAssets))
	mux.HandleFunc(api+"/appearance/assets/", s.auth(s.handleAppearanceAssetFile))
	mux.HandleFunc(api+"/appearance/preview", s.auth(s.handleAppearancePreview))
	mux.HandleFunc(api+"/audit", s.auth(s.handleAudit))
	mux.HandleFunc(api+"/upstreams", s.auth(s.handleUpstreams))
	mux.HandleFunc(api+"/upstreams/", s.auth(s.handleUpstreamID))
	mux.HandleFunc(api+"/routes", s.auth(s.handleRoutes))
	mux.HandleFunc(api+"/routes/", s.auth(s.handleRouteID))
	mux.HandleFunc(api+"/access-policies", s.auth(s.handleAccessPolicies))
	mux.HandleFunc(api+"/access-policies/", s.auth(s.handleAccessPolicyID))
	mux.HandleFunc(api+"/certs", s.auth(s.handleCerts))
	mux.HandleFunc(api+"/certs/", s.auth(s.handleCertsPath))
	mux.HandleFunc(api+"/logs", s.auth(s.handleLogs))
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func (s *Server) clientIP(r *http.Request) string {
	if s.Runtime != nil {
		cfg := s.Runtime.Config()
		var trusted []net.IPNet
		if strings.EqualFold(cfg.Trust.Mode, "behind_proxy") {
			trusted, _ = iputil.ParseCIDRs(cfg.Trust.TrustedProxies)
		}
		if ip := iputil.ClientIP(r, trusted, cfg.Trust.RealIPHeader); ip != nil {
			return ip.String()
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (s *Server) audit(actor Actor, r *http.Request, action, target, detail string) {
	id := actor.User.ID
	_ = s.Store.AppendAudit(&id, actor.User.Username, action, target, detail, s.clientIP(r))
}

func actorFrom(r *http.Request) Actor {
	v, _ := r.Context().Value(actorKey).(Actor)
	return v
}

func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		actor, ok := s.resolveActor(r)
		if !ok {
			writeErr(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), actorKey, actor)))
	}
}

func (s *Server) csrf(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		actor := actorFrom(r)
		if actor.TokenAuth || r.Method == http.MethodGet || r.Method == http.MethodHead {
			next(w, r)
			return
		}
		if r.Header.Get(csrfHeader) == "" || r.Header.Get(csrfHeader) != actor.CSRF {
			writeErr(w, http.StatusForbidden, "csrf")
			return
		}
		next(w, r)
	}
}

func (s *Server) resolveActor(r *http.Request) (Actor, bool) {
	authz := r.Header.Get("Authorization")
	if strings.HasPrefix(strings.ToLower(authz), "bearer ") {
		raw := strings.TrimSpace(authz[7:])
		tok, u, err := s.Store.LookupAPIToken(raw)
		if err != nil {
			return Actor{}, false
		}
		if rbac.Rank(tok.Role) < rbac.Rank(u.Role) {
			u.Role = tok.Role
		}
		return Actor{User: u, TokenAuth: true}, true
	}
	c, err := r.Cookie(sessionCookie)
	if err != nil || c.Value == "" {
		return Actor{}, false
	}
	sess, u, err := s.Store.GetSessionByToken(c.Value)
	if err != nil {
		return Actor{}, false
	}
	return Actor{User: u, Session: &sess, CSRF: sess.CSRFToken}, true
}

func (s *Server) setSessionCookie(w http.ResponseWriter, raw string, expires time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: raw, Path: s.cookiePath(),
		HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: s.SecureCookie, Expires: expires,
	})
}

func (s *Server) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: "", Path: s.cookiePath(),
		HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: s.SecureCookie, MaxAge: -1,
	})
}

func (s *Server) cookiePath() string {
	if s.Admin.BasePath == "" || s.Admin.BasePath == "/" {
		return "/"
	}
	return s.Admin.BasePath
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method")
		return
	}
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	ip := s.clientIP(r)
	userKey := strings.ToLower(strings.TrimSpace(body.Username))
	if s.Lockout.Locked(userKey) || s.Lockout.Locked("ip:"+ip) {
		writeErr(w, http.StatusTooManyRequests, "locked")
		return
	}
	u, err := s.Store.GetUserByName(body.Username)
	if err != nil || u.Disabled {
		s.Lockout.Fail(userKey)
		s.Lockout.Fail("ip:" + ip)
		writeErr(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	if err := auth.VerifyPassword(u.PasswordHash, body.Password); err != nil {
		s.Lockout.Fail(userKey)
		s.Lockout.Fail("ip:" + ip)
		writeErr(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	s.Lockout.Clear(userKey)
	s.Lockout.Clear("ip:" + ip)
	ttl := s.Admin.SessionTTL.Duration
	if ttl <= 0 {
		ttl = 12 * time.Hour
	}
	_, raw, csrf, exp, err := s.Store.CreateSession(u.ID, ttl, ip, r.UserAgent())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "session")
		return
	}
	s.setSessionCookie(w, raw, exp)
	u.PasswordHash = ""
	s.audit(Actor{User: u}, r, "auth.login", u.Username, "")
	passFile := filepath.Join(s.Admin.DataDir, "initial_admin_password")
	_ = os.Remove(passFile)
	writeJSON(w, http.StatusOK, map[string]any{"user": u, "csrf_token": csrf})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method")
		return
	}
	actor := actorFrom(r)
	if actor.Session != nil {
		_ = s.Store.DeleteSession(actor.Session.ID)
	}
	s.clearSessionCookie(w)
	s.audit(actor, r, "auth.logout", actor.User.Username, "")
	writeJSON(w, http.StatusOK, map[string]string{"ok": "1"})
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "method")
		return
	}
	actor := actorFrom(r)
	u := actor.User
	u.PasswordHash = ""
	writeJSON(w, http.StatusOK, map[string]any{"user": u, "csrf_token": actor.CSRF, "token_auth": actor.TokenAuth})
}

func (s *Server) handlePassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method")
		return
	}
	var body struct {
		Current string `json:"current"`
		New     string `json:"new"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	actor := actorFrom(r)
	u, err := s.Store.GetUser(actor.User.ID)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if err := auth.VerifyPassword(u.PasswordHash, body.Current); err != nil {
		writeErr(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	hash, err := auth.HashPassword(body.New)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.Store.SetPassword(u.ID, hash); err != nil {
		writeErr(w, http.StatusInternalServerError, "update failed")
		return
	}
	_ = s.Store.DeleteSessionsForUser(u.ID)
	s.clearSessionCookie(w)
	s.audit(actor, r, "auth.password", u.Username, "")
	writeJSON(w, http.StatusOK, map[string]string{"ok": "1"})
}

func (s *Server) handleProfile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPatch && r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method")
		return
	}
	var body struct {
		Username string `json:"username"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	actor := actorFrom(r)
	oldName := actor.User.Username
	u, err := s.Store.SetUsername(actor.User.ID, body.Username)
	if errors.Is(err, store.ErrConflict) {
		writeErr(w, http.StatusConflict, "username taken")
		return
	}
	if errors.Is(err, store.ErrInvalidUser) {
		writeErr(w, http.StatusBadRequest, "invalid username")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "update failed")
		return
	}
	u.PasswordHash = ""
	s.audit(actor, r, "auth.profile", oldName, "renamed to "+u.Username)
	writeJSON(w, http.StatusOK, map[string]any{"user": u})
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "method")
		return
	}
	writeJSON(w, http.StatusOK, s.Runtime.Status())
}

func (s *Server) handleStatusHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "method")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"samples": s.Runtime.History()})
}

func (s *Server) handleBans(w http.ResponseWriter, r *http.Request) {
	actor := actorFrom(r)
	switch r.Method {
	case http.MethodGet:
		bans := []any{}
		if s.Runtime.Protect != nil {
			writeJSON(w, http.StatusOK, map[string]any{"bans": s.Runtime.Protect.ListBans()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"bans": bans})
	case http.MethodPost:
		if !rbac.CanWriteOps(actor.User.Role) {
			writeErr(w, http.StatusForbidden, "forbidden")
			return
		}
		if s.Runtime.Protect == nil {
			writeErr(w, http.StatusBadRequest, "protect disabled")
			return
		}
		if !s.checkCSRF(w, r, actor) {
			return
		}
		var body struct {
			Key string `json:"key"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || strings.TrimSpace(body.Key) == "" {
			writeErr(w, http.StatusBadRequest, "key required")
			return
		}
		s.Runtime.Protect.BanNow(body.Key)
		s.audit(actor, r, "bans.create", body.Key, "")
		writeJSON(w, http.StatusOK, map[string]string{"ok": "1"})
	case http.MethodDelete:
		if !rbac.CanWriteOps(actor.User.Role) {
			writeErr(w, http.StatusForbidden, "forbidden")
			return
		}
		if s.Runtime.Protect == nil {
			writeErr(w, http.StatusBadRequest, "protect disabled")
			return
		}
		if !s.checkCSRF(w, r, actor) {
			return
		}
		key := r.URL.Query().Get("key")
		if key == "" {
			writeErr(w, http.StatusBadRequest, "key required")
			return
		}
		ok := s.Runtime.Protect.Unban(key)
		s.audit(actor, r, "bans.delete", key, "")
		writeJSON(w, http.StatusOK, map[string]any{"ok": ok})
	default:
		writeErr(w, http.StatusMethodNotAllowed, "method")
	}
}

func (s *Server) checkCSRF(w http.ResponseWriter, r *http.Request, actor Actor) bool {
	if actor.TokenAuth {
		return true
	}
	if r.Header.Get(csrfHeader) == "" || r.Header.Get(csrfHeader) != actor.CSRF {
		writeErr(w, http.StatusForbidden, "csrf")
		return false
	}
	return true
}

func (s *Server) handleBlocklists(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "method")
		return
	}
	stats := s.Runtime.Lists.Stats()
	ipFiles, dnsFiles, uaFiles := s.Runtime.Lists.Files()
	out := map[string]any{
		"ip_count":    stats.IPCount,
		"dns_count":   stats.DNSCount,
		"ua_count":    stats.UACount,
		"overlay_dir": s.Runtime.Lists.OverlayDir(),
		"ip_files":    ipFiles,
		"dns_files":   dnsFiles,
		"ua_files":    uaFiles,
	}
	if !stats.LastReload.IsZero() {
		out["last_reload"] = stats.LastReload
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleBlocklistReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method")
		return
	}
	actor := actorFrom(r)
	if !rbac.CanWriteOps(actor.User.Role) {
		writeErr(w, http.StatusForbidden, "forbidden")
		return
	}
	if err := s.Runtime.Lists.ReloadNow(); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(actor, r, "blocklists.reload", "", "")
	writeJSON(w, http.StatusOK, s.Runtime.Lists.Stats())
}

func (s *Server) handleBlocklistEntries(w http.ResponseWriter, r *http.Request) {
	kind := r.URL.Query().Get("kind")
	if kind == "" {
		kind = "ip"
	}
	actor := actorFrom(r)
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{
			"kind":    kind,
			"entries": s.Runtime.Lists.ListEntries(kind),
		})
	case http.MethodPost:
		if !rbac.CanWriteOps(actor.User.Role) {
			writeErr(w, http.StatusForbidden, "forbidden")
			return
		}
		if !s.checkCSRF(w, r, actor) {
			return
		}
		var body struct {
			Kind  string `json:"kind"`
			Value string `json:"value"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid json")
			return
		}
		if body.Kind == "" {
			body.Kind = kind
		}
		if err := s.Runtime.Lists.AddEntry(body.Kind, body.Value); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		s.audit(actor, r, "blocklists.add", body.Kind, body.Value)
		writeJSON(w, http.StatusOK, map[string]any{
			"kind":    body.Kind,
			"entries": s.Runtime.Lists.ListEntries(body.Kind),
			"stats":   s.Runtime.Lists.Stats(),
		})
	case http.MethodPut:
		if !rbac.CanWriteOps(actor.User.Role) {
			writeErr(w, http.StatusForbidden, "forbidden")
			return
		}
		if !s.checkCSRF(w, r, actor) {
			return
		}
		var body struct {
			Kind string `json:"kind"`
			From string `json:"from"`
			To   string `json:"to"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid json")
			return
		}
		if body.Kind == "" {
			body.Kind = kind
		}
		if err := s.Runtime.Lists.RemoveEntry(body.Kind, body.From); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		if err := s.Runtime.Lists.AddEntry(body.Kind, body.To); err != nil {
			_ = s.Runtime.Lists.AddEntry(body.Kind, body.From)
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		s.audit(actor, r, "blocklists.edit", body.Kind, body.From+" -> "+body.To)
		writeJSON(w, http.StatusOK, map[string]any{
			"kind":    body.Kind,
			"entries": s.Runtime.Lists.ListEntries(body.Kind),
			"stats":   s.Runtime.Lists.Stats(),
		})
	case http.MethodDelete:
		if !rbac.CanWriteOps(actor.User.Role) {
			writeErr(w, http.StatusForbidden, "forbidden")
			return
		}
		if !s.checkCSRF(w, r, actor) {
			return
		}
		value := r.URL.Query().Get("value")
		if value == "" {
			var body struct {
				Kind  string `json:"kind"`
				Value string `json:"value"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body.Kind != "" {
				kind = body.Kind
			}
			value = body.Value
		}
		if value == "" {
			writeErr(w, http.StatusBadRequest, "value required")
			return
		}
		if err := s.Runtime.Lists.RemoveEntry(kind, value); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		s.audit(actor, r, "blocklists.remove", kind, value)
		writeJSON(w, http.StatusOK, map[string]any{
			"kind":    kind,
			"entries": s.Runtime.Lists.ListEntries(kind),
			"stats":   s.Runtime.Lists.Stats(),
		})
	default:
		writeErr(w, http.StatusMethodNotAllowed, "method")
	}
}

func (s *Server) handleQFeeds(w http.ResponseWriter, r *http.Request) {
	actor := actorFrom(r)
	switch r.Method {
	case http.MethodGet:
		st := s.Runtime.Status()
		writeJSON(w, http.StatusOK, map[string]any{
			"status": st.QFeeds,
			"config": s.Runtime.QFeedsView(),
		})
	case http.MethodPut:
		if !rbac.CanWriteConfig(actor.User.Role) {
			writeErr(w, http.StatusForbidden, "forbidden")
			return
		}
		if !s.checkCSRF(w, r, actor) {
			return
		}
		var safe ops.QFeedsSafe
		if err := json.NewDecoder(r.Body).Decode(&safe); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid json")
			return
		}
		if err := s.Runtime.ApplyQFeeds(safe); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		existing, _ := s.Store.GetConfigOverrides()
		payload, err := ops.MergeAndEncode(existing, func(sc *ops.SafeConfig) {
			q := safe
			sc.QFeeds = &q
		})
		if err == nil {
			_ = s.Store.SetConfigOverrides(payload, actor.User.ID)
		}
		s.audit(actor, r, "qfeeds.update", "", "")
		st := s.Runtime.Status()
		writeJSON(w, http.StatusOK, map[string]any{
			"status": st.QFeeds,
			"config": s.Runtime.QFeedsView(),
		})
	default:
		writeErr(w, http.StatusMethodNotAllowed, "method")
	}
}

func (s *Server) handleQFeedsRefresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method")
		return
	}
	actor := actorFrom(r)
	if !rbac.CanWriteOps(actor.User.Role) {
		writeErr(w, http.StatusForbidden, "forbidden")
		return
	}
	if s.Runtime.Feeds == nil {
		writeErr(w, http.StatusBadRequest, "qfeeds not active")
		return
	}
	ctx := r.Context()
	if s.Runtime.RootCtx != nil {
		ctx = s.Runtime.RootCtx
	}
	s.Runtime.Feeds.RefreshNow(ctx)
	s.audit(actor, r, "qfeeds.refresh", "", "")
	writeJSON(w, http.StatusOK, map[string]any{"status": s.Runtime.Status().QFeeds})
}

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	actor := actorFrom(r)
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.Runtime.ConfigView())
	case http.MethodPut:
		if !rbac.CanWriteConfig(actor.User.Role) {
			writeErr(w, http.StatusForbidden, "forbidden")
			return
		}
		if !s.checkCSRF(w, r, actor) {
			return
		}
		var safe ops.SafeConfig
		if err := json.NewDecoder(r.Body).Decode(&safe); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid json")
			return
		}
		if err := s.Runtime.ApplySafeConfig(safe); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		payload, _ := ops.EncodeSafeConfig(safe)
		_ = s.Store.SetConfigOverrides(payload, actor.User.ID)
		s.audit(actor, r, "config.update", "", "")
		writeJSON(w, http.StatusOK, s.Runtime.ConfigView())
	default:
		writeErr(w, http.StatusMethodNotAllowed, "method")
	}
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "method")
		return
	}
	var after int64
	if v := r.URL.Query().Get("cursor"); v != "" {
		after, _ = strconv.ParseInt(v, 10, 64)
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	events, err := s.Store.ListAudit(after, limit)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "audit")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": events})
}

func (s *Server) handleUsers(w http.ResponseWriter, r *http.Request) {
	actor := actorFrom(r)
	switch r.Method {
	case http.MethodGet:
		if !rbac.CanManageUsers(actor.User.Role) {
			writeErr(w, http.StatusForbidden, "forbidden")
			return
		}
		users, err := s.Store.ListUsers()
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "list")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"users": users})
	case http.MethodPost:
		if !rbac.CanManageUsers(actor.User.Role) {
			writeErr(w, http.StatusForbidden, "forbidden")
			return
		}
		if !s.checkCSRF(w, r, actor) {
			return
		}
		var body struct {
			Username string `json:"username"`
			Password string `json:"password"`
			Role     string `json:"role"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid json")
			return
		}
		role := rbac.Normalize(body.Role)
		if role == "" {
			role = rbac.RoleViewer
		}
		if role == rbac.RoleOwner && !rbac.CanManageOwners(actor.User.Role) {
			writeErr(w, http.StatusForbidden, "forbidden")
			return
		}
		hash, err := auth.HashPassword(body.Password)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		u, err := s.Store.CreateUser(body.Username, hash, role)
		if errors.Is(err, store.ErrConflict) {
			writeErr(w, http.StatusConflict, "username taken")
			return
		}
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		u.PasswordHash = ""
		s.audit(actor, r, "users.create", u.Username, u.Role)
		writeJSON(w, http.StatusCreated, u)
	default:
		writeErr(w, http.StatusMethodNotAllowed, "method")
	}
}

func (s *Server) handleUserID(w http.ResponseWriter, r *http.Request) {
	actor := actorFrom(r)
	if !rbac.CanManageUsers(actor.User.Role) {
		writeErr(w, http.StatusForbidden, "forbidden")
		return
	}
	idStr := strings.TrimPrefix(r.URL.Path, strings.TrimSuffix(s.Admin.BasePath, "/")+"/api/v1/users/")
	if idStr == "" || strings.Contains(idStr, "/") {
		// fallback: last path segment
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		idStr = parts[len(parts)-1]
	}
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	switch r.Method {
	case http.MethodPatch:
		if !s.checkCSRF(w, r, actor) {
			return
		}
		var body struct {
			Role     *string `json:"role"`
			Disabled *bool   `json:"disabled"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid json")
			return
		}
		target, err := s.Store.GetUser(id)
		if err != nil {
			writeErr(w, http.StatusNotFound, "not found")
			return
		}
		if (target.Role == rbac.RoleOwner || (body.Role != nil && rbac.Normalize(*body.Role) == rbac.RoleOwner)) &&
			!rbac.CanManageOwners(actor.User.Role) {
			writeErr(w, http.StatusForbidden, "forbidden")
			return
		}
		role := ""
		if body.Role != nil {
			role = *body.Role
		}
		u, err := s.Store.UpdateUser(id, role, body.Disabled)
		if errors.Is(err, store.ErrLastOwner) {
			writeErr(w, http.StatusConflict, "last owner")
			return
		}
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		u.PasswordHash = ""
		s.audit(actor, r, "users.update", u.Username, u.Role)
		writeJSON(w, http.StatusOK, u)
	case http.MethodDelete:
		if !s.checkCSRF(w, r, actor) {
			return
		}
		target, err := s.Store.GetUser(id)
		if err != nil {
			writeErr(w, http.StatusNotFound, "not found")
			return
		}
		if target.Role == rbac.RoleOwner && !rbac.CanManageOwners(actor.User.Role) {
			writeErr(w, http.StatusForbidden, "forbidden")
			return
		}
		if err := s.Store.DeleteUser(id); errors.Is(err, store.ErrLastOwner) {
			writeErr(w, http.StatusConflict, "last owner")
			return
		} else if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		s.audit(actor, r, "users.delete", target.Username, "")
		writeJSON(w, http.StatusOK, map[string]string{"ok": "1"})
	default:
		writeErr(w, http.StatusMethodNotAllowed, "method")
	}
}

func (s *Server) handleTokens(w http.ResponseWriter, r *http.Request) {
	actor := actorFrom(r)
	switch r.Method {
	case http.MethodGet:
		all := rbac.CanManageOwners(actor.User.Role)
		tokens, err := s.Store.ListAPITokens(actor.User.ID, all)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "list")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"tokens": tokens})
	case http.MethodPost:
		if !s.checkCSRF(w, r, actor) {
			return
		}
		var body struct {
			Name      string `json:"name"`
			Role      string `json:"role"`
			ExpiresIn string `json:"expires_in"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid json")
			return
		}
		role := rbac.Normalize(body.Role)
		if role == "" {
			role = actor.User.Role
		}
		if rbac.Rank(role) > rbac.Rank(actor.User.Role) {
			writeErr(w, http.StatusForbidden, "role too high")
			return
		}
		var exp *time.Time
		if body.ExpiresIn != "" {
			d, err := time.ParseDuration(body.ExpiresIn)
			if err != nil {
				writeErr(w, http.StatusBadRequest, "expires_in")
				return
			}
			t := time.Now().UTC().Add(d)
			exp = &t
		}
		tok, raw, err := s.Store.CreateAPIToken(actor.User.ID, body.Name, role, exp)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		s.audit(actor, r, "tokens.create", tok.ID, tok.Name)
		writeJSON(w, http.StatusCreated, map[string]any{"token": tok, "secret": raw})
	default:
		writeErr(w, http.StatusMethodNotAllowed, "method")
	}
}

func (s *Server) handleTokenID(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		writeErr(w, http.StatusMethodNotAllowed, "method")
		return
	}
	actor := actorFrom(r)
	if !s.checkCSRF(w, r, actor) {
		return
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	id := parts[len(parts)-1]
	tok, err := s.Store.GetAPIToken(id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	if tok.UserID != actor.User.ID && !rbac.CanManageOwners(actor.User.Role) {
		writeErr(w, http.StatusForbidden, "forbidden")
		return
	}
	if err := s.Store.RevokeAPIToken(id); err != nil {
		writeErr(w, http.StatusInternalServerError, "revoke")
		return
	}
	s.audit(actor, r, "tokens.revoke", id, "")
	writeJSON(w, http.StatusOK, map[string]string{"ok": "1"})
}
