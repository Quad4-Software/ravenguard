// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package api_test

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Quad4-Software/ravenguard/internal/admin/api"
	"github.com/Quad4-Software/ravenguard/internal/admin/auth"
	"github.com/Quad4-Software/ravenguard/internal/admin/ops"
	"github.com/Quad4-Software/ravenguard/internal/admin/store"
	"github.com/Quad4-Software/ravenguard/internal/blocklist"
	"github.com/Quad4-Software/ravenguard/internal/config"
	"github.com/Quad4-Software/ravenguard/internal/protect"
)

func TestLoginStatusBanAudit(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "data"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	hash, _ := auth.HashPassword("bootstrap-pass-1")
	if _, err := st.BootstrapOwner("owner", hash); err != nil {
		t.Fatal(err)
	}

	prot := protect.New(protect.Config{Enabled: true, BanAfterStrikes: 3, BanTTL: time.Minute})
	lists := blocklist.New()
	rt := ops.NewRuntime(config.Default(), prot, lists, nil, nil, nil, nil)
	srv := &api.Server{
		Store:   st,
		Runtime: rt,
		Admin: config.AdminConfig{
			BasePath:   "/",
			SessionTTL: config.Duration{Duration: time.Hour},
		},
		Lockout: auth.NewLockout(),
	}
	mux := http.NewServeMux()
	srv.Mount(mux, "/")

	loginBody, _ := json.Marshal(map[string]string{"username": "owner", "password": "bootstrap-pass-1"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(loginBody))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("login %d %s", rec.Code, rec.Body.String())
	}
	var loginResp struct {
		CSRFToken string `json:"csrf_token"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &loginResp)
	var sessionCookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == "rg_admin_session" {
			sessionCookie = c
		}
	}
	if sessionCookie == nil || loginResp.CSRFToken == "" {
		t.Fatal("missing session or csrf")
	}

	statusReq := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	statusReq.AddCookie(sessionCookie)
	statusRec := httptest.NewRecorder()
	mux.ServeHTTP(statusRec, statusReq)
	if statusRec.Code != http.StatusOK {
		t.Fatalf("status %d", statusRec.Code)
	}

	banBody, _ := json.Marshal(map[string]string{"key": "client-abc"})
	banReq := httptest.NewRequest(http.MethodPost, "/api/v1/bans", bytes.NewReader(banBody))
	banReq.AddCookie(sessionCookie)
	banReq.Header.Set("X-CSRF-Token", loginResp.CSRFToken)
	banRec := httptest.NewRecorder()
	mux.ServeHTTP(banRec, banReq)
	if banRec.Code != http.StatusOK {
		t.Fatalf("ban %d %s", banRec.Code, banRec.Body.String())
	}
	if !prot.Banned("client-abc") {
		t.Fatal("expected ban")
	}

	auditReq := httptest.NewRequest(http.MethodGet, "/api/v1/audit", nil)
	auditReq.AddCookie(sessionCookie)
	auditRec := httptest.NewRecorder()
	mux.ServeHTTP(auditRec, auditReq)
	if auditRec.Code != http.StatusOK {
		t.Fatalf("audit %d", auditRec.Code)
	}
	var audit struct {
		Events []map[string]any `json:"events"`
	}
	_ = json.Unmarshal(auditRec.Body.Bytes(), &audit)
	if len(audit.Events) == 0 {
		t.Fatal("expected audit events")
	}
}

func TestCSRFRejection(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "data"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	hash, _ := auth.HashPassword("bootstrap-pass-1")
	_, _ = st.BootstrapOwner("owner", hash)
	prot := protect.New(protect.Config{Enabled: true, BanTTL: time.Minute})
	rt := ops.NewRuntime(config.Default(), prot, blocklist.New(), nil, nil, nil, nil)
	srv := &api.Server{
		Store: st, Runtime: rt,
		Admin:   config.AdminConfig{BasePath: "/", SessionTTL: config.Duration{Duration: time.Hour}},
		Lockout: auth.NewLockout(),
	}
	mux := http.NewServeMux()
	srv.Mount(mux, "/")

	loginBody, _ := json.Marshal(map[string]string{"username": "owner", "password": "bootstrap-pass-1"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(loginBody))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	var cookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == "rg_admin_session" {
			cookie = c
		}
	}

	banBody, _ := json.Marshal(map[string]string{"key": "x"})
	banReq := httptest.NewRequest(http.MethodPost, "/api/v1/bans", bytes.NewReader(banBody))
	banReq.AddCookie(cookie)
	banRec := httptest.NewRecorder()
	mux.ServeHTTP(banRec, banReq)
	if banRec.Code != http.StatusForbidden {
		t.Fatalf("want csrf forbid got %d", banRec.Code)
	}
}

func TestSessionRefresh(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "data"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	hash, _ := auth.HashPassword("bootstrap-pass-1")
	_, _ = st.BootstrapOwner("owner", hash)
	prot := protect.New(protect.Config{Enabled: true, BanTTL: time.Minute})
	rt := ops.NewRuntime(config.Default(), prot, blocklist.New(), nil, nil, nil, nil)
	srv := &api.Server{
		Store: st, Runtime: rt,
		Admin:   config.AdminConfig{BasePath: "/", SessionTTL: config.Duration{Duration: time.Hour}},
		Lockout: auth.NewLockout(),
	}
	mux := http.NewServeMux()
	srv.Mount(mux, "/")

	loginBody, _ := json.Marshal(map[string]string{"username": "owner", "password": "bootstrap-pass-1"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(loginBody))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("login %d", rec.Code)
	}
	var loginResp struct {
		CSRFToken string `json:"csrf_token"`
		ExpiresAt string `json:"expires_at"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &loginResp)
	var cookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == "rg_admin_session" {
			cookie = c
		}
	}
	if cookie == nil || loginResp.CSRFToken == "" || loginResp.ExpiresAt == "" {
		t.Fatal("missing session csrf or expires_at")
	}
	if cookie.MaxAge <= 0 {
		t.Fatalf("expected MaxAge on login cookie got %d", cookie.MaxAge)
	}

	refreshReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", nil)
	refreshReq.AddCookie(cookie)
	refreshReq.Header.Set("X-CSRF-Token", loginResp.CSRFToken)
	refreshRec := httptest.NewRecorder()
	mux.ServeHTTP(refreshRec, refreshReq)
	if refreshRec.Code != http.StatusOK {
		t.Fatalf("refresh %d %s", refreshRec.Code, refreshRec.Body.String())
	}
	var refreshResp struct {
		CSRFToken string `json:"csrf_token"`
		ExpiresAt string `json:"expires_at"`
	}
	_ = json.Unmarshal(refreshRec.Body.Bytes(), &refreshResp)
	if refreshResp.CSRFToken == "" || refreshResp.CSRFToken == loginResp.CSRFToken {
		t.Fatal("expected rotated csrf on refresh")
	}
	var refreshedCookie *http.Cookie
	for _, c := range refreshRec.Result().Cookies() {
		if c.Name == "rg_admin_session" {
			refreshedCookie = c
		}
	}
	if refreshedCookie == nil || refreshedCookie.Value != cookie.Value {
		t.Fatal("expected same session cookie value after refresh")
	}

	meReq := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	meReq.AddCookie(cookie)
	meRec := httptest.NewRecorder()
	mux.ServeHTTP(meRec, meReq)
	if meRec.Code != http.StatusOK {
		t.Fatalf("me %d", meRec.Code)
	}
	var meResp struct {
		CSRFToken string `json:"csrf_token"`
		ExpiresAt string `json:"expires_at"`
	}
	_ = json.Unmarshal(meRec.Body.Bytes(), &meResp)
	if meResp.CSRFToken != refreshResp.CSRFToken {
		t.Fatalf("me csrf=%s want %s", meResp.CSRFToken, refreshResp.CSRFToken)
	}
	if meResp.ExpiresAt == "" {
		t.Fatal("expected expires_at on me")
	}

	badRefresh := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", nil)
	badRefresh.AddCookie(cookie)
	badRefresh.Header.Set("X-CSRF-Token", loginResp.CSRFToken)
	badRec := httptest.NewRecorder()
	mux.ServeHTTP(badRec, badRefresh)
	if badRec.Code != http.StatusForbidden {
		t.Fatalf("want csrf forbid after rotate got %d", badRec.Code)
	}
}

func TestSessionListAndRevoke(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "data"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	hash, _ := auth.HashPassword("bootstrap-pass-1")
	owner, err := st.BootstrapOwner("owner", hash)
	if err != nil {
		t.Fatal(err)
	}
	prot := protect.New(protect.Config{Enabled: true, BanTTL: time.Minute})
	rt := ops.NewRuntime(config.Default(), prot, blocklist.New(), nil, nil, nil, nil)
	srv := &api.Server{
		Store: st, Runtime: rt,
		Admin:   config.AdminConfig{BasePath: "/", SessionTTL: config.Duration{Duration: time.Hour}},
		Lockout: auth.NewLockout(),
	}
	mux := http.NewServeMux()
	srv.Mount(mux, "/")

	login := func(ua string) (cookie *http.Cookie, csrf string) {
		t.Helper()
		body, _ := json.Marshal(map[string]string{"username": "owner", "password": "bootstrap-pass-1"})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(body))
		req.Header.Set("User-Agent", ua)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("login %d", rec.Code)
		}
		var resp struct {
			CSRFToken string `json:"csrf_token"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &resp)
		for _, c := range rec.Result().Cookies() {
			if c.Name == "rg_admin_session" {
				cookie = c
			}
		}
		if cookie == nil || resp.CSRFToken == "" {
			t.Fatal("missing session")
		}
		return cookie, resp.CSRFToken
	}

	cookieA, csrfA := login("ua-a")
	cookieB, _ := login("ua-b")

	listReq := httptest.NewRequest(http.MethodGet, "/api/v1/auth/sessions", nil)
	listReq.AddCookie(cookieA)
	listRec := httptest.NewRecorder()
	mux.ServeHTTP(listRec, listReq)
	if listRec.Code != http.StatusOK {
		t.Fatalf("list %d %s", listRec.Code, listRec.Body.String())
	}
	var listResp struct {
		Sessions []struct {
			ID      string `json:"id"`
			Current bool   `json:"current"`
		} `json:"sessions"`
	}
	_ = json.Unmarshal(listRec.Body.Bytes(), &listResp)
	if len(listResp.Sessions) != 2 {
		t.Fatalf("want 2 sessions got %d", len(listResp.Sessions))
	}
	var otherID string
	currentCount := 0
	for _, sess := range listResp.Sessions {
		if sess.Current {
			currentCount++
		} else {
			otherID = sess.ID
		}
	}
	if currentCount != 1 || otherID == "" {
		t.Fatalf("current=%d other=%q", currentCount, otherID)
	}

	revOther := httptest.NewRequest(http.MethodDelete, "/api/v1/auth/sessions/"+otherID, nil)
	revOther.AddCookie(cookieA)
	revOther.Header.Set("X-CSRF-Token", csrfA)
	revOtherRec := httptest.NewRecorder()
	mux.ServeHTTP(revOtherRec, revOther)
	if revOtherRec.Code != http.StatusOK {
		t.Fatalf("revoke other %d %s", revOtherRec.Code, revOtherRec.Body.String())
	}
	var revOtherResp struct {
		SignedOut bool `json:"signed_out"`
	}
	_ = json.Unmarshal(revOtherRec.Body.Bytes(), &revOtherResp)
	if revOtherResp.SignedOut {
		t.Fatal("revoking other should keep current signed in")
	}

	meB := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	meB.AddCookie(cookieB)
	meBRec := httptest.NewRecorder()
	mux.ServeHTTP(meBRec, meB)
	if meBRec.Code != http.StatusUnauthorized {
		t.Fatalf("revoked session me want 401 got %d", meBRec.Code)
	}

	_, rawKeep, _, _, err := st.CreateSession(owner.ID, time.Hour, "127.0.0.1", "keep")
	if err != nil {
		t.Fatal(err)
	}
	_ = rawKeep

	revAll := httptest.NewRequest(http.MethodDelete, "/api/v1/auth/sessions", nil)
	revAll.AddCookie(cookieA)
	revAll.Header.Set("X-CSRF-Token", csrfA)
	revAllRec := httptest.NewRecorder()
	mux.ServeHTTP(revAllRec, revAll)
	if revAllRec.Code != http.StatusOK {
		t.Fatalf("revoke all %d %s", revAllRec.Code, revAllRec.Body.String())
	}
	var revAllResp struct {
		SignedOut bool `json:"signed_out"`
	}
	_ = json.Unmarshal(revAllRec.Body.Bytes(), &revAllResp)
	if !revAllResp.SignedOut {
		t.Fatal("revoke all should sign out")
	}

	meA := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	meA.AddCookie(cookieA)
	meARec := httptest.NewRecorder()
	mux.ServeHTTP(meARec, meA)
	if meARec.Code != http.StatusUnauthorized {
		t.Fatalf("after revoke all me want 401 got %d", meARec.Code)
	}
}

var png1x1 = []byte{
	0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a,
	0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52,
	0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
	0x08, 0x06, 0x00, 0x00, 0x00, 0x1f, 0x15, 0xc4,
	0x89, 0x00, 0x00, 0x00, 0x0a, 0x49, 0x44, 0x41, 0x54,
	0x78, 0x9c, 0x63, 0x00, 0x01, 0x00, 0x00, 0x05, 0x00, 0x01,
	0x0d, 0x0a, 0x2d, 0xb4, 0x00, 0x00, 0x00, 0x00,
	0x49, 0x45, 0x4e, 0x44, 0xae, 0x42, 0x60, 0x82,
}

func TestAppearanceUploadAndPreview(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "data"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	hash, _ := auth.HashPassword("bootstrap-pass-1")
	if _, err := st.BootstrapOwner("owner", hash); err != nil {
		t.Fatal(err)
	}
	rt := ops.NewRuntime(config.Default(), nil, blocklist.New(), nil, nil, nil, nil)
	srv := &api.Server{
		Store:   st,
		Runtime: rt,
		Admin: config.AdminConfig{
			BasePath:   "/",
			DataDir:    dir,
			SessionTTL: config.Duration{Duration: time.Hour},
		},
		Lockout: auth.NewLockout(),
	}
	mux := http.NewServeMux()
	srv.Mount(mux, "/")

	loginBody, _ := json.Marshal(map[string]string{"username": "owner", "password": "bootstrap-pass-1"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(loginBody))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	var loginResp struct {
		CSRFToken string `json:"csrf_token"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &loginResp)
	var sessionCookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == "rg_admin_session" {
			sessionCookie = c
		}
	}
	if sessionCookie == nil || loginResp.CSRFToken == "" {
		t.Fatal("missing session or csrf")
	}

	previewBody, _ := json.Marshal(map[string]any{
		"ui": map[string]string{"brand": "PreviewCo", "status_text": "Hold on"},
	})
	previewReq := httptest.NewRequest(http.MethodPost, "/api/v1/appearance/preview?page=block", bytes.NewReader(previewBody))
	previewReq.AddCookie(sessionCookie)
	previewReq.Header.Set("X-CSRF-Token", loginResp.CSRFToken)
	previewRec := httptest.NewRecorder()
	mux.ServeHTTP(previewRec, previewReq)
	if previewRec.Code != http.StatusOK {
		t.Fatalf("preview %d %s", previewRec.Code, previewRec.Body.String())
	}
	if ct := previewRec.Header().Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Fatalf("preview content-type %s", ct)
	}
	if !strings.Contains(previewRec.Body.String(), "PreviewCo") {
		t.Fatalf("preview missing brand: %s", previewRec.Body.String())
	}

	buf, ctype := multipartPNG(t, "logo.png", "logo", png1x1)
	upReq := httptest.NewRequest(http.MethodPost, "/api/v1/appearance/assets?kind=logo", buf)
	upReq.AddCookie(sessionCookie)
	upReq.Header.Set("X-CSRF-Token", loginResp.CSRFToken)
	upReq.Header.Set("Content-Type", ctype)
	upRec := httptest.NewRecorder()
	mux.ServeHTTP(upRec, upReq)
	if upRec.Code != http.StatusOK {
		t.Fatalf("upload %d %s", upRec.Code, upRec.Body.String())
	}
	var upResp struct {
		URL string `json:"url"`
	}
	_ = json.Unmarshal(upRec.Body.Bytes(), &upResp)
	if upResp.URL != "/api/v1/appearance/assets/logo" {
		t.Fatalf("upload url %s", upResp.URL)
	}
	if rt.Config().UI.LogoURL != upResp.URL {
		t.Fatalf("runtime logo_url %s", rt.Config().UI.LogoURL)
	}

	getReq := httptest.NewRequest(http.MethodGet, upResp.URL, nil)
	getReq.AddCookie(sessionCookie)
	getRec := httptest.NewRecorder()
	mux.ServeHTTP(getRec, getReq)
	if getRec.Code != http.StatusOK {
		t.Fatalf("get asset %d %s", getRec.Code, getRec.Body.String())
	}
	if getRec.Header().Get("Content-Type") != "image/png" {
		t.Fatalf("asset content-type %s", getRec.Header().Get("Content-Type"))
	}
	if !bytes.Equal(getRec.Body.Bytes(), png1x1) {
		t.Fatal("asset bytes mismatch")
	}

	badBuf, badType := multipartPNG(t, "note.txt", "logo", []byte("not-an-image"))
	badReq := httptest.NewRequest(http.MethodPost, "/api/v1/appearance/assets?kind=logo", badBuf)
	badReq.AddCookie(sessionCookie)
	badReq.Header.Set("X-CSRF-Token", loginResp.CSRFToken)
	badReq.Header.Set("Content-Type", badType)
	badRec := httptest.NewRecorder()
	mux.ServeHTTP(badRec, badReq)
	if badRec.Code != http.StatusBadRequest {
		t.Fatalf("want reject unsupported type got %d %s", badRec.Code, badRec.Body.String())
	}
}

func multipartPNG(t *testing.T, filename, kind string, data []byte) (*bytes.Buffer, string) {
	t.Helper()
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	if err := w.WriteField("kind", kind); err != nil {
		t.Fatal(err)
	}
	fw, err := w.CreateFormFile("file", filename)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return &buf, w.FormDataContentType()
}
