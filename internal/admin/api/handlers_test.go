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
