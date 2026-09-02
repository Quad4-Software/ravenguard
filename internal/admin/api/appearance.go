// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"

	"github.com/Quad4-Software/ravenguard/internal/admin/ops"
	"github.com/Quad4-Software/ravenguard/internal/admin/rbac"
	"github.com/Quad4-Software/ravenguard/internal/ui"
)

const maxAppearanceBytes = 512 << 10

var appearanceExtMIME = map[string]string{
	".png":  "image/png",
	".jpg":  "image/jpeg",
	".jpeg": "image/jpeg",
	".webp": "image/webp",
	".ico":  "image/x-icon",
	".svg":  "image/svg+xml",
}

func (s *Server) handleAppearanceAssets(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method")
		return
	}
	actor := actorFrom(r)
	if !rbac.CanWriteConfig(actor.User.Role) {
		writeErr(w, http.StatusForbidden, "forbidden")
		return
	}
	if !s.checkCSRF(w, r, actor) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxAppearanceBytes+64<<10)
	if err := r.ParseMultipartForm(maxAppearanceBytes + 32<<10); err != nil {
		writeErr(w, http.StatusBadRequest, "file too large")
		return
	}
	kind := appearanceKind(r.URL.Query().Get("kind"))
	if kind == "" {
		kind = appearanceKind(r.FormValue("kind"))
	}
	if kind == "" {
		writeErr(w, http.StatusBadRequest, "kind must be logo or favicon")
		return
	}
	f, hdr, err := r.FormFile("file")
	if err != nil {
		writeErr(w, http.StatusBadRequest, "file required")
		return
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, maxAppearanceBytes+1))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "read failed")
		return
	}
	if len(data) == 0 {
		writeErr(w, http.StatusBadRequest, "empty file")
		return
	}
	if len(data) > maxAppearanceBytes {
		writeErr(w, http.StatusRequestEntityTooLarge, "file too large")
		return
	}
	ext, _, ok := sniffAppearance(data)
	if !ok {
		writeErr(w, http.StatusBadRequest, "unsupported image type")
		return
	}
	if _, err := s.replaceAppearanceFile(kind, ext, data); err != nil {
		writeErr(w, http.StatusInternalServerError, "save failed")
		return
	}
	assetURL := s.appearanceAssetURL(kind)
	s.persistAppearanceURL(actor.User.ID, kind, assetURL)
	filename := ""
	if hdr != nil {
		filename = hdr.Filename
	}
	s.audit(actor, r, "appearance.upload", kind, filename)
	writeJSON(w, http.StatusOK, map[string]string{"url": assetURL})
}

func (s *Server) handleAppearanceAssetFile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeErr(w, http.StatusMethodNotAllowed, "method")
		return
	}
	kind := appearanceKind(pathID(r, "assets"))
	if kind == "" {
		writeErr(w, http.StatusBadRequest, "kind must be logo or favicon")
		return
	}
	path, mimeType, err := s.findAppearanceFile(kind)
	if err != nil || path == "" {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	w.Header().Set("Content-Type", mimeType)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write(data)
	}
}

func (s *Server) handleAppearancePreview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method")
		return
	}
	actor := actorFrom(r)
	if !s.checkCSRF(w, r, actor) {
		return
	}
	if s.Runtime == nil {
		writeErr(w, http.StatusServiceUnavailable, "runtime unavailable")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	cfg := s.Runtime.Config()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	body = bytes.TrimSpace(body)
	if len(body) > 0 {
		var draft ops.SafeConfig
		if err := json.Unmarshal(body, &draft); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid json")
			return
		}
		cfg = ops.OverlaySafe(cfg, draft)
	}
	pages, err := ui.New(ui.SiteFromConfig(cfg))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "preview render")
		return
	}
	page := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("page")))
	if page == "" {
		page = "challenge"
	}
	rec := httptest.NewRecorder()
	switch page {
	case "challenge":
		pages.ServeChallenge(rec, ui.Data{
			RayID:          "preview",
			ChallengeURL:   "#",
			Token:          "preview",
			Difficulty:     cfg.Challenge.Difficulty,
			CaptchaEnabled: cfg.Challenge.Captcha.Enabled,
			StatusText:     cfg.UI.StatusText,
		})
	case "block":
		pages.RenderBlock(rec, "preview", "Access denied")
	case "ratelimit":
		pages.RenderRateLimit(rec, "preview")
	case "upstream":
		pages.RenderUpstream(rec, "preview")
	case "error":
		pages.RenderError(rec, "preview", "", "Something went wrong", http.StatusInternalServerError)
	case "access":
		pages.ServeAccessForm(rec, "password", "#")
	default:
		writeErr(w, http.StatusBadRequest, "unknown page")
		return
	}
	if rec.Code >= 500 && rec.Body.Len() == 0 {
		writeErr(w, http.StatusInternalServerError, "preview render")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(rec.Body.Bytes())
}

func appearanceKind(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "logo":
		return "logo"
	case "favicon":
		return "favicon"
	default:
		return ""
	}
}

func (s *Server) appearanceDir() string {
	return filepath.Join(s.Admin.DataDir, "appearance")
}

func (s *Server) appearanceAssetURL(kind string) string {
	base := strings.TrimSuffix(s.Admin.BasePath, "/")
	return base + "/api/v1/appearance/assets/" + kind
}

func (s *Server) replaceAppearanceFile(kind, ext string, data []byte) (string, error) {
	kind = appearanceKind(kind)
	if kind == "" {
		return "", os.ErrInvalid
	}
	ext = strings.ToLower(filepath.Ext(filepath.Base(ext)))
	if _, ok := appearanceExtMIME[ext]; !ok {
		return "", os.ErrInvalid
	}
	dir := s.appearanceDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", err
	}
	prefix := kind + "."
	for _, e := range entries {
		name := filepath.Base(e.Name())
		if strings.HasPrefix(name, prefix) {
			_ = os.Remove(filepath.Join(dir, name))
		}
	}
	dest := filepath.Join(dir, filepath.Base(kind+ext))
	if err := os.WriteFile(dest, data, 0o600); err != nil {
		return "", err
	}
	return dest, nil
}

func (s *Server) findAppearanceFile(kind string) (string, string, error) {
	kind = appearanceKind(kind)
	if kind == "" {
		return "", "", os.ErrInvalid
	}
	dir := s.appearanceDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", "", err
	}
	prefix := kind + "."
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := filepath.Base(e.Name())
		if !strings.HasPrefix(name, prefix) {
			continue
		}
		ext := strings.ToLower(filepath.Ext(name))
		mimeType, ok := appearanceExtMIME[ext]
		if !ok {
			continue
		}
		return filepath.Join(dir, name), mimeType, nil
	}
	return "", "", os.ErrNotExist
}

func (s *Server) persistAppearanceURL(userID int64, kind, assetURL string) {
	if s.Runtime == nil {
		return
	}
	cfg := s.Runtime.Config()
	if kind == "logo" {
		cfg.UI.LogoURL = assetURL
	} else {
		cfg.UI.FaviconURL = assetURL
	}
	s.Runtime.ReplaceConfig(cfg)
	if s.Runtime.Pipeline != nil {
		s.Runtime.Pipeline.ApplyConfig(cfg)
	}
	if s.Pages != nil {
		s.Pages.UpdateSite(ui.SiteFromConfig(cfg))
	}
	if s.Store == nil {
		return
	}
	existing, _ := s.Store.GetConfigOverrides()
	if existing == "" || existing == "{}" {
		existing, _ = ops.EncodeSafeConfig(s.Runtime.ConfigView().Live)
	}
	payload, err := ops.MergeAndEncode(existing, func(sc *ops.SafeConfig) {
		if kind == "logo" {
			sc.UI.LogoURL = assetURL
		} else {
			sc.UI.FaviconURL = assetURL
		}
	})
	if err == nil {
		_ = s.Store.SetConfigOverrides(payload, userID)
	}
}

func sniffAppearance(data []byte) (ext, mimeType string, ok bool) {
	switch {
	case bytes.HasPrefix(data, []byte("\x89PNG\r\n\x1a\n")):
		return ".png", "image/png", true
	case bytes.HasPrefix(data, []byte{0xff, 0xd8, 0xff}):
		return ".jpg", "image/jpeg", true
	case len(data) >= 12 && bytes.Equal(data[:4], []byte("RIFF")) && bytes.Equal(data[8:12], []byte("WEBP")):
		return ".webp", "image/webp", true
	case len(data) >= 4 && data[0] == 0 && data[1] == 0 && (data[2] == 1 || data[2] == 2) && data[3] == 0:
		return ".ico", "image/x-icon", true
	case svgLooksLike(data):
		return ".svg", "image/svg+xml", true
	}
	return "", "", false
}

func svgLooksLike(data []byte) bool {
	s := strings.TrimSpace(string(data))
	lower := strings.ToLower(s)
	if strings.HasPrefix(lower, "<?xml") {
		return strings.Contains(lower, "<svg")
	}
	return strings.HasPrefix(lower, "<svg")
}
