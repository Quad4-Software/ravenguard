// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package ui

import (
	"embed"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strconv"
	"strings"
)

//go:embed all:dist
var distFS embed.FS

func Handler(basePath string) http.Handler {
	sub, err := fs.Sub(distFS, "dist")
	if err != nil {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "admin ui missing", http.StatusServiceUnavailable)
		})
	}
	base := strings.TrimSuffix(basePath, "/")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		p := r.URL.Path
		if base != "" && base != "/" {
			p = strings.TrimPrefix(p, base)
		}
		if p == "" {
			p = "/"
		}
		if strings.HasPrefix(p, "/api/") {
			http.NotFound(w, r)
			return
		}
		rel := strings.TrimPrefix(path.Clean(p), "/")
		if rel == "." || rel == "" {
			rel = "index.html"
		}
		if serveAsset(w, r, sub, rel) {
			return
		}
		// SPA fallback for client routes
		_ = serveAsset(w, r, sub, "index.html")
	})
}

func serveAsset(w http.ResponseWriter, r *http.Request, sub fs.FS, rel string) bool {
	f, err := sub.Open(rel)
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if err != nil || st.IsDir() {
		return false
	}
	ctype := mime.TypeByExtension(path.Ext(rel))
	if ctype == "" {
		ctype = "application/octet-stream"
	}
	if strings.HasSuffix(rel, ".html") {
		w.Header().Set("Cache-Control", "no-store")
	} else if strings.HasPrefix(rel, "_app/") {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	}
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("Content-Length", strconv.FormatInt(st.Size(), 10))
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return true
	}
	w.WriteHeader(http.StatusOK)
	_, _ = io.Copy(w, f)
	return true
}
