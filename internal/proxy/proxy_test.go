// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package proxy_test

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Quad4-Software/ravenguard/internal/proxy"
	"github.com/Quad4-Software/ravenguard/internal/tlscerts"
)

func TestParseUnixURL(t *testing.T) {
	u, err := proxy.ParseUpstreamURL("unix:///tmp/app.sock")
	if err != nil {
		t.Fatal(err)
	}
	if !proxy.IsUnix(u) {
		t.Fatal("expected unix")
	}
	if proxy.UnixPath(u) != "/tmp/app.sock" {
		t.Fatalf("path=%q", proxy.UnixPath(u))
	}
}

func TestNormalizeUpstreamSchemes(t *testing.T) {
	cases := []struct {
		raw        string
		wantScheme string
		wantHost   string
	}{
		{"ws://127.0.0.1:8000/socket", "http", "127.0.0.1:8000"},
		{"wss://origin.example:9443", "https", "origin.example:9443"},
		{"https://origin.example", "https", "origin.example"},
		{"http://127.0.0.1:8000", "http", "127.0.0.1:8000"},
		{"h3://origin.example", "https", "origin.example"},
	}
	for _, tc := range cases {
		u, err := proxy.ParseUpstreamURL(tc.raw)
		if err != nil {
			t.Fatalf("%s: parse: %v", tc.raw, err)
		}
		n := proxy.NormalizeTarget(u)
		if n.Scheme != tc.wantScheme {
			t.Fatalf("%s: scheme=%q want %q", tc.raw, n.Scheme, tc.wantScheme)
		}
		if n.Host != tc.wantHost {
			t.Fatalf("%s: host=%q want %q", tc.raw, n.Host, tc.wantHost)
		}
	}
}

func TestUnixDial(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "app.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	defer os.Remove(sock)

	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 8)
		_, _ = c.Read(buf)
		_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"))
	}()

	u, _ := proxy.ParseUpstreamURL("unix://" + sock)
	dial := proxy.DialFunc(u, time.Second)
	conn, err := dial(context.Background(), "tcp", "ignored")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	rp := proxy.New(proxy.Config{
		Target:         u,
		ConnectTimeout: time.Second,
		MaxIdleConns:   2,
	})
	srv := &http.Server{Handler: rp, ReadHeaderTimeout: 5 * time.Second}
	if srv.Handler == nil {
		t.Fatal("expected handler")
	}
}

func newHTTP2Server(h http.Handler) *httptest.Server {
	s := httptest.NewUnstartedServer(h)
	s.EnableHTTP2 = true
	s.StartTLS()
	return s
}

func newHTTP11TLSServer(h http.Handler) *httptest.Server {
	s := httptest.NewUnstartedServer(h)
	s.TLS = &tls.Config{NextProtos: []string{"http/1.1"}}
	s.StartTLS()
	return s
}

func newH2AndH1TLSServer(h http.Handler) *httptest.Server {
	s := httptest.NewUnstartedServer(h)
	s.EnableHTTP2 = true
	s.TLS = &tls.Config{NextProtos: []string{"h2", "http/1.1"}}
	s.StartTLS()
	return s
}

func TestReverseProxyHTTP2Default(t *testing.T) {
	var got http.Request
	backend := newHTTP2Server(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = *r
		w.Header().Set("X-Proto", r.Proto)
		w.Write([]byte("ok"))
	}))
	defer backend.Close()

	target, _ := url.Parse(backend.URL)
	rp := proxy.New(proxy.Config{
		Target:          target,
		Protocol:        "h2",
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	})
	defer rp.Close()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://edge.example/path", nil)
	req.Host = "edge.example"
	rp.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if rec.Body.String() != "ok" {
		t.Fatalf("body=%q", rec.Body.String())
	}
	if got.Header.Get("X-Forwarded-Host") != "edge.example" {
		t.Fatalf("X-Forwarded-Host=%q", got.Header.Get("X-Forwarded-Host"))
	}
	if got.ProtoMajor < 2 {
		t.Fatalf("expected HTTP/2, got proto %s", got.Proto)
	}
}

func TestReverseProxyHTTP2NoHTTP1Fallback(t *testing.T) {
	// A server that only offers http/1.1 ALPN should fail when h2 is
	// requested without the allow_http1 fallback.
	backend := newHTTP11TLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer backend.Close()

	target, _ := url.Parse(backend.URL)
	rp := proxy.New(proxy.Config{
		Target:          target,
		Protocol:        "h2",
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	})
	defer rp.Close()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://edge.example/path", nil)
	rp.ServeHTTP(rec, req)

	if rec.Code == http.StatusOK {
		t.Fatal("expected HTTP/2-only upstream to fail against h1-only server")
	}
}

func TestReverseProxyHTTP2AllowHTTP1(t *testing.T) {
	backend := newHTTP11TLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer backend.Close()

	target, _ := url.Parse(backend.URL)
	rp := proxy.New(proxy.Config{
		Target:          target,
		Protocol:        "h2",
		AllowHTTP1:      true,
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	})
	defer rp.Close()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://edge.example/path", nil)
	rp.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestReverseProxyIgnoresProxyEnvironment(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://10.255.255.1:1")
	t.Setenv("HTTPS_PROXY", "http://10.255.255.1:1")

	var called atomic.Bool
	backend := newHTTP2Server(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called.Store(true)
		w.Write([]byte("ok"))
	}))
	defer backend.Close()

	target, _ := url.Parse(backend.URL)
	rp := proxy.New(proxy.Config{
		Target:          target,
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	})
	defer rp.Close()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://edge.example/path", nil)
	rp.ServeHTTP(rec, req)

	if !called.Load() {
		t.Fatal("upstream was not reached; HTTP_PROXY may have been honored")
	}
}

func TestReverseProxyMaxConnsPerHost(t *testing.T) {
	backend := newHTTP2Server(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer backend.Close()

	target, _ := url.Parse(backend.URL)
	rp := proxy.New(proxy.Config{
		Target:          target,
		MaxConnsPerHost: 1,
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	})
	defer rp.Close()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://edge.example/path", nil)
	rp.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}
}

func TestReverseProxyWebSocketUsesHTTP1(t *testing.T) {
	var gotProto, gotUpgrade string
	backend := newH2AndH1TLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotProto = r.Proto
		gotUpgrade = r.Header.Get("Upgrade")
		// Return 200 instead of 101 so we do not need a hijackable
		// ResponseWriter in the test; the h1 transport will still be
		// selected because of the Upgrade header.
		w.Write([]byte("ok"))
	}))
	defer backend.Close()

	target, _ := url.Parse(backend.URL)
	rp := proxy.New(proxy.Config{
		Target:          target,
		Protocol:        "h2",
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	})
	defer rp.Close()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://edge.example/ws", nil)
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	req.Header.Set("Sec-WebSocket-Version", "13")
	rp.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.HasPrefix(gotProto, "HTTP/1.1") {
		t.Fatalf("expected HTTP/1.1, got %q", gotProto)
	}
	if gotUpgrade != "websocket" {
		t.Fatalf("expected Upgrade: websocket, got %q", gotUpgrade)
	}
}

func TestReverseProxyProtocolHTTP11Only(t *testing.T) {
	var gotProto string
	backend := newHTTP11TLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotProto = r.Proto
		w.Write([]byte("ok"))
	}))
	defer backend.Close()

	target, _ := url.Parse(backend.URL)
	rp := proxy.New(proxy.Config{
		Target:          target,
		Protocol:        "http1.1",
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	})
	defer rp.Close()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://edge.example/path", nil)
	rp.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}
	if !strings.HasPrefix(gotProto, "HTTP/1.1") && gotProto != "HTTP/1.1" {
		t.Fatalf("got proto %q, want HTTP/1.1", gotProto)
	}
}

func TestReverseProxyStripPrefix(t *testing.T) {
	var gotPath string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Write([]byte("ok"))
	}))
	defer backend.Close()

	target, _ := url.Parse(backend.URL)
	rp := proxy.New(proxy.Config{
		Target:      target,
		Protocol:    "http1.1",
		StripPrefix: "/api",
	})
	defer rp.Close()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://edge.example/api/v1/x", nil)
	rp.ServeHTTP(rec, req)

	if gotPath != "/v1/x" {
		t.Fatalf("path=%q", gotPath)
	}
}

func TestReverseProxyCloseReleasesConnections(t *testing.T) {
	backend := newHTTP2Server(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer backend.Close()

	target, _ := url.Parse(backend.URL)
	rp := proxy.New(proxy.Config{
		Target:          target,
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://edge.example/", nil)
	rp.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}

	if err := rp.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}

func TestBuildTLSClientConfig(t *testing.T) {
	// Verify the helper correctly reports a missing CA file.
	if _, err := proxy.BuildTLSClientConfig("/nonexistent/ca.pem", "", "", false); err == nil {
		t.Fatal("expected error for missing CA file")
	}

	// Generate a self-signed cert and use it as a CA.
	certPEM, keyPEM, err := generateSelfSignedCert("localhost")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.pem")
	keyPath := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(caPath, certPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := proxy.BuildTLSClientConfig(caPath, caPath, keyPath, false)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.RootCAs == nil || len(cfg.Certificates) != 1 {
		t.Fatal("expected root CA and client cert")
	}

	cfgInsecure, err := proxy.BuildTLSClientConfig("", "", "", true)
	if err != nil {
		t.Fatal(err)
	}
	if !cfgInsecure.InsecureSkipVerify {
		t.Fatal("expected InsecureSkipVerify")
	}
}

func generateSelfSignedCert(host string) (certPEM, keyPEM []byte, err error) {
	return tlscerts.Generate(tlscerts.GenerateOptions{Hosts: []string{host}})
}
