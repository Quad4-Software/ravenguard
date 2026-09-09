// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package proxy_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Quad4-Software/ravenguard/internal/proxy"
	"github.com/Quad4-Software/ravenguard/internal/tlscerts"
)

// parseUpstreamURLRef is an independent oracle that replicates the expected
// behaviour of ParseUpstreamURL for the special schemes and falls back to
// net/url.Parse for everything else.
func parseUpstreamURLRef(raw string) (*url.URL, error) {
	if after, ok := strings.CutPrefix(raw, "unix://"); ok {
		return &url.URL{Scheme: "unix", Path: after}, nil
	}
	if after, ok := strings.CutPrefix(raw, "unix:"); ok {
		return &url.URL{Scheme: "unix", Path: after}, nil
	}
	if after, ok := strings.CutPrefix(raw, "tunnel://"); ok {
		after = strings.TrimSpace(after)
		connectorID, upstreamID, cutOK := strings.Cut(after, "/")
		if !cutOK || connectorID == "" || upstreamID == "" {
			return nil, &url.Error{Op: "parse", URL: raw, Err: errors.New("tunnel:// requires connector_id/upstream_id")}
		}
		return &url.URL{Scheme: "tunnel", Host: connectorID, Path: "/" + upstreamID}, nil
	}
	if after, ok := strings.CutPrefix(raw, "h3://"); ok {
		return &url.URL{Scheme: "h3", Host: after}, nil
	}
	return url.Parse(raw)
}

// normalizeTargetRef is an independent oracle for NormalizeTarget.
func normalizeTargetRef(u *url.URL) *url.URL {
	if u == nil {
		return &url.URL{Scheme: "http", Host: "127.0.0.1"}
	}
	out := *u
	switch strings.ToLower(out.Scheme) {
	case "unix":
		out.Scheme = "http"
		out.Host = "localhost"
		out.Path = ""
		out.Opaque = ""
	case "ws":
		out.Scheme = "http"
	case "wss":
		out.Scheme = "https"
	case "h3", "http3", "quic":
		out.Scheme = "https"
	case "tunnel":
		out.Scheme = "http"
		out.Host = "tunnel.local"
		out.Path = ""
		out.Opaque = ""
	}
	return &out
}

// buildTLSClientConfigRef is an independent oracle that builds a tls.Config
// from files using only the standard library.
func buildTLSClientConfigRef(caFile, clientCertFile, clientKeyFile string, insecure bool) (*tls.Config, error) {
	cfg := &tls.Config{}
	if insecure {
		cfg.InsecureSkipVerify = true
	}
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("upstream ca_file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("upstream ca_file: no valid certificates")
		}
		cfg.RootCAs = pool
	}
	if clientCertFile != "" && clientKeyFile != "" {
		cert, err := tls.LoadX509KeyPair(clientCertFile, clientKeyFile)
		if err != nil {
			return nil, fmt.Errorf("upstream client cert: %w", err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}
	return cfg, nil
}

func compareTLSConfigs(t *testing.T, got, want *tls.Config) {
	t.Helper()
	if (got == nil) != (want == nil) {
		t.Fatalf("nil config mismatch: got=%v want=%v", got, want)
	}
	if got == nil {
		return
	}
	if got.InsecureSkipVerify != want.InsecureSkipVerify {
		t.Fatalf("InsecureSkipVerify: got=%v want=%v", got.InsecureSkipVerify, want.InsecureSkipVerify)
	}
	if (got.RootCAs == nil) != (want.RootCAs == nil) {
		t.Fatalf("RootCAs nil mismatch: got=%v want=%v", got.RootCAs, want.RootCAs)
	}
	if got.RootCAs != nil {
		if !got.RootCAs.Equal(want.RootCAs) {
			t.Fatalf("RootCAs mismatch")
		}
	}
	if len(got.Certificates) != len(want.Certificates) {
		t.Fatalf("Certificates count: got=%d want=%d", len(got.Certificates), len(want.Certificates))
	}
	for i := range got.Certificates {
		if len(got.Certificates[i].Certificate) != len(want.Certificates[i].Certificate) {
			t.Fatalf("Certificate %d chain length mismatch", i)
		}
		for j := range got.Certificates[i].Certificate {
			if !bytes.Equal(got.Certificates[i].Certificate[j], want.Certificates[i].Certificate[j]) {
				t.Fatalf("Certificate %d DER %d mismatch", i, j)
			}
		}
	}
}

func hasSpecialPrefix(raw string) bool {
	return strings.HasPrefix(raw, "unix://") ||
		strings.HasPrefix(raw, "unix:") ||
		strings.HasPrefix(raw, "h3://") ||
		strings.HasPrefix(raw, "tunnel://")
}

func token(r *rand.Rand) string {
	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	n := r.IntN(10) + 1
	b := make([]byte, n)
	for i := range b {
		b[i] = chars[r.IntN(len(chars))]
	}
	return string(b)
}

func generateRawURL(r *rand.Rand) string {
	schemes := []string{"http", "https", "ws", "wss", "h3", "http3", "quic", "foo", "bar"}
	hosts := []string{"localhost", "127.0.0.1", "example.com", "edge.local"}

	switch r.IntN(10) {
	case 0, 1, 2, 3:
		scheme := schemes[r.IntN(len(schemes))]
		host := hosts[r.IntN(len(hosts))]
		if r.IntN(2) == 0 {
			host += ":" + strconv.Itoa(r.IntN(65536))
		}
		path := "/" + token(r)
		if r.IntN(3) == 0 {
			path += "?" + token(r) + "=" + token(r)
		}
		if r.IntN(3) == 0 {
			path += "#" + token(r)
		}
		return scheme + "://" + host + path
	case 4, 5:
		switch r.IntN(4) {
		case 0:
			return "unix://" + "/tmp/" + token(r) + ".sock"
		case 1:
			return "unix:" + "/tmp/" + token(r) + ".sock"
		case 2:
			return "h3://" + token(r) + ".example:" + strconv.Itoa(r.IntN(65536))
		case 3:
			return "tunnel://" + token(r) + "/" + token(r)
		}
	case 6, 7:
		adversarial := []string{
			"", "://", "http://", "https://", "h3://", "unix://", "unix:",
			"tunnel://", "tunnel://a", "tunnel:///b", "http://[",
			"http://host:abc", "http://host:99999", "%", " ",
			"foo://bar/baz", "http://host:-1",
		}
		return adversarial[r.IntN(len(adversarial))]
	}

	// Random characters from the URL legal set.
	n := r.IntN(40) + 1
	b := make([]byte, n)
	chars := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~:/?#[]@!$&'()*+,;=%"
	for i := range b {
		b[i] = chars[r.IntN(len(chars))]
	}
	return string(b)
}

func TestParseUpstreamURLPBT(t *testing.T) {
	for _, seed := range []uint64{1, 17, 42, 99, 12345} {
		t.Run(fmt.Sprintf("seed=%d", seed), func(t *testing.T) {
			r := rand.New(rand.NewPCG(seed, 1))
			for range 200 {
				raw := generateRawURL(r)
				got, gotErr := proxy.ParseUpstreamURL(raw)
				ref, refErr := parseUpstreamURLRef(raw)
				std, stdErr := url.Parse(raw)

				if (gotErr == nil) != (refErr == nil) {
					t.Fatalf("raw=%q: error nil mismatch with reference: got=%v ref=%v", raw, gotErr, refErr)
				}
				if gotErr == nil && got.String() != ref.String() {
					t.Fatalf("raw=%q: got=%+v ref=%+v", raw, got, ref)
				}

				// Differential against net/url.Parse for inputs that are not handled by the
				// special-cased schemes.
				if !hasSpecialPrefix(raw) {
					if (gotErr == nil) != (stdErr == nil) {
						t.Fatalf("raw=%q: error nil mismatch with url.Parse: got=%v std=%v", raw, gotErr, stdErr)
					}
					if gotErr == nil && got.String() != std.String() {
						t.Fatalf("raw=%q: ParseUpstreamURL differs from url.Parse: got=%+v std=%+v", raw, got, std)
					}
				}
			}
		})
	}
}

func TestNormalizeTargetPBT(t *testing.T) {
	for _, seed := range []uint64{1, 17, 42, 99, 12345} {
		t.Run(fmt.Sprintf("seed=%d", seed), func(t *testing.T) {
			r := rand.New(rand.NewPCG(seed, 1))
			valid := 0
			for valid < 200 {
				raw := generateRawURL(r)
				u, err := url.Parse(raw)
				if err != nil {
					continue
				}
				valid++

				got := proxy.NormalizeTarget(u)
				ref := normalizeTargetRef(u)
				if got.String() != ref.String() {
					t.Fatalf("raw=%q: got=%+v ref=%+v", raw, got, ref)
				}

				// Idempotence.
				again := proxy.NormalizeTarget(got)
				if again.String() != got.String() {
					t.Fatalf("NormalizeTarget not idempotent: first=%s second=%s", got.String(), again.String())
				}

				// Host preservation oracle.
				if u.Host != "" && !strings.EqualFold(u.Scheme, "unix") && !strings.EqualFold(u.Scheme, "tunnel") {
					if got.Host != u.Host {
						t.Fatalf("host not preserved for %q: got=%q want=%q", raw, got.Host, u.Host)
					}
				}

				// Scheme-specific host expectations.
				switch strings.ToLower(u.Scheme) {
				case "unix":
					if got.Host != "localhost" {
						t.Fatalf("unix host: got=%q want=localhost", got.Host)
					}
				case "tunnel":
					if got.Host != "tunnel.local" {
						t.Fatalf("tunnel host: got=%q want=tunnel.local", got.Host)
					}
				}
			}
		})
	}
}

func TestNormalizeTargetNilAndDefaults(t *testing.T) {
	got := proxy.NormalizeTarget(nil)
	want := &url.URL{Scheme: "http", Host: "127.0.0.1"}
	if got.String() != want.String() {
		t.Fatalf("nil target: got=%s want=%s", got.String(), want.String())
	}

	cases := []struct {
		raw    string
		scheme string
		host   string
	}{
		{"ws://127.0.0.1:8000/socket", "http", "127.0.0.1:8000"},
		{"wss://origin.example:9443", "https", "origin.example:9443"},
		{"h3://origin.example", "https", "origin.example"},
		{"http3://origin.example", "https", "origin.example"},
		{"quic://origin.example", "https", "origin.example"},
		{"unix:///tmp/app.sock", "http", "localhost"},
		{"tunnel://conn/up", "http", "tunnel.local"},
	}
	for _, tc := range cases {
		u, err := proxy.ParseUpstreamURL(tc.raw)
		if err != nil {
			t.Fatal(err)
		}
		n := proxy.NormalizeTarget(u)
		if n.Scheme != tc.scheme || n.Host != tc.host {
			t.Fatalf("%s: got scheme=%q host=%q want scheme=%q host=%q", tc.raw, n.Scheme, n.Host, tc.scheme, tc.host)
		}
	}
}

func TestDialFuncPBT(t *testing.T) {
	t.Run("empty target invalid network", func(t *testing.T) {
		dial := proxy.DialFunc(nil, time.Second)
		_, err := dial(context.Background(), "invalid", "x")
		if err == nil {
			t.Fatal("expected error for invalid network")
		}
		if !strings.Contains(err.Error(), "unknown network") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("missing port", func(t *testing.T) {
		target, _ := url.Parse("http://127.0.0.1")
		dial := proxy.DialFunc(target, time.Second)
		_, err := dial(context.Background(), "tcp", "127.0.0.1")
		if err == nil {
			t.Fatal("expected error for missing port")
		}
		if !strings.Contains(err.Error(), "missing port in address") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("h3 scheme uses network addr", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		target := &url.URL{Scheme: "h3", Host: ln.Addr().String()}
		dial := proxy.DialFunc(target, time.Second)
		conn, err := dial(context.Background(), "tcp", ln.Addr().String())
		if err != nil {
			t.Fatalf("dial failed: %v", err)
		}
		defer conn.Close()
	})

	t.Run("unix path", func(t *testing.T) {
		dir, err := os.MkdirTemp("/tmp", "proxyunix")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(dir) })
		sock := filepath.Join(dir, "app.sock")
		ln, err := net.Listen("unix", sock)
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()

		go func() {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer c.Close()
			_, _ = c.Write([]byte("pong"))
		}()

		u, _ := proxy.ParseUpstreamURL("unix://" + sock)
		dial := proxy.DialFunc(u, time.Second)
		conn, err := dial(context.Background(), "tcp", "ignored")
		if err != nil {
			t.Fatalf("dial failed: %v", err)
		}
		defer conn.Close()
		buf := make([]byte, 4)
		_, err = io.ReadFull(conn, buf)
		if err != nil || string(buf) != "pong" {
			t.Fatalf("expected pong, got %q err=%v", buf, err)
		}
	})

	t.Run("random targets never panic", func(t *testing.T) {
		schemes := []string{"", "http", "https", "h3", "http3", "quic", "ws", "wss", "foo", "bar"}
		for _, seed := range []uint64{1, 17, 42, 99, 12345} {
			r := rand.New(rand.NewPCG(seed, 1))
			for range 100 {
				scheme := schemes[r.IntN(len(schemes))]
				host := "127.0.0.1:1"
				target := &url.URL{Scheme: scheme, Host: host}
				dial := proxy.DialFunc(target, time.Millisecond)
				_, err := dial(context.Background(), "invalid", "x")
				if err == nil {
					t.Fatalf("scheme=%q: expected error for invalid network", scheme)
				}
			}
		}
	})
}

func TestBuildTLSClientConfigPBT(t *testing.T) {
	certPEM, keyPEM, err := tlscerts.Generate(tlscerts.GenerateOptions{Hosts: []string{"localhost"}})
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.pem")
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	garbagePath := filepath.Join(dir, "garbage.pem")
	emptyPath := filepath.Join(dir, "empty.pem")

	if err := os.WriteFile(caPath, certPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(garbagePath, []byte("not a certificate"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(emptyPath, []byte{}, 0o644); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name       string
		ca         string
		clientCert string
		clientKey  string
		insecure   bool
		wantErr    bool
	}{
		{"valid all", caPath, certPath, keyPath, false, false},
		{"valid ca only", caPath, "", "", false, false},
		{"insecure skip verify", "", "", "", true, false},
		{"missing ca", "/does/not/exist.pem", "", "", false, true},
		{"invalid ca", garbagePath, "", "", false, true},
		{"empty ca", emptyPath, "", "", false, true},
		{"client cert without key", "", certPath, "", false, false},
		{"client key without cert", "", "", keyPath, false, false},
		{"mismatched key pair", "", certPath, garbagePath, false, true},
		{"missing client cert file", "", "/does/not/exist.pem", keyPath, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, gotErr := proxy.BuildTLSClientConfig(tc.ca, tc.clientCert, tc.clientKey, tc.insecure)
			ref, refErr := buildTLSClientConfigRef(tc.ca, tc.clientCert, tc.clientKey, tc.insecure)
			if (gotErr == nil) != (refErr == nil) {
				t.Fatalf("error mismatch: got=%v ref=%v", gotErr, refErr)
			}
			if tc.wantErr && gotErr == nil {
				t.Fatal("expected error")
			}
			if gotErr == nil {
				compareTLSConfigs(t, got, ref)
			}
		})
	}

	// Randomly generated file scenarios against the reference oracle.
	for _, seed := range []uint64{1, 17, 42} {
		t.Run(fmt.Sprintf("random-%d", seed), func(t *testing.T) {
			r := rand.New(rand.NewPCG(seed, 1))
			for i := range 50 {
				d := t.TempDir()
				caF := filepath.Join(d, "ca.pem")
				certF := filepath.Join(d, "cert.pem")
				keyF := filepath.Join(d, "key.pem")

				var ca, cert, key []byte
				switch r.IntN(6) {
				case 0:
					ca = certPEM
				case 1:
					ca = []byte("garbage")
				case 2:
					ca = []byte{}
				}
				switch r.IntN(6) {
				case 0:
					cert = certPEM
					key = keyPEM
				case 1:
					cert = certPEM
					key = certPEM
				case 2:
					cert = []byte("garbage")
					key = []byte("garbage")
				case 3:
					cert = []byte{}
					key = []byte{}
				case 4:
					cert = certPEM
				case 5:
					key = keyPEM
				}

				caFile, certFile, keyFile := "", "", ""
				if len(ca) > 0 {
					caFile = caF
					_ = os.WriteFile(caF, ca, 0o644)
				}
				if len(cert) > 0 {
					certFile = certF
					_ = os.WriteFile(certF, cert, 0o644)
				}
				if len(key) > 0 {
					keyFile = keyF
					_ = os.WriteFile(keyF, key, 0o644)
				}

				insecure := r.IntN(2) == 0
				got, gotErr := proxy.BuildTLSClientConfig(caFile, certFile, keyFile, insecure)
				ref, refErr := buildTLSClientConfigRef(caFile, certFile, keyFile, insecure)
				if (gotErr == nil) != (refErr == nil) {
					t.Fatalf("iteration %d: error mismatch: got=%v ref=%v", i, gotErr, refErr)
				}
				if gotErr == nil {
					compareTLSConfigs(t, got, ref)
				}
			}
		})
	}
}

func protoHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Proto", r.Proto)
	if v := r.Header.Get("X-Forwarded-Host"); v != "" {
		w.Header().Set("X-Forwarded-Host", v)
	}
	w.Write([]byte("ok"))
}

func TestProtocolSelectionPBT(t *testing.T) {
	h2Only := newHTTP2Server(http.HandlerFunc(protoHandler))
	defer h2Only.Close()
	h1Only := newHTTP11TLSServer(http.HandlerFunc(protoHandler))
	defer h1Only.Close()
	h2AndH1 := newH2AndH1TLSServer(http.HandlerFunc(protoHandler))
	defer h2AndH1.Close()
	h3URL, h3Cleanup := startH3Server(t)
	defer h3Cleanup()
	plainH1 := httptest.NewServer(http.HandlerFunc(protoHandler))
	defer plainH1.Close()

	type protoCase struct {
		name       string
		target     string
		protocol   string
		allowHTTP1 bool
		ws         bool
		wantOK     bool
		wantProto  string
	}

	cases := []protoCase{
		{"h2-only/default", h2Only.URL, "", false, false, true, "HTTP/2.0"},
		{"h2-only/h2", h2Only.URL, "h2", false, false, true, "HTTP/2.0"},
		{"h2-only/h2-allow-h1", h2Only.URL, "h2", true, false, true, "HTTP/2.0"},
		{"h2-only/h1-only", h2Only.URL, "http1.1", false, false, true, "HTTP/1.1"},
		{"h1-only/h2-fail", h1Only.URL, "h2", false, false, false, ""},
		{"h1-only/h2-allow-h1", h1Only.URL, "h2", true, false, true, "HTTP/1.1"},
		{"h1-only/h1", h1Only.URL, "http1.1", false, false, true, "HTTP/1.1"},
		{"h2+h1/h2", h2AndH1.URL, "h2", false, false, true, "HTTP/2.0"},
		{"h2+h1/h2-allow-h1", h2AndH1.URL, "h2", true, false, true, "HTTP/2.0"},
		{"h2+h1/websocket", h2AndH1.URL, "h2", false, true, true, "HTTP/1.1"},
		{"h3/h3", h3URL, "h3", false, false, true, "HTTP/3.0"},
		{"h3/auto", h3URL, "auto", false, false, true, "HTTP/3.0"},
		{"plain/h1", plainH1.URL, "http1.1", false, false, true, "HTTP/1.1"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			target, err := url.Parse(tc.target)
			if err != nil {
				t.Fatal(err)
			}
			cfg := proxy.Config{
				Target:   target,
				Protocol: tc.protocol,
			}
			if tc.allowHTTP1 {
				cfg.AllowHTTP1 = true
			}
			if strings.HasPrefix(tc.target, "https://") || strings.HasPrefix(tc.target, "h3://") {
				cfg.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
			}

			rp := proxy.New(cfg)
			defer rp.Close()

			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "http://edge.example/path", nil)
			req.Host = "edge.example"
			if tc.ws {
				req.Header.Set("Upgrade", "websocket")
				req.Header.Set("Connection", "Upgrade")
				req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
				req.Header.Set("Sec-WebSocket-Version", "13")
			}
			rp.ServeHTTP(rec, req)

			if tc.wantOK {
				if rec.Code != http.StatusOK {
					t.Fatalf("status=%d body=%q", rec.Code, rec.Body.String())
				}
				if got := rec.Header().Get("X-Proto"); got != tc.wantProto {
					t.Fatalf("X-Proto=%q want %q", got, tc.wantProto)
				}
				// The HTTP/3 test helper does not echo request headers, so we only
				// verify X-Forwarded-Host for TCP-based transports.
				if !strings.HasPrefix(tc.target, "h3://") {
					if got := rec.Header().Get("X-Forwarded-Host"); got != "edge.example" {
						t.Fatalf("X-Forwarded-Host=%q", got)
					}
				}
			} else {
				if rec.Code != http.StatusBadGateway {
					t.Fatalf("status=%d, want 502", rec.Code)
				}
			}
		})
	}
}

func TestBadTLSAdversarial(t *testing.T) {
	backend := httptest.NewTLSServer(http.HandlerFunc(protoHandler))
	defer backend.Close()

	target, _ := url.Parse(backend.URL)
	rp := proxy.New(proxy.Config{Target: target, Protocol: "http1.1"})
	defer rp.Close()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://edge.example/", nil)
	rp.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status=%d, want 502", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "upstream unavailable") {
		t.Fatalf("body=%q", rec.Body.String())
	}
}

func TestUnknownSchemeAdversarial(t *testing.T) {
	target, _ := url.Parse("foo://127.0.0.1:1")
	rp := proxy.New(proxy.Config{Target: target})
	defer rp.Close()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://edge.example/", nil)
	rp.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status=%d, want 502", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "upstream unavailable") {
		t.Fatalf("body=%q", rec.Body.String())
	}
}

func TestLandlockBlockedConnectionAdversarial(t *testing.T) {
	target, _ := url.Parse("http://127.0.0.1:1")
	handlerCalled := false
	rp := proxy.New(proxy.Config{
		Target: target,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return nil, fmt.Errorf("dial tcp 127.0.0.1:1: connect: permission denied")
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			handlerCalled = true
			if err == nil || !strings.Contains(err.Error(), "permission denied") {
				t.Errorf("expected permission denied error, got %v", err)
			}
			http.Error(w, "landlock blocked", http.StatusBadGateway)
		},
	})
	defer rp.Close()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://edge.example/", nil)
	rp.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status=%d", rec.Code)
	}
	if !handlerCalled {
		t.Fatal("error handler not called")
	}
	if !strings.Contains(rec.Body.String(), "landlock blocked") {
		t.Fatalf("body=%q", rec.Body.String())
	}
}

func TestServeHTTPHugeBodyPBT(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Read the full body before writing; interleaving reads and writes on
		// HTTP/1.x can cause the server to close the request body early.
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write(body)
	}))
	defer backend.Close()

	target, _ := url.Parse(backend.URL)

	for _, seed := range []uint64{1, 17, 42} {
		t.Run(fmt.Sprintf("seed=%d", seed), func(t *testing.T) {
			r := rand.New(rand.NewPCG(seed, 1))
			for range 20 {
				size := r.IntN(64*1024) + 1
				body := make([]byte, size)
				for j := range body {
					body[j] = byte(r.IntN(256))
				}

				rp := proxy.New(proxy.Config{Target: target, Protocol: "http1.1"})
				defer rp.Close()

				rec := httptest.NewRecorder()
				req := httptest.NewRequest(http.MethodPost, "http://edge.example/upload", bytes.NewReader(body))
				rp.ServeHTTP(rec, req)

				if rec.Code != http.StatusOK {
					t.Fatalf("status=%d body=%q", rec.Code, rec.Body.String())
				}
				if !bytes.Equal(rec.Body.Bytes(), body) {
					t.Fatalf("body mismatch for size %d", size)
				}
			}
		})
	}
}

func TestConnectionLimitsAdversarial(t *testing.T) {
	backend := newHTTP2Server(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer backend.Close()

	target, _ := url.Parse(backend.URL)
	rp := proxy.New(proxy.Config{
		Target:          target,
		Protocol:        "h2",
		MaxConnsPerHost: 1,
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	})
	defer rp.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	const n = 20
	var wg sync.WaitGroup
	var ok atomic.Int64
	for range n {
		wg.Go(func() {
			req := httptest.NewRequest(http.MethodGet, "http://edge.example/", nil).WithContext(ctx)
			rec := httptest.NewRecorder()
			rp.ServeHTTP(rec, req)
			if rec.Code == http.StatusOK && rec.Body.String() == "ok" {
				ok.Add(1)
			}
		})
	}
	wg.Wait()

	if got := ok.Load(); got != n {
		t.Fatalf("only %d/%d requests succeeded under MaxConnsPerHost=1", got, n)
	}
}
