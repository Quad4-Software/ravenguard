// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

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

func FuzzParseUpstreamURL(f *testing.F) {
	seeds := []string{
		"",
		"://",
		"http://example.com/path?q=1",
		"https://127.0.0.1:8443",
		"ws://edge.local/socket",
		"wss://origin.example:9443",
		"h3://origin.example",
		"h3://host:443/path",
		"h3://",
		"unix:///tmp/app.sock",
		"unix:/tmp/app.sock",
		"unix:",
		"tunnel://connector/upstream",
		"tunnel://",
		"tunnel://a",
		"tunnel:///b",
		"foo://bar/baz",
		"http://[",
		"http://host:abc",
		"http://host:99999",
		"%",
		" ",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, raw string) {
		got, gotErr := ParseUpstreamURL(raw)
		ref, refErr := parseUpstreamURLRef(raw)

		if (gotErr == nil) != (refErr == nil) {
			t.Fatalf("raw=%q: error nil mismatch: got=%v ref=%v", raw, gotErr, refErr)
		}
		if gotErr == nil && got.String() != ref.String() {
			t.Fatalf("raw=%q: got=%+v ref=%+v", raw, got, ref)
		}

		// Differential against net/url.Parse for non-special inputs.
		if !hasSpecialPrefix(raw) {
			std, stdErr := url.Parse(raw)
			if (gotErr == nil) != (stdErr == nil) {
				t.Fatalf("raw=%q: error nil mismatch with url.Parse: got=%v std=%v", raw, gotErr, stdErr)
			}
			if gotErr == nil && got.String() != std.String() {
				t.Fatalf("raw=%q: ParseUpstreamURL differs from url.Parse: got=%+v std=%+v", raw, got, std)
			}
		}

		// Metamorphic round-trip: for inputs that do not require the special
		// scheme handling, the parsed URL should reparse to the same value.
		if gotErr == nil && !hasSpecialPrefix(raw) {
			round, roundErr := ParseUpstreamURL(got.String())
			if roundErr != nil {
				t.Fatalf("round-trip parse of %q failed: %v", got.String(), roundErr)
			}
			if round.String() != got.String() {
				t.Fatalf("round-trip mismatch: %q -> %q", got.String(), round.String())
			}
		}
	})
}

func FuzzNormalizeTarget(f *testing.F) {
	seeds := []string{
		"http://example.com",
		"https://127.0.0.1:8443",
		"ws://edge.local/socket",
		"wss://origin.example",
		"h3://origin.example",
		"http3://origin.example",
		"quic://origin.example",
		"unix:///tmp/app.sock",
		"tunnel://connector/upstream",
		"foo://bar/baz",
		"",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, raw string) {
		u, err := url.Parse(raw)
		if err != nil {
			return
		}

		got := NormalizeTarget(u)
		ref := normalizeTargetRef(u)
		if got.String() != ref.String() {
			t.Fatalf("raw=%q: got=%+v ref=%+v", raw, got, ref)
		}

		// Idempotence.
		again := NormalizeTarget(got)
		if again.String() != got.String() {
			t.Fatalf("not idempotent: first=%s second=%s", got.String(), again.String())
		}

		// Host preservation oracle.
		if u.Host != "" && !strings.EqualFold(u.Scheme, "unix") && !strings.EqualFold(u.Scheme, "tunnel") {
			if got.Host != u.Host {
				t.Fatalf("host not preserved for %q: got=%q want=%q", raw, got.Host, u.Host)
			}
		}
	})
}

func FuzzBuildTLSClientConfig(f *testing.F) {
	certPEM, keyPEM, err := tlscerts.Generate(tlscerts.GenerateOptions{Hosts: []string{"localhost"}})
	if err != nil {
		f.Fatal(err)
	}

	f.Add(certPEM, certPEM, keyPEM, false)
	f.Add(certPEM, []byte("garbage"), []byte("garbage"), false)
	f.Add([]byte("not a cert"), []byte{}, []byte{}, false)
	f.Add([]byte{}, []byte{}, []byte{}, true)
	f.Add([]byte{}, certPEM, keyPEM, true)
	f.Add(certPEM, certPEM, certPEM, false)

	f.Fuzz(func(t *testing.T, ca, clientCert, clientKey []byte, insecure bool) {
		dir := t.TempDir()
		caFile, clientCertFile, clientKeyFile := "", "", ""

		if len(ca) > 0 {
			caFile = filepath.Join(dir, "ca.pem")
			_ = os.WriteFile(caFile, ca, 0o644)
		}
		if len(clientCert) > 0 {
			clientCertFile = filepath.Join(dir, "cert.pem")
			_ = os.WriteFile(clientCertFile, clientCert, 0o644)
		}
		if len(clientKey) > 0 {
			clientKeyFile = filepath.Join(dir, "key.pem")
			_ = os.WriteFile(clientKeyFile, clientKey, 0o644)
		}

		got, gotErr := BuildTLSClientConfig(caFile, clientCertFile, clientKeyFile, insecure)
		ref, refErr := buildTLSClientConfigRef(caFile, clientCertFile, clientKeyFile, insecure)

		if (gotErr == nil) != (refErr == nil) {
			t.Fatalf("error mismatch: got=%v ref=%v", gotErr, refErr)
		}
		if gotErr == nil {
			compareTLSConfigs(t, got, ref)
		}
	})
}

func FuzzIsLandlockBlocked(f *testing.F) {
	f.Add("dial tcp 127.0.0.1:5280: connect: permission denied", false)
	f.Add("dial tcp 127.0.0.1:5280: connect: connection refused", false)
	f.Add("i/o timeout", false)
	f.Add("", true)

	f.Fuzz(func(t *testing.T, msg string, wrapPermission bool) {
		var err error
		if wrapPermission {
			err = fmt.Errorf("dial: %w", os.ErrPermission)
		} else {
			err = errors.New(msg)
		}

		got := isLandlockBlocked(err)
		want := errors.Is(err, os.ErrPermission) || strings.Contains(err.Error(), "connect: permission denied")
		if got != want {
			t.Fatalf("isLandlockBlocked(%v) = %v want %v", err, got, want)
		}
	})
}

func FuzzDialFunc(f *testing.F) {
	f.Add("http://127.0.0.1:1")
	f.Add("https://example.com")
	f.Add("h3://example.com")
	f.Add("ws://edge.local")
	f.Add("foo://bar/baz")
	f.Add("")

	f.Fuzz(func(t *testing.T, raw string) {
		u, err := ParseUpstreamURL(raw)
		if err != nil {
			return
		}

		// Skip unix sockets: they can succeed if a socket happens to exist at the
		// fuzz-generated path. The non-unix dialer must reject an unknown network.
		if IsUnix(u) {
			return
		}

		dial := DialFunc(u, time.Millisecond)
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		conn, err := dial(ctx, "invalid", "x")
		if conn != nil {
			_ = conn.Close()
		}
		if err == nil {
			t.Fatalf("expected error for invalid network with target %q", u.String())
		}
	})
}

func FuzzProtocolSelection(f *testing.F) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Proto", r.Proto)
		if v := r.Header.Get("X-Forwarded-Host"); v != "" {
			w.Header().Set("X-Forwarded-Host", v)
		}
		w.Write([]byte("ok"))
	})
	s := httptest.NewUnstartedServer(h)
	s.EnableHTTP2 = true
	s.TLS = &tls.Config{NextProtos: []string{"h2", "http/1.1"}}
	s.StartTLS()
	defer s.Close()

	target, _ := url.Parse(s.URL)

	f.Add([]byte("h2"), false, false)
	f.Add([]byte("h2"), true, false)
	f.Add([]byte("http1.1"), false, false)
	f.Add([]byte(""), false, false)
	f.Add([]byte("garbage-protocol"), false, false)
	f.Add([]byte("h2"), false, true)

	f.Fuzz(func(t *testing.T, protocol []byte, allowHTTP1, ws bool) {
		proto := strings.TrimSpace(string(protocol))
		if len(proto) > 64 {
			proto = proto[:64]
		}

		// Avoid the 5-second HTTP/3 probe in auto/h3 mode with a non-QUIC backend.
		p := normalizeProtocol(proto)
		if p == ProtocolH3 || p == ProtocolAuto {
			return
		}

		cfg := Config{
			Target:          target,
			Protocol:        proto,
			AllowHTTP1:      allowHTTP1,
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		rp := New(cfg)
		defer rp.Close()

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "http://edge.example/path", nil)
		req.Host = "edge.example"
		if ws {
			req.Header.Set("Upgrade", "websocket")
			req.Header.Set("Connection", "Upgrade")
			req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
			req.Header.Set("Sec-WebSocket-Version", "13")
		}
		rp.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status=%d body=%q protocol=%q ws=%v", rec.Code, rec.Body.String(), proto, ws)
		}

		var wantProto string
		if ws || p == ProtocolHTTP1 {
			wantProto = "HTTP/1.1"
		} else {
			wantProto = "HTTP/2.0"
		}
		if got := rec.Header().Get("X-Proto"); got != wantProto {
			t.Fatalf("X-Proto=%q want %q for protocol=%q ws=%v", got, wantProto, proto, ws)
		}
		if got := rec.Header().Get("X-Forwarded-Host"); got != "edge.example" {
			t.Fatalf("X-Forwarded-Host=%q", got)
		}
	})
}

func TestDialFuncLandlockPBT(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("landlock is linux-only; dial error semantics differ elsewhere")
	}

	dir, err := os.MkdirTemp("/tmp", "proxylk")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "not-a-socket")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o000)
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()

	u, err := ParseUpstreamURL("unix://" + path)
	if err != nil {
		t.Fatal(err)
	}

	dial := DialFunc(u, time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err = dial(ctx, "tcp", "ignored")
	if err == nil {
		t.Fatal("expected error dialing a non-socket with no permissions")
	}

	if isLandlockBlocked(err) {
		return
	}
	if os.Geteuid() == 0 {
		t.Skip("running as root; cannot trigger permission-denied landlock error")
	}
	t.Fatalf("expected landlock-blocked error, got %v", err)
}
