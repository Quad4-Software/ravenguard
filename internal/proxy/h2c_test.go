// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package proxy_test

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"

	"github.com/Quad4-Software/ravenguard/internal/proxy"
	"github.com/Quad4-Software/ravenguard/internal/tlscerts"
)

// startClearOrigin starts a cleartext origin. When h2c is true the server
// accepts prior-knowledge HTTP/2 as well as HTTP/1.1.
func startClearOrigin(t *testing.T, h2c bool) (*url.URL, func()) {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		var n int64
		if r.Body != nil {
			n, _ = io.Copy(io.Discard, r.Body)
		}
		w.Header().Set("X-Origin-Proto", r.Proto)
		fmt.Fprintf(w, "proto=%s body=%d", r.Proto, n)
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	p := &http.Protocols{}
	p.SetHTTP1(true)
	if h2c {
		p.SetUnencryptedHTTP2(true)
	}
	srv.Protocols = p
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(ln) }()
	return &url.URL{Scheme: "http", Host: ln.Addr().String()}, func() { _ = srv.Close() }
}

func serveOnce(rp *proxy.Proxy, method, body string) *httptest.ResponseRecorder {
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(method, "http://edge.example/x", rdr)
	rp.ServeHTTP(rec, req)
	return rec
}

func TestH2CFallbackToHTTP1(t *testing.T) {
	target, cleanup := startClearOrigin(t, false)
	defer cleanup()

	rp := proxy.New(proxy.Config{Target: target, Protocol: "h2", AllowHTTP1: true})
	defer rp.Close()

	for i := 0; i < 20; i++ {
		rec := serveOnce(rp, http.MethodGet, "")
		if rec.Code != http.StatusOK {
			t.Fatalf("req %d status=%d", i, rec.Code)
		}
		if got := rec.Header().Get("X-Origin-Proto"); got != "HTTP/1.1" {
			t.Fatalf("req %d origin proto=%q want HTTP/1.1", i, got)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestH2CUpstream(t *testing.T) {
	target, cleanup := startClearOrigin(t, true)
	defer cleanup()

	rp := proxy.New(proxy.Config{Target: target, Protocol: "h2", AllowHTTP1: true})
	defer rp.Close()

	// The first requests use HTTP/1.1 while the h2c probe is in flight.
	deadline := time.Now().Add(3 * time.Second)
	for {
		rec := serveOnce(rp, http.MethodPost, "ping")
		if rec.Code != http.StatusOK {
			t.Fatalf("status=%d", rec.Code)
		}
		if got := rec.Header().Get("X-Origin-Proto"); got == "HTTP/2.0" {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("origin never saw h2c; last proto=%q", rec.Header().Get("X-Origin-Proto"))
		}
		time.Sleep(25 * time.Millisecond)
	}
}

func TestH2CStrictWorks(t *testing.T) {
	target, cleanup := startClearOrigin(t, true)
	defer cleanup()

	rp := proxy.New(proxy.Config{Target: target, Protocol: "h2", AllowHTTP1: false})
	defer rp.Close()

	rec := serveOnce(rp, http.MethodGet, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("X-Origin-Proto"); got != "HTTP/2.0" {
		t.Fatalf("origin proto=%q want HTTP/2.0", got)
	}
}

func TestH2CStrictFailsOnHTTP1Origin(t *testing.T) {
	target, cleanup := startClearOrigin(t, false)
	defer cleanup()

	rp := proxy.New(proxy.Config{Target: target, Protocol: "h2", AllowHTTP1: false})
	defer rp.Close()

	rec := serveOnce(rp, http.MethodGet, "")
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status=%d want 502 for h2c against h1-only origin", rec.Code)
	}
}

// startTCPAndH3 starts a TLS origin serving h1/h2 on TCP and HTTP/3 on UDP,
// both on the same port.
func startTCPAndH3(t *testing.T) (*url.URL, func()) {
	t.Helper()
	certPEM, keyPEM, err := tlscerts.Generate(tlscerts.GenerateOptions{
		Hosts: []string{"localhost"},
		IPs:   []net.IP{net.ParseIP("127.0.0.1")},
	})
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		var n int64
		if r.Body != nil {
			n, _ = io.Copy(io.Discard, r.Body)
		}
		w.Header().Set("X-Origin-Proto", r.Proto)
		fmt.Fprintf(w, "proto=%s body=%d", r.Proto, n)
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port

	tcpSrv := &http.Server{
		Handler:   mux,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2", "http/1.1"}},
	}
	tp := &http.Protocols{}
	tp.SetHTTP1(true)
	tp.SetHTTP2(true)
	tcpSrv.Protocols = tp
	go func() { _ = tcpSrv.ServeTLS(ln, "", "") }()

	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: port})
	if err != nil {
		_ = tcpSrv.Close()
		t.Fatal(err)
	}
	h3srv := &http3.Server{
		Handler:   mux,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h3"}},
	}
	go func() { _ = h3srv.Serve(conn) }()

	u := &url.URL{Scheme: "https", Host: fmt.Sprintf("127.0.0.1:%d", port)}
	return u, func() {
		_ = tcpSrv.Close()
		_ = h3srv.Close()
		_ = conn.Close()
	}
}

func TestAutoUpstreamNoQUIC(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		var n int64
		if r.Body != nil {
			n, _ = io.Copy(io.Discard, r.Body)
		}
		w.Header().Set("X-Origin-Proto", r.Proto)
		fmt.Fprintf(w, "proto=%s body=%d", r.Proto, n)
	})
	backend := httptest.NewTLSServer(mux)
	defer backend.Close()

	target, _ := url.Parse(backend.URL)
	rp := proxy.New(proxy.Config{
		Target:          target,
		Protocol:        "auto",
		AllowHTTP1:      true,
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	})
	defer rp.Close()

	// The QUIC probe must not stall the first request and must not consume
	// the request body.
	start := time.Now()
	rec := serveOnce(rp, http.MethodPost, "0123456789abcdef")
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("first request stalled %v", elapsed)
	}
	if got := rec.Body.String(); !strings.Contains(got, "body=16") {
		t.Fatalf("body mangled: %q", got)
	}
}

func TestAutoUpstreamH3(t *testing.T) {
	target, cleanup := startTCPAndH3(t)
	defer cleanup()

	rp := proxy.New(proxy.Config{
		Target:          target,
		Protocol:        "auto",
		AllowHTTP1:      true,
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	})
	defer rp.Close()

	// First request goes over TCP while QUIC is probed in the background.
	rec := serveOnce(rp, http.MethodGet, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}
	if got := rec.Header().Get("X-Origin-Proto"); got == "HTTP/3.0" {
		t.Fatalf("first request should use TCP, got %q", got)
	}

	deadline := time.Now().Add(5 * time.Second)
	for {
		rec = serveOnce(rp, http.MethodPost, "payload")
		if rec.Code != http.StatusOK {
			t.Fatalf("status=%d", rec.Code)
		}
		if got := rec.Header().Get("X-Origin-Proto"); got == "HTTP/3.0" {
			if !strings.Contains(rec.Body.String(), "body=7") {
				t.Fatalf("body mangled: %q", rec.Body.String())
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("origin never saw h3; last proto=%q", rec.Header().Get("X-Origin-Proto"))
		}
		time.Sleep(50 * time.Millisecond)
	}
}
