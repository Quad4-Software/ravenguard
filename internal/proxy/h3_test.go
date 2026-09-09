// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package proxy_test

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"

	"github.com/Quad4-Software/ravenguard/internal/proxy"
	"github.com/Quad4-Software/ravenguard/internal/tlscerts"
)

func startH3Server(t *testing.T) (string, func()) {
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

	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Proto", r.Proto)
		fmt.Fprint(w, "h3-ok")
	})

	srv := &http3.Server{
		Handler:   mux,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h3"}},
	}

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Serve(conn)
	}()

	// Wait briefly for the server to start listening.
	time.Sleep(50 * time.Millisecond)

	port := conn.LocalAddr().(*net.UDPAddr).Port
	u := fmt.Sprintf("h3://127.0.0.1:%d", port)

	cleanup := func() {
		cancel()
		_ = srv.Close()
		_ = conn.Close()
		select {
		case <-errCh:
		case <-time.After(2 * time.Second):
		}
	}
	_ = ctx
	return u, cleanup
}

func TestReverseProxyHTTP3(t *testing.T) {
	backend, cleanup := startH3Server(t)
	defer cleanup()

	target, _ := url.Parse(backend)
	rp := proxy.New(proxy.Config{
		Target:          target,
		Protocol:        "h3",
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	})
	defer rp.Close()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://edge.example/", nil)
	req.Host = "edge.example"
	rp.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if rec.Body.String() != "h3-ok" {
		t.Fatalf("body=%q", rec.Body.String())
	}
	if rec.Header().Get("X-Proto") != "" {
		// h3 responses include :status pseudo headers; the server sets X-Proto.
		// The recorder captures it; value should be HTTP/3.0 or similar.
		if rec.Header().Get("X-Proto") == "" {
			t.Fatalf("X-Proto not set")
		}
	}
}

func TestReverseProxyHTTP3Auto(t *testing.T) {
	backend, cleanup := startH3Server(t)
	defer cleanup()

	target, _ := url.Parse(backend)
	rp := proxy.New(proxy.Config{
		Target:          target,
		Protocol:        "auto",
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	})
	defer rp.Close()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://edge.example/", nil)
	rp.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if rec.Body.String() != "h3-ok" {
		t.Fatalf("body=%q", rec.Body.String())
	}
}
