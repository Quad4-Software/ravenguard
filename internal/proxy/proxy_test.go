// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package proxy_test

import (
	"context"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Quad4-Software/ravenguard/internal/proxy"
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
