// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package health_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/Quad4-Software/ravenguard/internal/health"
)

func TestCheckerProbeHealthyAndUnhealthy(t *testing.T) {
	okSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(okSrv.Close)
	badSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(badSrv.Close)

	okURL, _ := url.Parse(okSrv.URL)
	c := health.New(health.Config{
		URL:      okURL,
		Path:     "/",
		Interval: time.Hour,
		Timeout:  time.Second,
	})
	ctx := context.Background()
	c.Start(ctx)
	t.Cleanup(c.Stop)
	time.Sleep(20 * time.Millisecond)
	if !c.Healthy() {
		t.Fatal("expected healthy")
	}

	badURL, _ := url.Parse(badSrv.URL)
	c2 := health.New(health.Config{
		URL:      badURL,
		Path:     "/",
		Interval: time.Hour,
		Timeout:  time.Second,
	})
	c2.Start(ctx)
	t.Cleanup(c2.Stop)
	time.Sleep(20 * time.Millisecond)
	if c2.Healthy() {
		t.Fatal("expected unhealthy")
	}
}

func TestCheckerDefaultsAndUnixScheme(t *testing.T) {
	c := health.New(health.Config{})
	if c == nil {
		t.Fatal("nil checker")
	}
	u, _ := url.Parse("ws://example.com/app")
	c2 := health.New(health.Config{URL: u, Path: "/ready"})
	if c2 == nil {
		t.Fatal("nil ws checker")
	}
	u2, _ := url.Parse("unix:///tmp/rg.sock")
	c3 := health.New(health.Config{URL: u2})
	if c3 == nil {
		t.Fatal("nil unix checker")
	}
}
