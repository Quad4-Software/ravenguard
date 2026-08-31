// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package sentry_test

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Quad4-Software/ravenguard/internal/config"
	"github.com/Quad4-Software/ravenguard/internal/sentry"
)

func TestInitDisabled(t *testing.T) {
	r, err := sentry.Init(config.SentryConfig{Enabled: false})
	if err != nil {
		t.Fatal(err)
	}
	if r.Enabled() {
		t.Fatal("expected disabled")
	}
	r.CaptureException(nil)
	r.CaptureMessage("noop")
	r.Flush()
	h := r.Wrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/", nil))
	if rr.Code != http.StatusNoContent {
		t.Fatalf("code=%d", rr.Code)
	}
}

func TestInitRequiresValidDSNWhenEnabled(t *testing.T) {
	_, err := sentry.Init(config.SentryConfig{
		Enabled:      true,
		DSN:          "not-a-dsn",
		FlushTimeout: config.Duration{Duration: time.Second},
	})
	if err == nil {
		t.Fatal("expected init error for invalid dsn")
	}
}

func TestWrapHandlerPassthrough(t *testing.T) {
	r, err := sentry.Init(config.SentryConfig{})
	if err != nil {
		t.Fatal(err)
	}
	base := slog.Default().Handler()
	h := sentry.WrapHandler(base, r)
	if h != base {
		t.Fatal("disabled wrap should return base handler")
	}
}

func TestCaptureUpstreamGated(t *testing.T) {
	r, err := sentry.Init(config.SentryConfig{
		Enabled:         true,
		DSN:             "",
		CaptureUpstream: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if r.CaptureUpstream() {
		t.Fatal("empty dsn must leave reporter disabled")
	}
}
