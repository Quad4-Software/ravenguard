// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

// Package sentry wires the Sentry Go SDK for Sentry and GlitchTip backends.
package sentry

import (
	"fmt"
	"log/slog"
	"net/http"
	"runtime/debug"
	"strings"
	"time"

	sdk "github.com/getsentry/sentry-go"
	sentryhttp "github.com/getsentry/sentry-go/http"

	"github.com/Quad4-Software/ravenguard/internal/config"
)

// Reporter holds Sentry client state after Init.
type Reporter struct {
	enabled         bool
	flushTimeout    time.Duration
	captureUpstream bool
	handler         *sentryhttp.Handler
}

var active *Reporter

// Init configures the global Sentry client when enabled.
// Safe to call when disabled: returns a no-op reporter.
func Init(cfg config.SentryConfig) (*Reporter, error) {
	r := &Reporter{
		enabled:         cfg.Enabled && strings.TrimSpace(cfg.DSN) != "",
		flushTimeout:    cfg.FlushTimeout.Duration,
		captureUpstream: cfg.CaptureUpstream,
	}
	if r.flushTimeout <= 0 {
		r.flushTimeout = 2 * time.Second
	}
	if !r.enabled {
		active = r
		return r, nil
	}

	release := strings.TrimSpace(cfg.Release)
	if release == "" {
		release = defaultRelease()
	}

	opts := sdk.ClientOptions{
		Dsn:              strings.TrimSpace(cfg.DSN),
		Environment:      strings.TrimSpace(cfg.Environment),
		Release:          release,
		ServerName:       strings.TrimSpace(cfg.ServerName),
		SampleRate:       cfg.SampleRate,
		TracesSampleRate: cfg.TracesSampleRate,
		EnableTracing:    cfg.TracesSampleRate > 0,
		Debug:            cfg.Debug,
		AttachStacktrace: cfg.AttachStacktrace,
		BeforeSend:       scrubEvent,
	}
	if cfg.SendDefaultPII {
		opts.DataCollection = &sdk.DataCollection{
			UserInfo: sdk.Set(true),
		}
	} else {
		opts.DataCollection = &sdk.DataCollection{
			UserInfo: sdk.Set(false),
		}
	}
	if opts.SampleRate <= 0 {
		opts.SampleRate = 1.0
	}

	if err := sdk.Init(opts); err != nil {
		return nil, fmt.Errorf("sentry init: %w", err)
	}

	r.handler = sentryhttp.New(sentryhttp.Options{
		Repanic:         true,
		WaitForDelivery: false,
		Timeout:         r.flushTimeout,
	})
	active = r
	slog.Info("sentry enabled",
		"environment", opts.Environment,
		"release", opts.Release,
		"traces_sample_rate", opts.TracesSampleRate,
		"capture_upstream", r.captureUpstream,
	)
	return r, nil
}

func defaultRelease() string {
	info, ok := debug.ReadBuildInfo()
	if !ok || info == nil {
		return "ravenguard@unknown"
	}
	v := info.Main.Version
	if v == "" || v == "(devel)" {
		v = "devel"
	}
	return "ravenguard@" + v
}

func scrubEvent(event *sdk.Event, _ *sdk.EventHint) *sdk.Event {
	if event == nil {
		return nil
	}
	if event.Request != nil {
		event.Request.Cookies = ""
		if event.Request.Headers != nil {
			for k := range event.Request.Headers {
				lk := strings.ToLower(k)
				if lk == "cookie" || lk == "authorization" || lk == "proxy-authorization" ||
					lk == "x-api-key" || strings.Contains(lk, "secret") || strings.Contains(lk, "token") {
					delete(event.Request.Headers, k)
				}
			}
		}
	}
	return event
}

// Enabled reports whether events will be sent.
func (r *Reporter) Enabled() bool {
	return r != nil && r.enabled
}

// CaptureUpstream reports whether upstream proxy errors should be sent.
func (r *Reporter) CaptureUpstream() bool {
	return r != nil && r.enabled && r.captureUpstream
}

// Wrap attaches panic recovery and per-request Sentry hubs.
func (r *Reporter) Wrap(next http.Handler) http.Handler {
	if r == nil || !r.enabled || r.handler == nil {
		return next
	}
	return r.handler.Handle(next)
}

// CaptureException sends an error event when enabled.
func (r *Reporter) CaptureException(err error) {
	if r == nil || !r.enabled || err == nil {
		return
	}
	sdk.CaptureException(err)
}

// CaptureMessage sends a message event when enabled.
func (r *Reporter) CaptureMessage(msg string) {
	if r == nil || !r.enabled || msg == "" {
		return
	}
	sdk.CaptureMessage(msg)
}

// CaptureUpstreamError reports an origin proxy failure when configured.
func (r *Reporter) CaptureUpstreamError(err error, ray string) {
	if !r.CaptureUpstream() || err == nil {
		return
	}
	sdk.WithScope(func(scope *sdk.Scope) {
		scope.SetTag("component", "upstream")
		if ray != "" {
			scope.SetTag("ray", ray)
		}
		scope.SetLevel(sdk.LevelError)
		sdk.CaptureException(err)
	})
}

// Flush drains buffered events. Call on shutdown.
func (r *Reporter) Flush() {
	if r == nil || !r.enabled {
		return
	}
	sdk.Flush(r.flushTimeout)
}

// Active returns the last Init reporter, or a disabled no-op.
func Active() *Reporter {
	if active != nil {
		return active
	}
	return &Reporter{}
}

// CaptureException sends via the active reporter.
func CaptureException(err error) {
	Active().CaptureException(err)
}

// CaptureMessage sends via the active reporter.
func CaptureMessage(msg string) {
	Active().CaptureMessage(msg)
}
