// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package health

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"sync/atomic"
	"time"
)

type Checker struct {
	probeURL string
	interval time.Duration
	client   *http.Client
	healthy  atomic.Bool
	stop     chan struct{}
}

type Config struct {
	Enabled  bool
	URL      *url.URL
	Path     string
	Interval time.Duration
	Timeout  time.Duration
	Dial     func(ctx context.Context, network, addr string) (net.Conn, error)
}

func New(cfg Config) *Checker {
	if cfg.Path == "" {
		cfg.Path = "/healthz"
	}
	if cfg.Interval <= 0 {
		cfg.Interval = 10 * time.Second
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 3 * time.Second
	}
	transport := &http.Transport{}
	if cfg.Dial != nil {
		transport.DialContext = cfg.Dial
	}
	probe := "http://localhost" + cfg.Path
	if cfg.URL != nil && cfg.URL.Scheme != "unix" {
		u := *cfg.URL
		switch u.Scheme {
		case "ws":
			u.Scheme = "http"
		case "wss":
			u.Scheme = "https"
		}
		u.Path = cfg.Path
		u.RawQuery = ""
		probe = u.String()
	}
	c := &Checker{
		probeURL: probe,
		interval: cfg.Interval,
		client: &http.Client{
			Timeout:   cfg.Timeout,
			Transport: transport,
		},
		stop: make(chan struct{}),
	}
	c.healthy.Store(true)
	return c
}

func (c *Checker) Start(ctx context.Context) {
	c.probe(ctx)
	go func() {
		t := time.NewTicker(c.interval)
		defer t.Stop()
		for {
			select {
			case <-c.stop:
				return
			case <-ctx.Done():
				return
			case <-t.C:
				c.probe(ctx)
			}
		}
	}()
}

func (c *Checker) Stop() {
	select {
	case <-c.stop:
	default:
		close(c.stop)
	}
}

func (c *Checker) Healthy() bool {
	return c.healthy.Load()
}

func (c *Checker) probe(ctx context.Context) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.probeURL, nil)
	if err != nil {
		c.healthy.Store(false)
		return
	}
	resp, err := c.client.Do(req)
	if err != nil {
		slog.Debug("upstream health failed", "err", err)
		c.healthy.Store(false)
		return
	}
	_ = resp.Body.Close()
	ok := resp.StatusCode >= 200 && resp.StatusCode < 300
	c.healthy.Store(ok)
	if !ok {
		slog.Warn("upstream unhealthy", "status", resp.StatusCode)
	}
}
