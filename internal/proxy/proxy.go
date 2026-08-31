// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package proxy

import (
	"context"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"
)

type Config struct {
	Target                *url.URL
	ConnectTimeout        time.Duration
	ResponseHeaderTimeout time.Duration
	IdleConnTimeout       time.Duration
	MaxIdleConns          int
	MaxIdleConnsPerHost   int
	MaxConnsPerHost       int
	FlushInterval         time.Duration
	SetHeaders            map[string]string
	ErrorHandler          func(http.ResponseWriter, *http.Request, error)
}

func New(cfg Config) *httputil.ReverseProxy {
	dial := DialFunc(cfg.Target, cfg.ConnectTimeout)
	maxIdle := cfg.MaxIdleConns
	if maxIdle <= 0 {
		maxIdle = 256
	}
	perHost := cfg.MaxIdleConnsPerHost
	if perHost <= 0 {
		perHost = maxIdle
	}
	maxConns := max(cfg.MaxConnsPerHost, 0)
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           dial,
		ForceAttemptHTTP2:     !IsUnix(cfg.Target),
		MaxIdleConns:          maxIdle,
		MaxIdleConnsPerHost:   perHost,
		MaxConnsPerHost:       maxConns,
		IdleConnTimeout:       cfg.IdleConnTimeout,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: cfg.ResponseHeaderTimeout,
		DisableCompression:    true,
		WriteBufferSize:       32 << 10,
		ReadBufferSize:        32 << 10,
	}

	target := normalizeTarget(cfg.Target)
	setHeaders := cfg.SetHeaders
	rp := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = target.Scheme
			req.URL.Host = target.Host
			if IsUnix(cfg.Target) {
				req.URL.Scheme = "http"
				req.URL.Host = "localhost"
				req.Host = "localhost"
			} else {
				req.Host = target.Host
			}
			for k, v := range setHeaders {
				req.Header.Set(k, v)
			}
		},
		Transport:     transport,
		FlushInterval: cfg.FlushInterval,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			if cfg.ErrorHandler != nil {
				cfg.ErrorHandler(w, r, err)
				return
			}
			http.Error(w, "upstream unavailable", http.StatusBadGateway)
		},
	}
	return rp
}

func IsUnix(u *url.URL) bool {
	if u == nil {
		return false
	}
	return u.Scheme == "unix" || strings.HasPrefix(u.Path, "/") && u.Host == "" && u.Scheme == ""
}

func UnixPath(u *url.URL) string {
	if u == nil {
		return ""
	}
	if u.Scheme == "unix" {
		if u.Path != "" {
			return u.Path
		}
		return u.Opaque
	}
	return u.Path
}

func DialFunc(target *url.URL, timeout time.Duration) func(ctx context.Context, network, addr string) (net.Conn, error) {
	d := &net.Dialer{
		Timeout:   timeout,
		KeepAlive: 30 * time.Second,
	}
	if target != nil && target.Scheme == "unix" {
		path := UnixPath(target)
		return func(ctx context.Context, network, addr string) (net.Conn, error) {
			return d.DialContext(ctx, "unix", path)
		}
	}
	return d.DialContext
}

func normalizeTarget(u *url.URL) *url.URL {
	if u == nil {
		return &url.URL{Scheme: "http", Host: "127.0.0.1"}
	}
	out := *u
	if out.Scheme == "unix" {
		out.Scheme = "http"
		out.Host = "localhost"
		out.Path = ""
		out.Opaque = ""
	}
	return &out
}

func ParseSetHeaders(list []string) map[string]string {
	out := make(map[string]string, len(list))
	for _, s := range list {
		k, v, ok := strings.Cut(s, ":")
		if !ok {
			continue
		}
		out[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	return out
}

func ParseUpstreamURL(raw string) (*url.URL, error) {
	if after, ok := strings.CutPrefix(raw, "unix://"); ok {
		path := after
		return &url.URL{Scheme: "unix", Path: path}, nil
	}
	if after, ok := strings.CutPrefix(raw, "unix:"); ok {
		path := after
		return &url.URL{Scheme: "unix", Path: path}, nil
	}
	return url.Parse(raw)
}
