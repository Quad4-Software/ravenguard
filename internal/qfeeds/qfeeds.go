// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package qfeeds

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Quad4-Software/ravenguard/internal/blocklist"
)

type Config struct {
	APIToken string
	BaseURL  string
	Feeds    []string
	Refresh  time.Duration
	OnError  string
	Limit    int
}

type Cache struct {
	ips     atomic.Pointer[[]net.IPNet]
	domains atomic.Pointer[map[string]struct{}]
	cfg     Config
	client  *http.Client
	stop    chan struct{}
	failed  atomic.Bool
}

func New(cfg Config) *Cache {
	c := &Cache{
		cfg:  cfg,
		stop: make(chan struct{}),
		client: &http.Client{
			Timeout: 60 * time.Second,
		},
	}
	emptyNets := []net.IPNet{}
	emptyDom := map[string]struct{}{}
	c.ips.Store(&emptyNets)
	c.domains.Store(&emptyDom)
	if cfg.OnError == "" {
		c.cfg.OnError = "fail_open"
	}
	if cfg.BaseURL == "" {
		c.cfg.BaseURL = "https://api.qfeeds.com"
	}
	return c
}

func (c *Cache) Start(ctx context.Context) {
	c.refresh(ctx)
	go func() {
		t := time.NewTicker(c.cfg.Refresh)
		defer t.Stop()
		for {
			select {
			case <-c.stop:
				return
			case <-ctx.Done():
				return
			case <-t.C:
				c.refresh(ctx)
			}
		}
	}()
}

func (c *Cache) Stop() {
	select {
	case <-c.stop:
	default:
		close(c.stop)
	}
}

func (c *Cache) IPBlocked(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if c.failed.Load() && c.cfg.OnError == "fail_closed" {
		return true
	}
	nets := c.ips.Load()
	if nets == nil {
		return false
	}
	for i := range *nets {
		if (*nets)[i].Contains(ip) {
			return true
		}
	}
	return false
}

func (c *Cache) DomainBlocked(host string) bool {
	host = blocklist.NormalizeHost(host)
	if host == "" {
		return false
	}
	if c.failed.Load() && c.cfg.OnError == "fail_closed" {
		return true
	}
	m := c.domains.Load()
	if m == nil {
		return false
	}
	if _, ok := (*m)[host]; ok {
		return true
	}
	for h := host; ; {
		i := strings.IndexByte(h, '.')
		if i < 0 {
			return false
		}
		h = h[i+1:]
		if _, ok := (*m)[h]; ok {
			return true
		}
	}
}

func (c *Cache) refresh(ctx context.Context) {
	var allIPs []net.IPNet
	domains := make(map[string]struct{})
	ok := true
	for _, feed := range c.cfg.Feeds {
		feed = strings.TrimSpace(feed)
		if feed == "" {
			continue
		}
		body, err := c.fetch(ctx, feed)
		if err != nil {
			log.Printf("qfeeds: fetch %s: %v", feed, err)
			ok = false
			continue
		}
		ips, doms := ParseFeed(feed, body)
		allIPs = append(allIPs, ips...)
		for d := range doms {
			domains[d] = struct{}{}
		}
	}
	if !ok && len(allIPs) == 0 && len(domains) == 0 {
		c.failed.Store(true)
		return
	}
	c.failed.Store(false)
	c.ips.Store(&allIPs)
	c.domains.Store(&domains)
}

func (c *Cache) fetch(ctx context.Context, feedType string) ([]byte, error) {
	u, err := url.Parse(strings.TrimRight(c.cfg.BaseURL, "/") + "/api.php")
	if err != nil {
		return nil, err
	}
	q := u.Query()
	q.Set("feed_type", feedType)
	q.Set("api_token", c.cfg.APIToken)
	if c.cfg.Limit > 0 {
		q.Set("limit", fmt.Sprintf("%d", c.cfg.Limit))
	}
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	token := base64.StdEncoding.EncodeToString([]byte("api_token:" + c.cfg.APIToken))
	req.Header.Set("Authorization", "Basic "+token)
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("status %d: %s", resp.StatusCode, string(b))
	}
	return io.ReadAll(io.LimitReader(resp.Body, 64<<20))
}

func ParseFeed(feedType string, body []byte) ([]net.IPNet, map[string]struct{}) {
	domains := make(map[string]struct{})
	var ips []net.IPNet
	sc := bufio.NewScanner(strings.NewReader(string(body)))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	isIP := strings.Contains(feedType, "ip")
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if i := strings.IndexByte(line, ','); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if isIP {
			n, err := blocklist.ParseIPOrCIDR(line)
			if err == nil {
				ips = append(ips, n)
			}
			continue
		}
		h := blocklist.NormalizeHost(line)
		if h != "" {
			domains[h] = struct{}{}
		}
	}
	return ips, domains
}
