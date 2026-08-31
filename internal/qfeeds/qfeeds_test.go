// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package qfeeds_test

import (
	"net"
	"testing"

	"github.com/Quad4-Software/ravenguard/internal/qfeeds"
)

func TestParseFeedIP(t *testing.T) {
	body := []byte("1.2.3.4\n# comment\n5.6.7.8,extra\n")
	ips, domains := qfeeds.ParseFeed("malware_ip", body)
	if len(ips) != 2 {
		t.Fatalf("ips=%d", len(ips))
	}
	if len(domains) != 0 {
		t.Fatal("domains")
	}
	if !ips[0].Contains(net.ParseIP("1.2.3.4")) {
		t.Fatal("first")
	}
}

func TestParseFeedDomains(t *testing.T) {
	body := []byte("Bad.Example\nfoo.bar\n")
	ips, domains := qfeeds.ParseFeed("malware_domains", body)
	if len(ips) != 0 {
		t.Fatal("ips")
	}
	if _, ok := domains["bad.example"]; !ok {
		t.Fatalf("%v", domains)
	}
}

func FuzzParseFeed(f *testing.F) {
	f.Add("malware_ip", "1.2.3.4\n")
	f.Add("malware_domains", "evil.test\n")
	f.Fuzz(func(t *testing.T, feed, body string) {
		_, _ = qfeeds.ParseFeed(feed, []byte(body))
	})
}
