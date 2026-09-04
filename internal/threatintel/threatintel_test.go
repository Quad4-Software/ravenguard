// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package threatintel_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Quad4-Software/ravenguard/internal/agentprotocol"
	"github.com/Quad4-Software/ravenguard/internal/threatintel"
	"github.com/Quad4-Software/ravenguard/internal/threatshare"
)

func TestSTIXRoundTrip(t *testing.T) {
	entries := []agentprotocol.ThreatEntry{
		{ID: "a1", KeyType: agentprotocol.ThreatKeyIP, Key: "203.0.113.10", TTLSeconds: 600, Reason: "scraper", CreatedAtUnix: time.Now().Unix(), ExpiresAtUnix: time.Now().Add(time.Hour).Unix()},
		{ID: "a2", KeyType: agentprotocol.ThreatKeyDNS, Key: "evil.example", TTLSeconds: 600, CreatedAtUnix: time.Now().Unix(), ExpiresAtUnix: time.Now().Add(time.Hour).Unix()},
		{ID: "a3", KeyType: agentprotocol.ThreatKeyBind, Key: "bindhash", TTLSeconds: 600, CreatedAtUnix: time.Now().Unix(), ExpiresAtUnix: time.Now().Add(time.Hour).Unix()},
	}
	raw, n, err := threatintel.ExportSTIX(entries, threatintel.ExportOptions{ExportRawIP: true})
	if err != nil || n != 3 {
		t.Fatalf("export n=%d err=%v", n, err)
	}
	if bytes.Contains(raw, []byte(entries[0].Key)) == false {
		t.Fatal("expected ip in export when ExportRawIP")
	}
	iocs, err := threatintel.ParseSTIX(raw)
	if err != nil || len(iocs) < 2 {
		t.Fatalf("parse len=%d err=%v", len(iocs), err)
	}
}

func TestExportPrivacyHidesRawIP(t *testing.T) {
	entries := []agentprotocol.ThreatEntry{
		{ID: "1", KeyType: agentprotocol.ThreatKeyIP, Key: "198.51.100.9", TTLSeconds: 60, CreatedAtUnix: time.Now().Unix(), ExpiresAtUnix: time.Now().Add(time.Minute).Unix()},
		{ID: "2", KeyType: agentprotocol.ThreatKeyUA, Key: "badbot", TTLSeconds: 60, CreatedAtUnix: time.Now().Unix(), ExpiresAtUnix: time.Now().Add(time.Minute).Unix()},
	}
	raw, n, err := threatintel.ExportSTIX(entries, threatintel.ExportOptions{ExportRawIP: false})
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("want 1 (ua only) got %d", n)
	}
	if bytes.Contains(raw, []byte("198.51.100.9")) {
		t.Fatal("raw ip leaked")
	}
	var buf bytes.Buffer
	cn, err := threatintel.ExportCSV(&buf, entries, threatintel.ExportOptions{ExportRawIP: false})
	if err != nil || cn != 1 {
		t.Fatalf("csv n=%d err=%v", cn, err)
	}
	if strings.Contains(buf.String(), "198.51.100.9") {
		t.Fatal("csv leaked ip")
	}
}

func TestCSVParseAndIngest(t *testing.T) {
	csv := "type,value,ttl_seconds,reason,source,confidence\nipv4,203.0.113.50,300,bot,test,90\ndomain,bad.example,300,phish,test,80\n"
	iocs, err := threatintel.ParseCSV(strings.NewReader(csv))
	if err != nil || len(iocs) != 2 {
		t.Fatalf("parse %d %v", len(iocs), err)
	}
	sink := &memSink{}
	res, err := threatintel.IngestIOCs(sink, "csv", iocs, time.Hour)
	if err != nil || res.Stored != 2 {
		t.Fatalf("ingest %+v err=%v", res, err)
	}
	ov := threatshare.NewOverlay(100)
	ap := &threatshare.Applier{Overlay: ov}
	ap.Apply(sink.entries)
	if !ov.DNSBlocked("www.bad.example") {
		t.Fatal("dns")
	}
}

func TestCSVRejectsUnknownType(t *testing.T) {
	iocs, err := threatintel.ParseCSV(strings.NewReader("type,value\nftp,x\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(iocs) != 1 {
		t.Fatalf("len=%d", len(iocs))
	}
	if _, ok := threatintel.ToThreatEntry(iocs[0], time.Hour); ok {
		t.Fatal("ftp should not map")
	}
}

func TestMISPAttributeFilter(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(401)
			return
		}
		var req map[string]any
		_ = json.NewDecoder(r.Body).Decode(&req)
		typ, _ := req["type"].(string)
		attrs := []map[string]any{}
		switch typ {
		case "ip-dst":
			attrs = append(attrs, map[string]any{"type": "ip-dst", "value": "203.0.113.88"})
		case "domain":
			attrs = append(attrs, map[string]any{"type": "domain", "value": "phish.example"})
		case "user-agent":
			attrs = append(attrs, map[string]any{"type": "user-agent", "value": "EvilBot/"})
		case "hostname":
			attrs = append(attrs, map[string]any{"type": "hostname", "value": "bad.host.example"})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"response": map[string]any{"Attribute": attrs},
		})
	}))
	defer srv.Close()
	c := &threatintel.MISPClient{URL: srv.URL, APIKey: "k", HTTPClient: srv.Client()}
	iocs, err := c.FetchAttributes(context.Background(), time.Now().Add(-time.Hour), 50)
	if err != nil {
		t.Fatal(err)
	}
	var sawIP, sawDomain, sawUA bool
	for _, ioc := range iocs {
		switch ioc.Type {
		case threatintel.TypeIPv4:
			if ioc.Value == "203.0.113.88" {
				sawIP = true
			}
		case threatintel.TypeDomain:
			sawDomain = true
		case threatintel.TypeUA:
			sawUA = true
		}
	}
	if !sawIP || !sawDomain || !sawUA {
		t.Fatalf("filter incomplete: ip=%v domain=%v ua=%v len=%d", sawIP, sawDomain, sawUA, len(iocs))
	}
}

func TestAbuseIPDBMock(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Key") == "" {
			w.WriteHeader(401)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": []map[string]any{{"ipAddress": "203.0.113.77", "abuseConfidenceScore": 99}},
		})
	}))
	defer srv.Close()
	c := &threatintel.AbuseIPDBClient{APIKey: "k", BaseURL: srv.URL, HTTPClient: srv.Client()}
	iocs, err := c.FetchBlacklist(context.Background(), 80, 10)
	if err != nil || len(iocs) != 1 {
		t.Fatalf("%v %v", iocs, err)
	}
}

func TestUAToThreatEntry(t *testing.T) {
	iocs, err := threatintel.ParseCSV(strings.NewReader("type,value\nuser-agent,curl/\n"))
	if err != nil || len(iocs) != 1 {
		t.Fatal(err)
	}
	e, ok := threatintel.ToThreatEntry(iocs[0], time.Hour)
	if !ok || e.KeyType != agentprotocol.ThreatKeyUA {
		t.Fatalf("%+v", e)
	}
}

func TestIngestRace(t *testing.T) {
	sink := &memSink{}
	var wg sync.WaitGroup
	for i := range 16 {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for range 20 {
				_, _ = threatintel.IngestIOCs(sink, "race", []threatintel.IOC{
					{Type: threatintel.TypeDomain, Value: "x.example", TTLSeconds: 60},
				}, time.Minute)
			}
		}(i)
	}
	wg.Wait()
	if len(sink.entries) == 0 {
		t.Fatal("expected entries")
	}
}

func TestDNSOverlay(t *testing.T) {
	ov := threatshare.NewOverlay(10)
	now := time.Now()
	threatshare.ApplyOne(nil, ov, agentprotocol.ThreatEntry{
		ID: "d", KeyType: agentprotocol.ThreatKeyDNS, Key: "blocked.test",
		ExpiresAtUnix: now.Add(time.Minute).Unix(),
	}, now)
	if !ov.DNSBlocked("a.blocked.test") {
		t.Fatal("suffix")
	}
	st := ov.Stats()
	if st["dns"] != 1 {
		t.Fatalf("%+v", st)
	}
}

type memSink struct {
	mu      sync.Mutex
	entries []agentprotocol.ThreatEntry
	rev     int64
}

func (m *memSink) InsertThreatEntries(source string, entries []agentprotocol.ThreatEntry) ([]agentprotocol.ThreatEntry, int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]agentprotocol.ThreatEntry, 0, len(entries))
	for _, e := range entries {
		m.rev++
		e.ID = time.Now().Format("150405.000000000")
		e.Revision = m.rev
		e.SourceProxyID = source
		m.entries = append(m.entries, e)
		out = append(out, e)
	}
	return out, m.rev, nil
}
