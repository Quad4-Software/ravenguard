// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package threatintel

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// AbuseIPDBClient talks to api.abuseipdb.com v2.
type AbuseIPDBClient struct {
	APIKey     string
	HTTPClient *http.Client
	BaseURL    string
}

func (c *AbuseIPDBClient) client() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return http.DefaultClient
}

func (c *AbuseIPDBClient) base() string {
	if c.BaseURL != "" {
		return strings.TrimRight(c.BaseURL, "/")
	}
	return "https://api.abuseipdb.com/api/v2"
}

type abuseBlacklistResp struct {
	Data []struct {
		IPAddress            string  `json:"ipAddress"`
		AbuseConfidenceScore int     `json:"abuseConfidenceScore"`
		LastReportedAt       string  `json:"lastReportedAt"`
		CountryCode          string  `json:"countryCode"`
		Score                float64 `json:"score"`
	} `json:"data"`
}

// FetchBlacklist pulls the AbuseIPDB blacklist as IOCs.
func (c *AbuseIPDBClient) FetchBlacklist(ctx context.Context, minConfidence, limit int) ([]IOC, error) {
	if strings.TrimSpace(c.APIKey) == "" {
		return nil, fmt.Errorf("abuseipdb: api key required")
	}
	if limit <= 0 {
		limit = 10000
	}
	if minConfidence < 0 {
		minConfidence = 0
	}
	u, _ := url.Parse(c.base() + "/blacklist")
	q := u.Query()
	q.Set("confidenceMinimum", strconv.Itoa(minConfidence))
	q.Set("limit", strconv.Itoa(limit))
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Key", c.APIKey)
	req.Header.Set("Accept", "application/json")
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("abuseipdb: status %d", resp.StatusCode)
	}
	var parsed abuseBlacklistResp
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("abuseipdb: decode: %w", err)
	}
	out := make([]IOC, 0, len(parsed.Data))
	for _, row := range parsed.Data {
		ip := strings.TrimSpace(row.IPAddress)
		if ip == "" {
			continue
		}
		typ := TypeIPv4
		if strings.Contains(ip, ":") {
			typ = TypeIPv6
		}
		out = append(out, IOC{
			Type:       typ,
			Value:      ip,
			Confidence: row.AbuseConfidenceScore,
			Reason:     "abuseipdb blacklist",
			Source:     "abuseipdb",
			Tags:       []string{"abuseipdb"},
		})
	}
	return out, nil
}

// ReportIP reports a single IP to AbuseIPDB (categories as comma-separated ints).
func (c *AbuseIPDBClient) ReportIP(ctx context.Context, ip, comment string, categories []int) error {
	if strings.TrimSpace(c.APIKey) == "" {
		return fmt.Errorf("abuseipdb: api key required")
	}
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return fmt.Errorf("abuseipdb: ip required")
	}
	if len(categories) == 0 {
		categories = []int{14} // port scan default; 15=hacking, 21=web app attack
	}
	form := url.Values{}
	form.Set("ip", ip)
	cats := make([]string, len(categories))
	for i, c := range categories {
		cats[i] = strconv.Itoa(c)
	}
	form.Set("categories", strings.Join(cats, ","))
	if comment != "" {
		form.Set("comment", comment)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base()+"/report", bytes.NewBufferString(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Key", c.APIKey)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.client().Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 300 {
		return fmt.Errorf("abuseipdb: report status %d", resp.StatusCode)
	}
	return nil
}

// FetchURL downloads bytes from a URL for ingest.
func FetchURL(ctx context.Context, rawURL string, client *http.Client) ([]byte, string, error) {
	if client == nil {
		client = http.DefaultClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 300 {
		return nil, "", fmt.Errorf("fetch status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	ct := resp.Header.Get("Content-Type")
	return body, ct, err
}

// DetectFormat guesses csv vs stix from content-type or body.
func DetectFormat(contentType string, body []byte) string {
	ct := strings.ToLower(contentType)
	if strings.Contains(ct, "json") || strings.Contains(ct, "stix") {
		return "stix"
	}
	if strings.Contains(ct, "csv") || strings.Contains(ct, "text/plain") {
		trim := bytes.TrimSpace(body)
		if len(trim) > 0 && trim[0] == '{' {
			return "stix"
		}
		return "csv"
	}
	trim := bytes.TrimSpace(body)
	if len(trim) > 0 && (trim[0] == '{' || trim[0] == '[') {
		return "stix"
	}
	return "csv"
}

// ParseIngestBody parses CSV or STIX bytes into IOCs.
func ParseIngestBody(format string, body []byte) ([]IOC, error) {
	switch strings.ToLower(format) {
	case "stix", "json", "application/json", "application/stix+json":
		return ParseSTIX(body)
	default:
		return ParseCSV(bytes.NewReader(body))
	}
}

// Sleep is exported for tests to override.
var Sleep = time.Sleep
