// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package threatintel

import (
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

// MISPClient is a thin REST client for attribute pulls.
type MISPClient struct {
	URL        string
	APIKey     string
	HTTPClient *http.Client
	VerifyTLS  bool
}

func (c *MISPClient) client() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return http.DefaultClient
}

type mispAttrSearchReq struct {
	ReturnFormat string `json:"returnFormat"`
	Type         string `json:"type,omitempty"`
	Timestamp    string `json:"timestamp,omitempty"`
	Limit        int    `json:"limit,omitempty"`
	Page         int    `json:"page,omitempty"`
}

type mispAttrResp struct {
	Response struct {
		Attribute []struct {
			Type  string `json:"type"`
			Value string `json:"value"`
			Event struct {
				Info string `json:"info"`
			} `json:"Event"`
			Timestamp string `json:"timestamp"`
		} `json:"Attribute"`
	} `json:"response"`
}

// FetchAttributes pulls recent ip-dst, domain, and user-agent attributes.
func (c *MISPClient) FetchAttributes(ctx context.Context, since time.Time, limit int) ([]IOC, error) {
	if strings.TrimSpace(c.URL) == "" || strings.TrimSpace(c.APIKey) == "" {
		return nil, fmt.Errorf("misp: url and api key required")
	}
	if limit <= 0 {
		limit = 500
	}
	base := strings.TrimRight(c.URL, "/")
	types := []string{"ip-dst", "ip-src", "domain", "hostname", "user-agent"}
	var out []IOC
	for _, typ := range types {
		batch, err := c.fetchType(ctx, base, typ, since, limit)
		if err != nil {
			return out, err
		}
		out = append(out, batch...)
	}
	return out, nil
}

func (c *MISPClient) fetchType(ctx context.Context, base, typ string, since time.Time, limit int) ([]IOC, error) {
	body := mispAttrSearchReq{
		ReturnFormat: "json",
		Type:         typ,
		Limit:        limit,
		Page:         1,
	}
	if !since.IsZero() {
		body.Timestamp = strconv.FormatInt(since.Unix(), 10)
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	endpoint := base + "/attributes/restSearch"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(string(raw)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", c.APIKey)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("misp: status %d", resp.StatusCode)
	}
	var parsed mispAttrResp
	if err := json.Unmarshal(data, &parsed); err != nil {
		// Some MISP versions return Attribute at top level.
		var alt struct {
			Attribute []struct {
				Type  string `json:"type"`
				Value string `json:"value"`
			} `json:"Attribute"`
		}
		if uerr := json.Unmarshal(data, &alt); uerr != nil {
			return nil, fmt.Errorf("misp: decode: %w", err)
		}
		out := make([]IOC, 0, len(alt.Attribute))
		for _, a := range alt.Attribute {
			if ioc, ok := mispAttrToIOC(a.Type, a.Value); ok {
				out = append(out, ioc)
			}
		}
		return out, nil
	}
	out := make([]IOC, 0, len(parsed.Response.Attribute))
	for _, a := range parsed.Response.Attribute {
		ioc, ok := mispAttrToIOC(a.Type, a.Value)
		if !ok {
			continue
		}
		ioc.Reason = a.Event.Info
		if ioc.Reason == "" {
			ioc.Reason = "misp"
		}
		ioc.Source = "misp"
		out = append(out, ioc)
	}
	return out, nil
}

func mispAttrToIOC(typ, value string) (IOC, bool) {
	typ = strings.ToLower(strings.TrimSpace(typ))
	value = strings.TrimSpace(value)
	if value == "" {
		return IOC{}, false
	}
	switch typ {
	case "ip-dst", "ip-src":
		t := TypeIPv4
		if strings.Contains(value, ":") {
			t = TypeIPv6
		}
		return IOC{Type: t, Value: value, Source: "misp", Tags: []string{"misp"}}, true
	case "domain", "hostname":
		return IOC{Type: TypeDomain, Value: strings.ToLower(value), Source: "misp", Tags: []string{"misp"}}, true
	case "user-agent":
		return IOC{Type: TypeUA, Value: value, Source: "misp", Tags: []string{"misp"}}, true
	default:
		return IOC{}, false
	}
}

// ValidateURL soft-checks misp URL scheme.
func ValidateURL(raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("url scheme must be http or https")
	}
	if u.Host == "" {
		return fmt.Errorf("url host required")
	}
	return nil
}
