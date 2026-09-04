// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package threatintel

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Quad4-Software/ravenguard/internal/agentprotocol"
)

type stixBundle struct {
	Type    string       `json:"type"`
	ID      string       `json:"id"`
	Spec    string       `json:"spec_version"`
	Objects []stixObject `json:"objects"`
}

type stixObject struct {
	Type           string   `json:"type"`
	SpecVersion    string   `json:"spec_version"`
	ID             string   `json:"id"`
	Created        string   `json:"created"`
	Modified       string   `json:"modified"`
	Name           string   `json:"name,omitempty"`
	Description    string   `json:"description,omitempty"`
	Pattern        string   `json:"pattern,omitempty"`
	PatternType    string   `json:"pattern_type,omitempty"`
	ValidFrom      string   `json:"valid_from,omitempty"`
	ValidUntil     string   `json:"valid_until,omitempty"`
	Labels         []string `json:"labels,omitempty"`
	Confidence     int      `json:"confidence,omitempty"`
	IndicatorTypes []string `json:"indicator_types,omitempty"`
}

// ExportSTIX builds a STIX 2.1 bundle from ledger entries.
func ExportSTIX(entries []agentprotocol.ThreatEntry, opt ExportOptions) ([]byte, int, error) {
	now := time.Now().UTC()
	objs := make([]stixObject, 0, len(entries))
	for _, e := range entries {
		ioc, ok := FromThreatEntry(e, opt)
		if !ok {
			continue
		}
		pattern, name, ok := stixPattern(ioc)
		if !ok {
			continue
		}
		id := e.ID
		if id == "" {
			id = fmt.Sprintf("%x", time.Now().UnixNano())
		}
		created := now.Format(time.RFC3339)
		if !ioc.FirstSeen.IsZero() {
			created = ioc.FirstSeen.UTC().Format(time.RFC3339)
		}
		validUntil := ""
		if e.ExpiresAtUnix > 0 {
			validUntil = time.Unix(e.ExpiresAtUnix, 0).UTC().Format(time.RFC3339)
		}
		labels := []string{"ravenguard", ioc.Type}
		if ioc.Source != "" {
			labels = append(labels, "source:"+ioc.Source)
		}
		objs = append(objs, stixObject{
			Type:           "indicator",
			SpecVersion:    "2.1",
			ID:             "indicator--" + sanitizeSTIXID(id),
			Created:        created,
			Modified:       created,
			Name:           name,
			Description:    ioc.Reason,
			Pattern:        pattern,
			PatternType:    "stix",
			ValidFrom:      created,
			ValidUntil:     validUntil,
			Labels:         labels,
			Confidence:     ioc.Confidence,
			IndicatorTypes: []string{"malicious-activity"},
		})
	}
	b := stixBundle{
		Type:    "bundle",
		ID:      "bundle--" + sanitizeSTIXID(fmt.Sprintf("%d", now.UnixNano())),
		Spec:    "2.1",
		Objects: objs,
	}
	raw, err := json.MarshalIndent(b, "", "  ")
	return raw, len(objs), err
}

func stixPattern(ioc IOC) (pattern, name string, ok bool) {
	switch ioc.Type {
	case TypeIPv4:
		return fmt.Sprintf("[ipv4-addr:value = '%s']", escapeSTIX(ioc.Value)), "ipv4:" + ioc.Value, true
	case TypeIPv6:
		return fmt.Sprintf("[ipv6-addr:value = '%s']", escapeSTIX(ioc.Value)), "ipv6:" + ioc.Value, true
	case TypeDomain:
		return fmt.Sprintf("[domain-name:value = '%s']", escapeSTIX(ioc.Value)), "domain:" + ioc.Value, true
	case TypeUA:
		return fmt.Sprintf("[user-agent:value = '%s']", escapeSTIX(ioc.Value)), "ua", true
	case TypeJA4:
		return fmt.Sprintf("[x-ja4:value = '%s']", escapeSTIX(ioc.Value)), "ja4:" + ioc.Value, true
	case TypeBind:
		return fmt.Sprintf("[x-ravenguard-bind:value = '%s']", escapeSTIX(ioc.Value)), "bind", true
	default:
		return "", "", false
	}
}

func escapeSTIX(s string) string {
	return strings.ReplaceAll(s, "'", "\\'")
}

func sanitizeSTIXID(s string) string {
	s = strings.ToLower(s)
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			b.WriteRune(r)
		} else {
			b.WriteByte('-')
		}
	}
	out := b.String()
	if out == "" {
		return "0"
	}
	return out
}

// ParseSTIX extracts IOCs from a STIX 2.x bundle.
func ParseSTIX(raw []byte) ([]IOC, error) {
	var b stixBundle
	if err := json.Unmarshal(raw, &b); err != nil {
		return nil, fmt.Errorf("stix: %w", err)
	}
	var out []IOC
	for _, o := range b.Objects {
		if !strings.EqualFold(o.Type, "indicator") || o.Pattern == "" {
			continue
		}
		ioc, ok := parseSTIXPattern(o.Pattern)
		if !ok {
			continue
		}
		ioc.Reason = o.Description
		if ioc.Reason == "" {
			ioc.Reason = o.Name
		}
		ioc.Confidence = o.Confidence
		ioc.Tags = append([]string(nil), o.Labels...)
		if o.ValidUntil != "" {
			if t, err := time.Parse(time.RFC3339, o.ValidUntil); err == nil {
				ttl := int64(time.Until(t).Seconds())
				if ttl > 0 {
					ioc.TTLSeconds = ttl
				}
			}
		}
		out = append(out, ioc)
	}
	return out, nil
}

func parseSTIXPattern(pattern string) (IOC, bool) {
	pattern = strings.TrimSpace(pattern)
	// Minimal patterns: [type:value = 'x']
	patterns := []struct {
		prefix string
		typ    string
	}{
		{"[ipv4-addr:value = '", TypeIPv4},
		{"[ipv6-addr:value = '", TypeIPv6},
		{"[domain-name:value = '", TypeDomain},
		{"[user-agent:value = '", TypeUA},
		{"[x-ja4:value = '", TypeJA4},
		{"[x-ravenguard-bind:value = '", TypeBind},
	}
	for _, p := range patterns {
		if after, ok := strings.CutPrefix(pattern, p.prefix); ok {
			rest := after
			val, _, ok := strings.Cut(rest, "']")
			if !ok {
				continue
			}
			val = strings.ReplaceAll(val, "\\'", "'")
			return IOC{Type: p.typ, Value: val}, true
		}
	}
	return IOC{}, false
}
