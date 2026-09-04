// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package threatintel

import (
	"net"
	"strings"
	"time"

	"github.com/Quad4-Software/ravenguard/internal/agentprotocol"
)

// Normalized IOC types for interchange.
const (
	TypeIPv4   = "ipv4"
	TypeIPv6   = "ipv6"
	TypeDomain = "domain"
	TypeUA     = "ua"
	TypeJA4    = "ja4"
	TypeBind   = "bind"
)

// IOC is a normalized indicator of compromise.
type IOC struct {
	Type       string    `json:"type"`
	Value      string    `json:"value"`
	TTLSeconds int64     `json:"ttl_seconds"`
	Reason     string    `json:"reason,omitempty"`
	Source     string    `json:"source,omitempty"`
	Confidence int       `json:"confidence,omitempty"`
	Tags       []string  `json:"tags,omitempty"`
	FirstSeen  time.Time `json:"first_seen,omitempty"`
	LastSeen   time.Time `json:"last_seen,omitempty"`
}

// ExportOptions controls privacy of exports.
type ExportOptions struct {
	ExportRawIP bool
	DefaultTTL  time.Duration
}

// FromThreatEntry maps a ledger entry to an IOC for export.
func FromThreatEntry(e agentprotocol.ThreatEntry, opt ExportOptions) (IOC, bool) {
	kt := strings.ToLower(strings.TrimSpace(e.KeyType))
	key := strings.TrimSpace(e.Key)
	if key == "" {
		return IOC{}, false
	}
	ttl := e.TTLSeconds
	if ttl <= 0 && e.ExpiresAtUnix > 0 {
		ttl = e.ExpiresAtUnix - time.Now().Unix()
	}
	if ttl <= 0 {
		if opt.DefaultTTL > 0 {
			ttl = int64(opt.DefaultTTL / time.Second)
		} else {
			ttl = 86400
		}
	}
	ioc := IOC{
		TTLSeconds: ttl,
		Reason:     e.Reason,
		Source:     e.SourceProxyID,
		FirstSeen:  time.Unix(e.CreatedAtUnix, 0),
		LastSeen:   time.Unix(e.CreatedAtUnix, 0),
	}
	switch kt {
	case agentprotocol.ThreatKeyIP:
		ip := net.ParseIP(key)
		if ip == nil {
			return IOC{}, false
		}
		if !opt.ExportRawIP {
			return IOC{}, false
		}
		if ip.To4() != nil {
			ioc.Type = TypeIPv4
		} else {
			ioc.Type = TypeIPv6
		}
		ioc.Value = ip.String()
	case agentprotocol.ThreatKeyDNS:
		ioc.Type = TypeDomain
		ioc.Value = strings.ToLower(key)
	case agentprotocol.ThreatKeyUA:
		ioc.Type = TypeUA
		ioc.Value = key
	case agentprotocol.ThreatKeyJA4:
		ioc.Type = TypeJA4
		ioc.Value = key
	case agentprotocol.ThreatKeyBind, agentprotocol.ThreatKeyIPHash:
		ioc.Type = TypeBind
		ioc.Value = key
	default:
		return IOC{}, false
	}
	return ioc, true
}

// ToThreatEntry maps an ingested IOC to a ledger entry.
func ToThreatEntry(ioc IOC, defaultTTL time.Duration) (agentprotocol.ThreatEntry, bool) {
	typ := strings.ToLower(strings.TrimSpace(ioc.Type))
	val := strings.TrimSpace(ioc.Value)
	if val == "" {
		return agentprotocol.ThreatEntry{}, false
	}
	ttl := ioc.TTLSeconds
	if ttl <= 0 {
		if defaultTTL > 0 {
			ttl = int64(defaultTTL / time.Second)
		} else {
			ttl = 86400
		}
	}
	if ttl > 86400*7 {
		ttl = 86400 * 7
	}
	now := time.Now()
	e := agentprotocol.ThreatEntry{
		TTLSeconds:    ttl,
		Reason:        strings.TrimSpace(ioc.Reason),
		SourceProxyID: strings.TrimSpace(ioc.Source),
		CreatedAtUnix: now.Unix(),
		ExpiresAtUnix: now.Add(time.Duration(ttl) * time.Second).Unix(),
	}
	if e.SourceProxyID == "" {
		e.SourceProxyID = "threatintel"
	}
	if e.Reason == "" {
		e.Reason = "ingested"
	}
	switch typ {
	case TypeIPv4, TypeIPv6, "ip":
		ip := net.ParseIP(val)
		if ip == nil {
			return agentprotocol.ThreatEntry{}, false
		}
		e.KeyType = agentprotocol.ThreatKeyIP
		e.Key = ip.String()
	case TypeDomain, "dns", "hostname":
		e.KeyType = agentprotocol.ThreatKeyDNS
		e.Key = strings.ToLower(strings.TrimSuffix(val, "."))
	case TypeUA, "user-agent", "user_agent":
		e.KeyType = agentprotocol.ThreatKeyUA
		e.Key = val
		if len(e.Key) > 120 {
			e.Key = e.Key[:120]
		}
	case TypeJA4:
		e.KeyType = agentprotocol.ThreatKeyJA4
		e.Key = val
	case TypeBind:
		e.KeyType = agentprotocol.ThreatKeyBind
		e.Key = val
	default:
		return agentprotocol.ThreatEntry{}, false
	}
	return e, true
}
