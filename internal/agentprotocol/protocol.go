// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package agentprotocol

import "encoding/json"

const ProtocolVersion = 1

const ConnectPath = "/api/v1/agent/connect"

const (
	HeaderToken       = "X-Token"
	HeaderAgentVer    = "X-RG-Agent-Version"
	MaxFrameBytes     = 8 << 20
	ChallengeSkew     = 120 // seconds
	DefaultRPCTimeout = 30
)

const (
	OpAuthChallenge    = "auth.challenge"
	OpAuthFingerprint  = "auth.fingerprint"
	OpHeartbeat        = "heartbeat"
	OpStatus           = "status"
	OpStatusHistory    = "status.history"
	OpConfigSafeGet    = "config.safe.get"
	OpConfigSafePut    = "config.safe.put"
	OpRoutingPut       = "routing.put"
	OpDesiredApply     = "desired.apply"
	OpBansList         = "bans.list"
	OpBansCreate       = "bans.create"
	OpBansDelete       = "bans.delete"
	OpBlocklistsGet    = "blocklists.get"
	OpBlocklistsReload = "blocklists.reload"
	OpBlocklistsAdd    = "blocklists.add"
	OpBlocklistsRemove = "blocklists.remove"
	OpQFeedsGet        = "qfeeds.get"
	OpQFeedsPut        = "qfeeds.put"
	OpQFeedsRefresh    = "qfeeds.refresh"
	OpLogsSnapshot     = "logs.snapshot"
	OpRequestByRay     = "request.by_ray"
	OpRequestsRecent   = "requests.recent"
	OpCertsStatus      = "certs.status"
	OpCertsDetail      = "certs.detail"
	OpCertsPut         = "certs.put"
	OpCertsDelete      = "certs.delete"
	OpCertsExport      = "certs.export"
	OpCertsRenew       = "certs.renew"
	OpCertsManage      = "certs.manage"
	OpThreatReport     = "threat.report"
	OpThreatPull       = "threat.pull"
	OpThreatApply      = "threat.apply"
)

// Envelope is a versioned JSON RPC frame over the agent WebSocket.
type Envelope struct {
	V       int             `json:"v"`
	ID      string          `json:"id"`
	Op      string          `json:"op"`
	OK      *bool           `json:"ok,omitempty"`
	Error   string          `json:"error,omitempty"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

func okTrue() *bool {
	t := true
	return &t
}

func okFalse() *bool {
	f := false
	return &f
}

type ChallengePayload struct {
	Nonce     string `json:"nonce"`
	Timestamp int64  `json:"ts"`
	Signature string `json:"signature"`
}

type FingerprintPayload struct {
	Fingerprint string `json:"fingerprint"`
	Name        string `json:"name,omitempty"`
	Hostname    string `json:"hostname,omitempty"`
	Version     string `json:"version,omitempty"`
	ListenHTTP  string `json:"listen_http,omitempty"`
	ListenHTTPS string `json:"listen_https,omitempty"`
	ListenQUIC  string `json:"listen_quic,omitempty"`
}

type AuthOKPayload struct {
	ProxyID  string `json:"proxy_id"`
	Revision int64  `json:"revision"`
}

type DesiredState struct {
	Revision   int64           `json:"revision"`
	SafeConfig json.RawMessage `json:"safe_config,omitempty"`
	Routing    json.RawMessage `json:"routing,omitempty"`
	ACMEHosts  []string        `json:"acme_hosts,omitempty"`
}

type RoutingSnapshot struct {
	Upstreams      json.RawMessage `json:"upstreams"`
	Routes         json.RawMessage `json:"routes"`
	AccessPolicies json.RawMessage `json:"access_policies"`
	APISchemas     json.RawMessage `json:"api_schemas,omitempty"`
}

type BanCreatePayload struct {
	Key string `json:"key"`
	TTL string `json:"ttl,omitempty"`
}

type BanDeletePayload struct {
	Key string `json:"key"`
}

type BlocklistEntryPayload struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
}

type LogsPayload struct {
	Limit int    `json:"limit"`
	Level string `json:"level"`
}

type RequestByRayPayload struct {
	Ray string `json:"ray"`
}

type RequestsRecentPayload struct {
	Limit int `json:"limit"`
}

type CertHostPayload struct {
	Host    string `json:"host"`
	CertPEM string `json:"cert_pem,omitempty"`
	KeyPEM  string `json:"key_pem,omitempty"`
}

type CertExportPayload struct {
	Host    string `json:"host"`
	CertPEM string `json:"cert_pem"`
	KeyPEM  string `json:"key_pem"`
}

type CertManagePayload struct {
	Hosts []string `json:"hosts"`
}

type HeartbeatPayload struct {
	UptimeSeconds  int64 `json:"uptime_seconds"`
	ThreatRevision int64 `json:"threat_revision,omitempty"`
}

// Threat key types for fleet sharing.
const (
	ThreatKeyBind   = "bind"
	ThreatKeyUA     = "ua"
	ThreatKeyIP     = "ip"
	ThreatKeyIPHash = "ip_hash"
	ThreatKeyJA4    = "ja4"
)

// ThreatEntry is one shared threat signal (privacy-safe by default).
type ThreatEntry struct {
	ID            string `json:"id"`
	KeyType       string `json:"key_type"`
	Key           string `json:"key"`
	TTLSeconds    int64  `json:"ttl_seconds"`
	Reason        string `json:"reason,omitempty"`
	SourceProxyID string `json:"source_proxy_id,omitempty"`
	CreatedAtUnix int64  `json:"created_at_unix"`
	ExpiresAtUnix int64  `json:"expires_at_unix"`
	Revision      int64  `json:"revision,omitempty"`
}

type ThreatReportPayload struct {
	Entries []ThreatEntry `json:"entries"`
}

type ThreatPullPayload struct {
	SinceRevision int64 `json:"since_revision"`
	Limit         int   `json:"limit,omitempty"`
}

type ThreatPullResult struct {
	Revision int64         `json:"revision"`
	Entries  []ThreatEntry `json:"entries"`
}

type ThreatApplyPayload struct {
	Revision int64         `json:"revision"`
	Entries  []ThreatEntry `json:"entries"`
}
