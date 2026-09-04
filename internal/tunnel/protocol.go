// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package tunnel

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

const (
	ConnectPath   = "/api/v1/tunnel/connect"
	HeaderTicket  = "X-RG-Tunnel-Ticket"
	MaxUpstreamID = 128
	MaxStreams    = 256
	TicketTTL     = 15 * time.Minute
)

// Ticket is a short-lived hub-issued credential for tunnel dial.
type Ticket struct {
	ConnectorID string `json:"connector_id"`
	EdgeID      string `json:"edge_id,omitempty"`
	Exp         int64  `json:"exp"`
	Nonce       string `json:"nonce"`
}

type signedTicket struct {
	Ticket
	Sig string `json:"sig"`
}

// IssueTicket creates a HMAC-signed ticket.
func IssueTicket(secret []byte, connectorID, edgeID string, ttl time.Duration) (string, error) {
	if len(secret) == 0 || connectorID == "" {
		return "", fmt.Errorf("ticket secret and connector_id required")
	}
	if ttl <= 0 {
		ttl = TicketTTL
	}
	var nb [16]byte
	if _, err := rand.Read(nb[:]); err != nil {
		return "", err
	}
	t := Ticket{
		ConnectorID: connectorID,
		EdgeID:      edgeID,
		Exp:         time.Now().Add(ttl).Unix(),
		Nonce:       base64.RawURLEncoding.EncodeToString(nb[:]),
	}
	payload, err := json.Marshal(t)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(payload)
	st := signedTicket{Ticket: t, Sig: base64.RawURLEncoding.EncodeToString(mac.Sum(nil))}
	raw, err := json.Marshal(st)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// VerifyTicket validates signature, expiry, and optional edge binding.
func VerifyTicket(secret []byte, raw, expectEdge string) (Ticket, error) {
	if len(secret) == 0 || raw == "" {
		return Ticket{}, fmt.Errorf("missing ticket")
	}
	b, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return Ticket{}, fmt.Errorf("bad ticket encoding")
	}
	var st signedTicket
	if err := json.Unmarshal(b, &st); err != nil {
		return Ticket{}, fmt.Errorf("bad ticket json")
	}
	payload, err := json.Marshal(st.Ticket)
	if err != nil {
		return Ticket{}, err
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(payload)
	want := mac.Sum(nil)
	got, err := base64.RawURLEncoding.DecodeString(st.Sig)
	if err != nil || !hmac.Equal(want, got) {
		return Ticket{}, fmt.Errorf("bad ticket signature")
	}
	if time.Now().Unix() > st.Exp {
		return Ticket{}, fmt.Errorf("ticket expired")
	}
	if expectEdge != "" && st.EdgeID != "" && st.EdgeID != expectEdge {
		return Ticket{}, fmt.Errorf("ticket edge mismatch")
	}
	if strings.TrimSpace(st.ConnectorID) == "" {
		return Ticket{}, fmt.Errorf("missing connector_id")
	}
	return st.Ticket, nil
}

// WriteOpenHeader writes RG1 <upstream_id>\n to stream.
func WriteOpenHeader(w interface{ Write([]byte) (int, error) }, upstreamID string) error {
	upstreamID = strings.TrimSpace(upstreamID)
	if upstreamID == "" || len(upstreamID) > MaxUpstreamID {
		return fmt.Errorf("invalid upstream_id")
	}
	if strings.ContainsAny(upstreamID, "\r\n\x00") {
		return fmt.Errorf("invalid upstream_id chars")
	}
	_, err := w.Write([]byte("RG1 " + upstreamID + "\n"))
	return err
}

// ReadOpenHeader reads RG1 header from stream.
func ReadOpenHeader(r interface{ Read([]byte) (int, error) }) (string, error) {
	buf := make([]byte, 4+MaxUpstreamID+1)
	n := 0
	for n < 4 {
		c, err := r.Read(buf[n:4])
		if err != nil {
			return "", err
		}
		n += c
	}
	if string(buf[:4]) != "RG1 " {
		return "", fmt.Errorf("bad tunnel header version")
	}
	for n < len(buf) {
		c, err := r.Read(buf[n : n+1])
		if err != nil {
			return "", err
		}
		if c == 1 && buf[n] == '\n' {
			id := strings.TrimSpace(string(buf[4:n]))
			if id == "" || len(id) > MaxUpstreamID {
				return "", fmt.Errorf("invalid upstream_id")
			}
			return id, nil
		}
		n++
	}
	return "", fmt.Errorf("upstream_id too long")
}

// NonceBytes helpers for tests.
func NonceBytes() []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(time.Now().UnixNano()))
	return b[:]
}
