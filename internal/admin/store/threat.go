// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package store

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"strings"
	"time"

	"github.com/Quad4-Software/ravenguard/internal/agentprotocol"
)

const (
	threatMaxEntries   = 100000
	threatDefaultLimit = 500
)

func redactThreatKey(keyType, key string) string {
	key = strings.TrimSpace(key)
	if key == "" {
		return ""
	}
	switch strings.ToLower(keyType) {
	case agentprotocol.ThreatKeyUA:
		if len(key) <= 24 {
			return key
		}
		return key[:12] + "..." + key[len(key)-6:]
	case agentprotocol.ThreatKeyIP:
		return "[ip]"
	default:
		if len(key) <= 12 {
			n := min(len(key), 4)
			return key[:n] + "..."
		}
		return key[:6] + "..." + key[len(key)-4:]
	}
}

func hashThreatKey(keyType, key string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(keyType) + "\x00" + key))
	return hex.EncodeToString(sum[:])
}

func newThreatID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// InsertThreatEntries stores entries and returns them with IDs and revision assigned.
func (s *Store) InsertThreatEntries(sourceProxyID string, entries []agentprotocol.ThreatEntry) ([]agentprotocol.ThreatEntry, int64, error) {
	if err := s.EnsureThreatMeta(); err != nil {
		return nil, 0, err
	}
	if len(entries) == 0 {
		rev, err := s.ThreatRevision()
		return nil, rev, err
	}
	now := time.Now().UTC()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = tx.Rollback() }()

	var rev int64
	if err := tx.QueryRow(`SELECT COALESCE(revision, 0) FROM threat_meta WHERE id = 1`).Scan(&rev); err != nil {
		rev = 0
	}
	out := make([]agentprotocol.ThreatEntry, 0, len(entries))
	for _, e := range entries {
		e.KeyType = strings.ToLower(strings.TrimSpace(e.KeyType))
		e.Key = strings.TrimSpace(e.Key)
		e.Reason = strings.TrimSpace(e.Reason)
		if e.Key == "" || e.KeyType == "" {
			continue
		}
		if len(e.Key) > 256 || len(e.Reason) > 128 {
			continue
		}
		switch e.KeyType {
		case agentprotocol.ThreatKeyBind, agentprotocol.ThreatKeyUA, agentprotocol.ThreatKeyIP,
			agentprotocol.ThreatKeyIPHash, agentprotocol.ThreatKeyJA4, agentprotocol.ThreatKeyDNS:
		default:
			continue
		}
		ttl := e.TTLSeconds
		if ttl <= 0 {
			ttl = 600
		}
		if ttl > 86400*7 {
			ttl = 86400 * 7
		}
		exp := now.Add(time.Duration(ttl) * time.Second)
		if e.ExpiresAtUnix > 0 {
			t := time.Unix(e.ExpiresAtUnix, 0).UTC()
			if t.After(now) {
				exp = t
			}
		}
		id := e.ID
		if id == "" {
			id, err = newThreatID()
			if err != nil {
				return nil, 0, err
			}
		}
		rev++
		src := sourceProxyID
		if strings.TrimSpace(e.SourceProxyID) != "" {
			src = e.SourceProxyID
		}
		_, err = tx.Exec(`INSERT INTO threat_entries(
			id, key_type, key_hash, key_redacted, key_material, ttl_deadline, reason, source_proxy_id, revision, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			id, e.KeyType, hashThreatKey(e.KeyType, e.Key), redactThreatKey(e.KeyType, e.Key), e.Key,
			exp.Format(time.RFC3339Nano), e.Reason, src, rev, now.Format(time.RFC3339Nano),
		)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, agentprotocol.ThreatEntry{
			ID:            id,
			KeyType:       e.KeyType,
			Key:           e.Key,
			TTLSeconds:    ttl,
			Reason:        e.Reason,
			SourceProxyID: src,
			CreatedAtUnix: now.Unix(),
			ExpiresAtUnix: exp.Unix(),
			Revision:      rev,
		})
	}
	if _, err := tx.Exec(`UPDATE threat_meta SET revision = ? WHERE id = 1`, rev); err != nil {
		return nil, 0, err
	}
	var count int
	_ = tx.QueryRow(`SELECT COUNT(*) FROM threat_entries`).Scan(&count)
	if count > threatMaxEntries {
		trim := count - threatMaxEntries
		_, _ = tx.Exec(`DELETE FROM threat_entries WHERE id IN (
			SELECT id FROM threat_entries ORDER BY revision ASC LIMIT ?
		)`, trim)
	}
	if err := tx.Commit(); err != nil {
		return nil, 0, err
	}
	return out, rev, nil
}

func (s *Store) ThreatRevision() (int64, error) {
	var rev int64
	err := s.db.QueryRow(`SELECT COALESCE(revision, 0) FROM threat_meta WHERE id = 1`).Scan(&rev)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	return rev, err
}

// ListThreatSince returns non-expired entries with revision > since (includes key material for apply).
func (s *Store) ListThreatSince(since int64, limit int) ([]agentprotocol.ThreatEntry, int64, error) {
	if limit <= 0 || limit > threatDefaultLimit*4 {
		limit = threatDefaultLimit
	}
	rev, err := s.ThreatRevision()
	if err != nil {
		return nil, 0, err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	rows, err := s.db.Query(`SELECT id, key_type, key_material, ttl_deadline, reason, source_proxy_id, revision, created_at
		FROM threat_entries WHERE revision > ? AND ttl_deadline > ? ORDER BY revision ASC LIMIT ?`,
		since, now, limit)
	if err != nil {
		return nil, rev, err
	}
	defer func() { _ = rows.Close() }()
	var out []agentprotocol.ThreatEntry
	for rows.Next() {
		var id, kt, key, deadline, reason, src, created string
		var rrev int64
		if err := rows.Scan(&id, &kt, &key, &deadline, &reason, &src, &rrev, &created); err != nil {
			return nil, rev, err
		}
		exp, _ := time.Parse(time.RFC3339Nano, deadline)
		cr, _ := time.Parse(time.RFC3339Nano, created)
		ttl := max(int64(exp.Sub(time.Now().UTC()).Seconds()), 1)
		out = append(out, agentprotocol.ThreatEntry{
			ID: id, KeyType: kt, Key: key, TTLSeconds: ttl, Reason: reason, SourceProxyID: src,
			CreatedAtUnix: cr.Unix(), ExpiresAtUnix: exp.Unix(), Revision: rrev,
		})
	}
	return out, rev, rows.Err()
}

// ListThreatAdmin returns redacted entries for the admin API.
func (s *Store) ListThreatAdmin(limit int) ([]map[string]any, int64, error) {
	if limit <= 0 || limit > 200 {
		limit = 100
	}
	rev, err := s.ThreatRevision()
	if err != nil {
		return nil, 0, err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	rows, err := s.db.Query(`SELECT id, key_type, key_redacted, ttl_deadline, reason, source_proxy_id, revision, created_at
		FROM threat_entries WHERE ttl_deadline > ? ORDER BY revision DESC LIMIT ?`, now, limit)
	if err != nil {
		return nil, rev, err
	}
	defer func() { _ = rows.Close() }()
	var out []map[string]any
	for rows.Next() {
		var id, kt, kr, deadline, reason, src, created string
		var rrev int64
		if err := rows.Scan(&id, &kt, &kr, &deadline, &reason, &src, &rrev, &created); err != nil {
			return nil, rev, err
		}
		out = append(out, map[string]any{
			"id": id, "key_type": kt, "key_redacted": kr,
			"ttl_deadline": deadline, "reason": reason,
			"source_proxy_id": src, "revision": rrev, "created_at": created,
		})
	}
	return out, rev, rows.Err()
}

// SweepThreatEntries deletes expired rows.
func (s *Store) SweepThreatEntries() (int64, error) {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	res, err := s.db.Exec(`DELETE FROM threat_entries WHERE ttl_deadline <= ?`, now)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// EnsureThreatMeta creates meta row if missing.
func (s *Store) EnsureThreatMeta() error {
	_, err := s.db.Exec(`INSERT OR IGNORE INTO threat_meta(id, revision) VALUES (1, 0)`)
	return err
}
