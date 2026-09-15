// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// NebulaHost is one issued overlay host certificate.
type NebulaHost struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	IP          string     `json:"ip"`
	Fingerprint string     `json:"fingerprint"`
	Groups      []string   `json:"groups"`
	CertPEM     string     `json:"cert_pem,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	ExpiresAt   time.Time  `json:"expires_at"`
	Revoked     bool       `json:"revoked"`
	RevokedAt   *time.Time `json:"revoked_at,omitempty"`
}

func (s *Store) CreateNebulaHost(h NebulaHost) (NebulaHost, error) {
	h.Name = strings.TrimSpace(h.Name)
	h.IP = strings.TrimSpace(h.IP)
	if h.Name == "" {
		return NebulaHost{}, fmt.Errorf("name required")
	}
	if h.IP == "" {
		return NebulaHost{}, fmt.Errorf("ip required")
	}
	id, err := newID()
	if err != nil {
		return NebulaHost{}, err
	}
	groups, err := json.Marshal(h.Groups)
	if err != nil {
		return NebulaHost{}, err
	}
	_, err = s.db.Exec(`INSERT INTO nebula_hosts(
		id, name, ip, fingerprint, groups_json, cert_pem, created_at, expires_at, revoked
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)`,
		id, h.Name, h.IP, h.Fingerprint, string(groups), h.CertPEM, nowUTC(),
		h.ExpiresAt.UTC().Format(time.RFC3339Nano),
	)
	if err != nil {
		return NebulaHost{}, err
	}
	return s.GetNebulaHost(id)
}

func (s *Store) GetNebulaHost(id string) (NebulaHost, error) {
	row := s.db.QueryRow(`SELECT id, name, ip, fingerprint, groups_json, cert_pem, created_at, expires_at, revoked, revoked_at
		FROM nebula_hosts WHERE id = ?`, id)
	return scanNebulaHost(row)
}

func (s *Store) ListNebulaHosts() ([]NebulaHost, error) {
	rows, err := s.db.Query(`SELECT id, name, ip, fingerprint, groups_json, cert_pem, created_at, expires_at, revoked, revoked_at
		FROM nebula_hosts ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []NebulaHost{}
	for rows.Next() {
		h, err := scanNebulaHost(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// RevokeNebulaHost marks a host cert revoked. The fingerprint joins the
// blocklist exported for pki.blocklist in nebula configs.
func (s *Store) RevokeNebulaHost(id string) error {
	res, err := s.db.Exec(`UPDATE nebula_hosts SET revoked = 1, revoked_at = ? WHERE id = ? AND revoked = 0`,
		nowUTC(), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// NebulaUsedIPs returns every allocated overlay IP, including revoked hosts
// so addresses are never reissued while a stale cert might still be live.
func (s *Store) NebulaUsedIPs() (map[string]struct{}, error) {
	rows, err := s.db.Query(`SELECT ip FROM nebula_hosts`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]struct{}{}
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			return nil, err
		}
		out[ip] = struct{}{}
	}
	return out, rows.Err()
}

// NebulaBlocklist returns fingerprints of revoked certificates.
func (s *Store) NebulaBlocklist() ([]string, error) {
	rows, err := s.db.Query(`SELECT fingerprint FROM nebula_hosts WHERE revoked = 1 AND fingerprint != ''`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var fp string
		if err := rows.Scan(&fp); err != nil {
			return nil, err
		}
		out = append(out, fp)
	}
	return out, rows.Err()
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanNebulaHost(row rowScanner) (NebulaHost, error) {
	var h NebulaHost
	var groups, created, expires string
	var revoked int
	var revokedAt sql.NullString
	if err := row.Scan(&h.ID, &h.Name, &h.IP, &h.Fingerprint, &groups, &h.CertPEM, &created, &expires, &revoked, &revokedAt); err != nil {
		if err == sql.ErrNoRows {
			return NebulaHost{}, ErrNotFound
		}
		return NebulaHost{}, err
	}
	_ = json.Unmarshal([]byte(groups), &h.Groups)
	h.CreatedAt, _ = parseTime(created)
	h.ExpiresAt, _ = parseTime(expires)
	h.Revoked = revoked == 1
	if revokedAt.Valid {
		if t, err := parseTime(revokedAt.String); err == nil {
			h.RevokedAt = &t
		}
	}
	return h, nil
}
