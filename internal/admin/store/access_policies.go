// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Quad4-Software/ravenguard/internal/access"
)

// AccessPolicyRow is a persisted access policy with hashed secrets.
type AccessPolicyRow struct {
	ID        string        `json:"id"`
	Name      string        `json:"name"`
	Mode      string        `json:"mode"`
	Rules     []access.Rule `json:"rules"`
	CookieTTL string        `json:"cookie_ttl"`
	CreatedAt time.Time     `json:"created_at"`
	UpdatedAt time.Time     `json:"updated_at"`
}

func (s *Store) ListAccessPolicies() ([]AccessPolicyRow, error) {
	rows, err := s.db.Query(`SELECT id, name, mode, rules_json, cookie_ttl, created_at, updated_at
		FROM access_policies ORDER BY name ASC, id ASC`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []AccessPolicyRow
	for rows.Next() {
		p, err := scanAccessPolicy(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *Store) GetAccessPolicy(id string) (AccessPolicyRow, error) {
	row := s.db.QueryRow(`SELECT id, name, mode, rules_json, cookie_ttl, created_at, updated_at
		FROM access_policies WHERE id = ?`, id)
	p, err := scanAccessPolicy(row)
	if errors.Is(err, sql.ErrNoRows) {
		return AccessPolicyRow{}, ErrNotFound
	}
	return p, err
}

func (s *Store) CreateAccessPolicy(p AccessPolicyRow) (AccessPolicyRow, error) {
	p.Name = strings.TrimSpace(p.Name)
	if p.Name == "" {
		return AccessPolicyRow{}, fmt.Errorf("name required")
	}
	rules, err := prepareAccessRules(p.Rules)
	if err != nil {
		return AccessPolicyRow{}, err
	}
	id, err := newID()
	if err != nil {
		return AccessPolicyRow{}, err
	}
	p = normalizeAccessPolicy(p)
	raw, err := json.Marshal(rules) //nolint:gosec // G117: secret only on write input
	if err != nil {
		return AccessPolicyRow{}, err
	}
	now := nowUTC()
	_, err = s.db.Exec(`INSERT INTO access_policies(id, name, mode, rules_json, cookie_ttl, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		id, p.Name, p.Mode, string(raw), p.CookieTTL, now, now,
	)
	if err != nil {
		return AccessPolicyRow{}, err
	}
	return s.GetAccessPolicy(id)
}

func (s *Store) UpdateAccessPolicy(id string, p AccessPolicyRow) (AccessPolicyRow, error) {
	if _, err := s.GetAccessPolicy(id); err != nil {
		return AccessPolicyRow{}, err
	}
	p.Name = strings.TrimSpace(p.Name)
	if p.Name == "" {
		return AccessPolicyRow{}, fmt.Errorf("name required")
	}
	rules, err := prepareAccessRules(p.Rules)
	if err != nil {
		return AccessPolicyRow{}, err
	}
	p = normalizeAccessPolicy(p)
	raw, err := json.Marshal(rules) //nolint:gosec // G117: secret only on write input
	if err != nil {
		return AccessPolicyRow{}, err
	}
	res, err := s.db.Exec(`UPDATE access_policies SET name = ?, mode = ?, rules_json = ?, cookie_ttl = ?, updated_at = ?
		WHERE id = ?`,
		p.Name, p.Mode, string(raw), p.CookieTTL, nowUTC(), id,
	)
	if err != nil {
		return AccessPolicyRow{}, err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return AccessPolicyRow{}, ErrNotFound
	}
	return s.GetAccessPolicy(id)
}

func (s *Store) DeleteAccessPolicy(id string) error {
	res, err := s.db.Exec(`DELETE FROM access_policies WHERE id = ?`, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func prepareAccessRules(rules []access.Rule) ([]access.Rule, error) {
	if rules == nil {
		return []access.Rule{}, nil
	}
	out := make([]access.Rule, len(rules))
	copy(out, rules)
	for i := range out {
		out[i].Secret = strings.TrimSpace(out[i].Secret)
		if out[i].Secret == "" {
			out[i].Secret = ""
			continue
		}
		minLen := access.MinPasswordLen
		if out[i].Type == access.RulePIN {
			minLen = access.MinPINLen
		}
		hash, err := access.HashSecret(out[i].Secret, minLen)
		if err != nil {
			return nil, err
		}
		out[i].SecretHash = hash
		out[i].Secret = ""
	}
	return out, nil
}

func normalizeAccessPolicy(p AccessPolicyRow) AccessPolicyRow {
	mode := strings.ToLower(strings.TrimSpace(p.Mode))
	if mode == access.ModeAny {
		p.Mode = access.ModeAny
	} else {
		p.Mode = access.ModeAll
	}
	if strings.TrimSpace(p.CookieTTL) == "" {
		p.CookieTTL = "24h"
	}
	if p.Rules == nil {
		p.Rules = []access.Rule{}
	}
	return p
}

type accessPolicyScanner interface {
	Scan(dest ...any) error
}

func scanAccessPolicy(row accessPolicyScanner) (AccessPolicyRow, error) {
	var p AccessPolicyRow
	var rulesJSON string
	var created, updated string
	err := row.Scan(&p.ID, &p.Name, &p.Mode, &rulesJSON, &p.CookieTTL, &created, &updated)
	if err != nil {
		return AccessPolicyRow{}, err
	}
	p.Rules = nil
	if rulesJSON != "" && rulesJSON != "null" {
		_ = json.Unmarshal([]byte(rulesJSON), &p.Rules)
	}
	if p.Rules == nil {
		p.Rules = []access.Rule{}
	}
	p.CreatedAt, _ = parseTime(created)
	p.UpdatedAt, _ = parseTime(updated)
	return p, nil
}
