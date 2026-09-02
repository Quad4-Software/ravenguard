// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package store

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Quad4-Software/ravenguard/internal/admin/rbac"
)

type APIToken struct {
	ID         string     `json:"id"`
	UserID     int64      `json:"user_id"`
	Name       string     `json:"name"`
	Role       string     `json:"role"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	Revoked    bool       `json:"revoked"`
}

func (s *Store) CreateAPIToken(userID int64, name, role string, expires *time.Time) (tok APIToken, raw string, err error) {
	name = strings.TrimSpace(name)
	role = rbac.Normalize(role)
	if name == "" {
		return APIToken{}, "", fmt.Errorf("token name required")
	}
	if !rbac.ValidRole(role) {
		return APIToken{}, "", ErrInvalidRole
	}
	idBytes := make([]byte, 8)
	secret := make([]byte, 24)
	if _, err = rand.Read(idBytes); err != nil {
		return APIToken{}, "", err
	}
	if _, err = rand.Read(secret); err != nil {
		return APIToken{}, "", err
	}
	id := hex.EncodeToString(idBytes)
	rawSecret := hex.EncodeToString(secret)
	raw = "rgat_" + id + "." + rawSecret
	var exp any
	if expires != nil {
		exp = expires.UTC().Format(time.RFC3339Nano)
	}
	_, err = s.db.Exec(
		`INSERT INTO api_tokens(id, user_id, name, token_hash, role, created_at, expires_at, revoked) VALUES (?, ?, ?, ?, ?, ?, ?, 0)`,
		id, userID, name, HashToken(raw), role, nowUTC(), exp,
	)
	if err != nil {
		return APIToken{}, "", err
	}
	tok, err = s.GetAPIToken(id)
	return tok, raw, err
}

func (s *Store) GetAPIToken(id string) (APIToken, error) {
	var t APIToken
	var created string
	var exp, last sql.NullString
	var revoked int
	err := s.db.QueryRow(
		`SELECT id, user_id, name, role, created_at, expires_at, last_used_at, revoked FROM api_tokens WHERE id = ?`, id,
	).Scan(&t.ID, &t.UserID, &t.Name, &t.Role, &created, &exp, &last, &revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return APIToken{}, ErrNotFound
	}
	if err != nil {
		return APIToken{}, err
	}
	t.CreatedAt, _ = parseTime(created)
	if exp.Valid && exp.String != "" {
		tm, _ := parseTime(exp.String)
		t.ExpiresAt = &tm
	}
	if last.Valid && last.String != "" {
		tm, _ := parseTime(last.String)
		t.LastUsedAt = &tm
	}
	t.Revoked = revoked != 0
	return t, nil
}

func (s *Store) LookupAPIToken(raw string) (APIToken, User, error) {
	var t APIToken
	var created string
	var exp, last sql.NullString
	var revoked int
	err := s.db.QueryRow(
		`SELECT id, user_id, name, role, created_at, expires_at, last_used_at, revoked FROM api_tokens WHERE token_hash = ?`,
		HashToken(raw),
	).Scan(&t.ID, &t.UserID, &t.Name, &t.Role, &created, &exp, &last, &revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return APIToken{}, User{}, ErrNotFound
	}
	if err != nil {
		return APIToken{}, User{}, err
	}
	t.CreatedAt, _ = parseTime(created)
	if exp.Valid && exp.String != "" {
		tm, _ := parseTime(exp.String)
		t.ExpiresAt = &tm
		if time.Now().After(tm) {
			return APIToken{}, User{}, ErrNotFound
		}
	}
	if last.Valid && last.String != "" {
		tm, _ := parseTime(last.String)
		t.LastUsedAt = &tm
	}
	t.Revoked = revoked != 0
	if t.Revoked {
		return APIToken{}, User{}, ErrNotFound
	}
	u, err := s.GetUser(t.UserID)
	if err != nil {
		return APIToken{}, User{}, err
	}
	if u.Disabled {
		return APIToken{}, User{}, ErrNotFound
	}
	_, _ = s.db.Exec(`UPDATE api_tokens SET last_used_at = ? WHERE id = ?`, nowUTC(), t.ID)
	return t, u, nil
}

func (s *Store) ListAPITokens(userID int64, all bool) ([]APIToken, error) {
	var rows *sql.Rows
	var err error
	if all {
		rows, err = s.db.Query(`SELECT id, user_id, name, role, created_at, expires_at, last_used_at, revoked FROM api_tokens WHERE revoked = 0 ORDER BY created_at DESC`)
	} else {
		rows, err = s.db.Query(`SELECT id, user_id, name, role, created_at, expires_at, last_used_at, revoked FROM api_tokens WHERE user_id = ? AND revoked = 0 ORDER BY created_at DESC`, userID)
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []APIToken
	for rows.Next() {
		var t APIToken
		var created string
		var exp, last sql.NullString
		var revoked int
		if err := rows.Scan(&t.ID, &t.UserID, &t.Name, &t.Role, &created, &exp, &last, &revoked); err != nil {
			return nil, err
		}
		t.CreatedAt, _ = parseTime(created)
		if exp.Valid && exp.String != "" {
			tm, _ := parseTime(exp.String)
			t.ExpiresAt = &tm
		}
		if last.Valid && last.String != "" {
			tm, _ := parseTime(last.String)
			t.LastUsedAt = &tm
		}
		t.Revoked = revoked != 0
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *Store) RevokeAPIToken(id string) error {
	res, err := s.db.Exec(`UPDATE api_tokens SET revoked = 1 WHERE id = ?`, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}
