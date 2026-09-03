// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package store

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"time"
)

type Session struct {
	ID        string
	UserID    int64
	TokenHash string
	CSRFToken string
	ExpiresAt time.Time
	CreatedAt time.Time
	IP        string
	UserAgent string
}

func HashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func NewSessionToken() (raw string, err error) {
	b := make([]byte, 32)
	if _, err = rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func NewCSRFToken() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func (s *Store) CreateSession(userID int64, ttl time.Duration, ip, ua string) (sessionID, rawToken, csrf string, expires time.Time, err error) {
	rawToken, err = NewSessionToken()
	if err != nil {
		return "", "", "", time.Time{}, err
	}
	csrf, err = NewCSRFToken()
	if err != nil {
		return "", "", "", time.Time{}, err
	}
	idBytes := make([]byte, 16)
	if _, err = rand.Read(idBytes); err != nil {
		return "", "", "", time.Time{}, err
	}
	sessionID = hex.EncodeToString(idBytes)
	expires = time.Now().UTC().Add(ttl)
	_, err = s.db.Exec(
		`INSERT INTO sessions(id, user_id, token_hash, csrf_token, expires_at, created_at, ip, user_agent) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		sessionID, userID, HashToken(rawToken), csrf, expires.Format(time.RFC3339Nano), nowUTC(), ip, ua,
	)
	return sessionID, rawToken, csrf, expires, err
}

func (s *Store) GetSessionByToken(rawToken string) (Session, User, error) {
	var sess Session
	var exp, created string
	err := s.db.QueryRow(
		`SELECT id, user_id, token_hash, csrf_token, expires_at, created_at, ip, user_agent FROM sessions WHERE token_hash = ?`,
		HashToken(rawToken),
	).Scan(&sess.ID, &sess.UserID, &sess.TokenHash, &sess.CSRFToken, &exp, &created, &sess.IP, &sess.UserAgent)
	if errors.Is(err, sql.ErrNoRows) {
		return Session{}, User{}, ErrNotFound
	}
	if err != nil {
		return Session{}, User{}, err
	}
	sess.ExpiresAt, _ = parseTime(exp)
	sess.CreatedAt, _ = parseTime(created)
	if time.Now().After(sess.ExpiresAt) {
		_ = s.DeleteSession(sess.ID)
		return Session{}, User{}, ErrNotFound
	}
	u, err := s.GetUser(sess.UserID)
	if err != nil {
		return Session{}, User{}, err
	}
	if u.Disabled {
		_ = s.DeleteSession(sess.ID)
		return Session{}, User{}, ErrNotFound
	}
	return sess, u, nil
}

func (s *Store) DeleteSession(id string) error {
	_, err := s.db.Exec(`DELETE FROM sessions WHERE id = ?`, id)
	return err
}

func (s *Store) DeleteSessionsForUser(userID int64) error {
	_, err := s.db.Exec(`DELETE FROM sessions WHERE user_id = ?`, userID)
	return err
}

// ListSessionsForUser returns non-expired sessions for a user, newest first.
func (s *Store) ListSessionsForUser(userID int64) ([]Session, error) {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	rows, err := s.db.Query(
		`SELECT id, user_id, token_hash, csrf_token, expires_at, created_at, ip, user_agent
		 FROM sessions WHERE user_id = ? AND expires_at >= ? ORDER BY created_at DESC`,
		userID, now,
	)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Session
	for rows.Next() {
		var sess Session
		var exp, created string
		if err := rows.Scan(
			&sess.ID, &sess.UserID, &sess.TokenHash, &sess.CSRFToken, &exp, &created, &sess.IP, &sess.UserAgent,
		); err != nil {
			return nil, err
		}
		sess.ExpiresAt, _ = parseTime(exp)
		sess.CreatedAt, _ = parseTime(created)
		out = append(out, sess)
	}
	return out, rows.Err()
}

// DeleteSessionForUser deletes a session only if it belongs to userID.
func (s *Store) DeleteSessionForUser(userID int64, sessionID string) error {
	res, err := s.db.Exec(`DELETE FROM sessions WHERE id = ? AND user_id = ?`, sessionID, userID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// ExtendSession pushes expires_at forward by ttl and optionally rotates the CSRF token.
func (s *Store) ExtendSession(id string, ttl time.Duration, rotateCSRF bool) (expires time.Time, csrf string, err error) {
	if ttl <= 0 {
		ttl = 12 * time.Hour
	}
	expires = time.Now().UTC().Add(ttl)
	if rotateCSRF {
		csrf, err = NewCSRFToken()
		if err != nil {
			return time.Time{}, "", err
		}
		res, e := s.db.Exec(
			`UPDATE sessions SET expires_at = ?, csrf_token = ? WHERE id = ?`,
			expires.Format(time.RFC3339Nano), csrf, id,
		)
		if e != nil {
			return time.Time{}, "", e
		}
		n, _ := res.RowsAffected()
		if n == 0 {
			return time.Time{}, "", ErrNotFound
		}
		return expires, csrf, nil
	}
	var existing string
	err = s.db.QueryRow(`SELECT csrf_token FROM sessions WHERE id = ?`, id).Scan(&existing)
	if errors.Is(err, sql.ErrNoRows) {
		return time.Time{}, "", ErrNotFound
	}
	if err != nil {
		return time.Time{}, "", err
	}
	res, e := s.db.Exec(
		`UPDATE sessions SET expires_at = ? WHERE id = ?`,
		expires.Format(time.RFC3339Nano), id,
	)
	if e != nil {
		return time.Time{}, "", e
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return time.Time{}, "", ErrNotFound
	}
	return expires, existing, nil
}

func (s *Store) SweepSessions() error {
	_, err := s.db.Exec(`DELETE FROM sessions WHERE expires_at < ?`, time.Now().UTC().Format(time.RFC3339Nano))
	return err
}
