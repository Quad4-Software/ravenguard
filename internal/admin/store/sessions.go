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

func (s *Store) SweepSessions() error {
	_, err := s.db.Exec(`DELETE FROM sessions WHERE expires_at < ?`, time.Now().UTC().Format(time.RFC3339Nano))
	return err
}
