// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package store

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Quad4-Software/ravenguard/internal/admin/rbac"
)

var (
	ErrNotFound    = errors.New("not found")
	ErrConflict    = errors.New("conflict")
	ErrLastOwner   = errors.New("cannot remove or demote the last owner")
	ErrInvalidRole = errors.New("invalid role")
	ErrInvalidUser = errors.New("invalid username")
	ErrInUse       = errors.New("in use")
)

type User struct {
	ID           int64     `json:"id"`
	Username     string    `json:"username"`
	PasswordHash string    `json:"-"`
	Role         string    `json:"role"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	Disabled     bool      `json:"disabled"`
}

func (s *Store) CountUsers() (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n)
	return n, err
}

func (s *Store) CountOwners() (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM users WHERE role = ? AND disabled = 0`, rbac.RoleOwner).Scan(&n)
	return n, err
}

func (s *Store) CreateUser(username, passwordHash, role string) (User, error) {
	username = strings.TrimSpace(username)
	role = rbac.Normalize(role)
	if username == "" || len(username) > 64 {
		return User{}, ErrInvalidUser
	}
	if !rbac.ValidRole(role) {
		return User{}, ErrInvalidRole
	}
	now := nowUTC()
	res, err := s.db.Exec(
		`INSERT INTO users(username, password_hash, role, created_at, updated_at, disabled) VALUES (?, ?, ?, ?, ?, 0)`,
		username, passwordHash, role, now, now,
	)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			return User{}, ErrConflict
		}
		return User{}, err
	}
	id, _ := res.LastInsertId()
	return s.GetUser(id)
}

func (s *Store) GetUser(id int64) (User, error) {
	var u User
	var created, updated string
	var disabled int
	err := s.db.QueryRow(
		`SELECT id, username, password_hash, role, created_at, updated_at, disabled FROM users WHERE id = ?`, id,
	).Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Role, &created, &updated, &disabled)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, err
	}
	u.CreatedAt, _ = parseTime(created)
	u.UpdatedAt, _ = parseTime(updated)
	u.Disabled = disabled != 0
	return u, nil
}

func (s *Store) GetUserByName(username string) (User, error) {
	var u User
	var created, updated string
	var disabled int
	err := s.db.QueryRow(
		`SELECT id, username, password_hash, role, created_at, updated_at, disabled FROM users WHERE username = ? COLLATE NOCASE`,
		strings.TrimSpace(username),
	).Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Role, &created, &updated, &disabled)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, err
	}
	u.CreatedAt, _ = parseTime(created)
	u.UpdatedAt, _ = parseTime(updated)
	u.Disabled = disabled != 0
	return u, nil
}

func (s *Store) ListUsers() ([]User, error) {
	rows, err := s.db.Query(`SELECT id, username, password_hash, role, created_at, updated_at, disabled FROM users ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []User
	for rows.Next() {
		var u User
		var created, updated string
		var disabled int
		if err := rows.Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Role, &created, &updated, &disabled); err != nil {
			return nil, err
		}
		u.CreatedAt, _ = parseTime(created)
		u.UpdatedAt, _ = parseTime(updated)
		u.Disabled = disabled != 0
		u.PasswordHash = ""
		out = append(out, u)
	}
	return out, rows.Err()
}

func (s *Store) UpdateUser(id int64, role string, disabled *bool) (User, error) {
	u, err := s.GetUser(id)
	if err != nil {
		return User{}, err
	}
	if role != "" {
		role = rbac.Normalize(role)
		if !rbac.ValidRole(role) {
			return User{}, ErrInvalidRole
		}
		if u.Role == rbac.RoleOwner && role != rbac.RoleOwner {
			n, err := s.CountOwners()
			if err != nil {
				return User{}, err
			}
			if n <= 1 {
				return User{}, ErrLastOwner
			}
		}
		u.Role = role
	}
	if disabled != nil {
		if u.Role == rbac.RoleOwner && *disabled {
			n, err := s.CountOwners()
			if err != nil {
				return User{}, err
			}
			if n <= 1 {
				return User{}, ErrLastOwner
			}
		}
		u.Disabled = *disabled
	}
	dis := 0
	if u.Disabled {
		dis = 1
	}
	_, err = s.db.Exec(`UPDATE users SET role = ?, disabled = ?, updated_at = ? WHERE id = ?`, u.Role, dis, nowUTC(), id)
	if err != nil {
		return User{}, err
	}
	return s.GetUser(id)
}

func (s *Store) SetPassword(id int64, passwordHash string) error {
	res, err := s.db.Exec(`UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?`, passwordHash, nowUTC(), id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) SetUsername(id int64, username string) (User, error) {
	username = strings.TrimSpace(username)
	if username == "" || len(username) > 64 {
		return User{}, ErrInvalidUser
	}
	_, err := s.db.Exec(`UPDATE users SET username = ?, updated_at = ? WHERE id = ?`, username, nowUTC(), id)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			return User{}, ErrConflict
		}
		return User{}, err
	}
	return s.GetUser(id)
}

func (s *Store) DeleteUser(id int64) error {
	u, err := s.GetUser(id)
	if err != nil {
		return err
	}
	if u.Role == rbac.RoleOwner {
		n, err := s.CountOwners()
		if err != nil {
			return err
		}
		if n <= 1 {
			return ErrLastOwner
		}
	}
	_, err = s.db.Exec(`DELETE FROM users WHERE id = ?`, id)
	return err
}

func (s *Store) BootstrapOwner(username, passwordHash string) (User, error) {
	n, err := s.CountUsers()
	if err != nil {
		return User{}, err
	}
	if n > 0 {
		return User{}, fmt.Errorf("bootstrap refused: users already exist")
	}
	return s.CreateUser(username, passwordHash, rbac.RoleOwner)
}
