// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package store

import (
	"database/sql"
	"errors"
	"time"
)

type AuditEvent struct {
	ID        int64     `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	ActorID   *int64    `json:"actor_id,omitempty"`
	ActorName string    `json:"actor_name"`
	Action    string    `json:"action"`
	Target    string    `json:"target"`
	Detail    string    `json:"detail"`
	IP        string    `json:"ip"`
}

func (s *Store) AppendAudit(actorID *int64, actorName, action, target, detail, ip string) error {
	_, err := s.db.Exec(
		`INSERT INTO audit_events(created_at, actor_id, actor_name, action, target, detail, ip) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		nowUTC(), actorID, actorName, action, target, detail, ip,
	)
	return err
}

func (s *Store) ListAudit(afterID int64, limit int) ([]AuditEvent, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	var rows *sql.Rows
	var err error
	if afterID > 0 {
		rows, err = s.db.Query(
			`SELECT id, created_at, actor_id, actor_name, action, target, detail, ip FROM audit_events WHERE id < ? ORDER BY id DESC LIMIT ?`,
			afterID, limit,
		)
	} else {
		rows, err = s.db.Query(
			`SELECT id, created_at, actor_id, actor_name, action, target, detail, ip FROM audit_events ORDER BY id DESC LIMIT ?`,
			limit,
		)
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []AuditEvent
	for rows.Next() {
		var e AuditEvent
		var created string
		var actor sql.NullInt64
		if err := rows.Scan(&e.ID, &created, &actor, &e.ActorName, &e.Action, &e.Target, &e.Detail, &e.IP); err != nil {
			return nil, err
		}
		e.CreatedAt, _ = parseTime(created)
		if actor.Valid {
			v := actor.Int64
			e.ActorID = &v
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *Store) GetConfigOverrides() (string, error) {
	var payload string
	err := s.db.QueryRow(`SELECT payload FROM config_overrides WHERE id = 1`).Scan(&payload)
	if errors.Is(err, sql.ErrNoRows) {
		return "{}", nil
	}
	return payload, err
}

func (s *Store) SetConfigOverrides(payload string, updatedBy int64) error {
	_, err := s.db.Exec(
		`INSERT INTO config_overrides(id, payload, updated_at, updated_by) VALUES (1, ?, ?, ?)
		 ON CONFLICT(id) DO UPDATE SET payload = excluded.payload, updated_at = excluded.updated_at, updated_by = excluded.updated_by`,
		payload, nowUTC(), updatedBy,
	)
	return err
}
