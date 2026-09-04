// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package store

import (
	"database/sql"
	"errors"
	"time"

	"github.com/Quad4-Software/ravenguard/internal/requestlog"
)

// InsertWAFEvent persists a deny event (upsert by ray_id keeps newest).
func (s *Store) InsertWAFEvent(e requestlog.Event) error {
	if e.Ray == "" {
		return nil
	}
	created := e.CreatedAt
	if created.IsZero() {
		created = time.Now().UTC()
	}
	_, err := s.db.Exec(
		`INSERT INTO waf_events(ray_id, created_at, action, reason, method, path, host, ua, ip_hash, bind_id, score, detail_json)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(ray_id) DO UPDATE SET
		   created_at = excluded.created_at,
		   action = excluded.action,
		   reason = excluded.reason,
		   method = excluded.method,
		   path = excluded.path,
		   host = excluded.host,
		   ua = excluded.ua,
		   ip_hash = excluded.ip_hash,
		   bind_id = excluded.bind_id,
		   score = excluded.score,
		   detail_json = excluded.detail_json
		 WHERE waf_events.bind_id = '' OR waf_events.bind_id = excluded.bind_id`,
		e.Ray, created.UTC().Format(time.RFC3339Nano), e.Action, e.Reason, e.Method, e.Path, e.Host, e.UA,
		e.IPHash, e.BindID, e.Score, requestlog.DetailsJSON(e.Details),
	)
	return err
}

// GetWAFEventByRay loads one event by ray id.
func (s *Store) GetWAFEventByRay(ray string) (requestlog.Event, bool, error) {
	row := s.db.QueryRow(
		`SELECT ray_id, created_at, action, reason, method, path, host, ua, ip_hash, bind_id, score, detail_json
		 FROM waf_events WHERE ray_id = ?`, ray,
	)
	e, err := scanWAFEvent(row)
	if errors.Is(err, sql.ErrNoRows) {
		return requestlog.Event{}, false, nil
	}
	if err != nil {
		return requestlog.Event{}, false, err
	}
	return e, true, nil
}

// ListWAFEvents returns newest events first.
func (s *Store) ListWAFEvents(limit int) ([]requestlog.Event, error) {
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	rows, err := s.db.Query(
		`SELECT ray_id, created_at, action, reason, method, path, host, ua, ip_hash, bind_id, score, detail_json
		 FROM waf_events ORDER BY created_at DESC LIMIT ?`, limit,
	)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []requestlog.Event
	for rows.Next() {
		e, err := scanWAFEvent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// PurgeWAFEventsOlderThan deletes expired rows.
func (s *Store) PurgeWAFEventsOlderThan(cutoff time.Time) (int64, error) {
	res, err := s.db.Exec(`DELETE FROM waf_events WHERE created_at < ?`, cutoff.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

type wafScanner interface {
	Scan(dest ...any) error
}

func scanWAFEvent(row wafScanner) (requestlog.Event, error) {
	var e requestlog.Event
	var created, detail string
	if err := row.Scan(&e.Ray, &created, &e.Action, &e.Reason, &e.Method, &e.Path, &e.Host, &e.UA, &e.IPHash, &e.BindID, &e.Score, &detail); err != nil {
		return requestlog.Event{}, err
	}
	e.CreatedAt, _ = parseTime(created)
	e.Details = requestlog.ParseDetailsJSON(detail)
	return e, nil
}
