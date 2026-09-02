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
)

// UpstreamRow is a persisted upstream backend.
type UpstreamRow struct {
	ID                  string    `json:"id"`
	Name                string    `json:"name"`
	URL                 string    `json:"url"`
	ConnectTimeout      string    `json:"connect_timeout,omitempty"`
	ResponseHeader      string    `json:"response_header_timeout,omitempty"`
	IdleConnTimeout     string    `json:"idle_conn_timeout,omitempty"`
	MaxIdleConns        int       `json:"max_idle_conns,omitempty"`
	MaxIdleConnsPerHost int       `json:"max_idle_conns_per_host,omitempty"`
	MaxConnsPerHost     int       `json:"max_conns_per_host,omitempty"`
	FlushInterval       string    `json:"flush_interval,omitempty"`
	SetHeaders          []string  `json:"set_headers,omitempty"`
	HealthEnabled       bool      `json:"health_enabled"`
	HealthPath          string    `json:"health_path,omitempty"`
	HealthInterval      string    `json:"health_interval,omitempty"`
	HealthTimeout       string    `json:"health_timeout,omitempty"`
	CreatedAt           time.Time `json:"created_at"`
	UpdatedAt           time.Time `json:"updated_at"`
}

func (s *Store) ListUpstreams() ([]UpstreamRow, error) {
	rows, err := s.db.Query(`SELECT id, name, url, connect_timeout, response_header_timeout, idle_conn_timeout,
		max_idle_conns, max_idle_conns_per_host, max_conns_per_host, flush_interval, set_headers,
		health_enabled, health_path, health_interval, health_timeout, created_at, updated_at
		FROM upstreams ORDER BY name ASC, id ASC`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []UpstreamRow
	for rows.Next() {
		u, err := scanUpstream(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func (s *Store) GetUpstream(id string) (UpstreamRow, error) {
	row := s.db.QueryRow(`SELECT id, name, url, connect_timeout, response_header_timeout, idle_conn_timeout,
		max_idle_conns, max_idle_conns_per_host, max_conns_per_host, flush_interval, set_headers,
		health_enabled, health_path, health_interval, health_timeout, created_at, updated_at
		FROM upstreams WHERE id = ?`, id)
	u, err := scanUpstream(row)
	if errors.Is(err, sql.ErrNoRows) {
		return UpstreamRow{}, ErrNotFound
	}
	return u, err
}

func (s *Store) CreateUpstream(u UpstreamRow) (UpstreamRow, error) {
	u.Name = strings.TrimSpace(u.Name)
	u.URL = strings.TrimSpace(u.URL)
	if u.Name == "" {
		return UpstreamRow{}, fmt.Errorf("name required")
	}
	if u.URL == "" {
		return UpstreamRow{}, fmt.Errorf("url required")
	}
	id, err := newID()
	if err != nil {
		return UpstreamRow{}, err
	}
	u = normalizeUpstream(u)
	headers, err := json.Marshal(u.SetHeaders)
	if err != nil {
		return UpstreamRow{}, err
	}
	now := nowUTC()
	_, err = s.db.Exec(`INSERT INTO upstreams(
		id, name, url, connect_timeout, response_header_timeout, idle_conn_timeout,
		max_idle_conns, max_idle_conns_per_host, max_conns_per_host, flush_interval, set_headers,
		health_enabled, health_path, health_interval, health_timeout, created_at, updated_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, u.Name, u.URL, u.ConnectTimeout, u.ResponseHeader, u.IdleConnTimeout,
		u.MaxIdleConns, u.MaxIdleConnsPerHost, u.MaxConnsPerHost, u.FlushInterval, string(headers),
		boolInt(u.HealthEnabled), u.HealthPath, u.HealthInterval, u.HealthTimeout, now, now,
	)
	if err != nil {
		return UpstreamRow{}, err
	}
	return s.GetUpstream(id)
}

func (s *Store) UpdateUpstream(id string, u UpstreamRow) (UpstreamRow, error) {
	if _, err := s.GetUpstream(id); err != nil {
		return UpstreamRow{}, err
	}
	u.Name = strings.TrimSpace(u.Name)
	u.URL = strings.TrimSpace(u.URL)
	if u.Name == "" {
		return UpstreamRow{}, fmt.Errorf("name required")
	}
	if u.URL == "" {
		return UpstreamRow{}, fmt.Errorf("url required")
	}
	u = normalizeUpstream(u)
	headers, err := json.Marshal(u.SetHeaders)
	if err != nil {
		return UpstreamRow{}, err
	}
	res, err := s.db.Exec(`UPDATE upstreams SET
		name = ?, url = ?, connect_timeout = ?, response_header_timeout = ?, idle_conn_timeout = ?,
		max_idle_conns = ?, max_idle_conns_per_host = ?, max_conns_per_host = ?, flush_interval = ?, set_headers = ?,
		health_enabled = ?, health_path = ?, health_interval = ?, health_timeout = ?, updated_at = ?
		WHERE id = ?`,
		u.Name, u.URL, u.ConnectTimeout, u.ResponseHeader, u.IdleConnTimeout,
		u.MaxIdleConns, u.MaxIdleConnsPerHost, u.MaxConnsPerHost, u.FlushInterval, string(headers),
		boolInt(u.HealthEnabled), u.HealthPath, u.HealthInterval, u.HealthTimeout, nowUTC(), id,
	)
	if err != nil {
		return UpstreamRow{}, err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return UpstreamRow{}, ErrNotFound
	}
	return s.GetUpstream(id)
}

func (s *Store) DeleteUpstream(id string) error {
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM routes WHERE upstream_id = ?`, id).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return ErrInUse
	}
	res, err := s.db.Exec(`DELETE FROM upstreams WHERE id = ?`, id)
	if err != nil {
		return err
	}
	affected, _ := res.RowsAffected()
	if affected == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) CountUpstreams() (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM upstreams`).Scan(&n)
	return n, err
}

type upstreamScanner interface {
	Scan(dest ...any) error
}

func scanUpstream(row upstreamScanner) (UpstreamRow, error) {
	var u UpstreamRow
	var headers string
	var healthEnabled int
	var created, updated string
	err := row.Scan(
		&u.ID, &u.Name, &u.URL, &u.ConnectTimeout, &u.ResponseHeader, &u.IdleConnTimeout,
		&u.MaxIdleConns, &u.MaxIdleConnsPerHost, &u.MaxConnsPerHost, &u.FlushInterval, &headers,
		&healthEnabled, &u.HealthPath, &u.HealthInterval, &u.HealthTimeout, &created, &updated,
	)
	if err != nil {
		return UpstreamRow{}, err
	}
	u.HealthEnabled = healthEnabled != 0
	u.SetHeaders = nil
	if headers != "" && headers != "null" {
		_ = json.Unmarshal([]byte(headers), &u.SetHeaders)
	}
	if u.SetHeaders == nil {
		u.SetHeaders = []string{}
	}
	u.CreatedAt, _ = parseTime(created)
	u.UpdatedAt, _ = parseTime(updated)
	return u, nil
}

func normalizeUpstream(u UpstreamRow) UpstreamRow {
	if u.SetHeaders == nil {
		u.SetHeaders = []string{}
	}
	if u.HealthPath == "" {
		u.HealthPath = "/healthz"
	}
	if u.HealthInterval == "" {
		u.HealthInterval = "10s"
	}
	if u.HealthTimeout == "" {
		u.HealthTimeout = "3s"
	}
	return u
}

func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}
