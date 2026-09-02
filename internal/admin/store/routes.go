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

// RouteRow is a persisted host+path route.
type RouteRow struct {
	ID             string    `json:"id"`
	Name           string    `json:"name"`
	Enabled        bool      `json:"enabled"`
	Hosts          []string  `json:"hosts"`
	PathPrefix     string    `json:"path_prefix"`
	UpstreamID     string    `json:"upstream_id"`
	StripPrefix    bool      `json:"strip_prefix"`
	Priority       int       `json:"priority"`
	AccessPolicyID *string   `json:"access_policy_id,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

func (s *Store) ListRoutes() ([]RouteRow, error) {
	rows, err := s.db.Query(`SELECT id, name, enabled, hosts_json, path_prefix, upstream_id,
		strip_prefix, priority, access_policy_id, created_at, updated_at
		FROM routes ORDER BY priority DESC, name ASC, id ASC`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []RouteRow
	for rows.Next() {
		rt, err := scanRoute(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, rt)
	}
	return out, rows.Err()
}

func (s *Store) GetRoute(id string) (RouteRow, error) {
	row := s.db.QueryRow(`SELECT id, name, enabled, hosts_json, path_prefix, upstream_id,
		strip_prefix, priority, access_policy_id, created_at, updated_at
		FROM routes WHERE id = ?`, id)
	rt, err := scanRoute(row)
	if errors.Is(err, sql.ErrNoRows) {
		return RouteRow{}, ErrNotFound
	}
	return rt, err
}

func (s *Store) CreateRoute(rt RouteRow) (RouteRow, error) {
	rt.Name = strings.TrimSpace(rt.Name)
	rt.UpstreamID = strings.TrimSpace(rt.UpstreamID)
	if rt.Name == "" {
		return RouteRow{}, fmt.Errorf("name required")
	}
	if rt.UpstreamID == "" {
		return RouteRow{}, fmt.Errorf("upstream_id required")
	}
	if _, err := s.GetUpstream(rt.UpstreamID); err != nil {
		if errors.Is(err, ErrNotFound) {
			return RouteRow{}, fmt.Errorf("upstream not found")
		}
		return RouteRow{}, err
	}
	if err := s.validateAccessPolicyRef(rt.AccessPolicyID); err != nil {
		return RouteRow{}, err
	}
	id, err := newID()
	if err != nil {
		return RouteRow{}, err
	}
	rt = normalizeRoute(rt)
	hosts, err := json.Marshal(rt.Hosts)
	if err != nil {
		return RouteRow{}, err
	}
	now := nowUTC()
	_, err = s.db.Exec(`INSERT INTO routes(
		id, name, enabled, hosts_json, path_prefix, upstream_id,
		strip_prefix, priority, access_policy_id, created_at, updated_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, rt.Name, boolInt(rt.Enabled), string(hosts), rt.PathPrefix, rt.UpstreamID,
		boolInt(rt.StripPrefix), rt.Priority, nullStringPtr(rt.AccessPolicyID), now, now,
	)
	if err != nil {
		return RouteRow{}, err
	}
	return s.GetRoute(id)
}

func (s *Store) UpdateRoute(id string, rt RouteRow) (RouteRow, error) {
	if _, err := s.GetRoute(id); err != nil {
		return RouteRow{}, err
	}
	rt.Name = strings.TrimSpace(rt.Name)
	rt.UpstreamID = strings.TrimSpace(rt.UpstreamID)
	if rt.Name == "" {
		return RouteRow{}, fmt.Errorf("name required")
	}
	if rt.UpstreamID == "" {
		return RouteRow{}, fmt.Errorf("upstream_id required")
	}
	if _, err := s.GetUpstream(rt.UpstreamID); err != nil {
		if errors.Is(err, ErrNotFound) {
			return RouteRow{}, fmt.Errorf("upstream not found")
		}
		return RouteRow{}, err
	}
	if err := s.validateAccessPolicyRef(rt.AccessPolicyID); err != nil {
		return RouteRow{}, err
	}
	rt = normalizeRoute(rt)
	hosts, err := json.Marshal(rt.Hosts)
	if err != nil {
		return RouteRow{}, err
	}
	res, err := s.db.Exec(`UPDATE routes SET
		name = ?, enabled = ?, hosts_json = ?, path_prefix = ?, upstream_id = ?,
		strip_prefix = ?, priority = ?, access_policy_id = ?, updated_at = ?
		WHERE id = ?`,
		rt.Name, boolInt(rt.Enabled), string(hosts), rt.PathPrefix, rt.UpstreamID,
		boolInt(rt.StripPrefix), rt.Priority, nullStringPtr(rt.AccessPolicyID), nowUTC(), id,
	)
	if err != nil {
		return RouteRow{}, err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return RouteRow{}, ErrNotFound
	}
	return s.GetRoute(id)
}

func (s *Store) DeleteRoute(id string) error {
	res, err := s.db.Exec(`DELETE FROM routes WHERE id = ?`, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) validateAccessPolicyRef(id *string) error {
	if id == nil || strings.TrimSpace(*id) == "" {
		return nil
	}
	trimmed := strings.TrimSpace(*id)
	*id = trimmed
	if _, err := s.GetAccessPolicy(trimmed); err != nil {
		if errors.Is(err, ErrNotFound) {
			return fmt.Errorf("access_policy not found")
		}
		return err
	}
	return nil
}

type routeScanner interface {
	Scan(dest ...any) error
}

func scanRoute(row routeScanner) (RouteRow, error) {
	var rt RouteRow
	var hosts string
	var enabled, strip int
	var policy sql.NullString
	var created, updated string
	err := row.Scan(
		&rt.ID, &rt.Name, &enabled, &hosts, &rt.PathPrefix, &rt.UpstreamID,
		&strip, &rt.Priority, &policy, &created, &updated,
	)
	if err != nil {
		return RouteRow{}, err
	}
	rt.Enabled = enabled != 0
	rt.StripPrefix = strip != 0
	rt.Hosts = nil
	if hosts != "" && hosts != "null" {
		_ = json.Unmarshal([]byte(hosts), &rt.Hosts)
	}
	if rt.Hosts == nil {
		rt.Hosts = []string{}
	}
	if policy.Valid && policy.String != "" {
		p := policy.String
		rt.AccessPolicyID = &p
	}
	rt.CreatedAt, _ = parseTime(created)
	rt.UpdatedAt, _ = parseTime(updated)
	return rt, nil
}

func normalizeRoute(rt RouteRow) RouteRow {
	if rt.Hosts == nil {
		rt.Hosts = []string{}
	}
	if rt.PathPrefix == "" {
		rt.PathPrefix = "/"
	}
	if rt.AccessPolicyID != nil {
		v := strings.TrimSpace(*rt.AccessPolicyID)
		if v == "" {
			rt.AccessPolicyID = nil
		} else {
			rt.AccessPolicyID = &v
		}
	}
	return rt
}

func nullStringPtr(p *string) any {
	if p == nil || strings.TrimSpace(*p) == "" {
		return nil
	}
	return strings.TrimSpace(*p)
}
