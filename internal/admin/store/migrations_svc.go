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

// ServiceMigration tracks a route move between proxies.
type ServiceMigration struct {
	ID           string             `json:"id"`
	FromProxyID  string             `json:"from_proxy_id"`
	ToProxyID    string             `json:"to_proxy_id"`
	RouteIDs     []string           `json:"route_ids"`
	Phase        string             `json:"phase"`
	DNSChecklist []DNSChecklistItem `json:"dns_checklist"`
	CreatedBy    *int               `json:"created_by,omitempty"`
	CreatedAt    time.Time          `json:"created_at"`
	UpdatedAt    time.Time          `json:"updated_at"`
	Detail       string             `json:"detail"`
}

type DNSChecklistItem struct {
	Host          string `json:"host"`
	FromIPv4      string `json:"from_ipv4,omitempty"`
	FromIPv6      string `json:"from_ipv6,omitempty"`
	ToIPv4        string `json:"to_ipv4,omitempty"`
	ToIPv6        string `json:"to_ipv6,omitempty"`
	SuggestedA    string `json:"suggested_a,omitempty"`
	SuggestedAAAA string `json:"suggested_aaaa,omitempty"`
	Note          string `json:"note,omitempty"`
}

func (s *Store) CreateServiceMigration(fromID, toID string, routeIDs []string, createdBy *int, checklist []DNSChecklistItem) (ServiceMigration, error) {
	if fromID == "" || toID == "" {
		return ServiceMigration{}, fmt.Errorf("from_proxy_id and to_proxy_id required")
	}
	if fromID == toID {
		return ServiceMigration{}, fmt.Errorf("source and destination must differ")
	}
	if len(routeIDs) == 0 {
		return ServiceMigration{}, fmt.Errorf("route_ids required")
	}
	id, err := newID()
	if err != nil {
		return ServiceMigration{}, err
	}
	now := time.Now().UTC()
	routesJSON, _ := json.Marshal(routeIDs)
	checkJSON, _ := json.Marshal(checklist)
	var by any
	if createdBy != nil {
		by = *createdBy
	}
	_, err = s.db.Exec(`INSERT INTO service_migrations(
		id, from_proxy_id, to_proxy_id, route_ids_json, phase, dns_checklist_json, created_by, created_at, updated_at
	) VALUES (?, ?, ?, ?, 'created', ?, ?, ?, ?)`,
		id, fromID, toID, string(routesJSON), string(checkJSON), by,
		now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano),
	)
	if err != nil {
		return ServiceMigration{}, err
	}
	return s.GetServiceMigration(id)
}

func (s *Store) GetServiceMigration(id string) (ServiceMigration, error) {
	row := s.db.QueryRow(`SELECT id, from_proxy_id, to_proxy_id, route_ids_json, phase, dns_checklist_json,
		created_by, created_at, updated_at, detail FROM service_migrations WHERE id = ?`, id)
	m, err := scanMigration(row)
	if errors.Is(err, sql.ErrNoRows) {
		return ServiceMigration{}, ErrNotFound
	}
	return m, err
}

func (s *Store) ListServiceMigrations() ([]ServiceMigration, error) {
	rows, err := s.db.Query(`SELECT id, from_proxy_id, to_proxy_id, route_ids_json, phase, dns_checklist_json,
		created_by, created_at, updated_at, detail FROM service_migrations ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []ServiceMigration
	for rows.Next() {
		m, err := scanMigration(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func (s *Store) UpdateServiceMigration(id, phase, detail string, checklist []DNSChecklistItem) (ServiceMigration, error) {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if checklist != nil {
		checkJSON, _ := json.Marshal(checklist)
		_, err := s.db.Exec(`UPDATE service_migrations SET phase=?, detail=?, dns_checklist_json=?, updated_at=? WHERE id=?`,
			phase, detail, string(checkJSON), now, id)
		if err != nil {
			return ServiceMigration{}, err
		}
	} else {
		_, err := s.db.Exec(`UPDATE service_migrations SET phase=?, detail=?, updated_at=? WHERE id=?`,
			phase, detail, now, id)
		if err != nil {
			return ServiceMigration{}, err
		}
	}
	return s.GetServiceMigration(id)
}

func scanMigration(row scanner) (ServiceMigration, error) {
	var m ServiceMigration
	var routesJSON, checkJSON string
	var createdBy sql.NullInt64
	var created, updated string
	err := row.Scan(&m.ID, &m.FromProxyID, &m.ToProxyID, &routesJSON, &m.Phase, &checkJSON,
		&createdBy, &created, &updated, &m.Detail)
	if err != nil {
		return ServiceMigration{}, err
	}
	_ = json.Unmarshal([]byte(routesJSON), &m.RouteIDs)
	_ = json.Unmarshal([]byte(checkJSON), &m.DNSChecklist)
	if m.RouteIDs == nil {
		m.RouteIDs = []string{}
	}
	if m.DNSChecklist == nil {
		m.DNSChecklist = []DNSChecklistItem{}
	}
	if createdBy.Valid {
		v := int(createdBy.Int64)
		m.CreatedBy = &v
	}
	m.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
	m.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updated)
	m.Phase = strings.TrimSpace(m.Phase)
	return m, nil
}
