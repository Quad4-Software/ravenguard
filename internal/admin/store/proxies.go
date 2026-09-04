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

	"github.com/Quad4-Software/ravenguard/internal/agentprotocol"
)

// ProxyRow is a registered edge proxy in the hub fleet.
type ProxyRow struct {
	ID              string     `json:"id"`
	Name            string     `json:"name"`
	Tags            []string   `json:"tags"`
	Fingerprint     string     `json:"fingerprint"`
	TokenHash       string     `json:"-"`
	Universal       bool       `json:"universal"`
	PublicIPv4      string     `json:"public_ipv4"`
	PublicIPv6      string     `json:"public_ipv6"`
	ListenHTTP      string     `json:"listen_http"`
	ListenHTTPS     string     `json:"listen_https"`
	ListenQUIC      string     `json:"listen_quic"`
	Hostname        string     `json:"hostname"`
	AgentVersion    string     `json:"agent_version"`
	LastSeenAt      *time.Time `json:"last_seen_at,omitempty"`
	DesiredRevision int64      `json:"desired_revision"`
	DesiredJSON     string     `json:"-"`
	Online          bool       `json:"online,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
	EnrollmentToken string     `json:"enrollment_token,omitempty"`
}

func (s *Store) CreateProxy(name string, tags []string, publicIPv4, publicIPv6 string, universal bool) (ProxyRow, string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return ProxyRow{}, "", fmt.Errorf("name required")
	}
	id, err := newID()
	if err != nil {
		return ProxyRow{}, "", err
	}
	token, err := agentprotocol.NewToken()
	if err != nil {
		return ProxyRow{}, "", err
	}
	now := time.Now().UTC()
	tagsJSON, _ := json.Marshal(tags)
	_, err = s.db.Exec(`INSERT INTO proxies(
		id, name, tags_json, fingerprint, token_hash, universal,
		public_ipv4, public_ipv6, created_at, updated_at
	) VALUES (?, ?, ?, '', ?, ?, ?, ?, ?, ?)`,
		id, name, string(tagsJSON), agentprotocol.HashToken(token), boolInt(universal),
		strings.TrimSpace(publicIPv4), strings.TrimSpace(publicIPv6),
		now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano),
	)
	if err != nil {
		return ProxyRow{}, "", err
	}
	row, err := s.GetProxy(id)
	if err != nil {
		return ProxyRow{}, "", err
	}
	row.EnrollmentToken = token
	return row, token, nil
}

func (s *Store) ListProxies() ([]ProxyRow, error) {
	rows, err := s.db.Query(`SELECT id, name, tags_json, fingerprint, token_hash, universal,
		public_ipv4, public_ipv6, listen_http, listen_https, listen_quic, hostname, agent_version,
		last_seen_at, desired_revision, desired_json, created_at, updated_at
		FROM proxies ORDER BY name ASC, id ASC`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []ProxyRow
	for rows.Next() {
		p, err := scanProxy(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *Store) GetProxy(id string) (ProxyRow, error) {
	row := s.db.QueryRow(`SELECT id, name, tags_json, fingerprint, token_hash, universal,
		public_ipv4, public_ipv6, listen_http, listen_https, listen_quic, hostname, agent_version,
		last_seen_at, desired_revision, desired_json, created_at, updated_at
		FROM proxies WHERE id = ?`, id)
	p, err := scanProxy(row)
	if errors.Is(err, sql.ErrNoRows) {
		return ProxyRow{}, ErrNotFound
	}
	return p, err
}

func (s *Store) UpdateProxy(id string, name string, tags []string, publicIPv4, publicIPv6 string) (ProxyRow, error) {
	p, err := s.GetProxy(id)
	if err != nil {
		return ProxyRow{}, err
	}
	if strings.TrimSpace(name) != "" {
		p.Name = strings.TrimSpace(name)
	}
	if tags != nil {
		p.Tags = tags
	}
	p.PublicIPv4 = strings.TrimSpace(publicIPv4)
	p.PublicIPv6 = strings.TrimSpace(publicIPv6)
	tagsJSON, _ := json.Marshal(p.Tags)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err = s.db.Exec(`UPDATE proxies SET name=?, tags_json=?, public_ipv4=?, public_ipv6=?, updated_at=? WHERE id=?`,
		p.Name, string(tagsJSON), p.PublicIPv4, p.PublicIPv6, now, id)
	if err != nil {
		return ProxyRow{}, err
	}
	return s.GetProxy(id)
}

func (s *Store) DeleteProxy(id string) error {
	res, err := s.db.Exec(`DELETE FROM proxies WHERE id = ?`, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) RotateProxyToken(id string) (ProxyRow, string, error) {
	token, err := agentprotocol.NewToken()
	if err != nil {
		return ProxyRow{}, "", err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	res, err := s.db.Exec(`UPDATE proxies SET token_hash=?, fingerprint='', updated_at=? WHERE id=?`,
		agentprotocol.HashToken(token), now, id)
	if err != nil {
		return ProxyRow{}, "", err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ProxyRow{}, "", ErrNotFound
	}
	row, err := s.GetProxy(id)
	if err != nil {
		return ProxyRow{}, "", err
	}
	row.EnrollmentToken = token
	return row, token, nil
}

func (s *Store) LookupToken(tokenHash string) (proxyID string, fingerprint string, name string, universal bool, err error) {
	var uni int
	err = s.db.QueryRow(`SELECT id, fingerprint, name, universal FROM proxies WHERE token_hash = ?`, tokenHash).
		Scan(&proxyID, &fingerprint, &name, &uni)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", "", false, ErrNotFound
	}
	if err != nil {
		return "", "", "", false, err
	}
	return proxyID, fingerprint, name, uni != 0, nil
}

func (s *Store) BindFingerprint(proxyID, fingerprint, name, hostname string) error {
	fingerprint = strings.TrimSpace(fingerprint)
	if fingerprint == "" {
		return fmt.Errorf("fingerprint required")
	}
	var other string
	err := s.db.QueryRow(`SELECT id FROM proxies WHERE fingerprint = ? AND id != ? AND fingerprint != ''`, fingerprint, proxyID).Scan(&other)
	if err == nil {
		return fmt.Errorf("fingerprint already bound")
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	res, err := s.db.Exec(`UPDATE proxies SET fingerprint=?, name=CASE WHEN ? != '' THEN ? ELSE name END,
		hostname=?, last_seen_at=?, updated_at=?
		WHERE id=? AND (fingerprint = '' OR fingerprint = ?)`,
		fingerprint, name, name, hostname, now, now, proxyID, fingerprint)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("fingerprint mismatch")
	}
	return nil
}

func (s *Store) TouchProxy(proxyID string, listenHTTP, listenHTTPS, listenQUIC, agentVersion string) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := s.db.Exec(`UPDATE proxies SET listen_http=?, listen_https=?, listen_quic=?,
		agent_version=CASE WHEN ? != '' THEN ? ELSE agent_version END,
		last_seen_at=?, updated_at=? WHERE id=?`,
		listenHTTP, listenHTTPS, listenQUIC, agentVersion, agentVersion, now, now, proxyID)
	return err
}

func (s *Store) DesiredRevision(proxyID string) (int64, error) {
	var rev int64
	err := s.db.QueryRow(`SELECT desired_revision FROM proxies WHERE id = ?`, proxyID).Scan(&rev)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrNotFound
	}
	return rev, err
}

func (s *Store) DesiredState(proxyID string) (agentprotocol.DesiredState, error) {
	p, err := s.GetProxy(proxyID)
	if err != nil {
		return agentprotocol.DesiredState{}, err
	}
	state := agentprotocol.DesiredState{Revision: p.DesiredRevision}
	if strings.TrimSpace(p.DesiredJSON) != "" {
		if err := json.Unmarshal([]byte(p.DesiredJSON), &state); err != nil {
			return agentprotocol.DesiredState{}, err
		}
		state.Revision = p.DesiredRevision
	}
	return state, nil
}

func (s *Store) SetDesiredState(proxyID string, state agentprotocol.DesiredState) error {
	raw, err := json.Marshal(state)
	if err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	res, err := s.db.Exec(`UPDATE proxies SET desired_revision=?, desired_json=?, updated_at=? WHERE id=?`,
		state.Revision, string(raw), now, proxyID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) NextDesiredRevision(proxyID string) (int64, error) {
	rev, err := s.DesiredRevision(proxyID)
	if err != nil {
		return 0, err
	}
	return rev + 1, nil
}

func (s *Store) GetFleetDefaults() (string, error) {
	var payload string
	err := s.db.QueryRow(`SELECT safe_config FROM fleet_defaults WHERE id = 1`).Scan(&payload)
	if errors.Is(err, sql.ErrNoRows) {
		return "{}", nil
	}
	return payload, err
}

func (s *Store) SetFleetDefaults(payload string) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := s.db.Exec(`INSERT INTO fleet_defaults(id, safe_config, updated_at) VALUES (1, ?, ?)
		ON CONFLICT(id) DO UPDATE SET safe_config=excluded.safe_config, updated_at=excluded.updated_at`,
		payload, now)
	return err
}

func (s *Store) SetRouteProxy(routeID, proxyID string) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	res, err := s.db.Exec(`UPDATE routes SET proxy_id=?, updated_at=? WHERE id=?`, proxyID, now, routeID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) ListRoutesForProxy(proxyID string) ([]RouteRow, error) {
	rows, err := s.db.Query(`SELECT id, name, enabled, hosts_json, path_prefix, upstream_id,
		strip_prefix, priority, access_policy_id, COALESCE(proxy_id,''), openapi_schema_id, created_at, updated_at
		FROM routes WHERE proxy_id = ? OR (? = '' AND (proxy_id = '' OR proxy_id IS NULL))
		ORDER BY priority DESC, name ASC, id ASC`, proxyID, proxyID)
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

type scanner interface {
	Scan(dest ...any) error
}

func scanProxy(row scanner) (ProxyRow, error) {
	var p ProxyRow
	var tagsJSON string
	var uni int
	var lastSeen sql.NullString
	var created, updated string
	err := row.Scan(&p.ID, &p.Name, &tagsJSON, &p.Fingerprint, &p.TokenHash, &uni,
		&p.PublicIPv4, &p.PublicIPv6, &p.ListenHTTP, &p.ListenHTTPS, &p.ListenQUIC, &p.Hostname, &p.AgentVersion,
		&lastSeen, &p.DesiredRevision, &p.DesiredJSON, &created, &updated)
	if err != nil {
		return ProxyRow{}, err
	}
	p.Universal = uni != 0
	_ = json.Unmarshal([]byte(tagsJSON), &p.Tags)
	if p.Tags == nil {
		p.Tags = []string{}
	}
	if lastSeen.Valid && lastSeen.String != "" {
		t, err := time.Parse(time.RFC3339Nano, lastSeen.String)
		if err == nil {
			p.LastSeenAt = &t
		}
	}
	p.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
	p.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updated)
	return p, nil
}
