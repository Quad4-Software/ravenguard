// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package store

import (
	"database/sql"
	"fmt"
)

var migrations = []string{
	`CREATE TABLE IF NOT EXISTS schema_migrations (
		version INTEGER PRIMARY KEY,
		applied_at TEXT NOT NULL
	)`,
	`CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT NOT NULL UNIQUE COLLATE NOCASE,
		password_hash TEXT NOT NULL,
		role TEXT NOT NULL,
		created_at TEXT NOT NULL,
		updated_at TEXT NOT NULL,
		disabled INTEGER NOT NULL DEFAULT 0
	)`,
	`CREATE TABLE IF NOT EXISTS sessions (
		id TEXT PRIMARY KEY,
		user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		token_hash TEXT NOT NULL UNIQUE,
		csrf_token TEXT NOT NULL,
		expires_at TEXT NOT NULL,
		created_at TEXT NOT NULL,
		ip TEXT NOT NULL DEFAULT '',
		user_agent TEXT NOT NULL DEFAULT ''
	)`,
	`CREATE TABLE IF NOT EXISTS api_tokens (
		id TEXT PRIMARY KEY,
		user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		name TEXT NOT NULL,
		token_hash TEXT NOT NULL UNIQUE,
		role TEXT NOT NULL,
		created_at TEXT NOT NULL,
		expires_at TEXT,
		last_used_at TEXT,
		revoked INTEGER NOT NULL DEFAULT 0
	)`,
	`CREATE TABLE IF NOT EXISTS audit_events (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		created_at TEXT NOT NULL,
		actor_id INTEGER,
		actor_name TEXT NOT NULL DEFAULT '',
		action TEXT NOT NULL,
		target TEXT NOT NULL DEFAULT '',
		detail TEXT NOT NULL DEFAULT '',
		ip TEXT NOT NULL DEFAULT ''
	)`,
	`CREATE TABLE IF NOT EXISTS config_overrides (
		id INTEGER PRIMARY KEY CHECK (id = 1),
		payload TEXT NOT NULL,
		updated_at TEXT NOT NULL,
		updated_by INTEGER
	)`,
	`CREATE TABLE IF NOT EXISTS access_policies (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		mode TEXT NOT NULL DEFAULT 'all',
		rules_json TEXT NOT NULL DEFAULT '[]',
		cookie_ttl TEXT NOT NULL DEFAULT '24h',
		created_at TEXT NOT NULL,
		updated_at TEXT NOT NULL
	)`,
	`CREATE TABLE IF NOT EXISTS upstreams (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		url TEXT NOT NULL,
		connect_timeout TEXT NOT NULL DEFAULT '',
		response_header_timeout TEXT NOT NULL DEFAULT '',
		idle_conn_timeout TEXT NOT NULL DEFAULT '',
		max_idle_conns INTEGER NOT NULL DEFAULT 0,
		max_idle_conns_per_host INTEGER NOT NULL DEFAULT 0,
		max_conns_per_host INTEGER NOT NULL DEFAULT 0,
		flush_interval TEXT NOT NULL DEFAULT '',
		set_headers TEXT NOT NULL DEFAULT '[]',
		health_enabled INTEGER NOT NULL DEFAULT 0,
		health_path TEXT NOT NULL DEFAULT '/healthz',
		health_interval TEXT NOT NULL DEFAULT '10s',
		health_timeout TEXT NOT NULL DEFAULT '3s',
		created_at TEXT NOT NULL,
		updated_at TEXT NOT NULL
	)`,
	`CREATE TABLE IF NOT EXISTS routes (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		enabled INTEGER NOT NULL DEFAULT 1,
		hosts_json TEXT NOT NULL DEFAULT '[]',
		path_prefix TEXT NOT NULL DEFAULT '/',
		upstream_id TEXT NOT NULL REFERENCES upstreams(id),
		strip_prefix INTEGER NOT NULL DEFAULT 0,
		priority INTEGER NOT NULL DEFAULT 0,
		access_policy_id TEXT REFERENCES access_policies(id) ON DELETE SET NULL,
		created_at TEXT NOT NULL,
		updated_at TEXT NOT NULL
	)`,
	`CREATE TABLE IF NOT EXISTS proxies (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		tags_json TEXT NOT NULL DEFAULT '[]',
		fingerprint TEXT NOT NULL DEFAULT '',
		token_hash TEXT NOT NULL UNIQUE,
		universal INTEGER NOT NULL DEFAULT 0,
		public_ipv4 TEXT NOT NULL DEFAULT '',
		public_ipv6 TEXT NOT NULL DEFAULT '',
		listen_http TEXT NOT NULL DEFAULT '',
		listen_https TEXT NOT NULL DEFAULT '',
		listen_quic TEXT NOT NULL DEFAULT '',
		hostname TEXT NOT NULL DEFAULT '',
		agent_version TEXT NOT NULL DEFAULT '',
		last_seen_at TEXT,
		desired_revision INTEGER NOT NULL DEFAULT 0,
		desired_json TEXT NOT NULL DEFAULT '',
		created_at TEXT NOT NULL,
		updated_at TEXT NOT NULL
	)`,
	`CREATE TABLE IF NOT EXISTS fleet_defaults (
		id INTEGER PRIMARY KEY CHECK (id = 1),
		safe_config TEXT NOT NULL DEFAULT '{}',
		updated_at TEXT NOT NULL
	)`,
	`CREATE TABLE IF NOT EXISTS service_migrations (
		id TEXT PRIMARY KEY,
		from_proxy_id TEXT NOT NULL,
		to_proxy_id TEXT NOT NULL,
		route_ids_json TEXT NOT NULL DEFAULT '[]',
		phase TEXT NOT NULL DEFAULT 'created',
		dns_checklist_json TEXT NOT NULL DEFAULT '[]',
		created_by INTEGER,
		created_at TEXT NOT NULL,
		updated_at TEXT NOT NULL,
		detail TEXT NOT NULL DEFAULT ''
	)`,
	`ALTER TABLE routes ADD COLUMN proxy_id TEXT NOT NULL DEFAULT ''`,
}

func migrate(db *sql.DB) error {
	if _, err := db.Exec(migrations[0]); err != nil {
		return fmt.Errorf("schema_migrations: %w", err)
	}
	var current int
	_ = db.QueryRow(`SELECT COALESCE(MAX(version), 0) FROM schema_migrations`).Scan(&current)
	for i := 1; i < len(migrations); i++ {
		ver := i
		if ver <= current {
			continue
		}
		tx, err := db.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(migrations[i]); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("migration %d: %w", ver, err)
		}
		if _, err := tx.Exec(`INSERT INTO schema_migrations(version, applied_at) VALUES (?, datetime('now'))`, ver); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}
