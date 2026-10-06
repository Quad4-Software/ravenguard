// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

package store_test

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/Quad4-Software/ravenguard/internal/admin/store"
	"github.com/Quad4-Software/ravenguard/internal/requestlog"
)

// TestMigrateRenamesLegacyRayColumns seeds a database in the pre-rename
// layout (ray_id columns, all schema versions applied) and verifies Open
// upgrades it to request_id without losing rows.
func TestMigrateRenamesLegacyRayColumns(t *testing.T) {
	dir := t.TempDir()
	dsn := fmt.Sprintf("file:%s?_pragma=journal_mode(WAL)", filepath.ToSlash(filepath.Join(dir, "admin.db")))
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatal(err)
	}
	stmts := []string{
		`CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)`,
		`CREATE TABLE waf_events (
			ray_id TEXT PRIMARY KEY,
			created_at TEXT NOT NULL,
			action TEXT NOT NULL,
			reason TEXT NOT NULL DEFAULT '',
			method TEXT NOT NULL DEFAULT '',
			path TEXT NOT NULL DEFAULT '',
			host TEXT NOT NULL DEFAULT '',
			ua TEXT NOT NULL DEFAULT '',
			ip_hash TEXT NOT NULL DEFAULT '',
			bind_id TEXT NOT NULL DEFAULT '',
			score INTEGER NOT NULL DEFAULT 0,
			detail_json TEXT NOT NULL DEFAULT '{}'
		)`,
		`INSERT INTO waf_events(ray_id, created_at, action) VALUES ('legacy-ray-1', '2026-01-01T00:00:00Z', 'block')`,
		`CREATE TABLE ml_samples (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			ray_id TEXT NOT NULL DEFAULT '',
			created_at TEXT NOT NULL,
			prob REAL NOT NULL DEFAULT 0,
			points INTEGER NOT NULL DEFAULT 0,
			would_block INTEGER NOT NULL DEFAULT 0,
			would_challenge INTEGER NOT NULL DEFAULT 0,
			features_json TEXT NOT NULL DEFAULT '[]',
			label TEXT NOT NULL DEFAULT '',
			method TEXT NOT NULL DEFAULT '',
			path TEXT NOT NULL DEFAULT '',
			host TEXT NOT NULL DEFAULT ''
		)`,
		`INSERT INTO ml_samples(ray_id, created_at) VALUES ('legacy-ray-2', '2026-01-01T00:00:00Z')`,
	}
	for _, q := range stmts {
		if _, err := db.Exec(q); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	// Mark every known migration applied so only the rename step runs.
	for v := 1; v < 512; v++ {
		if _, err := db.Exec(`INSERT OR IGNORE INTO schema_migrations(version, applied_at) VALUES (?, '2026-01-01')`, v); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()

	for _, table := range []string{"waf_events", "ml_samples"} {
		rows, err := st.DB().Query(`SELECT name FROM pragma_table_info(?)`, table)
		if err != nil {
			t.Fatal(err)
		}
		var cols []string
		for rows.Next() {
			var name string
			if err := rows.Scan(&name); err != nil {
				t.Fatal(err)
			}
			cols = append(cols, name)
		}
		_ = rows.Close()
		var hasReq, hasRay bool
		for _, c := range cols {
			hasReq = hasReq || c == "request_id"
			hasRay = hasRay || c == "ray_id"
		}
		if !hasReq || hasRay {
			t.Fatalf("%s columns=%v, want request_id present and ray_id gone", table, cols)
		}
	}

	ev, ok, err := st.GetWAFEventByID("legacy-ray-1")
	if err != nil || !ok || ev.RequestID != "legacy-ray-1" {
		t.Fatalf("legacy row lookup: ok=%v err=%v ev=%+v", ok, err, ev)
	}
	if err := st.InsertWAFEvent(requestlog.Event{RequestID: "new-id", Action: requestlog.ActionBlock}); err != nil {
		t.Fatalf("insert post-rename: %v", err)
	}
}
