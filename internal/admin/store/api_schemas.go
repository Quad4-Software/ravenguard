// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package store

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Quad4-Software/ravenguard/internal/schemagate"
)

// APISchemaRow is a persisted OpenAPI document.
type APISchemaRow struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Mode      string    `json:"mode"`
	SpecText  string    `json:"spec_text"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (s *Store) ListAPISchemas() ([]APISchemaRow, error) {
	rows, err := s.db.Query(`SELECT id, name, mode, spec_text, created_at, updated_at FROM api_schemas ORDER BY name ASC, id ASC`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []APISchemaRow
	for rows.Next() {
		row, err := scanAPISchema(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

func (s *Store) GetAPISchema(id string) (APISchemaRow, error) {
	row := s.db.QueryRow(`SELECT id, name, mode, spec_text, created_at, updated_at FROM api_schemas WHERE id = ?`, id)
	p, err := scanAPISchema(row)
	if errors.Is(err, sql.ErrNoRows) {
		return APISchemaRow{}, ErrNotFound
	}
	return p, err
}

func (s *Store) CreateAPISchema(p APISchemaRow) (APISchemaRow, error) {
	p.Name = strings.TrimSpace(p.Name)
	p.SpecText = strings.TrimSpace(p.SpecText)
	if p.Name == "" {
		return APISchemaRow{}, fmt.Errorf("name required")
	}
	if p.SpecText == "" {
		return APISchemaRow{}, fmt.Errorf("spec_text required")
	}
	if err := schemagate.ValidateSpecText(p.SpecText); err != nil {
		return APISchemaRow{}, fmt.Errorf("invalid openapi: %w", err)
	}
	p = normalizeAPISchema(p)
	id, err := newID()
	if err != nil {
		return APISchemaRow{}, err
	}
	now := nowUTC()
	_, err = s.db.Exec(`INSERT INTO api_schemas(id, name, mode, spec_text, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)`,
		id, p.Name, p.Mode, p.SpecText, now, now,
	)
	if err != nil {
		return APISchemaRow{}, err
	}
	return s.GetAPISchema(id)
}

func (s *Store) UpdateAPISchema(id string, p APISchemaRow) (APISchemaRow, error) {
	if _, err := s.GetAPISchema(id); err != nil {
		return APISchemaRow{}, err
	}
	p.Name = strings.TrimSpace(p.Name)
	p.SpecText = strings.TrimSpace(p.SpecText)
	if p.Name == "" {
		return APISchemaRow{}, fmt.Errorf("name required")
	}
	if p.SpecText == "" {
		return APISchemaRow{}, fmt.Errorf("spec_text required")
	}
	if err := schemagate.ValidateSpecText(p.SpecText); err != nil {
		return APISchemaRow{}, fmt.Errorf("invalid openapi: %w", err)
	}
	p = normalizeAPISchema(p)
	res, err := s.db.Exec(`UPDATE api_schemas SET name = ?, mode = ?, spec_text = ?, updated_at = ? WHERE id = ?`,
		p.Name, p.Mode, p.SpecText, nowUTC(), id,
	)
	if err != nil {
		return APISchemaRow{}, err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return APISchemaRow{}, ErrNotFound
	}
	return s.GetAPISchema(id)
}

func (s *Store) DeleteAPISchema(id string) error {
	res, err := s.db.Exec(`DELETE FROM api_schemas WHERE id = ?`, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) validateAPISchemaRef(id *string) error {
	if id == nil || strings.TrimSpace(*id) == "" {
		return nil
	}
	trimmed := strings.TrimSpace(*id)
	*id = trimmed
	if _, err := s.GetAPISchema(trimmed); err != nil {
		if errors.Is(err, ErrNotFound) {
			return fmt.Errorf("openapi_schema not found")
		}
		return err
	}
	return nil
}

func normalizeAPISchema(p APISchemaRow) APISchemaRow {
	mode := strings.ToLower(strings.TrimSpace(p.Mode))
	if mode != "detect" {
		mode = "block"
	}
	p.Mode = mode
	return p
}

type apiSchemaScanner interface {
	Scan(dest ...any) error
}

func scanAPISchema(row apiSchemaScanner) (APISchemaRow, error) {
	var p APISchemaRow
	var created, updated string
	if err := row.Scan(&p.ID, &p.Name, &p.Mode, &p.SpecText, &created, &updated); err != nil {
		return APISchemaRow{}, err
	}
	p.CreatedAt, _ = parseTime(created)
	p.UpdatedAt, _ = parseTime(updated)
	return p, nil
}
