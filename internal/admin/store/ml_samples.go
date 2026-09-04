// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package store

import (
	"database/sql"
	"encoding/json"
	"time"

	"github.com/Quad4-Software/ravenguard/internal/ml"
)

// MLSampleRow is a persisted sample with database id.
type MLSampleRow struct {
	ID int64 `json:"id"`
	ml.Sample
}

// InsertMLSample persists a shadow ML observation.
func (s *Store) InsertMLSample(sample ml.Sample) error {
	created := sample.CreatedAt
	if created.IsZero() {
		created = time.Now().UTC()
	}
	wb, wc := 0, 0
	if sample.WouldBlock {
		wb = 1
	}
	if sample.WouldChal {
		wc = 1
	}
	_, err := s.db.Exec(
		`INSERT INTO ml_samples(ray_id, created_at, prob, points, would_block, would_challenge, features_json, label, method, path, host)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		sample.Ray, created.UTC().Format(time.RFC3339Nano), sample.Prob, sample.Points, wb, wc,
		ml.SampleJSON(sample.Features), sample.Label, sample.Method, sample.Path, sample.Host,
	)
	return err
}

// LabelMLSample sets FP/TP/ignore on a sample by id.
func (s *Store) LabelMLSample(id int64, label string) error {
	_, err := s.db.Exec(`UPDATE ml_samples SET label = ? WHERE id = ?`, label, id)
	return err
}

// ListMLSamples returns recent samples.
func (s *Store) ListMLSamples(limit int, unlabeledOnly bool) ([]MLSampleRow, error) {
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	q := `SELECT id, ray_id, created_at, prob, points, would_block, would_challenge, features_json, label, method, path, host
	      FROM ml_samples`
	if unlabeledOnly {
		q += ` WHERE label = ''`
	}
	q += ` ORDER BY created_at DESC LIMIT ?`
	rows, err := s.db.Query(q, limit)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []MLSampleRow
	for rows.Next() {
		var (
			created      string
			wb, wc       int
			featuresJSON string
			row          MLSampleRow
		)
		if err := rows.Scan(&row.ID, &row.Ray, &created, &row.Prob, &row.Points, &wb, &wc, &featuresJSON, &row.Label, &row.Method, &row.Path, &row.Host); err != nil {
			return nil, err
		}
		row.WouldBlock = wb == 1
		row.WouldChal = wc == 1
		if t, err := time.Parse(time.RFC3339Nano, created); err == nil {
			row.CreatedAt = t
		}
		_ = json.Unmarshal([]byte(featuresJSON), &row.Features)
		out = append(out, row)
	}
	return out, rows.Err()
}

// ListLabeledMLSamples returns labeled samples for adapt training.
func (s *Store) ListLabeledMLSamples(limit int) ([]ml.Sample, error) {
	if limit <= 0 || limit > 5000 {
		limit = 1000
	}
	rows, err := s.db.Query(
		`SELECT ray_id, created_at, prob, points, would_block, would_challenge, features_json, label, method, path, host
		 FROM ml_samples WHERE label IN ('fp','tp') ORDER BY created_at DESC LIMIT ?`, limit,
	)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []ml.Sample
	for rows.Next() {
		var (
			created      string
			wb, wc       int
			featuresJSON string
			sample       ml.Sample
		)
		if err := rows.Scan(&sample.Ray, &created, &sample.Prob, &sample.Points, &wb, &wc, &featuresJSON, &sample.Label, &sample.Method, &sample.Path, &sample.Host); err != nil {
			return nil, err
		}
		sample.WouldBlock = wb == 1
		sample.WouldChal = wc == 1
		if t, err := time.Parse(time.RFC3339Nano, created); err == nil {
			sample.CreatedAt = t
		}
		_ = json.Unmarshal([]byte(featuresJSON), &sample.Features)
		out = append(out, sample)
	}
	return out, rows.Err()
}

// MLSampleIDByRay finds newest sample id for a ray.
func (s *Store) MLSampleIDByRay(ray string) (int64, bool, error) {
	var id int64
	err := s.db.QueryRow(`SELECT id FROM ml_samples WHERE ray_id = ? ORDER BY created_at DESC LIMIT 1`, ray).Scan(&id)
	if err == sql.ErrNoRows {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	return id, true, nil
}
