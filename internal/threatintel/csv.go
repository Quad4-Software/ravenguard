// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package threatintel

import (
	"encoding/csv"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/Quad4-Software/ravenguard/internal/agentprotocol"
)

// ExportCSV writes IOCs derived from ledger entries.
func ExportCSV(w io.Writer, entries []agentprotocol.ThreatEntry, opt ExportOptions) (int, error) {
	cw := csv.NewWriter(w)
	if err := cw.Write([]string{"type", "value", "ttl_seconds", "reason", "source", "confidence"}); err != nil {
		return 0, err
	}
	n := 0
	for _, e := range entries {
		ioc, ok := FromThreatEntry(e, opt)
		if !ok {
			continue
		}
		if err := cw.Write([]string{
			ioc.Type,
			ioc.Value,
			strconv.FormatInt(ioc.TTLSeconds, 10),
			ioc.Reason,
			ioc.Source,
			strconv.Itoa(ioc.Confidence),
		}); err != nil {
			return n, err
		}
		n++
	}
	cw.Flush()
	return n, cw.Error()
}

// ParseCSV reads IOC rows. Header optional when first column is a known type.
func ParseCSV(r io.Reader) ([]IOC, error) {
	cr := csv.NewReader(r)
	cr.TrimLeadingSpace = true
	cr.FieldsPerRecord = -1
	rows, err := cr.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("csv: %w", err)
	}
	if len(rows) == 0 {
		return nil, nil
	}
	start := 0
	col := map[string]int{"type": 0, "value": 1, "ttl_seconds": 2, "reason": 3, "source": 4, "confidence": 5}
	if looksLikeHeader(rows[0]) {
		col = map[string]int{}
		for i, h := range rows[0] {
			col[strings.ToLower(strings.TrimSpace(h))] = i
		}
		start = 1
	}
	typeIdx, okT := col["type"]
	valueIdx, okV := col["value"]
	if !okT || !okV {
		return nil, fmt.Errorf("csv: type and value columns required")
	}
	var out []IOC
	for _, row := range rows[start:] {
		if len(row) <= valueIdx || len(row) <= typeIdx {
			continue
		}
		typ := strings.TrimSpace(row[typeIdx])
		val := strings.TrimSpace(row[valueIdx])
		if typ == "" || val == "" || strings.HasPrefix(typ, "#") {
			continue
		}
		ioc := IOC{Type: typ, Value: val}
		if i, ok := col["ttl_seconds"]; ok && i < len(row) {
			if n, err := strconv.ParseInt(strings.TrimSpace(row[i]), 10, 64); err == nil {
				ioc.TTLSeconds = n
			}
		}
		if i, ok := col["reason"]; ok && i < len(row) {
			ioc.Reason = strings.TrimSpace(row[i])
		}
		if i, ok := col["source"]; ok && i < len(row) {
			ioc.Source = strings.TrimSpace(row[i])
		}
		if i, ok := col["confidence"]; ok && i < len(row) {
			if n, err := strconv.Atoi(strings.TrimSpace(row[i])); err == nil {
				ioc.Confidence = n
			}
		}
		out = append(out, ioc)
	}
	return out, nil
}

func looksLikeHeader(row []string) bool {
	if len(row) == 0 {
		return false
	}
	h := strings.ToLower(strings.TrimSpace(row[0]))
	return h == "type" || h == "ioc_type" || h == "indicator_type"
}
