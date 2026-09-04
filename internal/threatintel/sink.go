// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package threatintel

import (
	"time"

	"github.com/Quad4-Software/ravenguard/internal/agentprotocol"
)

// Sink inserts normalized IOCs into the threat ledger.
type Sink interface {
	InsertThreatEntries(sourceProxyID string, entries []agentprotocol.ThreatEntry) ([]agentprotocol.ThreatEntry, int64, error)
}

// IngestResult summarizes an ingest batch.
type IngestResult struct {
	Accepted int   `json:"accepted"`
	Skipped  int   `json:"skipped"`
	Stored   int   `json:"stored"`
	Revision int64 `json:"revision"`
}

// IngestIOCs converts and stores IOCs via the hub ledger sink.
func IngestIOCs(sink Sink, source string, iocs []IOC, defaultTTL time.Duration) (IngestResult, error) {
	var res IngestResult
	if sink == nil || len(iocs) == 0 {
		return res, nil
	}
	if source == "" {
		source = "threatintel"
	}
	entries := make([]agentprotocol.ThreatEntry, 0, len(iocs))
	for _, ioc := range iocs {
		e, ok := ToThreatEntry(ioc, defaultTTL)
		if !ok {
			res.Skipped++
			continue
		}
		if e.SourceProxyID == "threatintel" || e.SourceProxyID == "" {
			e.SourceProxyID = source
		}
		entries = append(entries, e)
		res.Accepted++
	}
	if len(entries) == 0 {
		return res, nil
	}
	stored, rev, err := sink.InsertThreatEntries(source, entries)
	if err != nil {
		return res, err
	}
	res.Stored = len(stored)
	res.Revision = rev
	return res, nil
}
