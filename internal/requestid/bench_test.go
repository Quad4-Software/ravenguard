// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

package requestid_test

import (
	"testing"

	"github.com/Quad4-Software/ravenguard/internal/requestid"
)

func BenchmarkNew(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		_ = requestid.New()
	}
}
