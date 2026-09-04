// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package api

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Quad4-Software/ravenguard/internal/admin/ops"
	"github.com/Quad4-Software/ravenguard/internal/admin/store"
	"github.com/Quad4-Software/ravenguard/internal/agentprotocol"
	"github.com/Quad4-Software/ravenguard/internal/config"
)

func TestTargetForOfflineProxyDoesNotUseLocal(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	row, _, err := st.CreateProxy("edge", nil, "1.2.3.4", "", false)
	if err != nil {
		t.Fatal(err)
	}

	cfg := config.Default()
	cfg.Challenge.Secret = "test-secret-16chars"
	rt := ops.NewRuntime(cfg, nil, nil, nil, nil, nil, nil)
	s := &Server{
		Store:         st,
		Runtime:       rt,
		LocalTarget:   &ops.LocalTarget{Runtime: rt},
		AgentRegistry: agentprotocol.NewRegistry(),
	}
	target := s.targetFor(row.ID)
	if _, ok := target.(*ops.OfflineTarget); !ok {
		t.Fatalf("got %T want OfflineTarget", target)
	}
	if _, err := target.Status(context.Background()); err == nil {
		t.Fatal("expected offline error")
	}
}

func TestChallengePayloadOmitsToken(t *testing.T) {
	chal := agentprotocol.ChallengePayload{Nonce: "n", Timestamp: 1, Signature: "s"}
	raw, err := json.Marshal(chal)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), `"token"`) {
		t.Fatalf("challenge must not embed enrollment token: %s", raw)
	}
}
