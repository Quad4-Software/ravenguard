// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package ops

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/Quad4-Software/ravenguard/internal/agentprotocol"
)

// RuntimeDispatcher adapts Runtime for agent RPC.
type RuntimeDispatcher struct {
	Runtime      *Runtime
	ApplyRouting func(ctx context.Context, raw json.RawMessage) error
	ApplyDesired func(ctx context.Context, state agentprotocol.DesiredState) error
}

func (d *RuntimeDispatcher) Handle(ctx context.Context, op string, payload json.RawMessage) (any, error) {
	if d == nil || d.Runtime == nil {
		return nil, fmt.Errorf("runtime unavailable")
	}
	rt := d.Runtime
	switch op {
	case agentprotocol.OpHeartbeat:
		return agentprotocol.HeartbeatPayload{}, nil
	case agentprotocol.OpStatus:
		return rt.Status(), nil
	case agentprotocol.OpStatusHistory:
		return map[string]any{"history": rt.History()}, nil
	case agentprotocol.OpConfigSafeGet:
		view := rt.ConfigView()
		return view.Live, nil
	case agentprotocol.OpConfigSafePut:
		safe, err := DecodeSafeConfig(string(payload))
		if err != nil {
			var s SafeConfig
			if uerr := json.Unmarshal(payload, &s); uerr != nil {
				return nil, err
			}
			safe = s
		}
		if err := rt.ApplySafeConfig(safe); err != nil {
			return nil, err
		}
		return map[string]string{"status": "ok"}, nil
	case agentprotocol.OpRoutingPut:
		if d.ApplyRouting == nil {
			return nil, fmt.Errorf("routing apply unavailable")
		}
		if err := d.ApplyRouting(ctx, payload); err != nil {
			return nil, err
		}
		return map[string]string{"status": "ok"}, nil
	case agentprotocol.OpDesiredApply:
		var state agentprotocol.DesiredState
		if err := json.Unmarshal(payload, &state); err != nil {
			return nil, err
		}
		if d.ApplyDesired != nil {
			if err := d.ApplyDesired(ctx, state); err != nil {
				return nil, err
			}
		}
		return map[string]any{"revision": state.Revision}, nil
	case agentprotocol.OpBansList:
		if rt.Protect == nil {
			return map[string]any{"bans": []any{}}, nil
		}
		return map[string]any{"bans": rt.Protect.ListBans()}, nil
	case agentprotocol.OpBansCreate:
		var p agentprotocol.BanCreatePayload
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, err
		}
		if rt.Protect == nil {
			return nil, fmt.Errorf("protect disabled")
		}
		rt.Protect.BanNow(p.Key)
		return map[string]string{"status": "ok"}, nil
	case agentprotocol.OpBansDelete:
		var p agentprotocol.BanDeletePayload
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, err
		}
		if rt.Protect == nil {
			return nil, fmt.Errorf("protect disabled")
		}
		rt.Protect.Unban(p.Key)
		return map[string]string{"status": "ok"}, nil
	case agentprotocol.OpBlocklistsGet:
		if rt.Lists == nil {
			return map[string]any{}, nil
		}
		return rt.Lists.Stats(), nil
	case agentprotocol.OpBlocklistsReload:
		if rt.Lists == nil {
			return nil, fmt.Errorf("blocklists unavailable")
		}
		if err := rt.Lists.ReloadNow(); err != nil {
			return nil, err
		}
		return rt.Lists.Stats(), nil
	case agentprotocol.OpBlocklistsAdd:
		var p agentprotocol.BlocklistEntryPayload
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, err
		}
		if rt.Lists == nil {
			return nil, fmt.Errorf("blocklists unavailable")
		}
		if err := rt.Lists.AddEntry(p.Kind, p.Value); err != nil {
			return nil, err
		}
		return map[string]string{"status": "ok"}, nil
	case agentprotocol.OpBlocklistsRemove:
		var p agentprotocol.BlocklistEntryPayload
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, err
		}
		if rt.Lists == nil {
			return nil, fmt.Errorf("blocklists unavailable")
		}
		if err := rt.Lists.RemoveEntry(p.Kind, p.Value); err != nil {
			return nil, err
		}
		return map[string]string{"status": "ok"}, nil
	case agentprotocol.OpQFeedsGet:
		st := rt.Status()
		return map[string]any{"status": st.QFeeds, "config": rt.QFeedsView()}, nil
	case agentprotocol.OpQFeedsPut:
		var safe QFeedsSafe
		if err := json.Unmarshal(payload, &safe); err != nil {
			return nil, err
		}
		if err := rt.ApplyQFeeds(safe); err != nil {
			return nil, err
		}
		st := rt.Status()
		return map[string]any{"status": st.QFeeds, "config": rt.QFeedsView()}, nil
	case agentprotocol.OpQFeedsRefresh:
		if rt.Feeds == nil {
			return nil, fmt.Errorf("qfeeds unavailable")
		}
		rt.Feeds.RefreshNow(ctx)
		st := rt.Status()
		return map[string]any{"status": st.QFeeds}, nil
	case agentprotocol.OpLogsSnapshot:
		var p agentprotocol.LogsPayload
		_ = json.Unmarshal(payload, &p)
		if rt.LogSnapshot == nil {
			return []any{}, nil
		}
		return rt.LogSnapshot(p.Limit, p.Level), nil
	case agentprotocol.OpRequestByRay:
		var p agentprotocol.RequestByRayPayload
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, err
		}
		if rt.RequestByRay == nil {
			return nil, fmt.Errorf("request log unavailable")
		}
		ev, ok := rt.RequestByRay(p.Ray)
		if !ok {
			return nil, fmt.Errorf("not found")
		}
		return ev, nil
	case agentprotocol.OpRequestsRecent:
		var p agentprotocol.RequestsRecentPayload
		_ = json.Unmarshal(payload, &p)
		if rt.RequestsRecent == nil {
			return []any{}, nil
		}
		return rt.RequestsRecent(p.Limit), nil
	case agentprotocol.OpCertsStatus:
		if rt.CertStatus == nil {
			return map[string]any{"certs": []any{}}, nil
		}
		return rt.CertStatus(), nil
	case agentprotocol.OpCertsDetail:
		var p agentprotocol.CertHostPayload
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, err
		}
		if rt.CertDetail == nil {
			return nil, fmt.Errorf("certs unavailable")
		}
		return rt.CertDetail(p.Host)
	case agentprotocol.OpCertsPut:
		var p agentprotocol.CertHostPayload
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, err
		}
		if rt.ManualCertPut == nil {
			return nil, fmt.Errorf("manual certs unavailable")
		}
		if err := rt.ManualCertPut(p.Host, p.CertPEM, p.KeyPEM); err != nil {
			return nil, err
		}
		return map[string]string{"status": "ok"}, nil
	case agentprotocol.OpCertsDelete:
		var p agentprotocol.CertHostPayload
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, err
		}
		if rt.ManualCertDelete == nil {
			return nil, fmt.Errorf("manual certs unavailable")
		}
		if err := rt.ManualCertDelete(p.Host); err != nil {
			return nil, err
		}
		return map[string]string{"status": "ok"}, nil
	case agentprotocol.OpCertsExport:
		var p agentprotocol.CertHostPayload
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, err
		}
		if rt.CertExport == nil {
			return nil, fmt.Errorf("cert export unavailable")
		}
		certPEM, keyPEM, err := rt.CertExport(p.Host)
		if err != nil {
			return nil, err
		}
		return agentprotocol.CertExportPayload{Host: p.Host, CertPEM: certPEM, KeyPEM: keyPEM}, nil
	case agentprotocol.OpCertsRenew:
		var p agentprotocol.CertHostPayload
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, err
		}
		if rt.CertRenew == nil {
			return nil, fmt.Errorf("cert renew unavailable")
		}
		if err := rt.CertRenew(ctx, p.Host); err != nil {
			return nil, err
		}
		return map[string]string{"status": "ok"}, nil
	case agentprotocol.OpCertsManage:
		var p agentprotocol.CertManagePayload
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, err
		}
		if rt.ACMEManage == nil {
			return nil, fmt.Errorf("acme manage unavailable")
		}
		if err := rt.ACMEManage(ctx, p.Hosts); err != nil {
			return nil, err
		}
		return map[string]string{"status": "ok"}, nil
	default:
		return nil, fmt.Errorf("unknown op %s", op)
	}
}
