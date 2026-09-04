// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package api

import (
	"encoding/json"
	"fmt"

	"github.com/Quad4-Software/ravenguard/internal/admin/store"
	"github.com/Quad4-Software/ravenguard/internal/agentprotocol"
)

// BuildDesiredState merges fleet defaults with proxy routing assignment.
func (s *Server) BuildDesiredState(proxyID string) (agentprotocol.DesiredState, error) {
	rev, err := s.Store.NextDesiredRevision(proxyID)
	if err != nil {
		return agentprotocol.DesiredState{}, err
	}
	defaults, _ := s.Store.GetFleetDefaults()
	routes, err := s.Store.ListRoutesForProxy(proxyID)
	if err != nil {
		return agentprotocol.DesiredState{}, err
	}
	upstreams, err := s.Store.ListUpstreams()
	if err != nil {
		return agentprotocol.DesiredState{}, err
	}
	policies, err := s.Store.ListAccessPolicies()
	if err != nil {
		return agentprotocol.DesiredState{}, err
	}
	allSchemas, err := s.Store.ListAPISchemas()
	if err != nil {
		return agentprotocol.DesiredState{}, err
	}
	neededUp := map[string]store.UpstreamRow{}
	neededPol := map[string]store.AccessPolicyRow{}
	neededSchema := map[string]store.APISchemaRow{}
	var acmeHosts []string
	for _, rt := range routes {
		if up, err := findUpstream(upstreams, rt.UpstreamID); err == nil {
			neededUp[up.ID] = up
		}
		if rt.AccessPolicyID != nil {
			if p, err := findPolicy(policies, *rt.AccessPolicyID); err == nil {
				neededPol[p.ID] = p
			}
		}
		if rt.OpenAPISchemaID != nil {
			if sc, err := findSchema(allSchemas, *rt.OpenAPISchemaID); err == nil {
				neededSchema[sc.ID] = sc
			}
		}
		for _, h := range rt.Hosts {
			if h != "" && h != "*" {
				acmeHosts = append(acmeHosts, h)
			}
		}
	}
	upList := make([]store.UpstreamRow, 0, len(neededUp))
	for _, u := range neededUp {
		upList = append(upList, u)
	}
	polList := make([]store.AccessPolicyRow, 0, len(neededPol))
	for _, p := range neededPol {
		polList = append(polList, p)
	}
	schemaList := make([]store.APISchemaRow, 0, len(neededSchema))
	for _, sc := range neededSchema {
		schemaList = append(schemaList, sc)
	}
	upRaw, _ := json.Marshal(upList)
	rtRaw, _ := json.Marshal(routes)
	polRaw, _ := json.Marshal(polList)
	schemaRaw, _ := json.Marshal(schemaList)
	routing, _ := json.Marshal(agentprotocol.RoutingSnapshot{
		Upstreams:      upRaw,
		Routes:         rtRaw,
		AccessPolicies: polRaw,
		APISchemas:     schemaRaw,
	})
	var safe json.RawMessage
	if defaults != "" && defaults != "{}" {
		safe = json.RawMessage(defaults)
	}
	return agentprotocol.DesiredState{
		Revision:   rev,
		SafeConfig: safe,
		Routing:    routing,
		ACMEHosts:  uniqueStrings(acmeHosts),
	}, nil
}

func findUpstream(list []store.UpstreamRow, id string) (store.UpstreamRow, error) {
	for _, u := range list {
		if u.ID == id {
			return u, nil
		}
	}
	return store.UpstreamRow{}, fmt.Errorf("upstream not found")
}

func findPolicy(list []store.AccessPolicyRow, id string) (store.AccessPolicyRow, error) {
	for _, p := range list {
		if p.ID == id {
			return p, nil
		}
	}
	return store.AccessPolicyRow{}, fmt.Errorf("policy not found")
}

func findSchema(list []store.APISchemaRow, id string) (store.APISchemaRow, error) {
	for _, p := range list {
		if p.ID == id {
			return p, nil
		}
	}
	return store.APISchemaRow{}, fmt.Errorf("schema not found")
}

func uniqueStrings(in []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}
