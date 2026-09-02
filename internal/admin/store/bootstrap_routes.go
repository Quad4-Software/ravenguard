// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package store

import "strings"

// BootstrapDefaultUpstream creates a default upstream and catch-all route when none exist.
func (s *Store) BootstrapDefaultUpstream(name, url string) error {
	n, err := s.CountUpstreams()
	if err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	name = strings.TrimSpace(name)
	url = strings.TrimSpace(url)
	if name == "" {
		name = "default"
	}
	if url == "" {
		return nil
	}
	up, err := s.CreateUpstream(UpstreamRow{
		Name: name,
		URL:  url,
	})
	if err != nil {
		return err
	}
	_, err = s.CreateRoute(RouteRow{
		Name:       "default",
		Enabled:    true,
		Hosts:      []string{},
		PathPrefix: "/",
		UpstreamID: up.ID,
	})
	return err
}
