// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package faststr

// Matcher is a compact Aho-Corasick automaton for ASCII multipattern search.
// Patterns are matched as literal byte sequences (callers lowercase first).
type Matcher struct {
	root *acNode
}

type acNode struct {
	next [128]*acNode
	fail *acNode
	out  bool
}

// NewMatcher builds a matcher from patterns. Empty patterns are skipped.
func NewMatcher(patterns []string) *Matcher {
	m := &Matcher{root: &acNode{}}
	for _, p := range patterns {
		if p == "" {
			continue
		}
		n := m.root
		for i := 0; i < len(p); i++ {
			c := p[i]
			if c >= 128 {
				continue
			}
			if n.next[c] == nil {
				n.next[c] = &acNode{}
			}
			n = n.next[c]
		}
		n.out = true
	}
	m.buildFail()
	return m
}

func (m *Matcher) buildFail() {
	q := make([]*acNode, 0, 64)
	for c := 0; c < 128; c++ {
		if n := m.root.next[c]; n != nil {
			n.fail = m.root
			q = append(q, n)
		} else {
			m.root.next[c] = m.root
		}
	}
	for len(q) > 0 {
		r := q[0]
		q = q[1:]
		for c := 0; c < 128; c++ {
			u := r.next[c]
			if u == nil {
				r.next[c] = r.fail.next[c]
				continue
			}
			u.fail = r.fail.next[c]
			if u.fail.out {
				u.out = true
			}
			q = append(q, u)
		}
	}
}

// Contains reports whether any pattern occurs in haystack.
func (m *Matcher) Contains(haystack []byte) bool {
	if m == nil || m.root == nil || len(haystack) == 0 {
		return false
	}
	n := m.root
	for i := 0; i < len(haystack); i++ {
		c := haystack[i]
		if c >= 128 {
			n = m.root
			continue
		}
		n = n.next[c]
		if n.out {
			return true
		}
	}
	return false
}

// ContainsString is Contains for string haystacks without copying.
func (m *Matcher) ContainsString(haystack string) bool {
	if m == nil || m.root == nil || haystack == "" {
		return false
	}
	n := m.root
	for i := 0; i < len(haystack); i++ {
		c := haystack[i]
		if c >= 128 {
			n = m.root
			continue
		}
		n = n.next[c]
		if n.out {
			return true
		}
	}
	return false
}
