// Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
// Queries: licensing@hstles.com

package swarm

import (
	"sort"
	"sync"
)

// recordStore is a per-topic δ-CRDT keyed by (NodeID). Each NodeID slot
// holds at most one Record (the latest by HLC). Tombstones override live
// records.
//
// The δ-CRDT property: for any two stores A and B, A.merge(B) == B.merge(A).
// Merge is HLC-max (highest HLC wins; ties broken lexicographically on the
// signature bytes for determinism).
type recordStore struct {
	mu      sync.RWMutex
	byTopic map[Topic]*topicStore
}

type topicStore struct {
	// records[nodeID] = latest record from that node on this topic
	records map[NodeID]Record
}

func newRecordStore() *recordStore {
	return &recordStore{byTopic: make(map[Topic]*topicStore)}
}

// Apply attempts to merge r into the store. Returns:
//   - applied: true if the store changed (r was new or strictly newer)
//   - replaced: true if the slot already had a record (newer or same)
//
// Apply assumes r.Sig has already been verified by the caller.
func (s *recordStore) Apply(r Record) (applied bool, replaced bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	ts, ok := s.byTopic[r.Topic]
	if !ok {
		ts = &topicStore{records: make(map[NodeID]Record)}
		s.byTopic[r.Topic] = ts
	}

	cur, had := ts.records[r.NodeID]
	if !had {
		ts.records[r.NodeID] = r
		return true, false
	}
	replaced = true

	// HLC max wins; on tie use signature comparison (stable, deterministic)
	if r.HLC > cur.HLC || (r.HLC == cur.HLC && sigLess(cur.Sig, r.Sig)) {
		ts.records[r.NodeID] = r
		return true, true
	}
	return false, true
}

// Get returns the current record for (topic, node) if any.
func (s *recordStore) Get(topic Topic, node NodeID) (Record, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ts, ok := s.byTopic[topic]
	if !ok {
		return Record{}, false
	}
	r, ok := ts.records[node]
	return r, ok
}

// TopicRecords returns a snapshot of all records on a topic, sorted by NodeID.
func (s *recordStore) TopicRecords(topic Topic) []Record {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ts, ok := s.byTopic[topic]
	if !ok {
		return nil
	}
	out := make([]Record, 0, len(ts.records))
	for _, r := range ts.records {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].NodeID < out[j].NodeID })
	return out
}

// Topics returns the set of topics with at least one record.
func (s *recordStore) Topics() []Topic {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Topic, 0, len(s.byTopic))
	for t := range s.byTopic {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Count returns the total number of records across all topics.
func (s *recordStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	total := 0
	for _, ts := range s.byTopic {
		total += len(ts.records)
	}
	return total
}

// TopicCount returns the number of records on a topic.
func (s *recordStore) TopicCount(topic Topic) int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ts, ok := s.byTopic[topic]
	if !ok {
		return 0
	}
	return len(ts.records)
}

// sigLess returns true if a is lexicographically less than b.
// Used as a stable tie-break when HLCs match.
func sigLess(a, b []byte) bool {
	la, lb := len(a), len(b)
	min := la
	if lb < min {
		min = lb
	}
	for i := 0; i < min; i++ {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return la < lb
}
