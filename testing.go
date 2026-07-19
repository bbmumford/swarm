// Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
// Queries: licensing@hstles.com

package swarm

// ---------- Test/Sim helpers ----------
//
// These helpers expose internals for the deterministic simulator and
// for unit tests. They are NOT part of the production Node API.

// StoreView is a read-only view of the internal record store.
type StoreView interface {
	Topics() []Topic
	TopicRecords(topic Topic) []Record
	TopicCount(topic Topic) int
	Count() int
}

// InternalStore returns a read-only view of a Node's record store.
// Returns nil if n is not a *nodeImpl.
//
// Intended for the simulator's convergence assertion and for unit tests.
// Production code MUST NOT depend on this. Unlike the public Node.Get/
// TopicRecords (which honour the documented contract and hide tombstones),
// this view is RAW: tombstones and synthesised records are visible —
// exactly what convergence assertions need.
func InternalStore(n Node) StoreView {
	impl, ok := n.(*nodeImpl)
	if !ok {
		return nil
	}
	return rawStoreView{impl.store}
}

// rawStoreView adapts recordStore with tombstone-inclusive reads.
type rawStoreView struct{ s *recordStore }

func (v rawStoreView) Topics() []Topic                    { return v.s.Topics() }
func (v rawStoreView) TopicRecords(topic Topic) []Record  { return v.s.topicRecordsAll(topic) }
func (v rawStoreView) TopicCount(topic Topic) int         { return v.s.TopicCount(topic) }
func (v rawStoreView) Count() int                         { return v.s.Count() }
