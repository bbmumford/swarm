// Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
// Queries: licensing@hstles.com

package swarm

import (
	"sort"
	"sync"
	"time"
)

// recordStore is a per-topic δ-CRDT keyed by (NodeID, Key). Each slot holds
// at most one Record (the latest by HLC). Tombstones override live records.
//
// Key sub-divides a node's presence on a topic so one node can hold many
// records there — a latency observation per observed peer, a record per
// content hash it serves. Key == "" is the classical single-slot-per-node
// form, so a publisher that never sets Key behaves exactly as before.
// Each (Topic, NodeID, Key) converges independently under the same HLC-max
// rule; Key is covered by the record signature, so a record cannot be moved
// between keys (see signableBytes).
//
// Observer attestations are deliberately NOT keyed by Key. An attestation
// asserts that a NODE is dead, which is a statement about the node rather
// than about one of its records — so the witness set, the restored-at
// high-water-mark, and the synthesised tombstone all operate at NodeID
// granularity, and crossing quorum tombstones EVERY key that node holds on
// the topic. Keying the witness set by (NodeID, Key) would instead require
// K observers to independently witness each key, which no observer can do:
// they observe gossip silence from a node, not from a key.
//
// The δ-CRDT property: for any two stores A and B, A.merge(B) == B.merge(A).
// Merge is HLC-max (highest HLC wins; ties broken lexicographically on the
// signature bytes for determinism).
//
// Observer-tombstone (N-of-M witness) extension: when a Record carries
// IsObserverAttestation() == true it does NOT directly overwrite the
// target's slot. Instead it accumulates in a per-target attestation set
// keyed by (target NodeID, observer NodeID). When the set holds at least
// observerQuorum distinct ObserverNodeIDs whose ObservedAtUnixMs span a
// window <= observerCorroborationWindow, the store synthesises a local
// tombstone for the target. The synthesis is consumer-local — each node
// re-derives convergence from the gossiped attestations it has seen, so
// the K-of-N decision is eventually consistent across the mesh without
// requiring a new "consensus" wire record. A live target re-publishing
// with a higher HLC than any attestation auto-restores via the standard
// HLC-max path.
type recordStore struct {
	mu      sync.RWMutex
	byTopic map[Topic]*topicStore

	// observerQuorum (K) and observerCorroborationWindow (W) gate the
	// observer-attestation accumulator. Default to DefaultObserverQuorum
	// / DefaultObserverCorroborationWindow; tests override via SetQuorum.
	observerQuorum              int
	observerCorroborationWindow time.Duration

	// observerRoleCheck — when non-nil, rejects observer attestations
	// for which this returns false. Receives both the claimed
	// ObserverNodeID and the Sig-verified PubKey so the gate can bind
	// PubKey to a known-anchor pubkey (without that bind a Sybil
	// attacker can claim any NodeID and supply their own keypair).
	// Wired by HSTLES Library from its role_table; nil for tests
	// (accept all observers).
	observerRoleCheck func(observer NodeID, pubKey []byte) bool

	// nowFn — wall clock for attestation-window pruning. Defaults to
	// time.Now; the deterministic simulator overrides via SetNowFn.
	nowFn func() time.Time

	// Cardinality caps (Phase-0.5 hardening). Zero = defaults applied by
	// setCaps. Enforcement is reject-new, never evict-old: eviction under
	// pressure lets an attacker push out honest state.
	maxTopics          int
	maxRecordsPerTopic int
	maxKeysPerNode     int
	maxAttestations    int

	// rejectedCap counts records dropped by a cardinality cap.
	rejectedCap uint64
}

// recordKey identifies one slot within a topic. Key == "" is the classical
// single-slot-per-node form. Comparable, so it is used directly as a map key.
type recordKey struct {
	NodeID NodeID
	Key    string
}

// keyOf projects a record onto its store slot.
func keyOf(r Record) recordKey { return recordKey{NodeID: r.NodeID, Key: r.Key} }

// nodeSlots returns every slot key a node currently holds on this topic, in
// canonical order. Observer death is a per-NODE fact, so the attestation path
// works through this rather than a single slot.
//
// Callers hold the store lock.
func (ts *topicStore) nodeSlots(node NodeID) []recordKey {
	var out []recordKey
	for k := range ts.records {
		if k.NodeID == node {
			out = append(out, k)
		}
	}
	sort.Slice(out, func(i, j int) bool { return lessRecordKey(out[i], out[j]) })
	return out
}

// nodeDeadAtOrAbove reports whether the node holds any slot on this topic
// (had), and whether EVERY slot it holds is tombstoned with HLC >= hlc
// (allDead). A node with one live slot is not dead, however many of its
// other slots are tombstoned.
//
// Callers hold the store lock.
func (ts *topicStore) nodeDeadAtOrAbove(node NodeID, hlc uint64) (had, allDead bool) {
	allDead = true
	for k, r := range ts.records {
		if k.NodeID != node {
			continue
		}
		had = true
		if !r.Tombstone || r.HLC < hlc {
			allDead = false
		}
	}
	return had, had && allDead
}

// nodePresent reports whether the node holds any slot on this topic.
//
// Callers hold the store lock.
func (ts *topicStore) nodePresent(node NodeID) bool {
	for k := range ts.records {
		if k.NodeID == node {
			return true
		}
	}
	return false
}

// lessRecordKey is the canonical slot ordering: NodeID first, then Key. Every
// deterministic traversal (Merkle root, range collection, replay) uses it, so
// two stores holding the same slot set always visit them in the same order.
func lessRecordKey(a, b recordKey) bool {
	if a.NodeID != b.NodeID {
		return a.NodeID < b.NodeID
	}
	return a.Key < b.Key
}

type topicStore struct {
	// records[(nodeID,key)] = latest record from that node on this topic
	// under that key. Key "" is the node's classical single slot.
	records map[recordKey]Record

	// attestations[target][observer] = most recent observer attestation
	// for the target's record. Pruned when ObservedAtUnixMs falls outside
	// observerCorroborationWindow on every Apply.
	attestations map[NodeID]map[NodeID]Record

	// restoredAtUnixMs[target] = ObservedAtUnixMs high-water-mark from the
	// moment a live owner record was applied to that target's records[]
	// slot. Attestations with att.ObservedAtUnixMs <= this value are
	// stale — they were issued BEFORE the owner re-published — and MUST
	// be rejected. Without this fence a previously-attestation-evicted
	// peer that has now re-published can be re-tombstoned by a single
	// new attestation combined with two replayed pre-restore attestations
	// (the K-of-N invariant is silently violated; see the adversarial
	// review concern "Owner re-publish does not fence in-flight
	// attestations"). The HWM is updated only on owner records (NOT on
	// observer attestations) so the consumer-local synthesised tombstone
	// path does not reset it.
	restoredAtUnixMs map[NodeID]int64
}

func newRecordStore() *recordStore {
	s := &recordStore{
		byTopic:                     make(map[Topic]*topicStore),
		observerQuorum:              DefaultObserverQuorum,
		observerCorroborationWindow: DefaultObserverCorroborationWindow,
		nowFn:                       time.Now,
	}
	s.setCaps(0, 0, 0, 0)
	return s
}

// setCaps installs the cardinality caps, applying defaults for zero values.
func (s *recordStore) setCaps(maxTopics, maxRecordsPerTopic, maxKeysPerNode, maxAttestations int) {
	if maxTopics <= 0 {
		maxTopics = 4096
	}
	if maxRecordsPerTopic <= 0 {
		maxRecordsPerTopic = 65536
	}
	if maxKeysPerNode <= 0 {
		maxKeysPerNode = DefaultMaxKeysPerNodePerTopic
	}
	if maxAttestations <= 0 {
		maxAttestations = 64
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.maxTopics = maxTopics
	s.maxRecordsPerTopic = maxRecordsPerTopic
	s.maxKeysPerNode = maxKeysPerNode
	s.maxAttestations = maxAttestations
}

// SetObserverRoleCheck wires the anchor-role gate (or any other gate) for
// observer attestations. The gate receives both the claimed
// ObserverNodeID and the Sig-verified PubKey; it MUST verify the
// (NodeID, PubKey) binding against application-layer trust state (e.g.
// the HSTLES role_table) to prevent Sybil. Pass nil to disable the gate
// (accept all observers — only appropriate for tests).
func (s *recordStore) SetObserverRoleCheck(fn func(observer NodeID, pubKey []byte) bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.observerRoleCheck = fn
}

// SetObserverQuorum overrides the K-of-N threshold and corroboration
// window. K must be >= 1; W must be > 0. Used by tests and by the
// deterministic simulator.
func (s *recordStore) SetObserverQuorum(k int, w time.Duration) {
	if k < 1 || w <= 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.observerQuorum = k
	s.observerCorroborationWindow = w
}

// SetNowFn lets the deterministic simulator inject virtual time for the
// attestation pruning gate. Defaults to time.Now in production.
func (s *recordStore) SetNowFn(fn func() time.Time) {
	if fn == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nowFn = fn
}

// Apply attempts to merge r into the store. Returns:
//   - applied: true if the store changed (r was new or strictly newer, or
//     an attestation crossed the K-of-N quorum and synthesised a tombstone)
//   - replaced: true if the slot already had a record (newer or same)
//
// Apply assumes r.Sig has already been verified by the caller. For
// observer attestations (r.IsObserverAttestation()) the caller MUST have
// verified Sig against the OBSERVER's public key, not the target's —
// that's the v1 trust gate and the only way to keep Sybil resistance.
func (s *recordStore) Apply(r Record) (applied bool, replaced bool) {
	applied, replaced, _ = s.ApplyExt(r)
	return applied, replaced
}

// ApplyExt is Apply plus an `accumulated` signal for observer attestations:
// true when the attestation was FRESH (set or superseded its per-observer
// slot) even though quorum was not crossed. The dissemination layer relays
// exactly the accumulated-but-not-applied attestations — without that
// signal, below-quorum attestations die one hop from their emitter and
// K-of-N never converges on sparse topologies.
func (s *recordStore) ApplyExt(r Record) (applied bool, replaced bool, accumulated bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	ts, ok := s.byTopic[r.Topic]
	if !ok {
		// Cardinality cap: reject records for new topics beyond MaxTopics.
		if len(s.byTopic) >= s.maxTopics {
			s.rejectedCap++
			return false, false, false
		}
		ts = &topicStore{
			records:          make(map[recordKey]Record),
			attestations:     make(map[NodeID]map[NodeID]Record),
			restoredAtUnixMs: make(map[NodeID]int64),
		}
		s.byTopic[r.Topic] = ts
	}

	// Observer attestation path — accumulate, prune, then check quorum.
	if r.IsObserverAttestation() {
		return s.applyAttestationLocked(ts, r)
	}

	// Owner-signed record (or classical owner tombstone) — standard
	// HLC-max CRDT merge. A live owner re-publish with HLC > any
	// observer-synthesised tombstone auto-restores via this path.
	slot := keyOf(r)
	cur, had := ts.records[slot]
	if !had {
		// Cardinality cap: reject NEW slots beyond MaxRecordsPerTopic
		// (updates to existing slots always pass — convergence on known
		// state must never be blocked by the cap). With composite keys the
		// cap counts SLOTS, not nodes, so it now also bounds how many keys
		// one node may open on a topic.
		if len(ts.records) >= s.maxRecordsPerTopic {
			s.rejectedCap++
			return false, false, false
		}
		// Per-node slot cap. Composite keys let one node open many slots, so
		// without this a single publisher could consume the whole per-topic
		// budget and crowd out every honest peer — an amplification the
		// one-slot-per-node store could not express. Counted only for NEW
		// slots, so updates to a node's existing keys always converge.
		if s.maxKeysPerNode > 0 {
			held := 0
			for k := range ts.records {
				if k.NodeID == r.NodeID {
					held++
				}
			}
			if held >= s.maxKeysPerNode {
				s.rejectedCap++
				return false, false, false
			}
		}
		ts.records[slot] = r
		// First-time owner record: stamp the restored-at high-water-mark
		// so any in-flight attestations that were issued before this
		// moment are rejected. Without this fence a peer that was
		// observer-tombstoned and now re-publishes can be re-evicted by
		// stale pre-restore attestations arriving via gossip late or
		// via anti-entropy replay.
		if !r.Tombstone {
			ts.restoredAtUnixMs[r.NodeID] = s.nowFn().UnixMilli()
		}
		return true, false, false
	}
	replaced = true

	if r.HLC > cur.HLC || (r.HLC == cur.HLC && sigLess(cur.Sig, r.Sig)) {
		ts.records[slot] = r
		// A fresh owner publish supersedes any synthesised tombstone.
		// Clear stale attestations for this target so a future death
		// detection starts from an empty witness set (otherwise a
		// flapping peer would re-trip the quorum from old attestations).
		// Also stamp the restored-at high-water-mark so in-flight stale
		// attestations arriving AFTER this point are rejected by the
		// attestation gate (delete alone is insufficient — pre-restore
		// attestations can land in the freshly-empty set and combine
		// with a single fresh post-restore attestation to satisfy
		// K-of-N, silently violating the witness invariant).
		delete(ts.attestations, r.NodeID)
		if !r.Tombstone {
			ts.restoredAtUnixMs[r.NodeID] = s.nowFn().UnixMilli()
		}
		return true, true, false
	}
	return false, true, false
}

// applyAttestationLocked accumulates an observer attestation and, when
// K-of-N within W is satisfied, synthesises a tombstone in the standard
// records slot. Called under s.mu.
func (s *recordStore) applyAttestationLocked(ts *topicStore, att Record) (applied bool, replaced bool, accumulated bool) {
	// v1 anchor-only trust gate — reject attestations from non-anchor
	// observers (or observers whose claimed NodeID does not bind to the
	// Sig-verified PubKey) when the role check is wired.
	if s.observerRoleCheck != nil && !s.observerRoleCheck(att.ObserverNodeID, att.PubKey) {
		return false, false, false
	}

	// Forward-skew gate — reject any attestation whose ObservedAtUnixMs is
	// more than observerForwardSkewBudget ahead of wall-now. Without this
	// gate, a single observer with a clock skewed forward (or a malicious
	// anchor passing the role check) can post ObservedAtUnixMs = now+1h
	// and that value becomes the prune anchor — every honest observer's
	// in-real-time-window attestation falls outside (newest -
	// a.ObservedAtUnixMs > winMs) and is pruned, denying quorum
	// permanently with one message. See adversarial review concern
	// "Window pruning anchored on attestation timestamps lets a single
	// skewed/malicious observer deny quorum".
	nowMs := s.nowFn().UnixMilli()
	if att.ObservedAtUnixMs > nowMs+observerForwardSkewBudget.Milliseconds() {
		return false, false, false
	}

	// Restored-at high-water-mark gate — reject attestations issued
	// BEFORE the target last successfully re-published as owner. The
	// owner-publish path stamps restoredAtUnixMs at publish time; any
	// attestation whose ObservedAtUnixMs is <= that stamp is stale (it
	// was issued for the pre-restore lifecycle of the peer) and MUST
	// NOT be admitted to the witness set. Without this fence a peer
	// restored from observer-tombstone can be re-evicted by stale
	// in-flight attestations replayed via anti-entropy or late gossip,
	// combined with a single fresh post-restore attestation, satisfying
	// K-of-N while silently violating the witness invariant.
	if hwm, ok := ts.restoredAtUnixMs[att.NodeID]; ok && att.ObservedAtUnixMs <= hwm {
		return false, false, false
	}

	// If the target is ALREADY fully dead at or above this attestation's HLC,
	// the attestation is redundant. Don't pollute the witness set.
	//
	// "Fully" is load-bearing under composite keys: a node with a tombstoned
	// `metrics` key and a live `latency` key is not dead, and treating it as
	// redundant here would drop the witness that still needs to reap the live
	// slot. Only a node whose every slot is tombstoned qualifies.
	if had, allDead := ts.nodeDeadAtOrAbove(att.NodeID, att.HLC); had && allDead {
		return false, true, false
	}

	set, ok := ts.attestations[att.NodeID]
	if !ok {
		set = make(map[NodeID]Record)
		ts.attestations[att.NodeID] = set
	}

	// Each observer's most-recent attestation supersedes its prior ones.
	// Supersede when EITHER ObservedAtUnixMs OR HLC strictly advances —
	// using ObservedAtUnixMs alone lets an observer "pin" its slot by
	// re-gossiping the same attestation; honest HLC advances would be
	// dropped at equal timestamps, masking subsequent fresh attestations
	// from the same observer.
	if cur, had := set[att.ObserverNodeID]; had &&
		att.ObservedAtUnixMs <= cur.ObservedAtUnixMs && att.HLC <= cur.HLC {
		return false, true, false
	}
	// Cardinality cap: a NEW observer beyond MaxAttestationsPerTarget is
	// rejected (existing observers may still supersede their own slot).
	if _, had := set[att.ObserverNodeID]; !had && len(set) >= s.maxAttestations {
		s.rejectedCap++
		return false, true, false
	}
	set[att.ObserverNodeID] = att

	// Prune attestations outside the corroboration window. Window is
	// anchored on the NEWEST attestation rather than wall-now so cleanly-
	// gossiped batches that all arrived within W of each other still
	// count even if a few seconds of delivery lag elapsed. The
	// forward-skew gate above bounds "newest" so it cannot be poisoned
	// arbitrarily into the future.
	newest := int64(0)
	for _, a := range set {
		if a.ObservedAtUnixMs > newest {
			newest = a.ObservedAtUnixMs
		}
	}
	winMs := s.observerCorroborationWindow.Milliseconds()
	for obs, a := range set {
		if newest-a.ObservedAtUnixMs > winMs {
			delete(set, obs)
		}
	}

	// Quorum check — K distinct observers (set keys are observer NodeIDs,
	// so map size IS distinct-observer count after pruning).
	if len(set) < s.observerQuorum {
		// GC the empty set so a target that never crosses quorum doesn't
		// hold an empty map entry forever. The owner-publish path
		// already deletes the entire entry on restore, but a never-
		// crossed quorum that fully prunes (e.g. a single stale
		// attestation expired) would otherwise leak.
		if len(set) == 0 {
			delete(ts.attestations, att.NodeID)
		}
		// accumulated=true: this attestation was fresh (it set or
		// superseded its observer slot) — the dissemination layer must
		// relay it so OTHER nodes can count it toward THEIR quorum.
		return false, ts.nodePresent(att.NodeID), true
	}

	// Synthesise the tombstone. HLC = max(attestation HLCs) + 1 so it
	// beats every contributing attestation in HLC-max comparisons and
	// any future live publish from the target needs HLC > this to
	// restore (which is automatic given the target's HLC monotonically
	// increases per-node from time-of-publish).
	maxHLC := uint64(0)
	for _, a := range set {
		if a.HLC > maxHLC {
			maxHLC = a.HLC
		}
	}
	synth := Record{
		Topic:     att.Topic,
		NodeID:    att.NodeID,
		HLC:       maxHLC + 1,
		Tombstone: true,
		// PubKey/Sig left empty: this record is consumer-local — each
		// node re-derives it from the gossiped attestations. It MUST
		// never reach the wire or the Merkle tree: the merkle root and
		// range collection use topicRecordsSigned (Sig non-empty), so a
		// node that synthesised and one that hasn't still compute
		// identical roots, and ranges never carry an unverifiable
		// record a receiver would reject.
	}

	// The node is dead, so EVERY slot it holds on this topic dies — one
	// synthesised tombstone per key, each carrying its slot's Key so it
	// lands in that slot rather than collapsing them all onto "".
	// A node we hold no records for still gets the classical keyless
	// tombstone, so a death observed before any record arrives is recorded
	// exactly as it was pre-composite-key.
	slots := ts.nodeSlots(att.NodeID)
	had := len(slots) > 0
	if !had {
		ts.records[recordKey{NodeID: att.NodeID}] = synth
		return true, false, true
	}
	applied = false
	for _, k := range slots {
		if cur := ts.records[k]; synth.HLC > cur.HLC {
			tomb := synth
			tomb.Key = k.Key
			ts.records[k] = tomb
			applied = true
		}
	}
	// Keep the attestation set around: a target that re-publishes
	// MUST cross synth.HLC to restore; the set's role is fully
	// served once synth is recorded, but it's harmless to retain
	// (and cheap to drop on next live publish via Apply's
	// delete-on-overwrite).
	return applied, true, true
}

// Get returns the current LIVE record for (topic, node). Honouring the
// documented Node.Get contract, a tombstoned slot reports not-present.
// The returned record's byte slices are defensive copies — callers may
// mutate them without corrupting the store. (The gossip/merkle engines use
// getRaw, which sees tombstones.)
func (s *recordStore) Get(topic Topic, node NodeID) (Record, bool) {
	return s.GetKeyed(topic, node, "")
}

// GetKeyed is Get for a specific slot of a node. key "" is the classical
// single slot, so Get(topic, node) == GetKeyed(topic, node, "").
func (s *recordStore) GetKeyed(topic Topic, node NodeID, key string) (Record, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ts, ok := s.byTopic[topic]
	if !ok {
		return Record{}, false
	}
	r, ok := ts.records[recordKey{NodeID: node, Key: key}]
	if !ok || r.Tombstone {
		return Record{}, false
	}
	return cloneRecord(r), true
}

// NodeRecords returns every LIVE record a node holds on a topic, in
// canonical slot order, with defensively-copied byte slices. This is the
// composite-key read: one node's full set of per-key records (its latency
// observations, its content holdings) rather than a single slot.
func (s *recordStore) NodeRecords(topic Topic, node NodeID) []Record {
	s.mu.RLock()
	ts, ok := s.byTopic[topic]
	if !ok {
		s.mu.RUnlock()
		return nil
	}
	var keys []recordKey
	for k, r := range ts.records {
		if k.NodeID == node && !r.Tombstone {
			keys = append(keys, k)
		}
	}
	sort.Slice(keys, func(i, j int) bool { return lessRecordKey(keys[i], keys[j]) })
	out := make([]Record, 0, len(keys))
	for _, k := range keys {
		out = append(out, cloneRecord(ts.records[k]))
	}
	s.mu.RUnlock()
	return out
}

// getRaw returns the slot as stored — tombstones included, slices shared.
// Engine-internal (IHave freshness, graft replies).
func (s *recordStore) getRaw(topic Topic, node NodeID) (Record, bool) {
	return s.getRawKeyed(topic, node, "")
}

// getRawKeyed is getRaw for a specific slot. The lazy-push path MUST use
// this: an IHave/Graft names the slot it is about, and comparing it against
// the node's keyless slot would both re-graft records we already hold and
// serve the wrong record back.
func (s *recordStore) getRawKeyed(topic Topic, node NodeID, key string) (Record, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ts, ok := s.byTopic[topic]
	if !ok {
		return Record{}, false
	}
	r, ok := ts.records[recordKey{NodeID: node, Key: key}]
	return r, ok
}

// TopicRecords returns a snapshot of the LIVE records on a topic, sorted by
// NodeID, with defensively-copied byte slices — the documented public read
// contract (tombstoned records are not present).
func (s *recordStore) TopicRecords(topic Topic) []Record {
	out := s.topicRecordsWhere(topic, func(r Record) bool { return !r.Tombstone })
	for i := range out {
		out[i] = cloneRecord(out[i])
	}
	return out
}

// topicRecordsAll returns every slot including tombstones and synthesised
// records, slices shared. Engine/replay-internal: a late subscriber must
// still learn about deaths, so replay delivers tombstones.
func (s *recordStore) topicRecordsAll(topic Topic) []Record {
	return s.topicRecordsWhere(topic, func(Record) bool { return true })
}

// topicRecordsSigned returns every slot that carries a signature — the
// Merkle view. Consumer-local synthesised tombstones (empty Sig) are
// excluded so (a) two nodes at the same attestation state compute the same
// root whether or not they crossed quorum locally, and (b) ranges never
// ship a record the receiver's signature check must reject.
func (s *recordStore) topicRecordsSigned(topic Topic) []Record {
	return s.topicRecordsWhere(topic, func(r Record) bool { return len(r.Sig) > 0 })
}

func (s *recordStore) topicRecordsWhere(topic Topic, keep func(Record) bool) []Record {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ts, ok := s.byTopic[topic]
	if !ok {
		return nil
	}
	out := make([]Record, 0, len(ts.records))
	for _, r := range ts.records {
		if keep(r) {
			out = append(out, r)
		}
	}
	// Canonical order is (NodeID, Key) — with composite keys, sorting by
	// NodeID alone leaves the order of one node's slots at Go's map
	// iteration nondeterminism, which would make the Merkle root of two
	// identical stores differ run to run.
	sort.Slice(out, func(i, j int) bool { return lessRecordKey(keyOf(out[i]), keyOf(out[j])) })
	return out
}

// topicAttestations returns the below-quorum observer attestations for a
// topic (flattened, sorted for determinism). Merkle range responses append
// these so sparse-topology peers can repair their witness sets — the
// attestations are signed records, so the receiver's standard verify+apply
// path admits them. They are NOT part of the Merkle root (they are
// windowed, transient state; hashing them would make roots flap).
func (s *recordStore) topicAttestations(topic Topic) []Record {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ts, ok := s.byTopic[topic]
	if !ok {
		return nil
	}
	var out []Record
	for _, set := range ts.attestations {
		for _, a := range set {
			out = append(out, a)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].NodeID != out[j].NodeID {
			return out[i].NodeID < out[j].NodeID
		}
		return out[i].ObserverNodeID < out[j].ObserverNodeID
	})
	return out
}

// reapExpired applies per-topic TTL retention: live records whose HLC wall
// age exceeds ttl are dropped; tombstones are retained for 2×ttl (they must
// outlive the live records they supersede or deletes resurrect through
// anti-entropy). Topics with ttl<=0 are untouched. Returns records dropped.
func (s *recordStore) reapExpired(nowMs int64, ttlFor func(Topic) time.Duration) int {
	if ttlFor == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	dropped := 0
	for topic, ts := range s.byTopic {
		ttl := ttlFor(topic)
		if ttl <= 0 {
			continue
		}
		ttlMs := ttl.Milliseconds()
		for slot, r := range ts.records {
			wallMs, _ := Decompose(r.HLC)
			ageMs := nowMs - int64(wallMs)
			if (!r.Tombstone && ageMs > ttlMs) || (r.Tombstone && ageMs > 2*ttlMs) {
				delete(ts.records, slot)
				dropped++
			}
		}
		// The restored-at high-water-mark is per-NODE, so it may only be
		// dropped once the node has no slots left. Deleting it alongside
		// any single expiring slot would unfence a node that still holds
		// live records, letting a stale pre-restore attestation back into
		// its witness set.
		for node := range ts.restoredAtUnixMs {
			if !ts.nodePresent(node) {
				delete(ts.restoredAtUnixMs, node)
			}
		}
		if len(ts.records) == 0 && len(ts.attestations) == 0 {
			delete(s.byTopic, topic)
		}
	}
	return dropped
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
