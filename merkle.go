// Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
// Queries: licensing@hstles.com

package swarm

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	pb "github.com/bbmumford/swarm/proto/pb"
)

// topicMerkleRoot returns the SHA256 hash of all records on a topic,
// computed in deterministic NodeID order over an optional [start, end]
// range. Two stores with the same set of (topic, nodeID, hlc, sig) tuples
// produce identical roots.
//
// rangeStart and rangeEnd are NodeID byte strings; nil means open.
// Records with NodeID lexicographically in [rangeStart, rangeEnd] are
// included.
func topicMerkleRoot(s *recordStore, topic Topic, rangeStart, rangeEnd []byte) [32]byte {
	recs := s.TopicRecords(topic) // sorted by NodeID
	h := sha256.New()
	for _, r := range recs {
		nodeIDBytes := []byte(r.NodeID)
		if rangeStart != nil && bytesLess(nodeIDBytes, rangeStart) {
			continue
		}
		if rangeEnd != nil && bytesLess(rangeEnd, nodeIDBytes) {
			continue
		}
		nodeIDHash := sha256.Sum256(nodeIDBytes)
		h.Write(nodeIDHash[:])

		var hlcb [8]byte
		binary.BigEndian.PutUint64(hlcb[:], r.HLC)
		h.Write(hlcb[:])

		sigHash := sha256.Sum256(r.Sig)
		h.Write(sigHash[:])
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// merkleEngine drives periodic anti-entropy probes + range reconciliation
// for drift recovery.
//
// Probes pick a random non-tree-edge peer's root for each topic at a low
// cadence. If roots match, no action. If they differ, subdivide the
// NodeID range and recurse — fetching missing records via inline
// MerkleRange responses.
//
// While paused, the engine suppresses probes but continues to respond to
// peer probes (correctness-critical for cold-start resync).
type merkleEngine struct {
	store        *recordStore
	peers        *peerTable
	tport        Transport
	nowFn        func() time.Time
	probeEvery   time.Duration
	maxRangeSize int

	// probeSalt is a per-engine offset that shifts the deterministic
	// peer-selection index. Two nodes ticking at the same wall-clock
	// millisecond would otherwise probe the same peer (cache thundering
	// herd); mixing in the local NodeID hash distributes the load.
	probeSalt uint64

	mu        sync.Mutex
	lastProbe map[Topic]time.Time

	paused    atomic.Bool
	onApplied func(r Record)
}

// SetOnApplied installs the same delivery callback used by Plumtrees so
// records that arrive via merkle anti-entropy reach topic subscribers.
func (m *merkleEngine) SetOnApplied(fn func(r Record)) {
	m.onApplied = fn
}

func newMerkle(store *recordStore, peers *peerTable, tport Transport, nowFn func() time.Time, probeInterval time.Duration) *merkleEngine {
	if nowFn == nil {
		nowFn = time.Now
	}
	if probeInterval <= 0 {
		probeInterval = 60 * time.Second
	}
	salt := uint64(0)
	if tport != nil {
		// Hash the local NodeID into a uint64 salt so each node's tick
		// lands on a different peer index for the same wall-clock ms.
		h := sha256.Sum256([]byte(tport.LocalID()))
		salt = binary.BigEndian.Uint64(h[:8])
	}
	return &merkleEngine{
		store:        store,
		peers:        peers,
		tport:        tport,
		nowFn:        nowFn,
		probeEvery:   probeInterval,
		maxRangeSize: 64, // records per range before subdivision
		probeSalt:    salt,
		lastProbe:    make(map[Topic]time.Time),
	}
}

// SetPaused toggles the engine's pause state.
func (m *merkleEngine) SetPaused(paused bool) {
	m.paused.Store(paused)
}

// Tick is called by the Node to drive periodic probes. While paused, this
// is a no-op for outbound probes; incoming probe responses still flow.
func (m *merkleEngine) Tick() {
	if m.paused.Load() {
		return
	}
	now := m.nowFn()
	for _, topic := range m.store.Topics() {
		m.mu.Lock()
		last, ok := m.lastProbe[topic]
		due := !ok || now.Sub(last) >= m.probeEvery
		if due {
			m.lastProbe[topic] = now
		}
		m.mu.Unlock()
		if !due {
			continue
		}
		// Pick a random peer (excluding tree edges — they're already in sync
		// via eager push; non-tree peers are the drift-recovery candidates).
		peers := m.peers.NonTreeEdges()
		if len(peers) == 0 {
			continue
		}
		// Deterministic pick: wall-clock millis mixed with the engine's
		// per-node salt distributes selection across the peer set so
		// nodes ticking on the same ms don't converge on a single
		// target (cache thundering herd).
		idx := int((uint64(now.UnixMilli()) + m.probeSalt) % uint64(len(peers)))
		target := peers[idx]
		m.sendProbe(target, topic, nil, nil)
	}
}

// ProbePeer sends a full-range MerkleProbe to target for every topic
// this node stores records for. Called by Node.ProbePeer immediately
// after a peer joins so the new peer catches up via one root hash per
// topic (matched roots short-circuit), or O(log N) bandwidth when
// they differ — far faster than waiting for the periodic Tick() to
// pick the same target by random selection.
//
// Suppressed only on a stopped node; otherwise fires even while
// paused, because cold-start resync IS correctness-critical for the
// newly joining peer.
func (m *merkleEngine) ProbePeer(target NodeID) {
	if target == "" {
		return
	}
	for _, topic := range m.store.Topics() {
		m.sendProbe(target, topic, nil, nil)
	}
}

// Roots returns the current full-range Merkle roots for every topic. Used
// for observability.
func (m *merkleEngine) Roots() map[Topic][32]byte {
	out := make(map[Topic][32]byte)
	for _, t := range m.store.Topics() {
		out[t] = topicMerkleRoot(m.store, t, nil, nil)
	}
	return out
}

// sendProbe sends a MerkleProbe frame to peer for the given topic + range.
func (m *merkleEngine) sendProbe(to NodeID, topic Topic, rangeStart, rangeEnd []byte) {
	root := topicMerkleRoot(m.store, topic, rangeStart, rangeEnd)
	frame, err := encodeFrame(&pb.Frame{
		Kind: &pb.Frame_Merkle{
			Merkle: &pb.MerkleProbe{
				Topic:      string(topic),
				RangeStart: rangeStart,
				RangeEnd:   rangeEnd,
				RootHash:   root[:],
			},
		},
	})
	if err != nil {
		return
	}
	_ = m.tport.Send(to, frame)
}

// HandleProbe is the receiver side of a MerkleProbe. If our root matches
// theirs, no action; otherwise reply with MerkleRange.
func (m *merkleEngine) HandleProbe(from NodeID, p *pb.MerkleProbe) {
	topic := Topic(p.Topic)
	localRoot := topicMerkleRoot(m.store, topic, p.RangeStart, p.RangeEnd)
	if bytesEqual(localRoot[:], p.RootHash) {
		return // roots match, no drift
	}
	// Collect records in the requested range, sorted by NodeID.
	allRecs := m.store.TopicRecords(topic)
	inRange := make([]Record, 0, len(allRecs))
	for _, r := range allRecs {
		nidB := []byte(r.NodeID)
		if p.RangeStart != nil && bytesLess(nidB, p.RangeStart) {
			continue
		}
		if p.RangeEnd != nil && bytesLess(p.RangeEnd, nidB) {
			continue
		}
		inRange = append(inRange, r)
	}

	if len(inRange) <= m.maxRangeSize {
		// Range is small enough to send all records inline.
		m.sendRange(from, topic, inRange, false)
		return
	}
	// Range is too large — send first half, mark truncated so the
	// peer subdivides on its end.
	half := len(inRange) / 2
	m.sendRange(from, topic, inRange[:half], true)
}

// HandleRange is the receiver side of a MerkleRange response. Applies the
// included records; if truncated, recursively probes the second half.
func (m *merkleEngine) HandleRange(from NodeID, hlc *HLC, r *pb.MerkleRange) {
	for _, pr := range r.Records {
		rec := recordFromProto(pr)
		if len(rec.PubKey) != ed25519.PublicKeySize || !verifyRecord(rec, ed25519.PublicKey(rec.PubKey)) {
			continue
		}
		hlc.Observe(rec.HLC)
		applied, _ := m.store.Apply(rec)
		if applied && m.onApplied != nil {
			m.onApplied(rec)
		}
	}
	if r.Truncated && len(r.Records) > 0 {
		// Subdivide: ask for everything after the last record we received.
		last := r.Records[len(r.Records)-1]
		nextStart := append(append([]byte(nil), last.NodeId...), 0x01)
		m.sendProbe(from, Topic(r.Topic), nextStart, nil)
	}
}

func (m *merkleEngine) sendRange(to NodeID, topic Topic, recs []Record, truncated bool) {
	pbRecs := make([]*pb.Record, len(recs))
	for i, r := range recs {
		pbRecs[i] = recordToProto(r)
	}
	frame, err := encodeFrame(&pb.Frame{
		Kind: &pb.Frame_MerkleRange{
			MerkleRange: &pb.MerkleRange{
				Topic:     string(topic),
				Records:   pbRecs,
				Truncated: truncated,
			},
		},
	})
	if err != nil {
		return
	}
	_ = m.tport.Send(to, frame)
}

// ---------- helpers ----------

func bytesLess(a, b []byte) bool {
	min := len(a)
	if len(b) < min {
		min = len(b)
	}
	for i := 0; i < min; i++ {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return len(a) < len(b)
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ---------- sortMerkleRecords (currently unused — kept for explicit range ops) ----------

var _ = sort.Slice // silence importer if unused
