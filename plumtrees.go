// Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
// Queries: licensing@hstles.com

package swarm

import (
	"crypto/ed25519"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	pb "github.com/bbmumford/swarm/proto/pb"
)

// plumtreesEngine implements the Plumtrees epidemic broadcast protocol:
//   - eager push along tree edges (deterministic delivery)
//   - lazy push (IHave) to non-tree edges (redundancy + repair)
//   - graft/prune for partial-tree healing
//
// Tree-edge selection: prefer first-source-seen peer until proven slower.
// Tree degree is bounded by Config.TreeDegree.
type plumtreesEngine struct {
	mu sync.RWMutex

	localID  NodeID
	store    *recordStore
	peers    *peerTable
	tport    Transport
	hlc      *HLC
	treeDeg  int
	eagerTTL uint32
	nowFn    func() time.Time

	// missingIHaves tracks records announced via IHave but not yet received
	// via eager push. After grace period, we GRAFT to the announcer.
	missingMu     sync.Mutex
	missingIHaves map[ihaveKey]*ihaveEntry
	graftDelay    time.Duration

	paused    atomic.Bool
	merkle    *merkleEngine
	onApplied func(r Record)

	// Point-to-point content fetch handlers. Installed by Wire() so the
	// transport-routed Frame_FetchReq / Frame_FetchResp frames dispatch
	// to the ContentTopic implementation without exposing the node's
	// internals on the public Transport interface.
	onFetchReq  func(from NodeID, req *pb.ContentFetchRequest)
	onFetchResp func(from NodeID, resp *pb.ContentFetchResponse)
}

type ihaveKey struct {
	topic  Topic
	nodeID NodeID
	hlc    uint64
}

type ihaveEntry struct {
	announcer NodeID
	bodyHash  [32]byte
	seenAt    time.Time
	grafted   bool
}

func newPlumtrees(localID NodeID, store *recordStore, peers *peerTable, tport Transport, hlc *HLC, treeDeg int, nowFn func() time.Time, graftDelay time.Duration) *plumtreesEngine {
	if treeDeg <= 0 {
		treeDeg = 4
	}
	if nowFn == nil {
		nowFn = time.Now
	}
	if graftDelay <= 0 {
		graftDelay = 200 * time.Millisecond
	}
	return &plumtreesEngine{
		localID:       localID,
		store:         store,
		peers:         peers,
		tport:         tport,
		hlc:           hlc,
		treeDeg:       treeDeg,
		eagerTTL:      8, // bounded fan-out
		nowFn:         nowFn,
		missingIHaves: make(map[ihaveKey]*ihaveEntry),
		graftDelay:    graftDelay,
	}
}

// Publish broadcasts a freshly-signed Record. Called by Node.Publish after
// HLC stamp + signature.
func (e *plumtreesEngine) Publish(r Record) {
	// Apply locally first so we don't echo it back to ourselves.
	if applied, _ := e.store.Apply(r); !applied {
		return // we already have a newer record for this slot
	}
	e.eagerPushToTreeEdges(r)
	e.lazyPushToNonTreeEdges(r)
}

// ReceiveFrame is the entry point from the transport layer. It dispatches
// to the appropriate handler based on the Frame's kind.
func (e *plumtreesEngine) ReceiveFrame(from NodeID, raw []byte) error {
	f, err := decodeFrame(raw)
	if err != nil {
		return err
	}

	switch k := f.Kind.(type) {
	case *pb.Frame_Eager:
		return e.handleEager(from, k.Eager)
	case *pb.Frame_Ihave:
		return e.handleIHave(from, k.Ihave)
	case *pb.Frame_Graft:
		return e.handleGraft(from, k.Graft)
	case *pb.Frame_Prune:
		return e.handlePrune(from, k.Prune)
	case *pb.Frame_Merkle:
		if e.merkle != nil {
			e.merkle.HandleProbe(from, k.Merkle)
		}
		return nil
	case *pb.Frame_MerkleRange:
		if e.merkle != nil {
			e.merkle.HandleRange(from, e.hlc, k.MerkleRange)
		}
		return nil
	case *pb.Frame_Keepalive:
		return nil
	case *pb.Frame_FetchReq:
		if e.onFetchReq != nil {
			e.onFetchReq(from, k.FetchReq)
		}
		return nil
	case *pb.Frame_FetchResp:
		if e.onFetchResp != nil {
			e.onFetchResp(from, k.FetchResp)
		}
		return nil
	default:
		return nil
	}
}

// SetFetchHandlers installs the point-to-point content fetch dispatchers.
// Wire() calls this after the ContentTopic is constructed; production code
// should not call it directly.
func (e *plumtreesEngine) SetFetchHandlers(req func(NodeID, *pb.ContentFetchRequest), resp func(NodeID, *pb.ContentFetchResponse)) {
	e.onFetchReq = req
	e.onFetchResp = resp
}

// SetMerkle wires the merkle engine for inbound probe + range handling.
func (e *plumtreesEngine) SetMerkle(m *merkleEngine) {
	e.merkle = m
}

// SetOnApplied registers a callback invoked after a remote record is
// successfully applied to the local store. Used by the Node to deliver
// records to topic subscribers; not invoked for local publishes (those
// are delivered directly inside Node.Publish).
func (e *plumtreesEngine) SetOnApplied(fn func(r Record)) {
	e.onApplied = fn
}

// handleEager processes an EagerPush frame.
//
// If this is the first time we've seen this (topic, node_id, hlc), we
// apply the record locally and forward to other tree edges (modulo TTL).
//
// If we already had it, we PRUNE the sender — they're a redundant tree edge.
func (e *plumtreesEngine) handleEager(from NodeID, ep *pb.EagerPush) error {
	if ep.Record == nil {
		return nil
	}
	r := recordFromProto(ep.Record)

	// Verify signature against the public key embedded in the record. The
	// application's NodeID encoding may not be reversible to the public
	// key (e.g. fingerprint schemes), so the sender stamps PubKey on
	// every signed record. signableBytes covers PubKey so an attacker
	// cannot swap the claimed key on a captured record.
	if len(r.PubKey) != ed25519.PublicKeySize || !verifyRecord(r, ed25519.PublicKey(r.PubKey)) {
		return nil // drop malformed/forged records silently
	}

	// Observe HLC for future stamps
	e.hlc.Observe(r.HLC)

	applied, replaced := e.store.Apply(r)
	if !applied && replaced {
		// We had a newer or equal record. The sender is a redundant
		// tree edge — prune them for this topic.
		e.sendPrune(from, r.Topic)
		return nil
	}
	if !applied {
		return nil
	}

	// Promote sender to tree edge if not already (Plumtrees: first-source wins)
	e.peers.SetTreeEdge(from, true)

	// Clear any pending IHave for this record
	e.missingMu.Lock()
	delete(e.missingIHaves, ihaveKey{r.Topic, r.NodeID, r.HLC})
	e.missingMu.Unlock()

	// Notify Node so it delivers the record to topic subscribers.
	if e.onApplied != nil {
		e.onApplied(r)
	}

	// Forward to OTHER tree edges (not back to sender), decrement TTL
	if ep.Ttl > 1 {
		e.eagerForward(from, r, ep.Ttl-1)
	}
	// Also lazy-push to non-tree edges
	e.lazyPushToNonTreeEdges(r)
	return nil
}

// handleIHave processes a lazy-push announcement.
//
// If we already have the record (or newer), ignore.
// Otherwise, record the IHave and schedule a GRAFT request after graftDelay.
func (e *plumtreesEngine) handleIHave(from NodeID, ih *pb.IHave) error {
	topic := Topic(ih.Topic)
	nodeID := NodeID(ih.NodeId)
	if cur, ok := e.store.Get(topic, nodeID); ok && cur.HLC >= ih.Hlc {
		return nil
	}

	key := ihaveKey{topic, nodeID, ih.Hlc}
	var bh [32]byte
	copy(bh[:], ih.BodyHash)

	e.missingMu.Lock()
	if existing, ok := e.missingIHaves[key]; ok {
		// Already tracked; first announcer keeps priority
		_ = existing
	} else {
		e.missingIHaves[key] = &ihaveEntry{
			announcer: from,
			bodyHash:  bh,
			seenAt:    e.nowFn(),
		}
	}
	e.missingMu.Unlock()
	return nil
}

// handleGraft is invoked when a peer wants us to upgrade them to a tree
// edge for a specific record they're missing. We promote them + send
// the record they want via eager push.
func (e *plumtreesEngine) handleGraft(from NodeID, g *pb.Graft) error {
	e.peers.SetTreeEdge(from, true)
	topic := Topic(g.Topic)
	nodeID := NodeID(g.NodeId)
	r, ok := e.store.Get(topic, nodeID)
	if !ok {
		return nil
	}
	frame, _ := encodeFrame(frameEagerPush(r, e.eagerTTL))
	_ = e.tport.Send(from, frame)
	return nil
}

// handlePrune demotes the sender from tree-edge status. Prune is currently
// global per-peer rather than topic-scoped.
func (e *plumtreesEngine) handlePrune(from NodeID, p *pb.Prune) error {
	e.peers.SetTreeEdge(from, false)
	_ = p
	return nil
}

// Tick is called periodically by the Node to drive lazy-push timeouts
// (graft missing records) and tree-edge keepalives.
//
// Tick continues firing while the engine is paused — graft processing is
// considered correctness-critical (without it, lazy-only paths never heal).
// Merkle anti-entropy probes are suppressed during pause via the merkleEngine
// directly.
func (e *plumtreesEngine) Tick(now time.Time) {
	e.processGrafts(now)
}

// processGrafts checks for IHaves whose grace period has elapsed and
// issues GRAFT frames to the announcer.
func (e *plumtreesEngine) processGrafts(now time.Time) {
	e.missingMu.Lock()
	defer e.missingMu.Unlock()

	for key, entry := range e.missingIHaves {
		if entry.grafted {
			continue
		}
		if now.Sub(entry.seenAt) < e.graftDelay {
			continue
		}
		frame, _ := encodeFrame(frameGraft(key.topic, key.nodeID, key.hlc))
		_ = e.tport.Send(entry.announcer, frame)
		entry.grafted = true
	}
}

// ---------- Push logic ----------

func (e *plumtreesEngine) eagerPushToTreeEdges(r Record) {
	frame, err := encodeFrame(frameEagerPush(r, e.eagerTTL))
	if err != nil {
		return
	}
	for _, edge := range e.bestTreeEdges() {
		_ = e.tport.Send(edge, frame)
	}
}

func (e *plumtreesEngine) eagerForward(except NodeID, r Record, ttl uint32) {
	frame, err := encodeFrame(frameEagerPush(r, ttl))
	if err != nil {
		return
	}
	for _, edge := range e.peers.TreeEdges() {
		if edge == except {
			continue
		}
		_ = e.tport.Send(edge, frame)
	}
}

func (e *plumtreesEngine) lazyPushToNonTreeEdges(r Record) {
	// Suppress lazy push during pause — eager-push still flows because
	// it's the correctness path; lazy push is purely redundancy.
	if e.paused.Load() {
		return
	}
	bh := bodyHash(r)
	frame, err := encodeFrame(frameIHave(r.Topic, r.NodeID, r.HLC, bh))
	if err != nil {
		return
	}
	for _, p := range e.peers.NonTreeEdges() {
		// Backpressure: cap the rate of IHaves to slow peers via the
		// peer's adaptive interval. Each enqueue prunes older entries
		// first so a recovered peer's queue refills.
		interval := e.peers.Snapshot(p).AdaptiveInterval
		if interval <= 0 {
			interval = time.Second
		}
		entry := lazyEntry{topic: r.Topic, nodeID: r.NodeID, hlc: r.HLC, bodyHash: bh}
		if !e.peers.EnqueueLazy(p, entry, interval, e.nowFn) {
			continue
		}
		// Bandwidth cap: skip the send when the peer's token bucket is
		// exhausted. The entry stays queued so a future flush can retry
		// once tokens refill.
		if !e.peers.ConsumeTokens(p, int64(len(frame)), e.nowFn) {
			continue
		}
		_ = e.tport.Send(p, frame)
	}
}

// SetPaused flips the engine's pause state. While paused, lazy push and
// merkle probes are suppressed; eager push and graft processing continue.
func (e *plumtreesEngine) SetPaused(paused bool) {
	e.paused.Store(paused)
}

// bestTreeEdges returns the set of peers we eagerly push to. If the
// current tree-edge set is empty or below TreeDegree, we promote
// additional non-tree peers up to the degree budget. Promotion order
// honors PerPeerConfig.PriorityClass (descending) with NodeID as a
// deterministic tiebreaker, so high-priority peers (anchors, edge
// services) become tree edges before low-priority peers.
func (e *plumtreesEngine) bestTreeEdges() []NodeID {
	cur := e.peers.TreeEdges()
	if len(cur) >= e.treeDeg {
		return cur
	}

	all := e.peers.NonTreeEdges()
	sort.Slice(all, func(i, j int) bool {
		pi := e.peers.Snapshot(all[i]).PriorityClass
		pj := e.peers.Snapshot(all[j]).PriorityClass
		if pi != pj {
			return pi > pj
		}
		return all[i] < all[j]
	})

	need := e.treeDeg - len(cur)
	for i := 0; i < need && i < len(all); i++ {
		e.peers.SetTreeEdge(all[i], true)
		cur = append(cur, all[i])
	}
	return cur
}

// sendPrune notifies a peer to demote us from tree-edge status.
func (e *plumtreesEngine) sendPrune(to NodeID, topic Topic) {
	frame, err := encodeFrame(framePrune(topic))
	if err != nil {
		return
	}
	_ = e.tport.Send(to, frame)
}
