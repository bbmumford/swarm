// Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
// Queries: licensing@hstles.com

package swarm

import (
	"context"
	"crypto/ed25519"
	"sync"
	"sync/atomic"
	"time"
)

// nodeImpl is the concrete swarm.Node implementation.
type nodeImpl struct {
	cfg     Config
	priv    ed25519.PrivateKey
	id      NodeID
	hlc     *HLC
	store   *recordStore
	peers   *peerTable
	plum    *plumtreesEngine
	merkle  *merkleEngine
	content *contentTopicImpl

	// Subscribers indexed by topic, then by unique handle.
	subsMu sync.RWMutex
	subs   map[Topic]map[uint64]Subscriber
	subSeq atomic.Uint64

	// Lifecycle. lifeMu guards startCtx/startCancel handoff between
	// Start (writer) and Stop/engine goroutines (readers).
	lifeMu      sync.Mutex
	startCtx    context.Context
	startCancel context.CancelFunc
	started     atomic.Bool
	wired       atomic.Bool
	stopped     atomic.Bool
	paused      atomic.Bool
	wg          sync.WaitGroup

	// gate runs every inbound record through size/skew/binding/trust
	// checks before it can reach the store. Built in Wire from Config.
	gate *inboundGate

	// Atomic role/tenant
	role   atomic.Uint32 // Role
	tenant atomic.Value  // string

	// Pause/Resume hooks
	onPaused  func()
	onResumed func()

	// Role/tenant change hooks
	rolesMu        sync.Mutex
	onRoleChange   []func(prev, next Role)
	tenantMu       sync.Mutex
	onTenantChange []func(prev, next string)

	// Transport — set on Start via Wire().
	tport Transport
}

// New creates a Node. Returned Node is not started.
func New(cfg Config) (Node, error) {
	if cfg.PrivKey == nil || len(cfg.PrivKey) != ed25519.PrivateKeySize {
		return nil, ErrInvalidConfig
	}
	if cfg.NodeID == "" {
		pub, _ := cfg.PrivKey.Public().(ed25519.PublicKey)
		cfg.NodeID = nodeIDFromPub(pub)
	}
	if cfg.MaxRecordBytes <= 0 {
		cfg.MaxRecordBytes = 16384
	}
	if cfg.TreeDegree <= 0 {
		cfg.TreeDegree = 4
	}

	n := &nodeImpl{
		cfg:       cfg,
		priv:      cfg.PrivKey,
		id:        cfg.NodeID,
		hlc:       NewHLC(),
		store:     newRecordStore(),
		peers:     newPeerTable(cfg.PerPeerConfig),
		subs:      make(map[Topic]map[uint64]Subscriber),
		onPaused:  cfg.OnPaused,
		onResumed: cfg.OnResumed,
	}
	n.store.setCaps(cfg.MaxTopics, cfg.MaxRecordsPerTopic, cfg.MaxKeysPerNodePerTopic, cfg.MaxAttestationsPerTarget)
	if cfg.NowFn != nil {
		n.store.SetNowFn(cfg.NowFn)
	}
	n.tenant.Store("")
	return n, nil
}

// Wire connects the Node to a Transport. Must be called before Start. The
// transport's OnReceive / OnPeerJoin / OnPeerLeave callbacks are installed
// during this call.
func Wire(n Node, t Transport) error {
	impl, ok := n.(*nodeImpl)
	if !ok {
		return ErrInvalidConfig
	}
	if impl.wired.Swap(true) {
		// Re-wiring silently discards plumtree/merkle/graft state and
		// leaves the previous transport's callbacks dangling — refuse.
		return ErrAlreadyWired
	}
	impl.tport = t
	impl.gate = newInboundGate(impl.cfg)

	impl.plum = newPlumtrees(impl.id, impl.store, impl.peers, t, impl.hlc, impl.cfg.TreeDegree, impl.cfg.NowFn, impl.cfg.GraftDelay)
	impl.plum.SetInboundGate(impl.gate)
	impl.plum.SetMaxPendingIHaves(impl.cfg.MaxPendingIHaves)
	impl.merkle = newMerkle(impl.store, impl.peers, t, impl.cfg.NowFn, impl.cfg.MerkleProbeInterval)
	impl.merkle.SetInboundGate(impl.gate)
	impl.plum.SetMerkle(impl.merkle)
	impl.plum.SetOnApplied(impl.recordAccepted)
	impl.merkle.SetOnApplied(impl.recordAccepted)
	impl.content = newContentTopic(impl)
	impl.plum.SetFetchHandlers(impl.content.handleFetchRequest, impl.content.handleFetchResponse)

	t.OnReceive(func(from NodeID, frame []byte) {
		if impl.stopped.Load() {
			return
		}
		_ = impl.plum.ReceiveFrame(from, frame)
		impl.dispatchToSubscribers(from)
	})
	t.OnPeerJoin(func(id NodeID) {
		impl.peers.Ensure(id)
	})
	t.OnPeerLeave(func(id NodeID) {
		impl.peers.Remove(id)
	})

	// Pre-populate the peer table with currently-known peers.
	for _, p := range t.Peers() {
		impl.peers.Ensure(p)
	}
	return nil
}

// ---------- Node interface implementation ----------

func (n *nodeImpl) Start(ctx context.Context) error {
	if n.tport == nil {
		return ErrInvalidConfig
	}
	if n.stopped.Load() {
		return ErrStopped
	}
	if n.started.Swap(true) {
		// A second Start would spawn a duplicate ticker goroutine and
		// orphan the first invocation's cancel func — refuse.
		return ErrAlreadyStarted
	}
	startCtx, startCancel := context.WithCancel(ctx)
	n.lifeMu.Lock()
	n.startCtx, n.startCancel = startCtx, startCancel
	n.lifeMu.Unlock()

	if !n.cfg.DisableBackgroundTicker {
		// Background tick: drive Plumtrees graft timer, Merkle
		// anti-entropy probes, and TTL reaping.
		n.wg.Add(1)
		go func() {
			defer n.wg.Done()
			n.runTickLoop(startCtx)
		}()
	}

	<-startCtx.Done()
	return nil
}

// Tick drives the engine's periodic work. Exposed for the deterministic
// simulator. Production callers can ignore it — the background ticker
// calls it automatically.
func (n *nodeImpl) Tick(now time.Time) {
	if n.plum != nil {
		n.plum.Tick(now)
	}
	if n.merkle != nil {
		n.merkle.Tick()
	}
}

// ProbePeer triggers an immediate Merkle anti-entropy probe across every
// topic to the specified peer. The transport layer's session-join hook
// calls this so a newly-joined peer catches up in one round-trip per
// topic instead of waiting for the periodic Tick() loop to land on
// them. Silently no-ops when the engine isn't wired (pre-Start) or the
// peer is unknown — the underlying Transport.Send drops the frame.
func (n *nodeImpl) ProbePeer(peer NodeID) {
	if n.stopped.Load() {
		return
	}
	if n.merkle == nil {
		return
	}
	n.merkle.ProbePeer(peer)
}

func (n *nodeImpl) Stop() error {
	if !n.stopped.CompareAndSwap(false, true) {
		// Idempotent per the interface contract: a second Stop is a
		// no-op success, not an error.
		return nil
	}
	n.lifeMu.Lock()
	cancel := n.startCancel
	n.lifeMu.Unlock()
	if cancel != nil {
		cancel()
	}
	// Join the ticker goroutine so Stop returning means no engine work is
	// still in flight (Wire's OnReceive gate handles transport callbacks).
	n.wg.Wait()
	return nil
}

func (n *nodeImpl) Subscribe(topic Topic, sub Subscriber) (Unsubscribe, error) {
	if sub == nil {
		return nil, ErrInvalidConfig
	}
	id := n.subSeq.Add(1)

	// Gap-free replay: the subscriber is registered BEFORE the snapshot is
	// taken (so no record can slip between snapshot and registration), but
	// live deliveries are queued behind a gate until replay completes, then
	// flushed with per-slot HLC dedup. The subscriber therefore sees every
	// record exactly once, replay-then-live, with no interleaving.
	gate := &subGate{inner: sub, replaying: true}
	n.subsMu.Lock()
	if n.subs[topic] == nil {
		n.subs[topic] = make(map[uint64]Subscriber)
	}
	n.subs[topic][id] = gate.deliver
	n.subsMu.Unlock()

	// Replay the current state — including tombstones: a late subscriber
	// must learn about deaths, not just survivors.
	// Keyed by SLOT, not by node: under composite keys one node holds many
	// records on a topic, so a node-keyed map would keep only the last
	// replayed HLC and then suppress live deliveries for that node's OTHER
	// keys whose HLC happened to be lower — a silent, permanent delivery
	// loss. The dedup comment below always said "same slot"; with composite
	// keys the slot is (NodeID, Key).
	replayed := make(map[recordKey]uint64)
	for _, r := range n.store.topicRecordsAll(topic) {
		replayed[keyOf(r)] = r.HLC
		_ = sub(cloneRecord(r))
	}
	gate.finishReplay(replayed)

	return func() {
		n.subsMu.Lock()
		defer n.subsMu.Unlock()
		if subs := n.subs[topic]; subs != nil {
			delete(subs, id)
		}
	}, nil
}

// subGate serialises a subscriber's replay-then-live transition.
type subGate struct {
	mu        sync.Mutex
	inner     Subscriber
	replaying bool
	queue     []Record
}

func (g *subGate) deliver(r Record) error {
	g.mu.Lock()
	if g.replaying {
		g.queue = append(g.queue, r)
		g.mu.Unlock()
		return nil
	}
	g.mu.Unlock()
	return g.inner(r)
}

// finishReplay flushes live records queued during replay, skipping any
// already covered by the replayed snapshot (same slot, HLC not newer).
//
// 🛑 `replaying` stays TRUE until the queue is fully drained, and is cleared
// only while holding the lock with the queue empty. Clearing it before the
// flush — which is what this did — opens the transition in two ways at once:
// a concurrent deliver() reads replaying==false and calls g.inner directly,
// so (a) the subscriber is entered by several goroutines simultaneously,
// breaking the serialisation this type exists to provide, and (b) that live
// record can overtake records queued BEFORE it, so replay/live ordering is
// not monotonic. Measured before the fix: 6 concurrent entries, and a queued
// record delivered after three live ones.
//
// ⚠ `-race` is CLEAN on that defect and always was — the queue handoff is
// properly locked, so nothing races in this package's memory. What breaks is
// the contract the gate advertises, and the damage lands in the subscriber's
// state where the detector cannot see it.
//
// The drain loop re-checks under the lock because deliver() may enqueue more
// while the previous batch is being handed to the subscriber. A subscriber is
// never entered concurrently because only this goroutine calls g.inner while
// replaying is still set.
//
// ⚠ TERMINATION IS A RATE COMPARISON, AND IT IS THE PRICE OF THE GUARANTEE
// (measured by @Z-345, recorded here so nobody re-derives it): the loop exits
// when it finds the queue empty under the lock, so Subscribe returns only once
// the subscriber has caught up with arrivals. **A 2ms subscriber against a
// topic published for 3s returned after 5,695ms instead of 123ms — 46×.**
//
// This is NOT a defect to be bounded away: you cannot both hold the gate shut
// until the queue drains AND return early — an early return is precisely the
// pre-fix bug (live records overtaking queued ones, subscriber entered
// concurrently). The termination condition is already carried by
// `Subscriber`'s documented MUST-NOT-BLOCK contract, which @Z's probe
// deliberately violates to force the case. Every in-tree subscriber is an
// in-memory index update and outruns any publisher by orders of magnitude.
//
// 🛑 So the correct response to a slow Subscribe is to fix the SUBSCRIBER, not
// to weaken this loop. If a future subscriber genuinely must do slow work, it
// owes a hand-off to its own goroutine — which the Subscriber contract already
// requires of it.
func (g *subGate) finishReplay(replayed map[recordKey]uint64) {
	g.mu.Lock()
	for len(g.queue) > 0 {
		batch := g.queue
		g.queue = nil
		g.mu.Unlock()
		for _, r := range batch {
			if hlc, ok := replayed[keyOf(r)]; ok && r.HLC <= hlc {
				continue
			}
			_ = g.inner(r)
		}
		g.mu.Lock()
	}
	g.replaying = false
	g.mu.Unlock()
}

func (n *nodeImpl) Publish(topic Topic, body []byte) error {
	return n.PublishKeyed(topic, "", body)
}

func (n *nodeImpl) PublishKeyed(topic Topic, key string, body []byte) error {
	if n.stopped.Load() {
		return ErrStopped
	}
	if n.paused.Load() {
		// Eager-push records to existing tree edges still go out on
		// correctness paths during pause. Publish from the local node
		// is treated as correctness-critical.
	}
	if len(body) > n.cfg.MaxRecordBytes {
		return ErrTooLarge
	}
	// Enforced locally as well as at the inbound gate: MaxKeyBytes is an
	// encoding invariant (the u16 length prefix in signableBytes), so a
	// record that violates it must never be signed in the first place.
	if len(key) > MaxKeyBytes {
		return ErrTooLarge
	}

	r := Record{
		Topic:  topic,
		NodeID: n.id,
		Key:    key,
		HLC:    n.hlc.Now(),
		// Deep-copy: the store, the wire encoder, and every subscriber
		// share this slice from here on — a caller mutating its body
		// buffer after Publish must not corrupt any of them.
		Body: append([]byte(nil), body...),
	}
	signRecord(&r, n.priv)
	n.plum.Publish(r)

	// Notify local subscribers + the accepted-change stream.
	n.recordAccepted(r)
	return nil
}

func (n *nodeImpl) PublishTombstone(topic Topic) error {
	return n.PublishKeyedTombstone(topic, "")
}

func (n *nodeImpl) PublishKeyedTombstone(topic Topic, key string) error {
	if n.stopped.Load() {
		return ErrStopped
	}
	if len(key) > MaxKeyBytes {
		return ErrTooLarge
	}
	r := Record{
		Topic:     topic,
		NodeID:    n.id,
		Key:       key,
		HLC:       n.hlc.Now(),
		Tombstone: true,
	}
	signRecord(&r, n.priv)
	n.plum.Publish(r)
	n.recordAccepted(r)
	return nil
}

// PublishObserverTombstone implements swarm.Node. It signs an
// attestation that (topic, target) is dead with THIS node's private
// key, marks ObserverNodeID = n.id, and broadcasts. The CRDT on every
// consumer accumulates these attestations and only synthesises an
// effective tombstone after K-of-N distinct ObserverNodeIDs report
// within the corroboration window — see recordStore.applyAttestationLocked.
//
// Callers should restrict invocation to peers with the anchor role
// (HSTLES Library does this at the call site in
// mesh/node/peer_connections.go) and pair this call with the
// corresponding LAD EvictPeer so the LAD directory converges in
// lock-step.
func (n *nodeImpl) PublishObserverTombstone(topic Topic, target NodeID) error {
	if n.stopped.Load() {
		return ErrStopped
	}
	if target == "" || target == n.id {
		// Refuse to attest against self — that is the owner-tombstone
		// path (PublishTombstone). Refuse empty target — meaningless.
		return nil
	}
	now := time.Now()
	if n.cfg.NowFn != nil {
		now = n.cfg.NowFn()
	}
	r := Record{
		Topic:            topic,
		NodeID:           target,
		HLC:              n.hlc.Now(),
		Tombstone:        true,
		ObserverNodeID:   n.id,
		ObservedAtUnixMs: now.UnixMilli(),
	}
	signRecord(&r, n.priv)

	// Accumulate our own attestation locally and deliver ONLY if it crosses
	// quorum here — this node's attestation is ONE WITNESS, NOT A VERDICT.
	// Delivering it unconditionally would make the emitter K=1 while every peer
	// receiving it via plumtrees correctly waits for K distinct observers,
	// breaking the property stated on Config: "a single rogue anchor cannot
	// evict a live peer". (The owner path, PublishTombstone, stays K=1 by
	// design: a node signing its own death needs no corroboration.)
	if applied, _ := n.store.Apply(r); applied {
		n.recordAccepted(r)
	}

	// Broadcast unconditionally — NOT through Publish. Publish gates the send on
	// store.Apply returning applied=true, but an attestation below quorum
	// returns applied=false, so the first attestation of any target (all a lone
	// anchor can produce) would be applied locally and never sent. The whole
	// point of an attestation is to reach OTHER observers so THEY can count it
	// toward quorum; it must go on the wire regardless of local quorum state.
	n.plum.Broadcast(r)
	return nil
}

// SetObserverRoleCheck wires the application's anchor-role gate for
// observer attestations into the recordStore. The gate receives the
// claimed ObserverNodeID and the Sig-verified PubKey; it MUST verify
// the (NodeID, PubKey) binding against application trust state (e.g.
// HSTLES's role_table). Returning false from the gate rejects the
// attestation outright. Wire this once at startup, after the role_table
// has been initialised.
func (n *nodeImpl) SetObserverRoleCheck(fn func(observer NodeID, pubKey []byte) bool) {
	n.store.SetObserverRoleCheck(fn)
}

func (n *nodeImpl) SetRole(role Role) error {
	prev := Role(n.role.Swap(uint32(role)))
	if prev == role {
		return nil
	}
	// Tree-edge rebalance happens lazily: the next eager push picks fresh
	// edges via bestTreeEdges, which prefers anchor-role peers. Role-specific
	// republishers wire in through the OnRoleChange callback.
	n.rolesMu.Lock()
	for _, fn := range n.onRoleChange {
		fn(prev, role)
	}
	n.rolesMu.Unlock()
	return nil
}

func (n *nodeImpl) SetTenant(tenantID string) error {
	prevAny := n.tenant.Swap(tenantID)
	prev, _ := prevAny.(string)
	if prev == tenantID {
		return nil
	}

	// Tombstone all pre-tenant records published by THIS node.
	// We do this only for our own records — peers tombstone theirs.
	store := n.store
	store.mu.RLock()
	// Every slot, not just the keyless one: under composite keys this node
	// may hold many records per topic, and a tenant change must retire all
	// of them or the un-tombstoned ones keep gossiping under the old tenant.
	mine := make([]Record, 0)
	for _, ts := range store.byTopic {
		for k, r := range ts.records {
			if k.NodeID == n.id {
				mine = append(mine, r)
			}
		}
	}
	store.mu.RUnlock()

	for _, r := range mine {
		tomb := Record{
			Topic:     r.Topic,
			NodeID:    n.id,
			Key:       r.Key,
			HLC:       n.hlc.Now(),
			Tombstone: true,
		}
		signRecord(&tomb, n.priv)
		// Apply locally, then Broadcast — NOT Publish. Publish gates the
		// send on its own store.Apply returning applied=true; with the
		// tombstone pre-applied here, that second Apply is a no-op
		// (identical HLC + deterministic Ed25519 sig), so Publish
		// returned before pushing and the tenant-rebind tombstone NEVER
		// reached the wire. Broadcast is the same fix the observer
		// attestation path required, for the same double-apply reason.
		if applied, _ := n.store.Apply(tomb); applied {
			n.recordAccepted(tomb)
		}
		if n.plum != nil {
			n.plum.Broadcast(tomb)
		}
	}

	n.tenantMu.Lock()
	for _, fn := range n.onTenantChange {
		fn(prev, tenantID)
	}
	n.tenantMu.Unlock()
	return nil
}

// OnRoleChange registers a callback invoked when SetRole succeeds. Used by
// agent integrations to (re)publish role-specific topics.
func (n *nodeImpl) OnRoleChange(fn func(prev, next Role)) {
	n.rolesMu.Lock()
	defer n.rolesMu.Unlock()
	n.onRoleChange = append(n.onRoleChange, fn)
}

// OnTenantChange registers a callback invoked when SetTenant succeeds.
func (n *nodeImpl) OnTenantChange(fn func(prev, next string)) {
	n.tenantMu.Lock()
	defer n.tenantMu.Unlock()
	n.onTenantChange = append(n.onTenantChange, fn)
}

// Role returns the current role.
// SelfRole satisfies the Node interface — returns the role this node
// has been configured to play, bypassing the RoleTable's PeerRecord
// gossip-echo dependency. Equivalent to Role() but exposed on the
// interface for callers that must do "am I an anchor" checks during
// the boot window before our own PeerRecord has round-tripped.
func (n *nodeImpl) SelfRole() Role {
	return Role(n.role.Load())
}

func (n *nodeImpl) Role() Role {
	return Role(n.role.Load())
}

// Get returns the current record for (topic, node). Production read API over
// the convergence store; delegates to the same store the gossip path applies to.
func (n *nodeImpl) Get(topic Topic, node NodeID) (Record, bool) {
	return n.store.Get(topic, node)
}

// GetKeyed returns one per-key slot of a node on a topic.
func (n *nodeImpl) GetKeyed(topic Topic, node NodeID, key string) (Record, bool) {
	return n.store.GetKeyed(topic, node, key)
}

// NodeRecords returns every live record a node holds on a topic, in
// canonical (NodeID, Key) order.
func (n *nodeImpl) NodeRecords(topic Topic, node NodeID) []Record {
	return n.store.NodeRecords(topic, node)
}

// TopicRecords returns a snapshot of every live record on a topic.
func (n *nodeImpl) TopicRecords(topic Topic) []Record {
	return n.store.TopicRecords(topic)
}

// Topics returns every topic the store currently holds records for.
func (n *nodeImpl) Topics() []Topic {
	return n.store.Topics()
}

// SetObserverQuorum tunes the K-of-N observer-tombstone gate.
func (n *nodeImpl) SetObserverQuorum(k int, w time.Duration) {
	n.store.SetObserverQuorum(k, w)
}

// Tenant returns the current tenant ID.
func (n *nodeImpl) Tenant() string {
	v, _ := n.tenant.Load().(string)
	return v
}

func (n *nodeImpl) Pause() error {
	if !n.paused.CompareAndSwap(false, true) {
		return nil
	}
	if n.plum != nil {
		n.plum.SetPaused(true)
	}
	if n.merkle != nil {
		n.merkle.SetPaused(true)
	}
	if n.onPaused != nil {
		n.onPaused()
	}
	return nil
}

func (n *nodeImpl) Resume() error {
	if !n.paused.CompareAndSwap(true, false) {
		return nil
	}
	if n.plum != nil {
		n.plum.SetPaused(false)
	}
	if n.merkle != nil {
		n.merkle.SetPaused(false)
	}
	if n.onResumed != nil {
		n.onResumed()
	}
	return nil
}

func (n *nodeImpl) PerPeerConfig(peerID NodeID) PerPeerConfig {
	return n.peers.Snapshot(peerID)
}

func (n *nodeImpl) ContentTopic() ContentTopic {
	return n.content
}

// ---------- internal ----------

func (n *nodeImpl) runTickLoop(ctx context.Context) {
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	var lastReap time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case t := <-ticker.C:
			if n.plum != nil {
				n.plum.Tick(t)
			}
			// Drive Merkle anti-entropy from the production ticker too.
			// Previously only the simulator's Node.Tick called
			// merkle.Tick — in production the periodic drift-recovery
			// loop NEVER ran; reconciliation happened only on session
			// join. merkleEngine.Tick self-paces per topic via
			// MerkleProbeInterval, so a 50ms driver costs nothing
			// between due probes.
			if n.merkle != nil {
				n.merkle.Tick()
			}
			if n.cfg.TopicTTL != nil && t.Sub(lastReap) >= 30*time.Second {
				lastReap = t
				n.store.reapExpired(t.UnixMilli(), n.cfg.TopicTTL)
			}
		}
	}
}

// recordAccepted fans one accepted store change out to the OnAccepted
// stream and topic subscribers. The record is cloned ONCE here so neither
// the hook nor any subscriber shares byte slices with the store — a
// mutating consumer can corrupt its own view, never the CRDT.
func (n *nodeImpl) recordAccepted(r Record) {
	r = cloneRecord(r)
	if n.cfg.OnAccepted != nil {
		n.cfg.OnAccepted(r)
	}
	n.deliverToSubs(r)
}

// dispatchToSubscribers is invoked from ReceiveFrame after each successful
// Apply. The Plumtrees handler performs the apply; subscribers observe new
// records via the records-arrived-since-last-snapshot pattern exposed by
// InternalStore for tests + the convergence simulator.
func (n *nodeImpl) dispatchToSubscribers(from NodeID) {
	_ = from
}

// deliverToSubs delivers a record to all subscribers of its topic.
// Called from Node.Publish for local records, from plumtrees and merkle
// after applying remote records.
// 🛑 THE SNAPSHOT IS A SLICE, NOT THE MAP. `subs := n.subs[r.Topic]` copies a
// map HEADER — a pointer — so releasing the lock and then ranging over it
// iterates live shared state. Subscribe writes `n.subs[topic][id]` and the
// unsubscribe closure deletes from that same inner map; both hold subsMu,
// but this read did not, so a subscribe or unsubscribe concurrent with a
// delivery is a concurrent map read/write. Go may panic outright
// ("concurrent map iteration and map write") rather than merely tearing.
//
// MEASURED: the race detector fires on Subscribe (node.go:264) against this
// range. Copying the CALLBACKS under the lock closes it while still keeping
// subscriber code out of the critical section — which is why the lock was
// being released here in the first place.
func (n *nodeImpl) deliverToSubs(r Record) {
	n.subsMu.RLock()
	subs := n.subs[r.Topic]
	fns := make([]Subscriber, 0, len(subs))
	for _, fn := range subs {
		fns = append(fns, fn)
	}
	n.subsMu.RUnlock()
	for _, fn := range fns {
		_ = fn(r)
	}
}

// ---------- Internal record-store accessor ----------
//
// Used by the simulator + tests to assert convergence.

// internalStore exposes the recordStore for tests and the simulator wrapper.
// Not part of the public Node interface.
func internalStore(n Node) *recordStore {
	impl, ok := n.(*nodeImpl)
	if !ok {
		return nil
	}
	return impl.store
}
