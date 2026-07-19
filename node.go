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

	// Lifecycle
	startCtx    context.Context
	startCancel context.CancelFunc
	stopped     atomic.Bool
	paused      atomic.Bool

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
	impl.tport = t

	impl.plum = newPlumtrees(impl.id, impl.store, impl.peers, t, impl.hlc, impl.cfg.TreeDegree, impl.cfg.NowFn, impl.cfg.GraftDelay)
	impl.merkle = newMerkle(impl.store, impl.peers, t, impl.cfg.NowFn, impl.cfg.MerkleProbeInterval)
	impl.plum.SetMerkle(impl.merkle)
	impl.plum.SetOnApplied(impl.deliverToSubs)
	impl.merkle.SetOnApplied(impl.deliverToSubs)
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
	n.startCtx, n.startCancel = context.WithCancel(ctx)

	if !n.cfg.DisableBackgroundTicker {
		// Background tick: drive Plumtrees graft timer + keepalives.
		go n.runTickLoop()
	}

	<-n.startCtx.Done()
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
		return ErrStopped
	}
	if n.startCancel != nil {
		n.startCancel()
	}
	return nil
}

func (n *nodeImpl) Subscribe(topic Topic, sub Subscriber) (Unsubscribe, error) {
	if sub == nil {
		return nil, ErrInvalidConfig
	}
	id := n.subSeq.Add(1)

	n.subsMu.Lock()
	if n.subs[topic] == nil {
		n.subs[topic] = make(map[uint64]Subscriber)
	}
	n.subs[topic][id] = sub
	n.subsMu.Unlock()

	// Deliver any already-stored records for this topic to the new subscriber.
	for _, r := range n.store.TopicRecords(topic) {
		_ = sub(r)
	}

	return func() {
		n.subsMu.Lock()
		defer n.subsMu.Unlock()
		if subs := n.subs[topic]; subs != nil {
			delete(subs, id)
		}
	}, nil
}

func (n *nodeImpl) Publish(topic Topic, body []byte) error {
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

	r := Record{
		Topic:  topic,
		NodeID: n.id,
		HLC:    n.hlc.Now(),
		Body:   body,
	}
	signRecord(&r, n.priv)
	n.plum.Publish(r)

	// Notify local subscribers
	n.deliverToSubs(r)
	return nil
}

func (n *nodeImpl) PublishTombstone(topic Topic) error {
	if n.stopped.Load() {
		return ErrStopped
	}
	r := Record{
		Topic:     topic,
		NodeID:    n.id,
		HLC:       n.hlc.Now(),
		Tombstone: true,
	}
	signRecord(&r, n.priv)
	n.plum.Publish(r)
	n.deliverToSubs(r)
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
		n.deliverToSubs(r)
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
	mine := make([]Record, 0)
	for _, ts := range store.byTopic {
		if r, ok := ts.records[n.id]; ok {
			mine = append(mine, r)
		}
	}
	store.mu.RUnlock()

	for _, r := range mine {
		tomb := Record{
			Topic:     r.Topic,
			NodeID:    n.id,
			HLC:       n.hlc.Now(),
			Tombstone: true,
		}
		signRecord(&tomb, n.priv)
		n.store.Apply(tomb)
		if n.plum != nil {
			n.plum.Publish(tomb)
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

func (n *nodeImpl) runTickLoop() {
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-n.startCtx.Done():
			return
		case t := <-ticker.C:
			if n.plum != nil {
				n.plum.Tick(t)
			}
		}
	}
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
func (n *nodeImpl) deliverToSubs(r Record) {
	n.subsMu.RLock()
	subs := n.subs[r.Topic]
	n.subsMu.RUnlock()
	for _, fn := range subs {
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
