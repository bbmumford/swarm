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
func (n *nodeImpl) Role() Role {
	return Role(n.role.Load())
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
