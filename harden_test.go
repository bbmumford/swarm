// Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
// Queries: licensing@hstles.com

package swarm

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"sync"
	"testing"
	"time"

	pb "github.com/bbmumford/swarm/proto/pb"
)

// ---------- in-memory transport with explicit adjacency ----------

type memNet struct {
	mu    sync.Mutex
	ports map[NodeID]*memTransport
	adj   map[NodeID]map[NodeID]bool // nil = full mesh
}

func newMemNet() *memNet {
	return &memNet{ports: make(map[NodeID]*memTransport)}
}

// link restricts connectivity to the given undirected edges (call before
// attach for sparse topologies).
func (n *memNet) link(a, b NodeID) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.adj == nil {
		n.adj = make(map[NodeID]map[NodeID]bool)
	}
	for _, pair := range [][2]NodeID{{a, b}, {b, a}} {
		if n.adj[pair[0]] == nil {
			n.adj[pair[0]] = make(map[NodeID]bool)
		}
		n.adj[pair[0]][pair[1]] = true
	}
}

func (n *memNet) connected(a, b NodeID) bool {
	if n.adj == nil {
		return a != b
	}
	return n.adj[a][b]
}

func (n *memNet) attach(id NodeID) *memTransport {
	n.mu.Lock()
	defer n.mu.Unlock()
	t := &memTransport{net: n, id: id}
	n.ports[id] = t
	// announce join both ways to already-attached, connected peers
	for pid, p := range n.ports {
		if pid == id || !n.connected(id, pid) {
			continue
		}
		if p.onJoin != nil {
			p.onJoin(id)
		}
		if t.onJoin != nil {
			t.onJoin(pid)
		}
	}
	return t
}

type memTransport struct {
	net     *memNet
	id      NodeID
	mu      sync.Mutex
	onRecv  func(NodeID, []byte)
	onJoin  func(NodeID)
	onLeave func(NodeID)
}

func (t *memTransport) LocalID() NodeID { return t.id }

func (t *memTransport) Send(to NodeID, frame []byte) error {
	t.net.mu.Lock()
	peer := t.net.ports[to]
	ok := peer != nil && t.net.connected(t.id, to)
	t.net.mu.Unlock()
	if !ok {
		return nil // best-effort drop, like a real transport
	}
	peer.mu.Lock()
	recv := peer.onRecv
	peer.mu.Unlock()
	if recv != nil {
		// Async delivery: a synchronous call chain would recurse through
		// reciprocal probes and hold locks across engines.
		go recv(t.id, frame)
	}
	return nil
}

func (t *memTransport) Broadcast(frame []byte) error {
	t.net.mu.Lock()
	ids := make([]NodeID, 0, len(t.net.ports))
	for id := range t.net.ports {
		if id != t.id && t.net.connected(t.id, id) {
			ids = append(ids, id)
		}
	}
	t.net.mu.Unlock()
	for _, id := range ids {
		_ = t.Send(id, frame)
	}
	return nil
}

func (t *memTransport) Peers() []NodeID {
	t.net.mu.Lock()
	defer t.net.mu.Unlock()
	out := make([]NodeID, 0, len(t.net.ports))
	for id := range t.net.ports {
		if id != t.id && t.net.connected(t.id, id) {
			out = append(out, id)
		}
	}
	return out
}

func (t *memTransport) OnReceive(fn func(NodeID, []byte)) {
	t.mu.Lock()
	t.onRecv = fn
	t.mu.Unlock()
}
func (t *memTransport) OnPeerJoin(fn func(NodeID))  { t.mu.Lock(); t.onJoin = fn; t.mu.Unlock() }
func (t *memTransport) OnPeerLeave(fn func(NodeID)) { t.mu.Lock(); t.onLeave = fn; t.mu.Unlock() }

// ---------- helpers ----------

type testNode struct {
	node Node
	impl *nodeImpl
	priv ed25519.PrivateKey
	id   NodeID
	stop func()
}

func startNode(t *testing.T, net *memNet, cfg Config) *testNode {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cfg.PrivKey = priv
	if cfg.MerkleProbeInterval == 0 {
		cfg.MerkleProbeInterval = 50 * time.Millisecond
	}
	n, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	impl := n.(*nodeImpl)
	tport := net.attach(impl.id)
	if err := Wire(n, tport); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = n.Start(ctx); close(done) }()
	tn := &testNode{node: n, impl: impl, priv: priv, id: impl.id}
	tn.stop = func() {
		_ = n.Stop()
		cancel()
		<-done
	}
	t.Cleanup(tn.stop)
	return tn
}

func waitUntil(t *testing.T, timeout time.Duration, cond func() bool) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return cond()
}

// signedRecord builds a wire-valid record from an arbitrary keypair.
func signedRecord(topic Topic, priv ed25519.PrivateKey, id NodeID, hlc uint64, body []byte) Record {
	r := Record{Topic: topic, NodeID: id, HLC: hlc, Body: body}
	signRecord(&r, priv)
	return r
}

// inject delivers a record to target as an eager-push frame from a fake peer.
func inject(t *testing.T, net *memNet, target *testNode, from NodeID, r Record) {
	t.Helper()
	frame, err := encodeFrame(frameEagerPush(r, 4))
	if err != nil {
		t.Fatal(err)
	}
	net.mu.Lock()
	port := net.ports[target.id]
	recv := port.onRecv
	net.mu.Unlock()
	recv(from, frame)
}

// ---------- Blocker 1: lifecycle ----------

func TestLifecycleStartStopIdempotency(t *testing.T) {
	net := newMemNet()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	n, err := New(Config{PrivKey: priv})
	if err != nil {
		t.Fatal(err)
	}
	impl := n.(*nodeImpl)
	tport := net.attach(impl.id)
	if err := Wire(n, tport); err != nil {
		t.Fatal(err)
	}
	// Re-Wire must refuse.
	if err := Wire(n, tport); !errors.Is(err, ErrAlreadyWired) {
		t.Fatalf("second Wire = %v, want ErrAlreadyWired", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { _ = n.Start(ctx); close(done) }()

	if !waitUntil(t, time.Second, func() bool { return impl.started.Load() }) {
		t.Fatal("node did not start")
	}
	// Second Start must refuse rather than spawn a second ticker.
	if err := n.Start(ctx); !errors.Is(err, ErrAlreadyStarted) {
		t.Fatalf("second Start = %v, want ErrAlreadyStarted", err)
	}
	// Stop is idempotent: first nil, second nil, and it joins the ticker.
	if err := n.Stop(); err != nil {
		t.Fatalf("first Stop = %v", err)
	}
	if err := n.Stop(); err != nil {
		t.Fatalf("second Stop = %v, want nil (idempotent)", err)
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not return after Stop")
	}
}

// ---------- Blockers 1+2: production ticker drives merkle; empty node
// learns unknown topics via reciprocal reconciliation ----------

func TestPeriodicMerkleConvergesEmptyJoiner(t *testing.T) {
	net := newMemNet()
	a := startNode(t, net, Config{})
	if err := a.node.Publish(Topic("t.discover"), []byte("payload")); err != nil {
		t.Fatal(err)
	}

	// B joins EMPTY, with no session-join ProbePeer assist — only the
	// periodic production ticker runs. Pre-hardening this never
	// converged: (a) the production tick loop never called merkle.Tick,
	// (b) B holds no topics so it never probes, and (c) A's probe of B
	// only moved records B→A. The reciprocal probe closes the loop.
	b := startNode(t, net, Config{})
	ok := waitUntil(t, 5*time.Second, func() bool {
		_, ok := b.impl.store.getRaw(Topic("t.discover"), a.id)
		return ok
	})
	if !ok {
		t.Fatal("empty joiner never learned the unknown topic via periodic anti-entropy")
	}
}

// ---------- Blocker 3: attestation relay + synth exclusion ----------

func TestAttestationRelayAcrossSparseTopology(t *testing.T) {
	net := newMemNet()
	// Chain topology: A ↔ B ↔ C (A and C are NOT connected).
	// Pre-declare adjacency before attaching.
	_, privA, _ := ed25519.GenerateKey(rand.Reader)
	_, privB, _ := ed25519.GenerateKey(rand.Reader)
	_, privC, _ := ed25519.GenerateKey(rand.Reader)
	idA := nodeIDFromPub(privA.Public().(ed25519.PublicKey))
	idB := nodeIDFromPub(privB.Public().(ed25519.PublicKey))
	idC := nodeIDFromPub(privC.Public().(ed25519.PublicKey))
	net.link(idA, idB)
	net.link(idB, idC)

	mk := func(priv ed25519.PrivateKey) *testNode {
		cfg := Config{PrivKey: priv, DisableBackgroundTicker: true}
		n, err := New(cfg)
		if err != nil {
			t.Fatal(err)
		}
		impl := n.(*nodeImpl)
		tport := net.attach(impl.id)
		if err := Wire(n, tport); err != nil {
			t.Fatal(err)
		}
		return &testNode{node: n, impl: impl, priv: priv, id: impl.id}
	}
	a, b, c := mk(privA), mk(privB), mk(privC)
	target := NodeID("00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff")
	topic := Topic("t.attest")

	// A and C each observe the target dead. Their attestations must cross
	// the chain (A's via B to C and vice versa) so EVERY node counts 2
	// distinct observers — pre-hardening a below-quorum attestation was
	// never relayed past the first hop, so C never saw A's.
	if err := a.node.PublishObserverTombstone(topic, target); err != nil {
		t.Fatal(err)
	}
	if err := c.node.PublishObserverTombstone(topic, target); err != nil {
		t.Fatal(err)
	}

	for _, n := range []*testNode{a, b, c} {
		n := n
		ok := waitUntil(t, 5*time.Second, func() bool {
			r, ok := n.impl.store.getRaw(topic, target)
			return ok && r.Tombstone
		})
		if !ok {
			t.Fatalf("node %.8s never synthesised the K=2 tombstone", n.id)
		}
	}

	// Synth tombstones (unsigned) must NOT poison the Merkle root: every
	// node holds the same signed set (zero owner records for target), so
	// roots must be identical even though each synthesised locally.
	rootA := topicMerkleRoot(a.impl.store, topic, nil, nil)
	rootB := topicMerkleRoot(b.impl.store, topic, nil, nil)
	if rootA != rootB {
		t.Fatal("synthesised tombstone poisoned the Merkle root")
	}
}

// ---------- Blockers 4+5: inbound gate ----------

func TestInboundGateRejects(t *testing.T) {
	net := newMemNet()
	banned := errors.New("banned topic")
	a := startNode(t, net, Config{
		MaxRecordBytes: 128,
		TrustCheck: func(r Record) error {
			if r.Topic == "t.banned" {
				return banned
			}
			return nil
		},
	})
	_, attacker, _ := ed25519.GenerateKey(rand.Reader)
	attackerID := nodeIDFromPub(attacker.Public().(ed25519.PublicKey))
	now := uint64(time.Now().UnixMilli())

	// Oversize body (inbound previously skipped the MaxRecordBytes cap).
	big := signedRecord("t.size", attacker, attackerID, packHLC(now, 0), make([]byte, 4096))
	inject(t, net, a, attackerID, big)

	// Far-future HLC: raw remote HLC previously pinned the slot forever.
	future := signedRecord("t.skew", attacker, attackerID, packHLC(now+3_600_000, 0), []byte("x"))
	inject(t, net, a, attackerID, future)

	// Trust-hook rejection.
	trust := signedRecord("t.banned", attacker, attackerID, packHLC(now, 0), []byte("x"))
	inject(t, net, a, attackerID, trust)

	// A legitimate record on an allowed topic must still land.
	good := signedRecord("t.good", attacker, attackerID, packHLC(now, 1), []byte("x"))
	inject(t, net, a, attackerID, good)

	if !waitUntil(t, 2*time.Second, func() bool {
		_, ok := a.impl.store.getRaw(Topic("t.good"), attackerID)
		return ok
	}) {
		t.Fatal("legitimate record was not applied")
	}
	for _, topic := range []Topic{"t.size", "t.skew", "t.banned"} {
		if _, ok := a.impl.store.getRaw(topic, attackerID); ok {
			t.Fatalf("record on %s must have been rejected by the gate", topic)
		}
	}
	size, skew, _, trustN := a.impl.gate.Rejections()
	if size != 1 || skew != 1 || trustN != 1 {
		t.Fatalf("rejection counters = size:%d skew:%d trust:%d, want 1/1/1", size, skew, trustN)
	}
}

func TestNodeKeyBindingEnforced(t *testing.T) {
	net := newMemNet()
	a := startNode(t, net, Config{RequireNodeKeyBinding: true})
	_, attacker, _ := ed25519.GenerateKey(rand.Reader)
	attackerID := nodeIDFromPub(attacker.Public().(ed25519.PublicKey))
	now := uint64(time.Now().UnixMilli())

	// Signed by attacker but CLAIMING a victim's NodeID — must be dropped.
	victim := NodeID("aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11")
	spoof := signedRecord("t.bind", attacker, victim, packHLC(now, 0), []byte("x"))
	inject(t, net, a, attackerID, spoof)

	// Same key claiming its OWN NodeID — must land.
	honest := signedRecord("t.bind", attacker, attackerID, packHLC(now, 1), []byte("x"))
	inject(t, net, a, attackerID, honest)

	if !waitUntil(t, 2*time.Second, func() bool {
		_, ok := a.impl.store.getRaw(Topic("t.bind"), attackerID)
		return ok
	}) {
		t.Fatal("honest self-bound record was not applied")
	}
	if _, ok := a.impl.store.getRaw(Topic("t.bind"), victim); ok {
		t.Fatal("spoofed NodeID record must be rejected by key binding")
	}
}

// ---------- Blocker 6: SetTenant broadcast + subscribe replay ----------

func TestSetTenantTombstoneReachesPeers(t *testing.T) {
	net := newMemNet()
	a := startNode(t, net, Config{})
	b := startNode(t, net, Config{})

	topic := Topic("t.tenant")
	if err := a.node.Publish(topic, []byte("pre-tenant")); err != nil {
		t.Fatal(err)
	}
	if !waitUntil(t, 3*time.Second, func() bool {
		r, ok := b.impl.store.getRaw(topic, a.id)
		return ok && !r.Tombstone
	}) {
		t.Fatal("record never reached B")
	}

	// Pre-hardening: the tenant-rebind tombstone was applied locally then
	// routed through Publish, whose second Apply returned applied=false —
	// so it NEVER hit the wire and peers kept the stale record forever.
	if err := a.node.SetTenant("tenant-1"); err != nil {
		t.Fatal(err)
	}
	if !waitUntil(t, 3*time.Second, func() bool {
		r, ok := b.impl.store.getRaw(topic, a.id)
		return ok && r.Tombstone
	}) {
		t.Fatal("SetTenant tombstone never reached peer B")
	}
}

func TestSubscribeReplayThenLiveNoDuplicates(t *testing.T) {
	net := newMemNet()
	a := startNode(t, net, Config{})
	topic := Topic("t.sub")
	if err := a.node.Publish(topic, []byte("v1")); err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	var got []Record
	unsub, err := a.node.Subscribe(topic, func(r Record) error {
		mu.Lock()
		got = append(got, r)
		mu.Unlock()
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer unsub()

	if err := a.node.Publish(topic, []byte("v2")); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, time.Second, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(got) >= 2
	})
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 2 {
		t.Fatalf("subscriber saw %d deliveries, want exactly 2 (replay v1 + live v2): %v", len(got), got)
	}
	if string(got[0].Body) != "v1" || string(got[1].Body) != "v2" {
		t.Fatalf("order/dup violation: %q then %q", got[0].Body, got[1].Body)
	}
}

// ---------- Blocker 6/7: read contract + caps + TTL ----------

func TestGetHidesTombstonesAndClones(t *testing.T) {
	net := newMemNet()
	a := startNode(t, net, Config{})
	topic := Topic("t.read")
	if err := a.node.Publish(topic, []byte("live")); err != nil {
		t.Fatal(err)
	}
	r, ok := a.node.Get(topic, a.id)
	if !ok {
		t.Fatal("live record must be visible")
	}
	// Mutating the returned slice must not corrupt the store.
	r.Body[0] = 'X'
	r2, _ := a.node.Get(topic, a.id)
	if string(r2.Body) != "live" {
		t.Fatal("Get must return defensive copies")
	}

	if err := a.node.PublishTombstone(topic); err != nil {
		t.Fatal(err)
	}
	if _, ok := a.node.Get(topic, a.id); ok {
		t.Fatal("tombstoned slot must report not-present via Get")
	}
	if _, ok := a.impl.store.getRaw(topic, a.id); !ok {
		t.Fatal("tombstone must still exist internally")
	}
}

func TestTopicCapRejectsNew(t *testing.T) {
	net := newMemNet()
	a := startNode(t, net, Config{MaxTopics: 2})
	_ = a.node.Publish("t.one", []byte("1"))
	_ = a.node.Publish("t.two", []byte("2"))
	_ = a.node.Publish("t.three", []byte("3"))
	if got := len(a.node.Topics()); got != 2 {
		t.Fatalf("topics = %d, want 2 (cap rejects the third)", got)
	}
}

func TestTopicTTLReap(t *testing.T) {
	net := newMemNet()
	a := startNode(t, net, Config{
		TopicTTL: func(topic Topic) time.Duration {
			if topic == "t.ttl" {
				return 50 * time.Millisecond
			}
			return 0
		},
	})
	_ = a.node.Publish("t.ttl", []byte("ephemeral"))
	_ = a.node.Publish("t.keep", []byte("durable"))
	time.Sleep(80 * time.Millisecond)
	// Drive the reap directly (the background loop reaps on a 30s cadence).
	a.impl.store.reapExpired(time.Now().UnixMilli(), a.impl.cfg.TopicTTL)
	if _, ok := a.impl.store.getRaw(Topic("t.ttl"), a.id); ok {
		t.Fatal("expired record must be reaped")
	}
	if _, ok := a.impl.store.getRaw(Topic("t.keep"), a.id); !ok {
		t.Fatal("no-TTL topic must be untouched")
	}
}

// ---------- OnAccepted stream ----------

func TestOnAcceptedStream(t *testing.T) {
	net := newMemNet()
	var mu sync.Mutex
	var accepted []Record
	a := startNode(t, net, Config{
		OnAccepted: func(r Record) {
			mu.Lock()
			accepted = append(accepted, r)
			mu.Unlock()
		},
	})
	b := startNode(t, net, Config{})
	_ = b.node.Publish("t.stream", []byte("remote"))
	_ = a.node.Publish("t.stream", []byte("local"))

	if !waitUntil(t, 3*time.Second, func() bool {
		mu.Lock()
		defer mu.Unlock()
		haveLocal, haveRemote := false, false
		for _, r := range accepted {
			if r.NodeID == a.id {
				haveLocal = true
			}
			if r.NodeID == b.id {
				haveRemote = true
			}
		}
		return haveLocal && haveRemote
	}) {
		t.Fatal("OnAccepted must observe both local and remote accepted changes")
	}
}

// silence unused-import guard for pb (used via frame builders in helpers)
var _ = pb.Frame{}
