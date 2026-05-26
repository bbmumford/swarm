// Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
// Queries: licensing@hstles.com

package sim

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bbmumford/swarm"
)

// SwarmNode wraps a real swarm.Node so it satisfies sim.Node. The
// cold-start convergence test runs the real Plumtrees + δ-CRDT engine
// through this bridge.
type SwarmNode struct {
	id         NodeID
	swarmID    swarm.NodeID
	node       swarm.Node
	tport      *simTransport
	cancel     context.CancelFunc
	knownPeers []swarm.NodeID
	virtTime   atomic.Int64 // unix-millis virtual time
	priv       ed25519.PrivateKey
}

// virtualNow returns the SwarmNode's current virtual time. Used by the
// swarm engine via Config.NowFn so all timestamps (graft delay, etc.)
// align with the simulator's virtual clock.
func (n *SwarmNode) virtualNow() time.Time {
	return time.UnixMilli(n.virtTime.Load())
}

// NewSwarmNode creates a SwarmNode with a fresh Ed25519 keypair. peers is
// the list of expected peer SimNodeIDs (used to populate the transport's
// initial peer set). Tests call Publish() then run the mesh until all
// nodes converge.
func NewSwarmNode(id NodeID, peers []NodeID) *SwarmNode {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	swarmID := swarm.NodeID(nodeIDFromPub(pub))

	sn := &SwarmNode{
		id:      id,
		swarmID: swarmID,
		priv:    priv,
	}
	sn.virtTime.Store(0)

	tport := newSimTransport(sn, swarmID, peers)
	sn.tport = tport

	cfg := swarm.Config{
		NodeID:                  swarmID,
		PrivKey:                 priv,
		TreeDegree:              4,
		GraftDelay:              50 * time.Millisecond,
		MerkleProbeInterval:     200 * time.Millisecond,
		NowFn:                   sn.virtualNow,
		DisableBackgroundTicker: true,
	}
	node, err := swarm.New(cfg)
	if err != nil {
		panic(err)
	}
	if err := swarm.Wire(node, tport); err != nil {
		panic(err)
	}
	sn.node = node

	// Start in background with a cancellable context.
	ctx, cancel := context.WithCancel(context.Background())
	sn.cancel = cancel
	go func() { _ = node.Start(ctx) }()

	return sn
}

// ID implements sim.Node.
func (n *SwarmNode) ID() NodeID { return n.id }

// Step implements sim.Node — drains the transport's outbound queue and
// advances the engine's virtual clock + ticks it.
func (n *SwarmNode) Step(now VirtualTime) ([]Frame, error) {
	n.virtTime.Store(int64(now))
	n.node.Tick(time.UnixMilli(int64(now)))
	return n.tport.DrainOutbound(), nil
}

// Receive implements sim.Node — forwards to the swarm Node via the
// transport's OnReceive callback.
func (n *SwarmNode) Receive(now VirtualTime, frame Frame) error {
	// Look up the from sim.NodeID and translate to the swarm.NodeID.
	// We carry the swarm.NodeID inside Frame.Body's transport envelope
	// — see simTransport.Send for the encoding.
	return n.tport.DeliverInbound(frame)
}

// Records implements sim.Node — returns the underlying swarm store contents.
func (n *SwarmNode) Records() map[string][]Record {
	store := swarm.InternalStore(n.node)
	if store == nil {
		return nil
	}
	out := make(map[string][]Record)
	for _, t := range store.Topics() {
		recs := store.TopicRecords(t)
		simRecs := make([]Record, 0, len(recs))
		for _, r := range recs {
			simRecs = append(simRecs, Record{
				Topic:     string(r.Topic),
				NodeID:    NodeID(r.NodeID), // swarm NodeID -> sim NodeID (we use hex for both)
				HLC:       r.HLC,
				Body:      r.Body,
				Tombstone: r.Tombstone,
			})
		}
		out[string(t)] = simRecs
	}
	return out
}

// Publish proxies to the wrapped swarm.Node.
func (n *SwarmNode) Publish(topic string, hlc uint64, body []byte) {
	_ = hlc // swarm assigns its own HLC
	_ = n.node.Publish(swarm.Topic(topic), body)
}

// Stop halts the wrapped swarm.Node.
func (n *SwarmNode) Stop() {
	if n.cancel != nil {
		n.cancel()
	}
	_ = n.node.Stop()
}

// SwarmNodeID exposes the underlying swarm.NodeID (used by the simulator
// to wire transports together).
func (n *SwarmNode) SwarmNodeID() swarm.NodeID { return n.swarmID }

// Priv returns the node's Ed25519 private key. Tests use it to build
// signed payloads (e.g. content Manifests) without re-deriving keys.
func (n *SwarmNode) Priv() ed25519.PrivateKey { return n.priv }

// ---------- simTransport ----------

// simTransport bridges swarm.Transport to the simulator's Mesh.
// Outbound: queued to be drained by sim.Step.
// Inbound: delivered when Receive is called.
type simTransport struct {
	sim      *SwarmNode
	localID  swarm.NodeID
	peers    []swarm.NodeID
	peerByID map[swarm.NodeID]NodeID // map back to sim.NodeID for routing

	mu          sync.Mutex
	outbound    []Frame
	onReceive   func(from swarm.NodeID, frame []byte)
	onPeerJoin  func(id swarm.NodeID)
	onPeerLeave func(id swarm.NodeID)
}

func newSimTransport(sn *SwarmNode, local swarm.NodeID, _ []NodeID) *simTransport {
	// Peer mappings are wired in via RegisterPeer after construction;
	// the simPeers list is only retained at the SwarmNode level for
	// documentation purposes.
	return &simTransport{
		sim:      sn,
		localID:  local,
		peerByID: make(map[swarm.NodeID]NodeID),
	}
}

// RegisterPeer maps a sim NodeID ↔ swarm NodeID and adds the peer to the
// transport's known set. Called by the test harness when building the mesh.
func (t *simTransport) RegisterPeer(simID NodeID, swarmID swarm.NodeID) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.peers = append(t.peers, swarmID)
	t.peerByID[swarmID] = simID
	if t.onPeerJoin != nil {
		t.onPeerJoin(swarmID)
	}
}

func (t *simTransport) LocalID() swarm.NodeID { return t.localID }

func (t *simTransport) Send(to swarm.NodeID, frame []byte) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	target, ok := t.peerByID[to]
	if !ok {
		return nil // unknown peer; drop
	}
	body := append([]byte(nil), frame...)
	t.outbound = append(t.outbound, Frame{From: t.sim.id, To: target, Body: body})
	return nil
}

func (t *simTransport) Broadcast(frame []byte) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	body := append([]byte(nil), frame...)
	for _, simID := range t.peerByID {
		t.outbound = append(t.outbound, Frame{From: t.sim.id, To: simID, Body: append([]byte(nil), body...)})
	}
	return nil
}

func (t *simTransport) Peers() []swarm.NodeID {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]swarm.NodeID, len(t.peers))
	copy(out, t.peers)
	return out
}

func (t *simTransport) OnReceive(fn func(from swarm.NodeID, frame []byte)) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.onReceive = fn
}

func (t *simTransport) OnPeerJoin(fn func(id swarm.NodeID)) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.onPeerJoin = fn
}

func (t *simTransport) OnPeerLeave(fn func(id swarm.NodeID)) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.onPeerLeave = fn
}

// DrainOutbound returns and clears the queued outbound frames.
func (t *simTransport) DrainOutbound() []Frame {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := t.outbound
	t.outbound = nil
	return out
}

// DeliverInbound delivers a Frame to the swarm Node by translating the
// sim Frame's From back to a swarm.NodeID.
func (t *simTransport) DeliverInbound(f Frame) error {
	// We need to know which swarm.NodeID sent this. In sim, From is a
	// sim.NodeID. Look up which swarm.NodeID it maps to.
	t.mu.Lock()
	var from swarm.NodeID
	for swarmID, simID := range t.peerByID {
		if simID == f.From {
			from = swarmID
			break
		}
	}
	fn := t.onReceive
	t.mu.Unlock()
	if from == "" || fn == nil {
		return nil
	}
	fn(from, f.Body)
	return nil
}

// nodeIDFromPub is exposed via swarm.NodeIDFromPub.
func nodeIDFromPub(pub ed25519.PublicKey) string {
	const hex = "0123456789abcdef"
	out := make([]byte, 2*len(pub))
	for i, b := range pub {
		out[2*i] = hex[b>>4]
		out[2*i+1] = hex[b&0x0f]
	}
	return string(out)
}
