/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package swarm

import (
	"crypto/ed25519"
	"sync/atomic"
	"testing"
)

// loopbackTransport is a Transport with no peers: Send/Broadcast are
// no-ops and nothing is ever received. These tests exercise the LOCAL
// apply/deliver decision, which must not depend on any peer existing.
type loopbackTransport struct{ id NodeID }

func (l *loopbackTransport) LocalID() NodeID                { return l.id }
func (l *loopbackTransport) Send(NodeID, []byte) error      { return nil }
func (l *loopbackTransport) Broadcast([]byte) error         { return nil }
func (l *loopbackTransport) Peers() []NodeID                { return nil }
func (l *loopbackTransport) OnReceive(func(NodeID, []byte)) {}
func (l *loopbackTransport) OnPeerJoin(func(NodeID))        {}
func (l *loopbackTransport) OnPeerLeave(func(NodeID))       {}

func mustNode(t *testing.T, id NodeID) Node {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	n, err := New(Config{
		NodeID:                  id,
		PrivKey:                 priv,
		DisableBackgroundTicker: true,
	})
	if err != nil {
		t.Fatalf("new node %s: %v", id, err)
	}
	if err := Wire(n, &loopbackTransport{id: id}); err != nil {
		t.Fatalf("wire %s: %v", id, err)
	}
	t.Cleanup(func() { _ = n.Stop() })
	return n
}

// TestPublishObserverTombstone_EmitterDoesNotBypassQuorum guards the security
// property the doc on DefaultObserverQuorum states outright:
//
//	"DefaultObserverQuorum K must be >= 2 (anything less is no quorum at all);
//	 production values are tuned so a single rogue anchor cannot evict a live
//	 peer"
//
// Every REMOTE node receives an attestation through plumtrees, which routes
// it via store.Apply, and Apply returns applied=true only once K distinct
// observers corroborate (recordStore.applyAttestationLocked). The EMITTER
// holds to the same count: PublishObserverTombstone hands its own attestation
// to store.Apply and fans it out to its subscribers (recordAccepted) only on
// applied=true. Fanning it out unconditionally would make the quorum K=1 on
// the emitter and K everywhere else.
//
// That asymmetry would reach past this package. loom's node bridges this
// topic straight into the LAD directory (node/lad_reach_bridge.go), branching
// on bare r.Tombstone and writing propagating tombstones over the target's
// Reach, Member and Role records. One of loom's two callers, the callback
// InitSwarm registers on the directory's liveness sweep, attests on this
// node's view alone, a verdict that sweep itself keeps local. One anchor's
// un-corroborated attestation would then evict a live peer on every consumer
// of that directory on its own say-so, the cascade the quorum exists to
// prevent.
//
// A node's own attestation must COUNT TOWARD quorum, never BYPASS it.
func TestPublishObserverTombstone_EmitterDoesNotBypassQuorum(t *testing.T) {
	const topic = Topic("fleet.peer")

	n := mustNode(t, NodeID("anchor-a"))

	var fired atomic.Int32
	if _, err := n.Subscribe(topic, func(r Record) error {
		if r.Tombstone {
			fired.Add(1)
		}
		return nil
	}); err != nil {
		t.Fatalf("subscribe: %v", err)
	}

	if err := n.PublishObserverTombstone(topic, NodeID("victim")); err != nil {
		t.Fatalf("publish: %v", err)
	}

	if got := fired.Load(); got != 0 {
		t.Fatalf("emitter delivered a tombstone to its own subscribers from ONE "+
			"attestation (fired=%d, quorum K=%d) — a single anchor can evict a live "+
			"peer on its own say-so, which is the exact cascade the quorum prevents",
			got, DefaultObserverQuorum)
	}
}

// TestPublishObserverTombstone_SelfAndEmptyTargetRefused: attesting against
// self is the owner-tombstone path (PublishTombstone), and an empty target is
// meaningless. Neither may reach subscribers.
func TestPublishObserverTombstone_SelfAndEmptyTargetRefused(t *testing.T) {
	const topic = Topic("fleet.peer")

	n := mustNode(t, NodeID("anchor-a"))

	var fired atomic.Int32
	if _, err := n.Subscribe(topic, func(r Record) error {
		fired.Add(1)
		return nil
	}); err != nil {
		t.Fatalf("subscribe: %v", err)
	}

	if err := n.PublishObserverTombstone(topic, NodeID("anchor-a")); err != nil {
		t.Fatalf("self-attest should be a no-op, got: %v", err)
	}
	if err := n.PublishObserverTombstone(topic, NodeID("")); err != nil {
		t.Fatalf("empty-target attest should be a no-op, got: %v", err)
	}
	if got := fired.Load(); got != 0 {
		t.Fatalf("self/empty-target attestation reached subscribers (fired=%d)", got)
	}
}

// TestIsObserverAttestation_Discriminates guards the discriminator that tells
// an observer attestation from an owner-signed tombstone. The store's Apply,
// plumtrees and the inbound gate read it here, and loom node's swarm
// subscribers read it too. loom's LAD bridge branches on bare r.Tombstone,
// which cannot tell the two apart, so the store's quorum is all that keeps a
// single attestation from reaching the directory as a tombstone.
func TestIsObserverAttestation_Discriminates(t *testing.T) {
	owner := Record{Topic: "t", NodeID: "n", Tombstone: true}
	if owner.IsObserverAttestation() {
		t.Fatal("owner tombstone misreported as an observer attestation")
	}
	att := Record{Topic: "t", NodeID: "n", Tombstone: true, ObserverNodeID: "obs"}
	if !att.IsObserverAttestation() {
		t.Fatal("observer attestation not recognised")
	}
	live := Record{Topic: "t", NodeID: "n"}
	if live.IsObserverAttestation() {
		t.Fatal("live record misreported as an observer attestation")
	}
}
