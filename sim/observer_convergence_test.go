// Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
// Queries: licensing@hstles.com

package sim

import (
	"testing"

	"github.com/bbmumford/swarm"
)

// TestObserverAttestationConvergesToTombstone is the end-to-end proof that
// K distinct observers, on separate machines, converge to a synthesised
// tombstone the whole mesh applies.
//
// This is the property the fleet needs and never had. Observer attestations
// are how a node that died abruptly — every machine replaced by a deploy — gets
// forgotten: it cannot tombstone itself, so K anchors witness its silence and
// attest, and the K-of-N quorum turns those witnesses into a propagating death.
//
// The bug this guards against: PublishObserverTombstone broadcast the
// attestation through plumtrees.Publish, which applies the record locally first
// and returns WITHOUT sending when store.Apply reports applied=false. An
// observer attestation is applied=false until it crosses quorum — so the very
// first attestation of any target, the only kind a single anchor can produce,
// was never put on the wire. Each anchor accumulated its own attestations in
// isolation and no target ever reached K distinct observers on any node.
// Measured on the live fleet: two anchors emitting 96 and 12 attestations, zero
// tombstones formed, the ghost roster frozen at 40 against 11 real machines.
//
// The fix: an attestation is a novel signed record the emitter has already
// decided is worth propagating; it must broadcast regardless of local quorum,
// because its whole purpose is to reach OTHER observers' stores so THEY can
// count it. The receive path already handles quorum correctly — when the
// K-th distinct attestation lands, Apply returns applied=true and the synth
// tombstone is delivered.
func TestObserverAttestationConvergesToTombstone(t *testing.T) {
	const topic = "fleet.peer"
	const ghost = swarm.NodeID("vl1_ghost_target")

	// Three fully-connected nodes. DefaultObserverQuorum is 2, so two of them
	// attesting the same absent target must synthesise a tombstone on every
	// node that collects both attestations.
	ids := []NodeID{"n00", "n01", "n02"}
	nodes := make([]*SwarmNode, len(ids))
	mesh := NewMesh(1)
	for i, id := range ids {
		peers := make([]NodeID, 0, len(ids)-1)
		for _, p := range ids {
			if p != id {
				peers = append(peers, p)
			}
		}
		nodes[i] = NewSwarmNode(id, peers)
		mesh.AddNode(nodes[i])
	}
	for i, n := range nodes {
		for j, peer := range nodes {
			if i != j {
				n.tport.RegisterPeer(ids[j], peer.SwarmNodeID())
			}
		}
	}
	mesh.FullMesh(5, 1, 0)

	// Two distinct observers (n00, n01) attest that ghost is dead. n02 stays
	// silent — it must still learn the death once quorum forms and propagates.
	if err := nodes[0].node.PublishObserverTombstone(swarm.Topic(topic), ghost); err != nil {
		t.Fatalf("n00 attest: %v", err)
	}
	if err := nodes[1].node.PublishObserverTombstone(swarm.Topic(topic), ghost); err != nil {
		t.Fatalf("n01 attest: %v", err)
	}

	hasTombstone := func(n *SwarmNode) bool {
		for _, r := range n.Records()[topic] {
			if string(r.NodeID) == string(ghost) && r.Tombstone {
				return true
			}
		}
		return false
	}

	steps, err := mesh.Run(2000, func(m *Mesh) bool {
		// Converged once at least one node has synthesised the tombstone from
		// the two independent attestations.
		for _, n := range nodes {
			if hasTombstone(n) {
				return true
			}
		}
		return false
	})

	for _, n := range nodes {
		n.Stop()
	}

	if err != nil {
		t.Fatalf("two distinct anchor attestations never converged to a tombstone "+
			"(ran %d steps): the attestation is not reaching other observers' stores, "+
			"so K-of-N quorum can never form across machines", steps)
	}
	t.Logf("observer tombstone converged in %d virtual ticks", steps)
}

// TestSingleObserverDoesNotTombstone guards the safety half: ONE observer must
// never be enough. If a lone attestation synthesised a tombstone, a single
// anchor could evict any live peer — the exact cascade the quorum exists to
// prevent, and the property this package's Config doc states outright.
func TestSingleObserverDoesNotTombstone(t *testing.T) {
	const topic = "fleet.peer"
	const target = swarm.NodeID("vl1_live_peer")

	ids := []NodeID{"n00", "n01"}
	nodes := make([]*SwarmNode, len(ids))
	mesh := NewMesh(1)
	for i, id := range ids {
		peers := make([]NodeID, 0, len(ids)-1)
		for _, p := range ids {
			if p != id {
				peers = append(peers, p)
			}
		}
		nodes[i] = NewSwarmNode(id, peers)
		mesh.AddNode(nodes[i])
	}
	for i, n := range nodes {
		for j, peer := range nodes {
			if i != j {
				n.tport.RegisterPeer(ids[j], peer.SwarmNodeID())
			}
		}
	}
	mesh.FullMesh(5, 1, 0)

	// Only n00 attests. n01 receives it but must NOT tombstone on one witness.
	if err := nodes[0].node.PublishObserverTombstone(swarm.Topic(topic), target); err != nil {
		t.Fatalf("attest: %v", err)
	}

	hasTombstone := func(n *SwarmNode) bool {
		for _, r := range n.Records()[topic] {
			if string(r.NodeID) == string(target) && r.Tombstone {
				return true
			}
		}
		return false
	}

	// Let the single attestation propagate as far as it will.
	_, _ = mesh.Run(500, func(m *Mesh) bool { return false })

	for _, n := range nodes {
		if hasTombstone(n) {
			t.Fatalf("node %s tombstoned a target on ONE observer (quorum=%d) — "+
				"a single anchor must never be able to evict a peer",
				n.ID(), swarm.DefaultObserverQuorum)
		}
	}
	for _, n := range nodes {
		n.Stop()
	}
}
