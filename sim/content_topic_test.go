// Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
// Queries: licensing@hstles.com

package sim

import (
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/bbmumford/swarm"
)

// TestContentTopicHolderConvergence spawns N nodes; each announces one
// hash and the rest see it indexed in their ContentTopic holder map.
func TestContentTopicHolderConvergence(t *testing.T) {
	const numNodes = 8
	mesh := NewMesh(7)

	ids := make([]NodeID, numNodes)
	nodes := make([]*SwarmNode, numNodes)
	for i := 0; i < numNodes; i++ {
		ids[i] = NodeID(fmt.Sprintf("n%02d", i))
	}
	for i, id := range ids {
		peers := make([]NodeID, 0, numNodes-1)
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
			if i == j {
				continue
			}
			n.tport.RegisterPeer(ids[j], peer.SwarmNodeID())
		}
	}
	mesh.FullMesh(5, 2, 0)

	hashes := make([][32]byte, numNodes)
	for i := 0; i < numNodes; i++ {
		hashes[i] = sha256.Sum256([]byte(fmt.Sprintf("blob-%02d", i)))
		ct := nodes[i].node.ContentTopic()
		if err := ct.Announce(hashes[i]); err != nil {
			t.Fatalf("announce %02d: %v", i, err)
		}
	}

	// Each peer should learn about every other peer's hash.
	steps, err := mesh.Run(2000, func(m *Mesh) bool {
		for i := 0; i < numNodes; i++ {
			ct := nodes[i].node.ContentTopic()
			for j := 0; j < numNodes; j++ {
				if i == j {
					continue
				}
				holders := ct.Holders(hashes[j])
				found := false
				for _, h := range holders {
					if h == nodes[j].SwarmNodeID() {
						found = true
						break
					}
				}
				if !found {
					return false
				}
			}
		}
		return true
	})
	if err != nil {
		// Diagnostic dump.
		for i := 0; i < numNodes; i++ {
			ct := nodes[i].node.ContentTopic()
			for j := 0; j < numNodes; j++ {
				if i == j {
					continue
				}
				holders := ct.Holders(hashes[j])
				want := nodes[j].SwarmNodeID()
				found := false
				for _, h := range holders {
					if h == want {
						found = true
						break
					}
				}
				if !found {
					t.Logf("node %d (%s) missing holder %s for hash[%d]; holders=%v",
						i, nodes[i].SwarmNodeID()[:8], string(want)[:8], j, holders)
				}
			}
		}
		t.Fatalf("convergence failed at step %d: %v", steps, err)
	}
	t.Logf("ContentTopic holder convergence reached in %d ticks", steps)

	// Spot-check withdrawal: node 0 withdraws, others should see it gone
	// after a few more ticks of propagation.
	if err := nodes[0].node.ContentTopic().Withdraw(hashes[0]); err != nil {
		t.Fatalf("withdraw: %v", err)
	}
	steps2, err := mesh.Run(2000, func(m *Mesh) bool {
		ct := nodes[1].node.ContentTopic()
		for _, h := range ct.Holders(hashes[0]) {
			if h == nodes[0].SwarmNodeID() {
				return false
			}
		}
		return true
	})
	if err != nil {
		t.Fatalf("withdrawal not propagated within %d extra ticks: %v", steps2, err)
	}
	t.Logf("Withdrawal propagated in %d additional ticks", steps2)

	for _, n := range nodes {
		n.Stop()
	}

	_ = swarm.ErrNoHolders // sanity reference
}
