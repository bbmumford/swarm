// Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
// Queries: licensing@hstles.com

package sim

import (
	"fmt"
	"testing"
)

// TestSwarmNode_ColdStartConvergence asserts the real Plumtrees + δ-CRDT
// + signed-Record engine converges from cold start within bounded
// virtual ticks. Mirrors TestColdStartConvergence but runs SwarmNodes
// instead of flooding StubNodes.
func TestSwarmNode_ColdStartConvergence(t *testing.T) {
	for _, tc := range []struct {
		name      string
		numNodes  int
		latencyMs int
		jitterMs  int
		lossPct   float64
		maxSteps  int
	}{
		{name: "8_nodes_lan", numNodes: 8, latencyMs: 5, jitterMs: 2, lossPct: 0, maxSteps: 3000},
		{name: "32_nodes_wan", numNodes: 32, latencyMs: 30, jitterMs: 10, lossPct: 0, maxSteps: 5000},
		{name: "16_nodes_lossy", numNodes: 16, latencyMs: 30, jitterMs: 10, lossPct: 0.05, maxSteps: 8000},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mesh := NewMesh(42)

			// Create N SwarmNodes, each with a fresh Ed25519 keypair.
			ids := make([]NodeID, tc.numNodes)
			swarmNodes := make([]*SwarmNode, tc.numNodes)
			for i := 0; i < tc.numNodes; i++ {
				ids[i] = NodeID(fmt.Sprintf("n%02d", i))
			}
			for i, id := range ids {
				peers := make([]NodeID, 0, len(ids)-1)
				for _, p := range ids {
					if p != id {
						peers = append(peers, p)
					}
				}
				swarmNodes[i] = NewSwarmNode(id, peers)
				mesh.AddNode(swarmNodes[i])
			}

			// Cross-register each node's transport with the swarmIDs of
			// its peers so simTransport.Send can route by swarmID.
			for i, n := range swarmNodes {
				for j, peer := range swarmNodes {
					if i == j {
						continue
					}
					n.tport.RegisterPeer(ids[j], peer.SwarmNodeID())
				}
			}

			// Full-mesh edges between simulated peers.
			mesh.FullMesh(tc.latencyMs, tc.jitterMs, tc.lossPct)

			// Each node publishes a record on a shared topic.
			for i, n := range swarmNodes {
				n.Publish("test.topic", 1, []byte(fmt.Sprintf("hello from %s", ids[i])))
			}

			// Run until everyone has seen everyone's record.
			steps, err := mesh.Run(tc.maxSteps, func(m *Mesh) bool {
				return everyoneHasEverything(m, "test.topic", tc.numNodes)
			})
			if err != nil {
				dumpConvergence(t, mesh, "test.topic", tc.numNodes)
				t.Fatalf("did not converge within %d steps (final at %d): %v", tc.maxSteps, steps, err)
			}
			t.Logf("converged in %d virtual ticks (%v wall-equivalent)", steps, VirtualTime(steps).Duration())

			// Cleanup: stop background goroutines so the test binary exits cleanly.
			for _, n := range swarmNodes {
				n.Stop()
			}
		})
	}
}
