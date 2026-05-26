// Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
// Queries: licensing@hstles.com

package sim

import (
	"fmt"
	"testing"
)

// TestColdStartConvergence spawns N flooding StubNodes, has each publish
// one record, and asserts every node sees every record within T virtual
// ticks. The matching test against the real Plumtrees + δ-CRDT engine
// lives in TestSwarmNode_ColdStartConvergence.
func TestColdStartConvergence(t *testing.T) {
	for _, tc := range []struct {
		name       string
		numNodes   int
		latencyMs  int
		jitterMs   int
		lossPct    float64
		maxSteps   int
	}{
		{name: "8_nodes_lan", numNodes: 8, latencyMs: 5, jitterMs: 2, lossPct: 0, maxSteps: 500},
		{name: "32_nodes_wan", numNodes: 32, latencyMs: 30, jitterMs: 10, lossPct: 0, maxSteps: 2000},
		{name: "32_nodes_lossy", numNodes: 32, latencyMs: 30, jitterMs: 10, lossPct: 0.05, maxSteps: 5000},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mesh := NewMesh(42)

			// Each StubNode flood-forwards with payload dedup, so full
			// peer-list awareness is fine. The real Plumtrees engine
			// instead uses a small tree-edge subset.
			ids := make([]NodeID, tc.numNodes)
			for i := 0; i < tc.numNodes; i++ {
				ids[i] = NodeID(fmt.Sprintf("n%02d", i))
			}
			for _, id := range ids {
				peers := make([]NodeID, 0, len(ids)-1)
				for _, p := range ids {
					if p != id {
						peers = append(peers, p)
					}
				}
				mesh.AddNode(NewStubNode(id, peers))
			}

			// Full-mesh edges with configured link properties.
			mesh.FullMesh(tc.latencyMs, tc.jitterMs, tc.lossPct)

			// Each node publishes one record on a shared topic.
			for _, id := range ids {
				stub, ok := mesh.nodes[id].(*StubNode)
				if !ok {
					t.Fatalf("node %s is not a StubNode", id)
				}
				stub.Publish("test.topic", 1, []byte(fmt.Sprintf("hello from %s", id)))
			}

			// Run until everyone has seen everyone's record (convergence).
			steps, err := mesh.Run(tc.maxSteps, func(m *Mesh) bool {
				return everyoneHasEverything(m, "test.topic", tc.numNodes)
			})
			if err != nil {
				dumpConvergence(t, mesh, "test.topic", tc.numNodes)
				t.Fatalf("did not converge within %d steps (final at %d): %v", tc.maxSteps, steps, err)
			}
			t.Logf("converged in %d virtual ticks (%v wall-equivalent)", steps, VirtualTime(steps).Duration())
		})
	}
}

func everyoneHasEverything(m *Mesh, topic string, expected int) bool {
	m.mu.Lock()
	nodes := make([]Node, 0, len(m.nodes))
	for _, n := range m.nodes {
		nodes = append(nodes, n)
	}
	m.mu.Unlock()
	for _, n := range nodes {
		recs := n.Records()[topic]
		if len(recs) != expected {
			return false
		}
	}
	return true
}

func dumpConvergence(t *testing.T, mesh *Mesh, topic string, expected int) {
	t.Helper()
	mesh.mu.Lock()
	defer mesh.mu.Unlock()
	for id, n := range mesh.nodes {
		recs := n.Records()[topic]
		t.Logf("  %s has %d/%d records", id, len(recs), expected)
	}
}

// TestStepSummary smoke-tests the simulator's basic step semantics.
func TestStepSummary(t *testing.T) {
	mesh := NewMesh(1)

	a := NewStubNode("a", []NodeID{"b"})
	b := NewStubNode("b", []NodeID{"a"})
	mesh.AddNode(a)
	mesh.AddNode(b)
	mesh.AddEdge(Edge{From: "a", To: "b", LatencyMs: 10})
	mesh.AddEdge(Edge{From: "b", To: "a", LatencyMs: 10})

	a.Publish("hi", 1, []byte("ping"))

	// Step 1: a sends; nothing delivered yet (latency = 10ms)
	s1, _ := mesh.Step()
	if s1.FramesSent != 1 {
		t.Errorf("step1 FramesSent: got %d want 1", s1.FramesSent)
	}
	if s1.FramesDelivered != 0 {
		t.Errorf("step1 FramesDelivered: got %d want 0", s1.FramesDelivered)
	}

	// Step 1 enqueued the frame for delivery at now+10 = 11. Run until step 11.
	for i := 0; i < 10; i++ {
		_, _ = mesh.Step()
	}

	// By step 11, frame should be delivered.
	if got := len(b.Records()["hi"]); got != 1 {
		t.Errorf("b records[hi]: got %d want 1 (at step %d)", got, mesh.Now())
	}
}
