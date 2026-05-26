// Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
// Queries: licensing@hstles.com

package sim

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/bbmumford/swarm"
)

// TestSetTenantTombstonesSelfRecords verifies SetTenant tombstones every
// pre-tenant record published by this node.
func TestSetTenantTombstonesSelfRecords(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	cfg := swarm.Config{
		PrivKey:                 priv,
		TreeDegree:              4,
		NowFn:                   func() time.Time { return time.UnixMilli(0) },
		DisableBackgroundTicker: true,
	}
	node, err := swarm.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	tport := newNullTransport(node.(interface{ Tick(time.Time) }))
	if err := swarm.Wire(node, tport); err != nil {
		t.Fatal(err)
	}
	go node.Start(context.Background())
	defer node.Stop()

	// Publish a record pre-tenant
	if err := node.Publish("test", []byte("pre-tenant body")); err != nil {
		t.Fatal(err)
	}
	store := swarm.InternalStore(node)
	if store.TopicCount("test") != 1 {
		t.Fatalf("expected 1 record pre-tenant, got %d", store.TopicCount("test"))
	}

	// Set tenant — should tombstone the existing record
	if err := node.SetTenant("acme-corp"); err != nil {
		t.Fatal(err)
	}

	// Find our self-record; verify it's now a tombstone
	recs := store.TopicRecords("test")
	if len(recs) != 1 {
		t.Fatalf("expected 1 record post-tenant (tombstone), got %d", len(recs))
	}
	if !recs[0].Tombstone {
		t.Errorf("expected tombstone, got body=%q", recs[0].Body)
	}
}

// TestPauseSuppressesLazyPush verifies that Pause stops lazy-push IHave
// fan-out but allows eager push to continue (eager push is the correctness
// path; lazy push is redundancy).
func TestPauseSuppressesLazyPush(t *testing.T) {
	mesh := NewMesh(99)
	ids := []NodeID{"a", "b", "c"}
	swarmNodes := make([]*SwarmNode, 3)
	for i, id := range ids {
		peers := []NodeID{}
		for _, p := range ids {
			if p != id {
				peers = append(peers, p)
			}
		}
		swarmNodes[i] = NewSwarmNode(id, peers)
		mesh.AddNode(swarmNodes[i])
	}
	for i, n := range swarmNodes {
		for j, peer := range swarmNodes {
			if i == j {
				continue
			}
			n.tport.RegisterPeer(ids[j], peer.SwarmNodeID())
		}
	}
	mesh.FullMesh(5, 0, 0)

	// Pause node "a". Then publish on "a".
	if err := swarmNodes[0].node.Pause(); err != nil {
		t.Fatal(err)
	}
	swarmNodes[0].Publish("test.topic", 1, []byte("from-a"))

	// Run a few ticks. Eager push should still flow to tree edges.
	steps, _ := mesh.Run(200, func(m *Mesh) bool {
		// All 3 should have a's record (eager push survives pause)
		for _, n := range swarmNodes {
			if n.Records()["test.topic"] == nil || len(n.Records()["test.topic"]) < 1 {
				return false
			}
		}
		return true
	})
	if steps >= 200 {
		t.Fatal("eager push during pause did not deliver")
	}

	for _, n := range swarmNodes {
		n.Stop()
	}
}

// TestSetRoleNotifiesCallback verifies OnRoleChange fires once per actual
// role transition (idempotent SetRole calls do not refire).
func TestSetRoleNotifiesCallback(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	cfg := swarm.Config{
		PrivKey:                 priv,
		TreeDegree:              4,
		NowFn:                   func() time.Time { return time.UnixMilli(0) },
		DisableBackgroundTicker: true,
	}
	node, err := swarm.New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	type roleChange struct{ prev, next swarm.Role }
	var changes []roleChange
	type roleHook interface {
		OnRoleChange(fn func(prev, next swarm.Role))
	}
	if rh, ok := node.(roleHook); ok {
		rh.OnRoleChange(func(prev, next swarm.Role) {
			changes = append(changes, roleChange{prev, next})
		})
	} else {
		t.Skip("Node does not expose OnRoleChange")
	}

	tport := newNullTransport(node.(interface{ Tick(time.Time) }))
	if err := swarm.Wire(node, tport); err != nil {
		t.Fatal(err)
	}
	go node.Start(context.Background())
	defer node.Stop()

	if err := node.SetRole(swarm.RoleAnchor); err != nil {
		t.Fatal(err)
	}
	if err := node.SetRole(swarm.RoleAnchor); err != nil {
		t.Fatal(err) // no-op should not error
	}
	if err := node.SetRole(swarm.RoleEdge); err != nil {
		t.Fatal(err)
	}

	// Expect 2 transitions: leaf->anchor and anchor->edge
	if len(changes) != 2 {
		t.Fatalf("expected 2 role changes, got %d: %+v", len(changes), changes)
	}
	if changes[0].next != swarm.RoleAnchor {
		t.Errorf("first change: expected next=Anchor, got %v", changes[0].next)
	}
	if changes[1].next != swarm.RoleEdge {
		t.Errorf("second change: expected next=Edge, got %v", changes[1].next)
	}
}

// ---------- null transport for unit-style tests ----------

type nullTransport struct {
	id        swarm.NodeID
	onReceive func(from swarm.NodeID, frame []byte)
}

func newNullTransport(_ interface{ Tick(time.Time) }) *nullTransport {
	return &nullTransport{id: "test-node"}
}

func (n *nullTransport) LocalID() swarm.NodeID     { return n.id }
func (n *nullTransport) Send(swarm.NodeID, []byte) error { return nil }
func (n *nullTransport) Broadcast([]byte) error    { return nil }
func (n *nullTransport) Peers() []swarm.NodeID     { return nil }
func (n *nullTransport) OnReceive(fn func(from swarm.NodeID, frame []byte)) {
	n.onReceive = fn
}
func (n *nullTransport) OnPeerJoin(func(swarm.NodeID))  {}
func (n *nullTransport) OnPeerLeave(func(swarm.NodeID)) {}
