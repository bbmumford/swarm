// Copyright (c) 2026 Brandon Miller-Mumford.
// Licensed under the MIT License; see LICENSE.

package swarm

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	pb "github.com/bbmumford/swarm/proto/pb"
)

// chainOfTreeEdges builds A <-> B <-> C (A and C not connected) with the
// background ticker off, and marks every peer of every node a tree edge, so
// no node has a non-tree peer to lazy-push to or to probe.
func chainOfTreeEdges(t *testing.T) (a, b, c *testNode) {
	t.Helper()
	net := newMemNet()
	privs := make([]ed25519.PrivateKey, 3)
	ids := make([]NodeID, 3)
	for i := range privs {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		privs[i] = priv
		ids[i] = nodeIDFromPub(priv.Public().(ed25519.PublicKey))
	}
	net.link(ids[0], ids[1])
	net.link(ids[1], ids[2])

	mk := func(priv ed25519.PrivateKey) *testNode {
		n, err := New(Config{PrivKey: priv, DisableBackgroundTicker: true, TrustCheck: acceptAllRecords})
		if err != nil {
			t.Fatal(err)
		}
		impl := n.(*nodeImpl)
		if err := Wire(n, net.attach(impl.id)); err != nil {
			t.Fatal(err)
		}
		return &testNode{node: n, impl: impl, priv: priv, id: impl.id}
	}
	a, b, c = mk(privs[0]), mk(privs[1]), mk(privs[2])
	for _, n := range []*testNode{a, b, c} {
		for _, p := range n.impl.peers.All() {
			n.impl.peers.SetTreeEdge(p, true)
		}
		if len(n.impl.peers.NonTreeEdges()) != 0 {
			t.Fatalf("node %.8s still has a non-tree peer", n.id)
		}
	}
	return a, b, c
}

// holdOnly puts a record signed by n into n's store without pushing it,
// the state a node is in when its push of that record was lost.
func holdOnly(t *testing.T, n *testNode, topic Topic, body string) Record {
	t.Helper()
	r := signedRecord(topic, n.priv, n.id, n.impl.hlc.Now(), []byte(body))
	if applied, _ := n.impl.store.Apply(r); !applied {
		t.Fatal("store refused the held record")
	}
	return r
}

func holds(n *testNode, topic Topic, id NodeID) bool {
	_, ok := n.impl.store.getRaw(topic, id)
	return ok
}

// A record B receives only by Merkle repair from A reaches C, whose only
// link is B and who never probes: HandleRange's rumor carries it.
func TestRepairedRecordReachesTheThirdNodeOverTreeEdges(t *testing.T) {
	a, b, c := chainOfTreeEdges(t)
	topic := Topic("t.repair")
	holdOnly(t, a, topic, "repaired")

	// A probes B: B's root differs, so B probes A back and A answers with
	// the range holding the record. No node calls Tick, and C sends nothing.
	a.impl.merkle.ProbePeer(b.id)

	if !waitUntil(t, 5*time.Second, func() bool { return holds(b, topic, a.id) }) {
		t.Fatal("B never received the record by repair")
	}
	if !waitUntil(t, 5*time.Second, func() bool { return holds(c, topic, a.id) }) {
		t.Fatal("C never received the record B applied from a Merkle range")
	}
}

// With every peer a tree edge, a periodic probe still runs: A's Tick
// probes B, and the record A holds unpushed reaches B.
func TestTickProbesATreeEdgePeer(t *testing.T) {
	a, b, _ := chainOfTreeEdges(t)
	topic := Topic("t.tick")
	holdOnly(t, a, topic, "unpushed")

	a.impl.merkle.Tick()

	if !waitUntil(t, 5*time.Second, func() bool { return holds(b, topic, a.id) }) {
		t.Fatal("A's Tick sent no probe to its tree-edge peer B")
	}
}

// A range applied twice starts one rumor: the second application finds the
// record held and applies nothing new.
func TestARecordRepairedTwiceStartsOneRumor(t *testing.T) {
	a, b, _ := chainOfTreeEdges(t)
	topic := Topic("t.once")
	r := holdOnly(t, a, topic, "once")

	var rumors []NodeID
	b.impl.merkle.SetRumor(func(from NodeID, got Record) {
		if got.NodeID != r.NodeID || got.HLC != r.HLC {
			t.Errorf("rumor for %.8s/%d, want %.8s/%d", got.NodeID, got.HLC, r.NodeID, r.HLC)
		}
		rumors = append(rumors, from)
	})
	rng := &pb.MerkleRange{Topic: string(topic), Records: []*pb.Record{recordToProto(r)}}
	b.impl.merkle.HandleRange(a.id, b.impl.hlc, rng)
	b.impl.merkle.HandleRange(a.id, b.impl.hlc, rng)

	if len(rumors) != 1 || rumors[0] != a.id {
		t.Fatalf("rumors started = %v, want exactly one, from %.8s", rumors, a.id)
	}
}
