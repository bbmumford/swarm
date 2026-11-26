// Copyright (c) 2026 Brandon Miller-Mumford.
// Licensed under the MIT License; see LICENSE.

package swarm

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"sync/atomic"
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

// A range that repeats versions this node already holds is not verified and
// admitted again: Apply refuses a held or older version whatever it carries,
// and when both sides answer each probe with records the other holds, checking
// those again is the work that starves the records still missing. A newer
// version of a held slot, and a slot not held, are still admitted.
func TestHandleRangeAdmitsAHeldVersionOnce(t *testing.T) {
	var admitted atomic.Int64
	net := newMemNet()
	b := startNode(t, net, Config{TrustCheck: func(Record) error { admitted.Add(1); return nil }})
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := nodeIDFromPub(priv.Public().(ed25519.PublicKey))
	topic := Topic("t.held")
	keyedBody := func(key string, hlc uint64, body string) Record {
		r := Record{Topic: topic, NodeID: id, Key: key, HLC: hlc, Body: []byte(body)}
		signRecord(&r, priv)
		return r
	}
	keyed := func(key string, hlc uint64) Record { return keyedBody(key, hlc, key) }
	now := b.impl.hlc.Now()
	var recs []*pb.Record
	for i := 0; i < 10; i++ {
		recs = append(recs, recordToProto(keyed(fmt.Sprintf("k-%02d", i), now+uint64(i))))
	}
	rng := &pb.MerkleRange{Topic: string(topic), Records: recs}

	b.impl.merkle.HandleRange(id, b.impl.hlc, rng)
	if got := admitted.Load(); got != 10 {
		t.Fatalf("first range: %d records admitted, want 10", got)
	}
	if got := len(b.node.NodeRecords(topic, id)); got != 10 {
		t.Fatalf("first range: %d records held, want 10", got)
	}

	b.impl.merkle.HandleRange(id, b.impl.hlc, rng)
	if got := admitted.Load() - 10; got != 0 {
		t.Fatalf("a range of held versions was admitted %d more times, want none", got)
	}

	older := &pb.MerkleRange{Topic: string(topic), Records: []*pb.Record{recordToProto(keyed("k-05", now))}}
	b.impl.merkle.HandleRange(id, b.impl.hlc, older)
	if got := admitted.Load() - 10; got != 0 {
		t.Fatalf("an older version of a held slot was admitted %d times, want none", got)
	}

	// The same HLC under another signature is a rival version the tie-break
	// decides, so it is checked and admitted.
	tie := &pb.MerkleRange{Topic: string(topic), Records: []*pb.Record{recordToProto(keyedBody("k-03", now+3, "rival"))}}
	b.impl.merkle.HandleRange(id, b.impl.hlc, tie)
	if got := admitted.Load() - 10; got != 1 {
		t.Fatalf("a rival version at a held HLC: %d admitted, want 1", got)
	}

	fresh := &pb.MerkleRange{Topic: string(topic), Records: []*pb.Record{
		recordToProto(keyed("k-05", now+100)), recordToProto(keyed("k-new", now+101)),
	}}
	b.impl.merkle.HandleRange(id, b.impl.hlc, fresh)
	if got := admitted.Load() - 11; got != 2 {
		t.Fatalf("a newer version and a new slot: %d admitted, want 2", got)
	}
	if r, ok := b.node.GetKeyed(topic, id, "k-05"); !ok || r.HLC != now+100 {
		t.Fatalf("k-05 after the newer version: held=%v hlc=%d, want %d", ok, r.HLC, now+100)
	}

	// An observer attestation accumulates per observer instead of replacing its
	// target's slot, so a newer owner record held there does not make it held.
	_, obsPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	obs := nodeIDFromPub(obsPriv.Public().(ed25519.PublicKey))
	ownerHLC := b.impl.hlc.Now()
	owner := Record{Topic: Topic("fleet.peer"), NodeID: id, HLC: ownerHLC, Body: []byte("alive")}
	signRecord(&owner, priv)
	if applied, _ := b.impl.store.Apply(owner); !applied {
		t.Fatal("store refused the owner record")
	}
	before := admitted.Load()
	att := observerAttestation(t, obsPriv, obs, id, ownerHLC-1)
	b.impl.merkle.HandleRange(obs, b.impl.hlc, &pb.MerkleRange{Topic: "fleet.peer", Records: []*pb.Record{recordToProto(att)}})
	if got := admitted.Load() - before; got != 1 {
		t.Fatalf("an attestation about a node whose newer record is held: %d admitted, want 1", got)
	}
}
