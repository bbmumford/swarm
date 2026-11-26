// Copyright (c) 2026 Brandon Miller-Mumford.
// Licensed under the MIT License; see LICENSE.

package swarm

import (
	"crypto/ed25519"
	"crypto/rand"
	"sync"
	"testing"
	"time"
)

// collector records what a subscriber was handed.
type collector struct {
	mu   sync.Mutex
	got  []Record
	seen chan struct{}
}

func newCollector() *collector { return &collector{seen: make(chan struct{}, 64)} }

func (c *collector) sub(r Record) error {
	c.mu.Lock()
	c.got = append(c.got, r)
	c.mu.Unlock()
	c.seen <- struct{}{}
	return nil
}

func (c *collector) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.got)
}

// lineOfThree starts a, b and c, then links them a - b - c.
func lineOfThree(t *testing.T) (*memNet, *testNode, *testNode, *testNode) {
	t.Helper()
	net := newMemNet()
	a := startNode(t, net, Config{})
	b := startNode(t, net, Config{})
	c := startNode(t, net, Config{})
	net.link(a.id, b.id)
	net.link(b.id, c.id)
	// The nodes met while the net was a full mesh, so a still lists c as a
	// peer, but from here a frame between a and c is dropped: c can only
	// hear a through b.
	return net, a, b, c
}

// TestBroadcastReachesEverySubscriberOnceAndIsNeverStored: a broadcast from a
// crosses b to c's subscriber exactly once, and no node's store holds it.
func TestBroadcastReachesEverySubscriberOnceAndIsNeverStored(t *testing.T) {
	_, a, b, c := lineOfThree(t)
	col := newCollector()
	if _, err := c.node.Subscribe("chat.typing", col.sub); err != nil {
		t.Fatal(err)
	}
	if err := a.node.(Broadcaster).Broadcast("chat.typing", []byte("a is typing")); err != nil {
		t.Fatalf("Broadcast: %v", err)
	}
	if !waitUntil(t, 2*time.Second, func() bool { return col.count() >= 1 }) {
		t.Fatal("c's subscriber never received the broadcast")
	}
	time.Sleep(200 * time.Millisecond) // room for a duplicate to arrive
	if n := col.count(); n != 1 {
		t.Fatalf("c's subscriber received the broadcast %d times, want once", n)
	}
	r := col.got[0]
	if !r.Broadcast || string(r.Body) != "a is typing" || r.NodeID != a.id {
		t.Fatalf("delivered record: %+v", r)
	}
	for _, n := range []*testNode{a, b, c} {
		if recs := n.node.TopicRecords("chat.typing"); len(recs) != 0 {
			t.Fatalf("%s stored a broadcast: %v", n.id, recs)
		}
	}
}

// signedBroadcast builds a broadcast signed by a fresh key whose NodeID binds it.
func signedBroadcast(t *testing.T, topic Topic, body []byte) Record {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	r := Record{Topic: topic, NodeID: nodeIDFromPub(pub), HLC: NewHLC().Now(), Body: body, Broadcast: true}
	signRecord(&r, priv)
	return r
}

// TestBroadcastIsDeliveredOnceWhenReplayed: the same broadcast frame arriving
// twice (two paths, or a replay) reaches the subscriber once.
func TestBroadcastIsDeliveredOnceWhenReplayed(t *testing.T) {
	net := newMemNet()
	n := startNode(t, net, Config{})
	col := newCollector()
	if _, err := n.node.Subscribe("chat.typing", col.sub); err != nil {
		t.Fatal(err)
	}
	r := signedBroadcast(t, "chat.typing", []byte("x"))
	inject(t, net, n, r.NodeID, r)
	inject(t, net, n, r.NodeID, r)
	waitUntil(t, time.Second, func() bool { return col.count() >= 1 })
	time.Sleep(100 * time.Millisecond)
	if got := col.count(); got != 1 {
		t.Fatalf("a replayed broadcast was delivered %d times, want once", got)
	}
}

// TestBroadcastFlagIsSigned: stripping the broadcast flag from a signed
// broadcast (so a node would store it) breaks its signature, so it is dropped.
func TestBroadcastFlagIsSigned(t *testing.T) {
	net := newMemNet()
	n := startNode(t, net, Config{})
	r := signedBroadcast(t, "chat.typing", []byte("x"))
	r.Broadcast = false
	inject(t, net, n, r.NodeID, r)
	time.Sleep(100 * time.Millisecond)
	if recs := n.node.TopicRecords("chat.typing"); len(recs) != 0 {
		t.Fatalf("a broadcast relabelled as a stored record was admitted: %v", recs)
	}
	if verifyRecord(r, r.PubKey) {
		t.Fatal("the signature still verifies with the broadcast flag stripped")
	}
}
