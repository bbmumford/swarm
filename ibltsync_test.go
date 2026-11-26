// Copyright (c) 2026 Brandon Miller-Mumford.
// Licensed under the MIT License; see LICENSE.

package swarm

import (
	"crypto/ed25519"
	"crypto/rand"
	"sync/atomic"
	"testing"
	"time"

	pb "github.com/bbmumford/swarm/proto/pb"
)

// repairCounts counts what reaches one node: the records MerkleRange frames
// carry, and the sketches.
type repairCounts struct{ records, sketches atomic.Int64 }

// countRepair wraps n's receive hook so every frame it is handed is counted
// before the node handles it.
func countRepair(t *testing.T, net *memNet, n *testNode) *repairCounts {
	t.Helper()
	c := &repairCounts{}
	net.mu.Lock()
	port := net.ports[n.id]
	net.mu.Unlock()
	port.mu.Lock()
	inner := port.onRecv
	port.onRecv = func(from NodeID, raw []byte) {
		if f, err := decodeFrame(raw); err == nil {
			switch k := f.Kind.(type) {
			case *pb.Frame_MerkleRange:
				c.records.Add(int64(len(k.MerkleRange.Records)))
			case *pb.Frame_IbltSketch:
				c.sketches.Add(1)
			}
		}
		inner(from, raw)
	}
	port.mu.Unlock()
	return c
}

// freshRecords signs n records on topic, each by its own key, as n distinct
// publishers would.
func freshRecords(t *testing.T, topic Topic, n int) []Record {
	t.Helper()
	clock := NewHLC()
	out := make([]Record, n)
	for i := range out {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		out[i] = signedRecord(topic, priv, nodeIDFromPub(pub), clock.Now(), []byte("addr"))
	}
	return out
}

// repairPair starts two nodes that probe only when told to, holding the
// given records on topic.
func repairPair(t *testing.T, topic Topic, aRecs, bRecs []Record) (*memNet, *testNode, *testNode) {
	t.Helper()
	net := newMemNet()
	cfg := Config{MerkleProbeInterval: time.Hour, DisableBackgroundTicker: true}
	a := startNode(t, net, cfg)
	b := startNode(t, net, cfg)
	for _, r := range aRecs {
		a.impl.store.Apply(r)
	}
	for _, r := range bRecs {
		b.impl.store.Apply(r)
	}
	return net, a, b
}

func holding(n *testNode, topic Topic, want int) func() bool {
	return func() bool { return len(n.impl.store.topicRecordsSigned(topic)) == want }
}

// TestSketchRepairMovesOnlyTheDifference: two copies of a 300-record topic
// that differ in 35 records converge by moving those 35, not the topic.
func TestSketchRepairMovesOnlyTheDifference(t *testing.T) {
	const topic = Topic("fleet.peer")
	common, aOnly, bOnly := freshRecords(t, topic, 300), freshRecords(t, topic, 20), freshRecords(t, topic, 15)
	net, a, b := repairPair(t, topic, append(append([]Record(nil), common...), aOnly...), append(append([]Record(nil), common...), bOnly...))
	ca, cb := countRepair(t, net, a), countRepair(t, net, b)

	a.impl.merkle.ProbePeer(b.id)
	if !waitUntil(t, 5*time.Second, func() bool { return holding(a, topic, 335)() && holding(b, topic, 335)() }) {
		t.Fatalf("not converged: a holds %d, b holds %d, want 335 each", len(a.impl.store.topicRecordsSigned(topic)), len(b.impl.store.topicRecordsSigned(topic)))
	}
	if moved := ca.records.Load() + cb.records.Load(); moved > 2*35 {
		t.Fatalf("repairing a 35-record difference moved %d records (a received %d, b %d)", moved, ca.records.Load(), cb.records.Load())
	}
}

// TestSketchRepairGrowsTheSketch: an 800-record difference does not decode
// in 128 or 512 cells; the prober asks again four times larger each time and
// the 2048-cell sketch decodes, still moving only the difference.
func TestSketchRepairGrowsTheSketch(t *testing.T) {
	const topic = Topic("fleet.peer")
	common := freshRecords(t, topic, 100)
	net, a, b := repairPair(t, topic, append(append([]Record(nil), common...), freshRecords(t, topic, 400)...), append(append([]Record(nil), common...), freshRecords(t, topic, 400)...))
	ca, cb := countRepair(t, net, a), countRepair(t, net, b)

	a.impl.merkle.ProbePeer(b.id)
	if !waitUntil(t, 10*time.Second, func() bool { return holding(a, topic, 900)() && holding(b, topic, 900)() }) {
		t.Fatalf("not converged: a holds %d, b holds %d, want 900 each", len(a.impl.store.topicRecordsSigned(topic)), len(b.impl.store.topicRecordsSigned(topic)))
	}
	if got := ca.sketches.Load(); got != 3 {
		t.Fatalf("a received %d sketches, want 3 (128, 512, 2048 cells)", got)
	}
	if moved := ca.records.Load() + cb.records.Load(); moved > 800 {
		t.Fatalf("an 800-record difference moved %d records", moved)
	}
}

// TestSketchRepairFallsBackToRecords: a 4000-record difference is past every
// sketch; after the 2048-cell one fails the topic is probed for records, and
// records start to move. (How classic range repair then completes is not this
// test's subject.)
func TestSketchRepairFallsBackToRecords(t *testing.T) {
	const topic = Topic("fleet.peer")
	net, a, b := repairPair(t, topic, freshRecords(t, topic, 2000), freshRecords(t, topic, 2000))
	ca, cb := countRepair(t, net, a), countRepair(t, net, b)

	a.impl.merkle.ProbePeer(b.id)
	if !waitUntil(t, 30*time.Second, func() bool { return ca.records.Load()+cb.records.Load() > 0 }) {
		t.Fatalf("no records moved after the sketches failed (a received %d sketches)", ca.sketches.Load())
	}
	if got := ca.sketches.Load(); got != 3 {
		t.Fatalf("a received %d sketches before falling back, want 3", got)
	}
}

// TestSketchIsDeclinedForALargeCountGap: a responder that holds nothing of a
// 300-record topic cannot be decoded against in 128 cells (the difference is
// at least the 300-record gap), so it answers with records at once and sends
// no sketch.
func TestSketchIsDeclinedForALargeCountGap(t *testing.T) {
	const topic = Topic("fleet.peer")
	net, a, b := repairPair(t, topic, freshRecords(t, topic, 300), nil)
	ca, cb := countRepair(t, net, a), countRepair(t, net, b)

	a.impl.merkle.ProbePeer(b.id)
	if !waitUntil(t, 10*time.Second, func() bool { return cb.records.Load() > 0 }) {
		t.Fatal("the empty responder's records answer never brought a's records")
	}
	if got := ca.sketches.Load(); got != 0 {
		t.Fatalf("an empty responder sent %d sketches, want none", got)
	}
}

// TestUnaskedSketchIsDropped: a sketch this node never asked for is not
// decoded, so a peer cannot make it hash a topic and push the records the
// sketch says the peer lacks.
func TestUnaskedSketchIsDropped(t *testing.T) {
	const topic = Topic("fleet.peer")
	net, a, b := repairPair(t, topic, freshRecords(t, topic, 50), nil)
	cb := countRepair(t, net, b)
	frame, err := encodeFrame(&pb.Frame{Kind: &pb.Frame_IbltSketch{IbltSketch: &pb.IBLTSketch{
		Topic: string(topic), Cells: zeroCells(ibltFirstCells), K: ibltK, Seed: 7,
	}}})
	if err != nil {
		t.Fatal(err)
	}
	net.mu.Lock()
	port := net.ports[a.id]
	net.mu.Unlock()
	port.mu.Lock()
	recv := port.onRecv
	port.mu.Unlock()
	recv(b.id, frame)
	time.Sleep(200 * time.Millisecond)
	if got := cb.records.Load(); got != 0 {
		t.Fatalf("an unasked sketch made a push %d records", got)
	}
}

func zeroCells(n int) []*pb.IBLTCell {
	out := make([]*pb.IBLTCell, n)
	for i := range out {
		out[i] = &pb.IBLTCell{KeySum: make([]byte, 16)}
	}
	return out
}
