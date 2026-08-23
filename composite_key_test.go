// Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
// Queries: licensing@hstles.com

package swarm

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"runtime"
	"sync"
	"testing"
	"time"

	pb "github.com/bbmumford/swarm/proto/pb"
)

// ---------- Blocker 7: composite record keys ----------
//
// Phase-0.5 release blocker 7 of the loom plan: "Composite record keys are
// required for multiple latency observations/content holdings per node."
// Pre-hardening the store was keyed by (topic, nodeID) alone and each node
// slot held at most one record, so a node could publish exactly one fact per
// topic. These tests pin the four properties that make the composite key
// safe rather than merely present.

// legacySignableBytes is an INDEPENDENT re-implementation of the canonical
// signing encoding as it stood BEFORE Record.Key existed. It exists so
// TestKeylessRecordSignableBytesUnchanged compares signableBytes against a
// separately-written oracle rather than against itself — comparing the
// implementation to its own output would pass no matter what the encoding
// did, which is the whole risk being tested.
//
// Do not refactor this to call signableBytes. Its value is that it does not.
func legacySignableBytes(r Record) []byte {
	topic := []byte(r.Topic)
	observer := []byte(r.ObserverNodeID)
	var buf []byte

	var tlen [2]byte
	binary.BigEndian.PutUint16(tlen[:], uint16(len(topic)))
	buf = append(buf, tlen[:]...)
	buf = append(buf, topic...)
	buf = append(buf, []byte(r.NodeID)...)

	var hlcb [8]byte
	binary.BigEndian.PutUint64(hlcb[:], r.HLC)
	buf = append(buf, hlcb[:]...)

	if r.Tombstone {
		buf = append(buf, 1)
	} else {
		buf = append(buf, 0)
	}

	var blen [4]byte
	binary.BigEndian.PutUint32(blen[:], uint32(len(r.Body)))
	buf = append(buf, blen[:]...)
	buf = append(buf, r.Body...)
	buf = append(buf, r.PubKey...)

	var olen [2]byte
	binary.BigEndian.PutUint16(olen[:], uint16(len(observer)))
	buf = append(buf, olen[:]...)
	buf = append(buf, observer...)

	var oat [8]byte
	binary.BigEndian.PutUint64(oat[:], uint64(r.ObservedAtUnixMs))
	buf = append(buf, oat[:]...)

	return buf
}

// (b) The composite key must not invalidate a single existing signature.
// Every record in the fleet today has Key == "", so for those records the
// canonical signing bytes must be EXACTLY what they were — otherwise the
// change forces a coordinated fresh-mesh redeploy to re-sign the world.
func TestKeylessRecordSignableBytesUnchanged(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := nodeIDFromPub(pub)

	cases := []struct {
		name string
		rec  Record
	}{
		{"live", Record{Topic: "t.a", NodeID: id, HLC: 42, Body: []byte("payload")}},
		{"empty body", Record{Topic: "t.a", NodeID: id, HLC: 7}},
		{"owner tombstone", Record{Topic: "t.a", NodeID: id, HLC: 9, Tombstone: true}},
		{"observer attestation", Record{
			Topic: "t.a", NodeID: id, HLC: 11, Tombstone: true,
			ObserverNodeID: id, ObservedAtUnixMs: 1234567890,
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := tc.rec
			signRecord(&r, priv)
			got := signableBytes(r)
			want := legacySignableBytes(r)
			if len(got) != len(want) {
				t.Fatalf("length drift: got %d bytes, legacy encoding produced %d — "+
					"every existing signature in the fleet just became invalid", len(got), len(want))
			}
			for i := range want {
				if got[i] != want[i] {
					t.Fatalf("byte %d differs: got %#x want %#x", i, got[i], want[i])
				}
			}
			// And the signature must still verify, which is the property the
			// byte comparison exists to protect.
			if !verifyRecord(r, pub) {
				t.Fatal("keyless record no longer verifies against its own signature")
			}
		})
	}
}

// A keyed record's canonical bytes must EXTEND the legacy encoding rather
// than reshape it: same prefix, plus a length-prefixed key suffix. That is
// what makes the suffix unambiguous, and therefore what makes (c) hold.
func TestKeyedRecordExtendsLegacyEncoding(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := nodeIDFromPub(pub)

	keyed := Record{Topic: "t.a", NodeID: id, HLC: 42, Body: []byte("payload"), Key: "peer-7"}
	signRecord(&keyed, priv)

	keyless := keyed
	keyless.Key = ""
	prefix := legacySignableBytes(keyless)

	got := signableBytes(keyed)
	if len(got) != len(prefix)+2+len("peer-7") {
		t.Fatalf("keyed encoding is %d bytes, want legacy prefix (%d) + 2 + %d",
			len(got), len(prefix), len("peer-7"))
	}
	for i := range prefix {
		if got[i] != prefix[i] {
			t.Fatalf("keyed encoding diverges from the legacy prefix at byte %d", i)
		}
	}
	suffix := got[len(prefix):]
	if n := binary.BigEndian.Uint16(suffix[:2]); int(n) != len("peer-7") {
		t.Fatalf("key length prefix = %d, want %d", n, len("peer-7"))
	}
	if string(suffix[2:]) != "peer-7" {
		t.Fatalf("key suffix = %q, want %q", suffix[2:], "peer-7")
	}
}

// (c) A record must not be movable between keys. This is the security
// property: without it, an attacker could take a node's peer-scoped latency
// observation and re-label it as the node's canonical keyless record (or as
// another peer's), relocating a signed fact to a slot its author never
// authorised.
func TestKeySubstitutionInvalidatesSignature(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := nodeIDFromPub(pub)

	t.Run("keyed to keyless", func(t *testing.T) {
		r := Record{Topic: "t.a", NodeID: id, HLC: 42, Body: []byte("b"), Key: "peer-7"}
		signRecord(&r, priv)
		if !verifyRecord(r, pub) {
			t.Fatal("control failed: the keyed record does not verify as signed")
		}
		stripped := r
		stripped.Key = ""
		if verifyRecord(stripped, pub) {
			t.Fatal("stripping the key kept the signature valid — a keyed record " +
				"can be promoted into the node's canonical slot")
		}
	})

	t.Run("keyless to keyed", func(t *testing.T) {
		r := Record{Topic: "t.a", NodeID: id, HLC: 42, Body: []byte("b")}
		signRecord(&r, priv)
		if !verifyRecord(r, pub) {
			t.Fatal("control failed: the keyless record does not verify as signed")
		}
		relabelled := r
		relabelled.Key = "peer-7"
		if verifyRecord(relabelled, pub) {
			t.Fatal("adding a key kept the signature valid")
		}
	})

	t.Run("key to different key", func(t *testing.T) {
		r := Record{Topic: "t.a", NodeID: id, HLC: 42, Body: []byte("b"), Key: "peer-7"}
		signRecord(&r, priv)
		moved := r
		moved.Key = "peer-8"
		if verifyRecord(moved, pub) {
			t.Fatal("a record moved between keys kept its signature")
		}
	})
}

// (a) The point of the whole change: one node holding many records on one
// topic, each converging independently.
func TestOneNodeHoldsManyKeysOnATopic(t *testing.T) {
	net := newMemNet()
	a := startNode(t, net, Config{})
	topic := Topic("t.latency")

	for _, peer := range []string{"peer-1", "peer-2", "peer-3"} {
		if err := a.node.PublishKeyed(topic, peer, []byte(peer+"-rtt")); err != nil {
			t.Fatal(err)
		}
	}
	// Plus the classical keyless slot, which must coexist untouched.
	if err := a.node.Publish(topic, []byte("summary")); err != nil {
		t.Fatal(err)
	}

	for _, peer := range []string{"peer-1", "peer-2", "peer-3"} {
		got, ok := a.node.GetKeyed(topic, a.id, peer)
		if !ok {
			t.Fatalf("key %q missing — a node's keys are overwriting each other", peer)
		}
		if string(got.Body) != peer+"-rtt" {
			t.Fatalf("key %q body = %q, want %q", peer, got.Body, peer+"-rtt")
		}
	}
	if got, ok := a.node.Get(topic, a.id); !ok || string(got.Body) != "summary" {
		t.Fatalf("keyless slot = (%q, %v), want (\"summary\", true)", got.Body, ok)
	}

	recs := a.node.NodeRecords(topic, a.id)
	if len(recs) != 4 {
		t.Fatalf("NodeRecords returned %d records, want 4 (3 keyed + 1 keyless)", len(recs))
	}
	// Canonical (NodeID, Key) order: "" sorts before every named key.
	wantKeys := []string{"", "peer-1", "peer-2", "peer-3"}
	for i, want := range wantKeys {
		if recs[i].Key != want {
			t.Fatalf("NodeRecords[%d].Key = %q, want %q (order is not canonical)", i, recs[i].Key, want)
		}
	}
}

// A keyed tombstone must retire exactly its own slot, leaving the node's
// other keys alone.
func TestKeyedTombstoneRetiresOnlyItsSlot(t *testing.T) {
	net := newMemNet()
	a := startNode(t, net, Config{})
	topic := Topic("t.latency")

	if err := a.node.PublishKeyed(topic, "peer-1", []byte("one")); err != nil {
		t.Fatal(err)
	}
	if err := a.node.PublishKeyed(topic, "peer-2", []byte("two")); err != nil {
		t.Fatal(err)
	}
	if err := a.node.PublishKeyedTombstone(topic, "peer-1"); err != nil {
		t.Fatal(err)
	}

	if _, ok := a.node.GetKeyed(topic, a.id, "peer-1"); ok {
		t.Fatal("tombstoned key still reads as live")
	}
	if got, ok := a.node.GetKeyed(topic, a.id, "peer-2"); !ok || string(got.Body) != "two" {
		t.Fatal("tombstoning one key took a sibling key with it")
	}
}

// (d) Convergence: two nodes must agree on a multi-key topic through Merkle
// anti-entropy ALONE — no eager push, no graft. This is the property that
// the (NodeID, Key) ordering and the group-aware range subdivision protect.
//
// The record count is deliberately pushed past maxRangeSize so the responder
// must truncate and the initiator must subdivide: with a single node owning
// every slot, a naive split lands INSIDE that node's key group, and the
// `nextStart = lastNodeID || 0x01` cursor then skips every remaining key.
// Both sides would settle on a stable, self-consistent, WRONG state.
func TestMultiKeyConvergesViaMerkleAcrossRangeSubdivision(t *testing.T) {
	net := newMemNet()
	a := startNode(t, net, Config{})
	topic := Topic("t.content")

	// 150 keys on ONE node > maxRangeSize (64), forcing subdivision within
	// a single NodeID group.
	const nKeys = 150
	for i := 0; i < nKeys; i++ {
		key := fmt.Sprintf("blob-%03d", i)
		if err := a.node.PublishKeyed(topic, key, []byte(key)); err != nil {
			t.Fatal(err)
		}
	}

	// B joins empty and must pull the whole set via anti-entropy.
	b := startNode(t, net, Config{})

	ok := waitUntil(t, 15*time.Second, func() bool {
		return len(b.node.NodeRecords(topic, a.id)) == nKeys
	})
	if !ok {
		got := len(b.node.NodeRecords(topic, a.id))
		t.Fatalf("joiner converged on %d of %d keys — the range subdivision "+
			"stranded a node's remaining keys", got, nKeys)
	}

	// Convergence means identical content, not merely identical counts.
	for i := 0; i < nKeys; i++ {
		key := fmt.Sprintf("blob-%03d", i)
		rec, found := b.node.GetKeyed(topic, a.id, key)
		if !found {
			t.Fatalf("key %q never arrived", key)
		}
		if string(rec.Body) != key {
			t.Fatalf("key %q body = %q, want %q", key, rec.Body, key)
		}
	}

	// And the Merkle roots must agree — the count and bodies could match
	// while the roots diverge if slot ordering were nondeterministic.
	rootA := topicMerkleRoot(a.impl.store, topic, nil, nil)
	rootB := topicMerkleRoot(b.impl.store, topic, nil, nil)
	if rootA != rootB {
		t.Fatalf("roots diverge despite identical record sets: A=%x B=%x", rootA, rootB)
	}
}

// The Merkle root must be stable across repeated computation. With composite
// keys, one node owns many slots, so an ordering that fell back to Go's map
// iteration would make a store's own root flap between calls.
func TestMerkleRootDeterministicAcrossManyKeys(t *testing.T) {
	net := newMemNet()
	a := startNode(t, net, Config{})
	topic := Topic("t.content")

	for i := 0; i < 50; i++ {
		if err := a.node.PublishKeyed(topic, fmt.Sprintf("k-%02d", i), []byte("v")); err != nil {
			t.Fatal(err)
		}
	}
	first := topicMerkleRoot(a.impl.store, topic, nil, nil)
	for i := 0; i < 25; i++ {
		if got := topicMerkleRoot(a.impl.store, topic, nil, nil); got != first {
			t.Fatalf("root is not stable: call %d gave %x, first gave %x", i+2, got, first)
		}
	}
}

// An observer-attested death is a statement about a NODE, so crossing quorum
// must retire every key that node holds — not just its keyless slot. A node
// left half-dead would keep serving stale per-key facts forever.
func TestObserverQuorumTombstonesEveryKeyOfTheNode(t *testing.T) {
	store := newRecordStore()
	store.observerQuorum = 2
	store.observerCorroborationWindow = time.Minute

	_, targetPriv, _ := ed25519.GenerateKey(rand.Reader)
	targetID := nodeIDFromPub(targetPriv.Public().(ed25519.PublicKey))
	topic := Topic("t.latency")

	// The target publishes three keyed records.
	for i, key := range []string{"", "peer-1", "peer-2"} {
		r := Record{Topic: topic, NodeID: targetID, Key: key, HLC: uint64(10 + i), Body: []byte("v")}
		signRecord(&r, targetPriv)
		if applied, _ := store.Apply(r); !applied {
			t.Fatalf("control failed: target record for key %q did not apply", key)
		}
	}

	// Two distinct observers attest that the node is dead. The timestamp
	// must sit strictly AFTER the publishes above: the restored-at
	// high-water-mark gate rejects any attestation issued at or before the
	// target's last owner publish, and the publishes above land in the
	// current millisecond.
	attMs := time.Now().UnixMilli() + 1000
	crossed := false
	for i := 0; i < 2; i++ {
		_, obsPriv, _ := ed25519.GenerateKey(rand.Reader)
		obsID := nodeIDFromPub(obsPriv.Public().(ed25519.PublicKey))
		att := Record{
			Topic: topic, NodeID: targetID, HLC: uint64(100 + i),
			Tombstone: true, ObserverNodeID: obsID, ObservedAtUnixMs: attMs,
		}
		signRecord(&att, obsPriv)
		applied, _, accumulated := store.ApplyExt(att)
		if !accumulated {
			t.Fatalf("control failed: attestation %d was not accumulated — "+
				"quorum can never cross, so this test would assert nothing", i)
		}
		crossed = crossed || applied
	}
	if !crossed {
		t.Fatal("control failed: quorum never crossed, so no tombstone was synthesised")
	}

	for _, key := range []string{"", "peer-1", "peer-2"} {
		if _, ok := store.GetKeyed(topic, targetID, key); ok {
			t.Fatalf("key %q survived observer quorum — the node is only half dead", key)
		}
	}
}

// Composite keys let one node open many slots, so they introduce an
// amplification the one-slot-per-node store could not express: a single
// publisher consuming the whole per-topic budget and crowding out honest
// peers. The per-node cap must bound that, and must NOT block updates to a
// node's existing keys (convergence on known state is never optional).
func TestPerNodeKeyCapBoundsAmplification(t *testing.T) {
	store := newRecordStore()
	store.setCaps(0, 0, 4, 0) // 4 slots per node per topic

	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	id := nodeIDFromPub(priv.Public().(ed25519.PublicKey))
	topic := Topic("t.cap")

	for i := 0; i < 4; i++ {
		r := Record{Topic: topic, NodeID: id, Key: fmt.Sprintf("k%d", i), HLC: uint64(10 + i), Body: []byte("v")}
		signRecord(&r, priv)
		if applied, _ := store.Apply(r); !applied {
			t.Fatalf("slot %d rejected below the cap", i)
		}
	}

	over := Record{Topic: topic, NodeID: id, Key: "k4", HLC: 20, Body: []byte("v")}
	signRecord(&over, priv)
	if applied, _ := store.Apply(over); applied {
		t.Fatal("per-node cap did not bound a node's slot count")
	}

	// A DIFFERENT node must be unaffected — the cap bounds one node, it does
	// not close the topic.
	_, priv2, _ := ed25519.GenerateKey(rand.Reader)
	id2 := nodeIDFromPub(priv2.Public().(ed25519.PublicKey))
	other := Record{Topic: topic, NodeID: id2, Key: "k0", HLC: 30, Body: []byte("v")}
	signRecord(&other, priv2)
	if applied, _ := store.Apply(other); !applied {
		t.Fatal("one node hitting its cap blocked a different node — the cap is crowding out honest peers")
	}

	// And updates to an EXISTING key must still converge at the cap.
	upd := Record{Topic: topic, NodeID: id, Key: "k0", HLC: 999, Body: []byte("newer")}
	signRecord(&upd, priv)
	if applied, _ := store.Apply(upd); !applied {
		t.Fatal("a node at its cap can no longer update its own existing keys — convergence is blocked")
	}
}

// Subscribe replays current state, then flushes records that arrived DURING
// replay, skipping those the snapshot already covered. That dedup is
// per-SLOT. Keyed by node it keeps one HLC per node and then silently drops
// live deliveries for that node's other keys.
//
// This drives subGate directly rather than going through Subscribe: the
// dedup only governs the queue built while replaying, and a test that
// subscribes to an already-populated topic never enqueues anything, so it
// passes whatever the dedup does. (Measured — the first version of this test
// passed against a deliberately node-keyed build.)
func TestSubscribeReplayDedupIsPerSlotNotPerNode(t *testing.T) {
	const node = NodeID("n1")
	topic := Topic("t.replay")

	var delivered []Record
	gate := &subGate{
		inner:     func(r Record) error { delivered = append(delivered, r); return nil },
		replaying: true,
	}

	// Arrived while replay was in flight: a DIFFERENT key of the same node,
	// at a LOWER HLC than the key the snapshot covered.
	if err := gate.deliver(Record{Topic: topic, NodeID: node, Key: "b", HLC: 50}); err != nil {
		t.Fatal(err)
	}
	if len(delivered) != 0 {
		t.Fatal("control failed: the gate delivered during replay instead of queueing")
	}

	// The snapshot covered only slot (n1, "a") at HLC 100.
	gate.finishReplay(map[recordKey]uint64{{NodeID: node, Key: "a"}: 100})

	if len(delivered) != 1 {
		t.Fatalf("flushed %d records, want 1 — slot (n1,\"b\") was suppressed by "+
			"slot (n1,\"a\")'s HLC, so a node's keys are colliding in the replay set", len(delivered))
	}
	if delivered[0].Key != "b" {
		t.Fatalf("flushed key %q, want \"b\"", delivered[0].Key)
	}

	// Positive control: a record the snapshot DID cover must still be
	// skipped, or the test would pass simply by never deduping at all.
	delivered = nil
	gate2 := &subGate{
		inner:     func(r Record) error { delivered = append(delivered, r); return nil },
		replaying: true,
	}
	_ = gate2.deliver(Record{Topic: topic, NodeID: node, Key: "a", HLC: 90})
	gate2.finishReplay(map[recordKey]uint64{{NodeID: node, Key: "a"}: 100})
	if len(delivered) != 0 {
		t.Fatal("control failed: a record already covered by the snapshot was re-delivered")
	}
}

// End-to-end companion to the subGate unit test above: this one goes through
// the real Subscribe path, so it also pins the map that Subscribe BUILDS,
// not just the contract finishReplay honours.
//
// The scenario is the one that actually bites: an OLDER record for a
// different key of the same node arriving mid-replay. Per-node HLCs are
// monotonic, so a node's own fresh publish always outranks the snapshot and
// would never be wrongly suppressed — the hazard needs an out-of-order
// arrival, which anti-entropy replay produces routinely.
func TestOutOfOrderKeyArrivingDuringReplayIsDelivered(t *testing.T) {
	net := newMemNet()
	a := startNode(t, net, Config{})
	topic := Topic("t.replay.e2e")

	// Slot (a, "a") exists with a high HLC and will be replayed.
	if err := a.node.PublishKeyed(topic, "a", []byte("first")); err != nil {
		t.Fatal(err)
	}

	// Mid-replay, a record for slot (a, "b") arrives carrying a LOWER HLC.
	late := Record{Topic: topic, NodeID: a.id, Key: "b", HLC: 1, Body: []byte("late")}
	signRecord(&late, a.priv)

	var seen []string
	injected := false
	unsub, err := a.node.Subscribe(topic, func(r Record) error {
		seen = append(seen, r.Key)
		if !injected {
			injected = true
			// Delivered through the gate while replaying → queued, then
			// flushed by finishReplay against the replayed slot set.
			a.impl.recordAccepted(late)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer unsub()

	if !injected {
		t.Fatal("control failed: replay never invoked the subscriber, so nothing was injected")
	}
	var sawB bool
	for _, k := range seen {
		if k == "b" {
			sawB = true
		}
	}
	if !sawB {
		t.Fatalf("slot (node,\"b\") never reached the subscriber (saw %v) — an older "+
			"record for one key was suppressed by a newer record on a DIFFERENT key "+
			"of the same node, a permanent delivery gap", seen)
	}
}

// ---------- Blocker 6 (race half): replay/live must be serial + monotonic ----------
//
// subGate's doc says it "serialises a subscriber's replay-then-live
// transition". It did not: finishReplay cleared `replaying` and dropped the
// lock BEFORE flushing, so a concurrent deliver() saw replaying==false and
// called the subscriber directly, alongside and ahead of the queued records.
//
// 🛑 `-race` is CLEAN on this and always was — the queue handoff is properly
// locked, so nothing races in this package's memory. The violated thing is
// the contract the gate advertises, and the damage lands in the subscriber's
// state. A green `-race` says something about memory, never about
// serialisation a caller was promised.
// queuedHLCMax separates records queued during replay (HLC <= this) from the
// live ones published concurrently with the drain (HLC >= 100).
const queuedHLCMax = 20

func TestSubGateSerialisesAndOrdersReplayBeforeLive(t *testing.T) {
	var mu sync.Mutex
	var concurrent, maxDuringDrain int
	var order []uint64

	gate := &subGate{replaying: true}
	gate.inner = func(r Record) error {
		mu.Lock()
		concurrent++
		// Measure concurrency ONLY while a QUEUED record is in flight. Once
		// the transition completes the gate deliberately delivers live
		// records concurrently, so a whole-run maximum would assert a
		// property the gate does not promise — and would pass or fail purely
		// on whether the drain happened to outlast the live publishers.
		if r.HLC <= queuedHLCMax && concurrent > maxDuringDrain {
			maxDuringDrain = concurrent
		}
		order = append(order, r.HLC)
		mu.Unlock()
		// Widen the window the flush loop spends outside the lock, so a
		// concurrent deliver has a real chance to interleave.
		runtime.Gosched()
		mu.Lock()
		concurrent--
		mu.Unlock()
		return nil
	}

	const queued = queuedHLCMax
	for i := uint64(1); i <= queued; i++ {
		if err := gate.deliver(Record{HLC: i}); err != nil {
			t.Fatal(err)
		}
	}
	mu.Lock()
	if len(order) != 0 {
		mu.Unlock()
		t.Fatal("control failed: records were delivered during replay instead of queued")
	}
	mu.Unlock()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); gate.finishReplay(nil) }()
	for i := uint64(100); i < 110; i++ {
		wg.Add(1)
		go func(h uint64) { defer wg.Done(); _ = gate.deliver(Record{HLC: h}) }(i)
	}
	wg.Wait()

	if maxDuringDrain != 1 {
		t.Errorf("a QUEUED record was delivered while %d goroutines were inside the "+
			"subscriber, want 1 — the drain is not serial with respect to live delivery",
			maxDuringDrain)
	}
	// Every queued record (HLC <= 20) must precede every live one (>= 100).
	sawLive := false
	for _, h := range order {
		if h >= 100 {
			sawLive = true
			continue
		}
		if sawLive {
			t.Errorf("queued record %d delivered after a live record — replay/live "+
				"ordering is not monotonic; order=%v", h, order)
			break
		}
	}
	if len(order) != queued+10 {
		t.Errorf("delivered %d records, want %d — the drain loop lost arrivals that "+
			"landed while a batch was being handed to the subscriber", len(order), queued+10)
	}
}

// MaxKeyBytes is an encoding invariant, not a policy knob: the u16 length
// prefix means a longer key would wrap and let two distinct keys share one
// canonical byte string. Both the local publish path and the inbound gate
// must refuse it.
func TestOversizeKeyRejected(t *testing.T) {
	net := newMemNet()
	a := startNode(t, net, Config{})
	huge := make([]byte, MaxKeyBytes+1)
	for i := range huge {
		huge[i] = 'k'
	}
	if err := a.node.PublishKeyed(Topic("t.a"), string(huge), []byte("v")); err == nil {
		t.Fatal("PublishKeyed accepted a key longer than MaxKeyBytes")
	}

	gate := newInboundGate(Config{})
	r := Record{Topic: "t.a", NodeID: "n", HLC: 1, Key: string(huge)}
	if err := gate.Admit(r); err == nil {
		t.Fatal("inbound gate admitted a key longer than MaxKeyBytes")
	}
}

// ---------- Gate-2 data compatibility (#R-1400 ③): what does an OLDER
// swarm reader do when a composite-key record reaches it? ----------
//
// The wire is protobuf, so an old reader silently DROPS the unknown `key`
// field — which on its own would be the dangerous outcome: two keyed records
// from one node would both arrive as that node's single keyless slot and
// overwrite each other, last-writer-wins, with no error anywhere.
//
// What prevents that is the signature. Key is covered by signableBytes, and
// an old reader computes the canonical bytes WITHOUT the key suffix, so its
// Ed25519 check fails and the record is rejected before it can reach the
// store. The mixed-version failure mode is therefore FAIL-CLOSED (a keyed
// record is invisible to an old reader) rather than silently corrupting.
//
// legacySignableBytes is the independently-written pre-Key encoder — it is
// exactly what an old reader computes.
func TestOldReaderRejectsKeyedRecordRatherThanMisfilingIt(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := nodeIDFromPub(pub)

	// A node publishes two DIFFERENT keyed records on one topic at the same
	// HLC — precisely the pair that would collapse if an old reader accepted
	// them with the key stripped.
	a := Record{Topic: "fleet.latency", NodeID: id, Key: "peer-1", HLC: 99, Body: []byte("rtt-1")}
	b := Record{Topic: "fleet.latency", NodeID: id, Key: "peer-2", HLC: 99, Body: []byte("rtt-2")}
	signRecord(&a, priv)
	signRecord(&b, priv)

	// Control: the new reader accepts both, in distinct slots.
	if !verifyRecord(a, pub) || !verifyRecord(b, pub) {
		t.Fatal("control failed: a current reader rejects its own keyed records")
	}

	// An OLD reader recomputes the canonical bytes without the key suffix.
	for _, r := range []Record{a, b} {
		if ed25519.Verify(pub, legacySignableBytes(r), r.Sig) {
			t.Fatalf("an old reader ACCEPTED keyed record %q — it would store it in the "+
				"node's keyless slot, so %q and %q would overwrite each other silently",
				r.Key, a.Key, b.Key)
		}
	}

	// And the compatibility that must hold: a keyless record still verifies
	// identically under the old encoder, so normal traffic is unaffected.
	k := Record{Topic: "fleet.peer", NodeID: id, HLC: 99, Body: []byte("peer")}
	signRecord(&k, priv)
	if !ed25519.Verify(pub, legacySignableBytes(k), k.Sig) {
		t.Fatal("an old reader REJECTED a keyless record — every record in the fleet " +
			"today is keyless, so this would be a total mixed-version outage")
	}
}

// ---------- TTL reaping under composite keys ----------
//
// reapExpired had to change for composite keys (it deletes by slot now), and
// with it the retention rule for restoredAtUnixMs — the per-NODE high-water
// mark that fences stale observer attestations. These pin both halves; the
// second is security-relevant and had no coverage at all.

// TTL expiry is per SLOT: an expired key of a node must go, and that node's
// still-fresh keys must survive. Reaping by node would take the live ones too.
func TestTTLReapsExpiredKeysAndKeepsFreshOnes(t *testing.T) {
	s := newRecordStore()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	id := nodeIDFromPub(priv.Public().(ed25519.PublicKey))
	const topic = Topic("t.ttl.keys")

	nowMs := time.Now().UnixMilli()
	// "old" is 10s stale in HLC wall time; "fresh" is stamped now.
	mk := func(key string, wallMs int64) Record {
		r := Record{Topic: topic, NodeID: id, Key: key, HLC: packHLC(uint64(wallMs), 0), Body: []byte(key)}
		signRecord(&r, priv)
		return r
	}
	for _, r := range []Record{mk("old", nowMs-10_000), mk("fresh", nowMs)} {
		if applied, _ := s.Apply(r); !applied {
			t.Fatalf("control failed: %q did not apply", r.Key)
		}
	}

	dropped := s.reapExpired(nowMs, func(Topic) time.Duration { return time.Second })
	if dropped != 1 {
		t.Fatalf("reaped %d slots, want exactly 1 (the stale key only)", dropped)
	}
	if _, ok := s.getRawKeyed(topic, id, "old"); ok {
		t.Error("the expired key survived the reap")
	}
	if _, ok := s.getRawKeyed(topic, id, "fresh"); !ok {
		t.Error("a FRESH key of the same node was reaped — expiry is being applied per node, not per slot")
	}
}

// 🛑 The restored-at high-water-mark is per NODE and fences observer
// attestations issued before the node last re-published. Under composite keys
// it must survive while the node still holds ANY slot: dropping it when one
// key expires would unfence a node that is still live, letting a stale
// pre-restore attestation back into its witness set and satisfy K-of-N
// against a peer that never died.
func TestRestoredAtFenceSurvivesWhileNodeHoldsAnySlot(t *testing.T) {
	s := newRecordStore()
	s.observerQuorum = 2
	s.observerCorroborationWindow = time.Minute

	_, targetPriv, _ := ed25519.GenerateKey(rand.Reader)
	target := nodeIDFromPub(targetPriv.Public().(ed25519.PublicKey))
	const topic = Topic("t.fence")

	nowMs := time.Now().UnixMilli()
	mk := func(key string, wallMs int64) Record {
		r := Record{Topic: topic, NodeID: target, Key: key, HLC: packHLC(uint64(wallMs), 0), Body: []byte("v")}
		signRecord(&r, targetPriv)
		return r
	}
	// The node publishes two keys; one will expire, one stays fresh. Both
	// stamp the per-node restored-at fence.
	for _, r := range []Record{mk("stale", nowMs-10_000), mk("live", nowMs)} {
		if applied, _ := s.Apply(r); !applied {
			t.Fatalf("control failed: %q did not apply", r.Key)
		}
	}
	if dropped := s.reapExpired(nowMs, func(Topic) time.Duration { return time.Second }); dropped != 1 {
		t.Fatalf("control failed: reaped %d, want 1", dropped)
	}

	// A stale attestation — issued BEFORE the node's last publish — must
	// still be refused. Two distinct observers, so if the fence has been
	// dropped these would cross quorum and tombstone a live node.
	staleObservedAt := nowMs - 5_000
	for i := 0; i < 2; i++ {
		_, obsPriv, _ := ed25519.GenerateKey(rand.Reader)
		obs := nodeIDFromPub(obsPriv.Public().(ed25519.PublicKey))
		att := Record{
			Topic: topic, NodeID: target, HLC: packHLC(uint64(nowMs), uint64(i)),
			Tombstone: true, ObserverNodeID: obs, ObservedAtUnixMs: staleObservedAt,
		}
		signRecord(&att, obsPriv)
		s.Apply(att)
	}

	if _, ok := s.GetKeyed(topic, target, "live"); !ok {
		t.Fatal("a LIVE node was tombstoned by pre-restore attestations — expiring one " +
			"of its keys dropped the per-node restored-at fence")
	}
}

// ---------- Lazy-push repair must be key-aware (wire axis, #P-520's U12) ----------
//
// A GRAFT names the slot it wants. Serving the keyless slot regardless looks
// harmless — the record sent is genuine and lands in its correct slot on the
// requester — but the requester never gets what it asked for, re-announces,
// and grafts again forever. Convergence silently degrades to eager-push +
// Merkle only, with no error on either side.
//
// This is the graft path specifically: the existing composite-key convergence
// test drives Merkle anti-entropy and cannot see it.
func TestGraftServesTheKeyedSlotItAskedFor(t *testing.T) {
	net := newMemNet()
	a := startNode(t, net, Config{})
	topic := Topic("t.graft.keys")

	// One node, two slots with DIFFERENT bodies so a wrong answer is visible.
	if err := a.node.Publish(topic, []byte("keyless-body")); err != nil {
		t.Fatal(err)
	}
	if err := a.node.PublishKeyed(topic, "peer-1", []byte("keyed-body")); err != nil {
		t.Fatal(err)
	}

	// Capture what the responder puts on the wire for a keyed GRAFT.
	var served []Record
	var mu sync.Mutex
	b := startNode(t, net, Config{})
	unsub, err := b.node.Subscribe(topic, func(r Record) error {
		mu.Lock()
		served = append(served, r)
		mu.Unlock()
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer unsub()

	// Drive the responder's graft handler directly with a keyed request —
	// this is exactly the frame a peer sends after a keyed IHave.
	a.impl.plum.handleGraft(b.id, &pb.Graft{
		Topic:  string(topic),
		NodeId: []byte(a.id),
		Key:    "peer-1",
		Hlc:    0,
	})

	ok := waitUntil(t, 3*time.Second, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(served) > 0
	})
	if !ok {
		t.Fatal("responder served nothing for a keyed GRAFT")
	}
	mu.Lock()
	got := served[len(served)-1]
	mu.Unlock()
	if got.Key != "peer-1" {
		t.Fatalf("GRAFT for key %q was answered with slot %q (body %q) — the responder "+
			"ignores Graft.Key, so lazy-push repair can never deliver a keyed record",
			"peer-1", got.Key, got.Body)
	}
	if string(got.Body) != "keyed-body" {
		t.Fatalf("served body = %q, want %q", got.Body, "keyed-body")
	}
}

// ---------- Blocker 6, the OTHER half: the SUBSCRIBER MAP ----------
//
// §0.5.2 blocker 6 requires "subscriber maps AND replay/live ordering must be
// race-free". #M-484 closed the ordering half; this is the map half, and it
// was still open.
//
// deliverToSubs took RLock, copied `n.subs[topic]` — a map HEADER, i.e. a
// pointer — released the lock, then ranged over it. Subscribe and the
// unsubscribe closure both write that same inner map under the lock, so a
// subscribe concurrent with a delivery is a concurrent map read/write, which
// Go may answer with an outright panic rather than a torn read.
func TestSubscriberMapRaceFreeUnderConcurrentSubscribeAndDeliver(t *testing.T) {
	net := newMemNet()
	a := startNode(t, net, Config{})
	topic := Topic("t.submap")

	var wg sync.WaitGroup
	stop := make(chan struct{})

	// Continuous deliveries.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			_ = a.node.Publish(topic, []byte("v"))
		}
	}()

	// Continuous subscribe/unsubscribe against the same topic.
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				unsub, err := a.node.Subscribe(topic, func(Record) error { return nil })
				if err != nil {
					return
				}
				unsub()
			}
		}()
	}

	time.Sleep(200 * time.Millisecond)
	close(stop)
	wg.Wait()
	// The assertion is the race detector plus the absence of a
	// "concurrent map iteration and map write" panic; reaching here is the
	// pass condition.
}
