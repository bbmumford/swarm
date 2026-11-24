// Copyright (c) 2026 Brandon Miller-Mumford.
// Licensed under the MIT License; see LICENSE.

package swarm

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/ORBTR/aether"
	"github.com/bbmumford/swarm/proto/pb"
	"google.golang.org/protobuf/proto"
)

func aetherNodeID(t *testing.T, pub ed25519.PublicKey) NodeID {
	t.Helper()
	id, err := aether.NewNodeID(pub)
	if err != nil {
		t.Fatal(err)
	}
	return NodeID(string(id))
}

// A node's NodeID is the aether NodeID of its key, the identity its mesh
// sessions prove.
func TestTheDefaultNodeIDIsTheAetherNodeIDOfTheKey(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	n, err := New(Config{PrivKey: priv, TrustCheck: func(Record) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := n.(*nodeImpl).id, aetherNodeID(t, pub); got != want {
		t.Fatalf("NodeID = %q, want %q", got, want)
	}
}

// With a TrustCheck that admits every topic, a record signed by one key but
// written under another node's NodeID is still refused before the store, and
// the signer's record under its own NodeID is stored.
func TestARecordWrittenUnderAnotherNodesIDIsRefused(t *testing.T) {
	net := newMemNet()
	a := startNode(t, net, Config{})
	victimPub, _, _ := ed25519.GenerateKey(rand.Reader)
	attackerPub, attacker, _ := ed25519.GenerateKey(rand.Reader)
	victim, attackerID := aetherNodeID(t, victimPub), aetherNodeID(t, attackerPub)
	now := uint64(time.Now().UnixMilli())

	inject(t, net, a, attackerID, signedRecord("t.hijack", attacker, victim, packHLC(now, 0), []byte("x")))
	inject(t, net, a, attackerID, signedRecord("t.hijack", attacker, attackerID, packHLC(now, 1), []byte("own")))
	if !waitUntil(t, 2*time.Second, func() bool { _, ok := a.node.Get("t.hijack", attackerID); return ok }) {
		t.Fatal("the signer's record under its own NodeID was not stored")
	}
	if _, ok := a.node.Get("t.hijack", victim); ok {
		t.Fatal("a record signed by another key was stored in the victim's slot")
	}
	if _, _, binding, _ := a.impl.gate.Rejections(); binding == 0 {
		t.Fatal("the hijack was not counted as a binding rejection")
	}
}

// VerifyRecord accepts a record signed by the key its aether NodeID names, and
// refuses one written under another node's NodeID or carrying no key.
func TestVerifyRecordChecksTheAetherNodeIDBinding(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	r := Record{Topic: "fleet.peer", NodeID: aetherNodeID(t, pub), HLC: 1 << 16, Body: []byte("b")}
	signRecord(&r, priv)
	if !VerifyRecord(r) {
		t.Fatal("VerifyRecord refused a record signed by the key its NodeID names")
	}
	moved := r
	moved.NodeID = aetherNodeID(t, otherPub)
	if VerifyRecord(moved) {
		t.Fatal("VerifyRecord accepted a record moved to another node's NodeID")
	}
	keyless := r
	keyless.PubKey = nil
	if VerifyRecord(keyless) {
		t.Fatal("VerifyRecord accepted a record carrying no key")
	}
	// Another key signs a record of its own under this node's NodeID: the
	// signature is valid for the key the record carries, and only the binding
	// refuses it.
	_, attacker, _ := ed25519.GenerateKey(rand.Reader)
	forged := Record{Topic: "fleet.peer", NodeID: r.NodeID, HLC: 1 << 16, Body: []byte("b")}
	signRecord(&forged, attacker)
	if !verifyRecord(forged, ed25519.PublicKey(forged.PubKey)) {
		t.Fatal("the forged record's own signature did not verify, so the case tests nothing")
	}
	if VerifyRecord(forged) {
		t.Fatal("VerifyRecord accepted a record signed by another key under this node's NodeID")
	}
}

// A manifest verifies only under its publisher's key, which must be the key
// of its Publisher NodeID.
func TestAManifestVerifiesOnlyUnderItsPublishersKey(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	raw, _, _, _, err := BuildSignedManifest([]byte("blob body"), 4, "f", "text/plain", priv)
	if err != nil {
		t.Fatal(err)
	}
	var m pb.Manifest
	if err := proto.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if !verifyManifestSig(&m) {
		t.Fatal("a manifest its publisher signed did not verify")
	}
	swapped := proto.Clone(&m).(*pb.Manifest)
	swapped.PublisherKey = otherPub
	if verifyManifestSig(swapped) {
		t.Fatal("a manifest verified under a key that is not its Publisher's")
	}
	moved := proto.Clone(&m).(*pb.Manifest)
	moved.Publisher = []byte(aetherNodeID(t, otherPub))
	if verifyManifestSig(moved) {
		t.Fatal("a manifest verified after its Publisher was changed")
	}
	// Another key signs the manifest under this publisher's NodeID: the
	// signature is valid for the key it carries, and only the binding of
	// Publisher to PublisherKey refuses it.
	attackerPub, attacker, _ := ed25519.GenerateKey(rand.Reader)
	claimed := proto.Clone(&m).(*pb.Manifest)
	claimed.PublisherKey = attackerPub
	claimed.Sig = ed25519.Sign(attacker, signableManifestBytes(manifestSig{
		BlobHash: claimed.BlobHash, TotalSize: claimed.TotalSize, ChunkSize: claimed.ChunkSize, Chunks: claimed.Chunks,
		Filename: claimed.Filename, Mime: claimed.Mime, PublishedAt: claimed.PublishedAt, Publisher: claimed.Publisher,
	}))
	if verifyManifestSig(claimed) {
		t.Fatal("a manifest signed by another key under this publisher's NodeID verified")
	}
}
