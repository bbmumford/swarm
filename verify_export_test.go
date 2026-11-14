/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */

package swarm

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

// A swarm record's signature is worth nothing to anyone outside this package
// unless they can check it: signableBytes, signRecord and verifyRecord are
// unexported, and VerifyRecord is the one exported record verifier.
//
// The directory projection preserves Signature, AuthorPubKey and Body
// byte-identically, so a downstream consumer, an anchor snapshot receiver say,
// HOLDS a valid signature and checks it with VerifyRecord rather than trusting
// the relaying node: an observer fact is a third-party attestation, and the
// anchor role a peer advertises on its own record is not a trust root.
func TestVerifyRecordIsExportedAndAcceptsAGenuineRecord(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	r := Record{
		Topic:  "fleet.peer",
		NodeID: nodeIDFromPub(pub),
		HLC:    10 << 16,
		Body:   []byte("body"),
	}
	signRecord(&r, priv)

	if !VerifyRecord(r) {
		t.Fatal("a correctly signed record whose NodeID derives from its signing " +
			"key was rejected — the exported verifier is unusable")
	}
}

// 🛑 THE POINT OF THE EXPORT: it must NOT repeat the internal path's weakness.
//
// Both internal call sites (merkle.go, plumtrees.go) verify with
// ed25519.PublicKey(rec.PubKey) — the key the RECORD ITSELF SUPPLIES. That
// proves the record is internally consistent; it does NOT prove the record
// came from the NodeID it claims. An attacker signs with their own key and
// writes any NodeID they like into the slot. Config.RequireNodeKeyBinding
// closes that on the inbound gate when set, and it is off by default; loom's
// node leaves it off and binds through its own TrustCheck, since this
// package's hex(pubkey) NodeID differs from the mesh's NodeIDs.
//
// The exported verifier derives the key from the NodeID instead, so the bind
// holds BY CONSTRUCTION and cannot be left unwired.
func TestVerifyRecordRejectsAKeypairClaimingAnotherNodeID(t *testing.T) {
	victimPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	attackerPub, attackerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Attacker signs with their own key but claims the victim's slot.
	forged := Record{
		Topic:  "fleet.peer",
		NodeID: nodeIDFromPub(victimPub),
		HLC:    99 << 16,
		Body:   []byte("i am the victim"),
	}
	signRecord(&forged, attackerPriv) // sets forged.PubKey = attackerPub

	// CONTROL — the internal path ACCEPTS this, which is why the export cannot
	// simply delegate to it. If this control ever fails, the internal path has
	// been hardened and this test's premise needs revisiting.
	if !verifyRecord(forged, ed25519.PublicKey(forged.PubKey)) {
		t.Fatal("control: the internal verifier rejected the forgery — the " +
			"weakness this test exists to avoid inheriting is gone; re-read it")
	}
	if string(attackerPub) == string(victimPub) {
		t.Fatal("control: the two keys are identical, the test proves nothing")
	}

	if VerifyRecord(forged) {
		t.Fatal("the exported verifier accepted a record signed by one keypair " +
			"while claiming another node's NodeID — it has inherited the " +
			"internal path's missing NodeID<->key bind")
	}
}

// A record whose embedded PubKey disagrees with its NodeID is inconsistent on
// its face; fail closed rather than silently preferring one source.
func TestVerifyRecordRejectsPubKeyDisagreeingWithNodeID(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	r := Record{Topic: "fleet.peer", NodeID: nodeIDFromPub(pub), HLC: 1 << 16}
	signRecord(&r, priv)
	if !VerifyRecord(r) {
		t.Fatal("control: the honest record must verify before we corrupt it")
	}

	r.PubKey = append([]byte(nil), otherPub...)
	if VerifyRecord(r) {
		t.Fatal("a record whose PubKey disagrees with its NodeID was accepted")
	}
}

// A NodeID that is not a key encoding cannot be bound to anything, so it
// cannot be verified. Fail closed — never treat unverifiable as verified.
func TestVerifyRecordRejectsUnbindableNodeID(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	r := Record{Topic: "fleet.peer", NodeID: NodeID("not-a-hex-pubkey"), HLC: 1 << 16}
	signRecord(&r, priv)
	if VerifyRecord(r) {
		t.Fatal("a record whose NodeID is not a key encoding was reported verified")
	}
}

// Tampering after signing must fail, or the verifier is decorative.
func TestVerifyRecordRejectsTamperedBody(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	r := Record{Topic: "fleet.peer", NodeID: nodeIDFromPub(pub), HLC: 1 << 16, Body: []byte("original")}
	signRecord(&r, priv)
	if !VerifyRecord(r) {
		t.Fatal("control: the untampered record must verify")
	}
	r.Body = []byte("tampered")
	if VerifyRecord(r) {
		t.Fatal("a record whose body changed after signing was accepted")
	}
}

// Keyed records must verify too — the composite key is signature-covered, so
// changing it must invalidate the signature.
func TestVerifyRecordCoversTheCompositeKey(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	r := Record{Topic: "fleet.content", NodeID: nodeIDFromPub(pub), Key: "blob-a", HLC: 1 << 16}
	signRecord(&r, priv)
	if !VerifyRecord(r) {
		t.Fatal("control: a keyed record must verify")
	}
	r.Key = "blob-b"
	if VerifyRecord(r) {
		t.Fatal("changing Key did not invalidate the signature — the composite " +
			"key is not signature-covered after all")
	}
}
