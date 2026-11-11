/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */

package swarm

import (
	"crypto/ed25519"
	"testing"
	"time"
)

// observerAttestation is an attestation by the holder of priv, observer, that
// target is dead, signed as PublishObserverTombstone signs one; a peer that
// skips PublishObserverTombstone's own refusals can sign one about itself.
func observerAttestation(t *testing.T, priv ed25519.PrivateKey, observer, target NodeID, hlc uint64) Record {
	t.Helper()
	r := Record{
		Topic:            Topic("fleet.peer"),
		NodeID:           target,
		HLC:              hlc,
		Tombstone:        true,
		ObserverNodeID:   observer,
		ObservedAtUnixMs: time.Now().UnixMilli(),
	}
	signRecord(&r, priv)
	return r
}

// The observer gate is handed the attestation's subject, the target it says is
// dead, beside the observer and its Sig-verified key, so a gate that refuses a
// node attesting about itself refuses one that arrives over the wire: a
// self-attestation the gate refuses never counts toward the quorum, and an
// attestation about another node counts.
func TestTheObserverGateIsHandedTheAttestationsSubject(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	type asked struct{ observer, subject NodeID }
	var got []asked
	s := newRecordStore()
	s.SetObserverQuorum(1, time.Minute)
	s.SetObserverRoleCheck(func(observer NodeID, _ []byte, subject NodeID) bool {
		got = append(got, asked{observer, subject})
		return observer != subject
	})

	if applied, _ := s.Apply(observerAttestation(t, priv, "anchor-a", "anchor-a", 10)); applied {
		t.Fatal("a self-attestation the gate refuses evicted its own observer")
	}
	if len(got) == 0 || got[0] != (asked{"anchor-a", "anchor-a"}) {
		t.Fatalf("the gate was asked %v; want the observer and the attestation's own subject", got)
	}
	if applied, _ := s.Apply(observerAttestation(t, priv, "anchor-a", "victim", 11)); !applied {
		t.Fatal("an admitted attestation about another node did not count at K=1")
	}
	if last := got[len(got)-1]; last.subject != "victim" {
		t.Fatalf("the gate was asked about subject %q; want the attestation's target victim", last.subject)
	}
}
