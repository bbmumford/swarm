// Copyright (c) 2026 Brandon Miller-Mumford.
// Licensed under the MIT License; see LICENSE.

package swarm

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"
)

// A node without a TrustCheck would store every proved node's records on every
// topic, so New refuses the Config.
func TestNewRefusesAConfigWithoutATrustCheck(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	if n, err := New(Config{PrivKey: priv}); !errors.Is(err, ErrNoTrustCheck) || n != nil {
		t.Fatalf("New = %v, %v; want nil, ErrNoTrustCheck", n, err)
	}
	gate := newInboundGate(Config{})
	r := signedRecord("t.any", priv, nodeIDFromPub(priv.Public().(ed25519.PublicKey)), packHLC(uint64(time.Now().UnixMilli()), 0), nil)
	if err := gate.Admit(r); !errors.Is(err, ErrNoTrustCheck) {
		t.Fatalf("a gate with no TrustCheck admitted a bound record: %v", err)
	}
}

// With no observer gate wired, a store admits no attestation, so no node is
// evicted by observers nothing judged.
func TestAStoreWithNoObserverGateAdmitsNoAttestation(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	s := newRecordStore()
	s.SetObserverQuorum(1, time.Minute)
	if applied, _ := s.Apply(observerAttestation(t, priv, "anyone", "victim", 10)); applied {
		t.Fatal("an attestation evicted its subject with no observer gate wired")
	}
	if ts := s.byTopic["fleet.peer"]; ts != nil && len(ts.attestations) != 0 {
		t.Fatal("an attestation was held toward the quorum with no observer gate wired")
	}
	s.SetObserverRoleCheck(func(NodeID, []byte, NodeID) bool { return true })
	if applied, _ := s.Apply(observerAttestation(t, priv, "anyone", "victim", 11)); !applied {
		t.Fatal("an admitted attestation did not count at K=1")
	}
}
