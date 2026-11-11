/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */

package swarm

import (
	"crypto/ed25519"
	"sync"
	"testing"
	"time"
)

// An attestation counts toward the quorum only while the gate admits its
// observer: the gate admitted observer-1 when its attestation arrived and no
// longer does when observer-2's arrives (as loom's gate moves its one admitted
// node per anchor key to that key's fresher machine), so the two do not make
// K=2; a third admitted observer then does. An attestation held while the
// gate refuses its observer counts again once the gate admits it again.
func TestAnAttestationCountsOnlyWhileTheGateAdmitsItsObserver(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	admitted := map[NodeID]bool{"observer-1": true, "observer-2": true, "observer-3": true}
	set := func(id NodeID, ok bool) { mu.Lock(); admitted[id] = ok; mu.Unlock() }
	s := newRecordStore()
	s.SetObserverQuorum(2, time.Minute)
	s.SetObserverRoleCheck(func(observer NodeID, _ []byte, _ NodeID) bool {
		mu.Lock()
		defer mu.Unlock()
		return admitted[observer]
	})

	if applied, _ := s.Apply(observerAttestation(t, priv, "observer-1", "victim", 10)); applied {
		t.Fatal("one attestation crossed K=2")
	}
	set("observer-1", false)
	if applied, _ := s.Apply(observerAttestation(t, priv, "observer-2", "victim", 11)); applied {
		t.Fatal("an attestation whose observer the gate no longer admits counted toward K=2")
	}
	if applied, _ := s.Apply(observerAttestation(t, priv, "observer-3", "victim", 12)); !applied {
		t.Fatal("two attestations whose observers the gate admits did not cross K=2")
	}

	set("observer-1", true)
	set("observer-2", false)
	if applied, _ := s.Apply(observerAttestation(t, priv, "observer-1", "victim-2", 20)); applied {
		t.Fatal("one attestation crossed K=2")
	}
	set("observer-1", false)
	if applied, _ := s.Apply(observerAttestation(t, priv, "observer-3", "victim-2", 21)); applied {
		t.Fatal("an attestation whose observer the gate no longer admits counted toward K=2")
	}
	set("observer-1", true)
	if applied, _ := s.Apply(observerAttestation(t, priv, "observer-3", "victim-2", 22)); !applied {
		t.Fatal("an attestation held while its observer was refused did not count once the gate admits it again")
	}
}
