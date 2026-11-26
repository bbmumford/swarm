// Copyright (c) 2026 Brandon Miller-Mumford.
// Licensed under the MIT License; see LICENSE.

package swarm

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"testing"

	pb "github.com/bbmumford/swarm/proto/pb"
)

// highestCounterWins is a stateful merge: the body is a big-endian counter,
// the higher counter wins whatever its HLC, and HLC then the signature break
// ties, so it is a strict order over a slot's records.
func highestCounterWins(cur, in Record) bool {
	ci, ii := binary.BigEndian.Uint64(cur.Body), binary.BigEndian.Uint64(in.Body)
	if ii != ci {
		return ii > ci
	}
	if in.HLC != cur.HLC {
		return in.HLC > cur.HLC
	}
	return bytes.Compare(in.Sig, cur.Sig) > 0
}

func counterRecord(t *testing.T, priv ed25519.PrivateKey, id NodeID, topic Topic, hlc, counter uint64) Record {
	t.Helper()
	body := make([]byte, 8)
	binary.BigEndian.PutUint64(body, counter)
	return signedRecord(topic, priv, id, hlc, body)
}

func mergeStore(t *testing.T) *recordStore {
	t.Helper()
	s := newRecordStore()
	s.setMerge(func(topic Topic) MergeFunc {
		if topic == "ledger.counter" {
			return highestCounterWins
		}
		return nil
	})
	return s
}

// TestTopicMergeDecidesTheSlot: on a topic with a merge, a record with the
// higher counter keeps its slot against a later-stamped one, in either
// arrival order; a topic without a merge keeps the highest HLC.
func TestTopicMergeDecidesTheSlot(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	id := nodeIDFromPub(pub)
	early := counterRecord(t, priv, id, "ledger.counter", 10, 5) // older stamp, higher counter
	late := counterRecord(t, priv, id, "ledger.counter", 20, 3)

	for _, order := range [][2]Record{{early, late}, {late, early}} {
		s := mergeStore(t)
		s.Apply(order[0])
		s.Apply(order[1])
		got, ok := s.getRaw("ledger.counter", id)
		if !ok || got.HLC != 10 {
			t.Fatalf("merge topic, arrival order HLC %d then %d: slot holds HLC %d, want 10 (counter 5)", order[0].HLC, order[1].HLC, got.HLC)
		}
	}

	plainEarly := counterRecord(t, priv, id, "plain", 10, 5)
	plainLate := counterRecord(t, priv, id, "plain", 20, 3)
	s := mergeStore(t)
	s.Apply(plainEarly)
	s.Apply(plainLate)
	if got, _ := s.getRaw("plain", id); got.HLC != 20 {
		t.Fatalf("a topic without a merge keeps the highest HLC: got %d, want 20", got.HLC)
	}
}

// TestTopicMergeGraftsAnAnnouncedLowerStamp: on a merge topic an IHave
// announcing a lower stamp than the one held may still carry the winner, so it
// is grafted; on a plain topic it is skipped, since the held stamp wins.
func TestTopicMergeGraftsAnAnnouncedLowerStamp(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	id := nodeIDFromPub(pub)
	for _, c := range []struct {
		topic Topic
		want  bool
	}{{"ledger.counter", true}, {"plain", false}} {
		s := mergeStore(t)
		s.Apply(counterRecord(t, priv, id, c.topic, 20, 3))
		e := newPlumtrees("self", s, newPeerTable(nil), nil, NewHLC(), 4, nil, 0)
		if err := e.handleIHave("peer", &pb.IHave{Topic: string(c.topic), NodeId: []byte(id), Hlc: 10}); err != nil {
			t.Fatal(err)
		}
		e.missingMu.Lock()
		_, pending := e.missingIHaves[ihaveKey{c.topic, id, "", 10}]
		e.missingMu.Unlock()
		if pending != c.want {
			t.Fatalf("topic %s: IHave of a lower stamp pending a graft = %v, want %v", c.topic, pending, c.want)
		}
	}
}
