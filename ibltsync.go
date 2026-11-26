// Copyright (c) 2026 Brandon Miller-Mumford.
// Licensed under the MIT License; see LICENSE.

package swarm

import (
	"crypto/sha256"
	"math/rand/v2"

	"github.com/bbmumford/swarm/iblt"
	pb "github.com/bbmumford/swarm/proto/pb"
)

// Set-difference repair. A MerkleProbe of a whole topic answered with the
// topic's records costs the whole topic whenever the roots differ, however
// few records differ. A prober holding at least one range's worth of records
// asks instead for an IBLT sketch (MerkleProbe.ibltCells): the responder
// sketches the version keys of its records, the prober subtracts its own
// sketch and decodes the difference, asks for the records only the responder
// holds (IBLTWant) and sends those only it holds, so the repair costs the
// difference. A sketch too small for the difference is retried four times
// larger, and past ibltMaxCells the topic is probed asking for records. A
// responder that does not know the field answers with records, so the mode
// is negotiated per probe.
const (
	ibltK          = 3    // hash functions per key
	ibltFirstCells = 128  // the first sketch a prober asks for: decodes about 85 differing records
	ibltMaxCells   = 4096 // the largest sketch asked for, answered or accepted
	ibltGrowth     = 4    // a failed decode asks next for a sketch this many times larger
)

// versionKey is the IBLT key of a stored record version: the first 16 bytes
// of SHA256 over its signable bytes and its signature, so every node holding
// that version derives the same key.
func versionKey(r Record) iblt.Key {
	h := sha256.New()
	h.Write(signableBytes(r))
	h.Write(r.Sig)
	var k iblt.Key
	copy(k[:], h.Sum(nil))
	return k
}

// ibltSlot names the outstanding sketch request to one peer for one topic.
func ibltSlot(peer NodeID, topic Topic) string { return string(peer) + "\x00" + string(topic) }

// firstSketchCells is the sketch a whole-topic probe asks for when this node
// holds held records on the topic: none below one MerkleRange's worth, whose
// records cost no more than a sketch.
func (m *merkleEngine) firstSketchCells(held int) uint32 {
	if held < m.maxRangeSize {
		return 0
	}
	return ibltFirstCells
}

// answerWithSketch answers a whole-topic probe whose root differs with an
// IBLTSketch when the prober asked for one, and reports whether it did. It
// declines, leaving HandleProbe to answer with records, for a partial range,
// a size above ibltMaxCells, or a gap between the two record counts above two
// thirds of the cells: the difference is at least that gap, and a table of m
// cells decodes about m/1.5 keys.
func (m *merkleEngine) answerWithSketch(from NodeID, p *pb.MerkleProbe) bool {
	if p.IbltCells == 0 || p.IbltCells > ibltMaxCells || p.RangeStart != nil || p.RangeEnd != nil {
		return false
	}
	recs := m.store.topicRecordsSigned(Topic(p.Topic))
	gap := int64(len(recs)) - int64(p.RecordCount)
	if gap < 0 {
		gap = -gap
	}
	if gap*3 > int64(p.IbltCells)*2 {
		return false
	}
	seed := rand.Uint64()
	t := iblt.New(int(p.IbltCells), ibltK, seed)
	for _, r := range recs {
		t.Insert(versionKey(r))
	}
	cells := make([]*pb.IBLTCell, len(t.Cells()))
	for i, c := range t.Cells() {
		cells[i] = &pb.IBLTCell{KeySum: append([]byte(nil), c.KeySum[:]...), KeyHashSum: c.KeyHashSum, Count: c.Count}
	}
	frame, err := encodeFrame(&pb.Frame{Kind: &pb.Frame_IbltSketch{IbltSketch: &pb.IBLTSketch{
		Topic: p.Topic, Cells: cells, K: ibltK, Seed: seed,
	}}})
	if err != nil {
		return false
	}
	_ = m.tport.Send(from, frame)
	return true
}

// HandleSketch decodes a sketch this node asked for against its own records
// on the topic. On success it asks for the records only the responder holds
// and sends, in MerkleRange frames of at most maxRangeSize records, those only
// it holds; the responder applies them as any repair. A failed decode probes
// again for a sketch ibltGrowth times larger, or past ibltMaxCells for
// records. A sketch nobody asked for, or of another size than asked, is
// dropped, so a peer cannot make this node hash its topics on demand.
func (m *merkleEngine) HandleSketch(from NodeID, s *pb.IBLTSketch) {
	topic := Topic(s.Topic)
	slot := ibltSlot(from, topic)
	m.ibltMu.Lock()
	asked := m.ibltAsked[slot]
	delete(m.ibltAsked, slot)
	m.ibltMu.Unlock()
	if asked == 0 || uint32(len(s.Cells)) != asked || s.K < 2 || s.K > 8 {
		return
	}
	cells := make([]iblt.Cell, len(s.Cells))
	for i, c := range s.Cells {
		if c == nil || len(c.KeySum) != len(iblt.Key{}) {
			return
		}
		copy(cells[i].KeySum[:], c.KeySum)
		cells[i].KeyHashSum = c.KeyHashSum
		cells[i].Count = c.Count
	}
	theirs := iblt.FromCells(cells, int(s.K), s.Seed)
	mine := iblt.New(len(cells), int(s.K), s.Seed)
	own := m.store.topicRecordsSigned(topic)
	byKey := make(map[iblt.Key]Record, len(own))
	for _, r := range own {
		k := versionKey(r)
		mine.Insert(k)
		byKey[k] = r
	}
	theirs.Subtract(mine)
	res := theirs.Decode()
	if !res.Complete {
		next := asked * ibltGrowth
		if next > ibltMaxCells {
			next = 0
		}
		m.sendProbeAsking(from, topic, next)
		return
	}
	if len(res.Positive) > 0 {
		keys := make([][]byte, len(res.Positive))
		for i, k := range res.Positive {
			keys[i] = append([]byte(nil), k[:]...)
		}
		if frame, err := encodeFrame(&pb.Frame{Kind: &pb.Frame_IbltWant{IbltWant: &pb.IBLTWant{Topic: s.Topic, Keys: keys}}}); err == nil {
			_ = m.tport.Send(from, frame)
		}
	}
	var push []Record
	for _, k := range res.Negative {
		if r, ok := byKey[k]; ok {
			push = append(push, r)
		}
	}
	m.sendRecords(from, topic, push)
}

// HandleWant answers an IBLTWant with the records it holds whose version keys
// were asked for, in MerkleRange frames of at most maxRangeSize records. A
// request naming more than ibltMaxCells keys, more than any sketch decodes,
// is dropped.
func (m *merkleEngine) HandleWant(from NodeID, w *pb.IBLTWant) {
	if len(w.Keys) == 0 || len(w.Keys) > ibltMaxCells {
		return
	}
	want := make(map[iblt.Key]bool, len(w.Keys))
	for _, b := range w.Keys {
		if len(b) != len(iblt.Key{}) {
			return
		}
		var k iblt.Key
		copy(k[:], b)
		want[k] = true
	}
	topic := Topic(w.Topic)
	var out []Record
	for _, r := range m.store.topicRecordsSigned(topic) {
		if want[versionKey(r)] {
			out = append(out, r)
		}
	}
	m.sendRecords(from, topic, out)
}

// sendRecords sends recs in untruncated MerkleRange frames of at most
// maxRangeSize records each.
func (m *merkleEngine) sendRecords(to NodeID, topic Topic, recs []Record) {
	for len(recs) > 0 {
		n := len(recs)
		if n > m.maxRangeSize {
			n = m.maxRangeSize
		}
		m.sendRange(to, topic, recs[:n], false)
		recs = recs[n:]
	}
}
