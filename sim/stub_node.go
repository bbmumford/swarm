// Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
// Queries: licensing@hstles.com

package sim

import (
	"crypto/sha256"
	"encoding/json"
	"sync"
)

// StubNode is a minimal flooding Node implementation. Every received
// Record is forwarded to every neighbor that has not seen it yet.
// Useful as a baseline reference for simulator wiring; the real
// Plumtrees engine lives behind SwarmNode.
type StubNode struct {
	id        NodeID
	peers     []NodeID
	mu        sync.Mutex
	records   map[string]map[NodeID]Record // records[topic][node_id]
	pending   []Frame                       // outbound queue
	delivered map[[32]byte]struct{}         // dedup hashes
}

// NewStubNode creates a StubNode with the given ID + peer list.
func NewStubNode(id NodeID, peers []NodeID) *StubNode {
	return &StubNode{
		id:        id,
		peers:     peers,
		records:   make(map[string]map[NodeID]Record),
		delivered: make(map[[32]byte]struct{}),
	}
}

// ID implements Node.
func (n *StubNode) ID() NodeID { return n.id }

// Publish enqueues a Record to be broadcast on next Step.
func (n *StubNode) Publish(topic string, hlc uint64, body []byte) {
	n.mu.Lock()
	defer n.mu.Unlock()

	r := Record{
		Topic:  topic,
		NodeID: n.id,
		HLC:    hlc,
		Body:   body,
	}
	if n.records[topic] == nil {
		n.records[topic] = make(map[NodeID]Record)
	}
	n.records[topic][n.id] = r

	// Enqueue to all peers
	payload := encodeRecord(r)
	for _, peer := range n.peers {
		if peer == n.id {
			continue
		}
		n.pending = append(n.pending, Frame{From: n.id, To: peer, Body: payload})
	}
	n.delivered[sha256.Sum256(payload)] = struct{}{}
}

// Step implements Node.
func (n *StubNode) Step(now VirtualTime) ([]Frame, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	out := n.pending
	n.pending = nil
	return out, nil
}

// Receive implements Node. Flooding: forward to peers that haven't seen
// this exact payload yet.
func (n *StubNode) Receive(now VirtualTime, f Frame) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	hash := sha256.Sum256(f.Body)
	if _, seen := n.delivered[hash]; seen {
		return nil
	}
	n.delivered[hash] = struct{}{}

	r, err := decodeRecord(f.Body)
	if err != nil {
		return err
	}
	if n.records[r.Topic] == nil {
		n.records[r.Topic] = make(map[NodeID]Record)
	}
	// HLC monotonicity: newer wins
	if existing, ok := n.records[r.Topic][r.NodeID]; !ok || r.HLC > existing.HLC {
		n.records[r.Topic][r.NodeID] = r
	}

	// Forward to peers
	for _, peer := range n.peers {
		if peer == n.id || peer == f.From {
			continue
		}
		n.pending = append(n.pending, Frame{From: n.id, To: peer, Body: f.Body})
	}
	return nil
}

// Records implements Node.
func (n *StubNode) Records() map[string][]Record {
	n.mu.Lock()
	defer n.mu.Unlock()
	out := make(map[string][]Record, len(n.records))
	for topic, byNode := range n.records {
		recs := make([]Record, 0, len(byNode))
		for _, r := range byNode {
			recs = append(recs, r)
		}
		out[topic] = recs
	}
	return out
}

// ---------- record codec ----------

type wireRecord struct {
	Topic     string `json:"t"`
	NodeID    string `json:"n"`
	HLC       uint64 `json:"h"`
	Body      []byte `json:"b,omitempty"`
	Tombstone bool   `json:"d,omitempty"`
}

func encodeRecord(r Record) []byte {
	b, _ := json.Marshal(wireRecord{
		Topic:     r.Topic,
		NodeID:    string(r.NodeID),
		HLC:       r.HLC,
		Body:      r.Body,
		Tombstone: r.Tombstone,
	})
	return b
}

func decodeRecord(data []byte) (Record, error) {
	var w wireRecord
	if err := json.Unmarshal(data, &w); err != nil {
		return Record{}, err
	}
	return Record{
		Topic:     w.Topic,
		NodeID:    NodeID(w.NodeID),
		HLC:       w.HLC,
		Body:      w.Body,
		Tombstone: w.Tombstone,
	}, nil
}
