// Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
// Queries: licensing@hstles.com

package sim

import (
	"container/heap"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/rand"
	"sort"
	"sync"
	"time"
)

// VirtualTime is the simulator's clock. One tick = 1 ms by default.
type VirtualTime int64

// NodeID is an opaque per-simulated-peer identifier.
type NodeID string

// Frame is the on-wire payload between simulated nodes. Body is opaque to
// the simulator — typically a serialized swarm.Frame.
type Frame struct {
	From NodeID
	To   NodeID
	Body []byte
}

// Edge describes a directed link between two nodes.
type Edge struct {
	From      NodeID
	To        NodeID
	LatencyMs int     // base latency in ms
	JitterMs  int     // +/- ms random jitter
	LossPct   float64 // 0.0 - 1.0
	BandwidthBps uint64 // 0 = unlimited
}

// Node represents a participant in the simulation. The Step method drives
// the node by one virtual tick; Receive is called by the Mesh when a
// frame arrives. SwarmNode wraps a real swarm.Node behind this interface;
// StubNode is a flooding fallback retained for simulator smoke tests.
type Node interface {
	ID() NodeID
	Step(now VirtualTime) (out []Frame, err error)
	Receive(now VirtualTime, frame Frame) error

	// Records returns a debug snapshot of the local record store, indexed
	// by topic. Used by tests to assert convergence.
	Records() map[string][]Record
}

// Record is a debug-friendly mirror of swarm.Record for test assertions.
type Record struct {
	Topic     string
	NodeID    NodeID
	HLC       uint64
	Body      []byte
	Tombstone bool
}

// Mesh is the simulated network. Holds N Nodes connected by directed
// Edges. Step(t) advances the clock by 1 ms, fires each Node's Step, and
// delivers any frames whose latency has elapsed.
type Mesh struct {
	mu          sync.Mutex
	nodes       map[NodeID]Node
	edges       map[NodeID]map[NodeID]Edge // edges[from][to]
	pendingFrames pendingHeap                // min-heap by deliveryAt
	now         VirtualTime
	rng         *rand.Rand
}

// pendingFrame is a Frame scheduled for delivery.
type pendingFrame struct {
	deliveryAt VirtualTime
	frame      Frame
	index      int // heap index
}

// NewMesh creates an empty mesh.
func NewMesh(seed int64) *Mesh {
	return &Mesh{
		nodes:         make(map[NodeID]Node),
		edges:         make(map[NodeID]map[NodeID]Edge),
		pendingFrames: pendingHeap{},
		rng:           rand.New(rand.NewSource(seed)),
	}
}

// AddNode registers a Node in the mesh.
func (m *Mesh) AddNode(n Node) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nodes[n.ID()] = n
}

// AddEdge adds a directed edge between two nodes. Use two AddEdge calls
// for bidirectional links.
func (m *Mesh) AddEdge(e Edge) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.edges[e.From] == nil {
		m.edges[e.From] = make(map[NodeID]Edge)
	}
	m.edges[e.From][e.To] = e
}

// FullMesh adds bidirectional edges between every pair of nodes with the
// given default link properties. Useful for small convergence tests.
func (m *Mesh) FullMesh(latencyMs, jitterMs int, lossPct float64) {
	ids := m.NodeIDs()
	for _, a := range ids {
		for _, b := range ids {
			if a == b {
				continue
			}
			m.AddEdge(Edge{From: a, To: b, LatencyMs: latencyMs, JitterMs: jitterMs, LossPct: lossPct})
		}
	}
}

// NodeIDs returns the sorted set of all NodeIDs in the mesh.
func (m *Mesh) NodeIDs() []NodeID {
	m.mu.Lock()
	defer m.mu.Unlock()
	ids := make([]NodeID, 0, len(m.nodes))
	for id := range m.nodes {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids
}

// Now returns the current virtual clock value.
func (m *Mesh) Now() VirtualTime {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.now
}

// Step advances the virtual clock by 1 ms, calls Step on every node, and
// delivers any frames whose delivery time has arrived.
//
// Returns a snapshot summary for tests to inspect: frames in flight,
// frames delivered this tick, errors encountered.
func (m *Mesh) Step() (StepSummary, error) {
	m.mu.Lock()
	m.now++
	now := m.now
	nodes := make([]Node, 0, len(m.nodes))
	for _, n := range m.nodes {
		nodes = append(nodes, n)
	}
	m.mu.Unlock()

	sort.Slice(nodes, func(i, j int) bool { return nodes[i].ID() < nodes[j].ID() })

	summary := StepSummary{Now: now}

	// Fire Step on every node; collect outbound frames.
	for _, n := range nodes {
		out, err := n.Step(now)
		if err != nil {
			summary.Errors = append(summary.Errors, fmt.Errorf("step %s: %w", n.ID(), err))
		}
		for _, f := range out {
			m.sendFrame(now, f)
			summary.FramesSent++
		}
	}

	// Deliver any pending frames whose time has come.
	m.mu.Lock()
	defer m.mu.Unlock()

	for m.pendingFrames.Len() > 0 {
		head := m.pendingFrames[0]
		if head.deliveryAt > now {
			break
		}
		heap.Pop(&m.pendingFrames)
		target, ok := m.nodes[head.frame.To]
		if !ok {
			continue
		}
		if err := target.Receive(now, head.frame); err != nil {
			summary.Errors = append(summary.Errors, fmt.Errorf("recv %s<-%s: %w", head.frame.To, head.frame.From, err))
		}
		summary.FramesDelivered++
	}

	summary.FramesInFlight = m.pendingFrames.Len()
	return summary, nil
}

// Run steps the mesh until the predicate returns true or maxSteps is reached.
func (m *Mesh) Run(maxSteps int, predicate func(*Mesh) bool) (int, error) {
	for i := 0; i < maxSteps; i++ {
		if predicate(m) {
			return i, nil
		}
		if _, err := m.Step(); err != nil {
			return i, err
		}
	}
	return maxSteps, errors.New("sim: maxSteps reached without convergence")
}

// sendFrame schedules a frame for delivery according to its edge properties.
// Mesh.mu must be held by caller.
func (m *Mesh) sendFrame(now VirtualTime, f Frame) {
	m.mu.Lock()
	defer m.mu.Unlock()

	edge, ok := m.edges[f.From][f.To]
	if !ok {
		// No edge: silently drop. Production simulator would log this; in
		// the cold-start test, peers only send to known edges.
		return
	}

	// Apply loss.
	if edge.LossPct > 0 && m.rng.Float64() < edge.LossPct {
		return
	}

	// Compute delivery time: latency +/- jitter.
	delay := VirtualTime(edge.LatencyMs)
	if edge.JitterMs > 0 {
		delay += VirtualTime(m.rng.Intn(2*edge.JitterMs+1) - edge.JitterMs)
	}
	if delay < 1 {
		delay = 1
	}

	heap.Push(&m.pendingFrames, &pendingFrame{
		deliveryAt: now + delay,
		frame:      f,
	})
}

// StepSummary is the per-tick result returned by Step.
type StepSummary struct {
	Now             VirtualTime
	FramesSent      int
	FramesDelivered int
	FramesInFlight  int
	Errors          []error
}

// ---------- heap impl ----------

type pendingHeap []*pendingFrame

func (h pendingHeap) Len() int           { return len(h) }
func (h pendingHeap) Less(i, j int) bool { return h[i].deliveryAt < h[j].deliveryAt }
func (h pendingHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].index = i
	h[j].index = j
}
func (h *pendingHeap) Push(x any) {
	n := len(*h)
	pf := x.(*pendingFrame)
	pf.index = n
	*h = append(*h, pf)
}
func (h *pendingHeap) Pop() any {
	old := *h
	n := len(old)
	pf := old[n-1]
	pf.index = -1
	*h = old[:n-1]
	return pf
}

// ---------- helpers ----------

// HashFrame returns a stable SHA256 of a Frame body for dedup in tests.
func HashFrame(f Frame) [32]byte {
	return sha256.Sum256(f.Body)
}

// Duration converts VirtualTime to time.Duration (1 tick = 1ms).
func (v VirtualTime) Duration() time.Duration {
	return time.Duration(v) * time.Millisecond
}
