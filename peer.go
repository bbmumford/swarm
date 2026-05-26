// Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
// Queries: licensing@hstles.com

package swarm

import (
	"sync"
	"time"
)

// peerCtx is per-peer state owned by the swarm engine. It holds the
// adaptive interval / backpressure / RTT data plus the PerPeerConfig
// snapshot used by the Plumtrees tree-edge picker.
type peerCtx struct {
	id NodeID

	mu sync.RWMutex

	// Configuration (from Config.PerPeerConfig or PerPeerOverride)
	cfg PerPeerConfig

	// Adaptive state
	lastRTT       time.Duration
	rttEMA        time.Duration // exponential moving average
	missedKeepalives int

	// Backpressure
	lazyQueue     []lazyEntry // pending IHave announcements to this peer
	lastEagerSent time.Time

	// Liveness
	lastSeen   time.Time
	lastSentAt time.Time

	// Tree-edge state (Plumtrees)
	isTreeEdge bool // true if we eagerly push to this peer

	// Token bucket for BandwidthCap. tokens carries the remaining
	// bytes-per-second budget; lastRefill is the time of the last
	// refill. When BandwidthCap is 0 the bucket is bypassed.
	tokens     int64
	lastRefill time.Time
}

type lazyEntry struct {
	topic    Topic
	nodeID   NodeID
	hlc      uint64
	bodyHash [32]byte
	queuedAt time.Time
}

// peerTable holds the live set of peers known to this Node.
type peerTable struct {
	mu       sync.RWMutex
	ctxBy    map[NodeID]*peerCtx
	configFn func(NodeID) PerPeerConfig
}

func newPeerTable(configFn func(NodeID) PerPeerConfig) *peerTable {
	if configFn == nil {
		configFn = func(NodeID) PerPeerConfig { return DefaultPerPeerConfig() }
	}
	return &peerTable{
		ctxBy:    make(map[NodeID]*peerCtx),
		configFn: configFn,
	}
}

// Ensure returns the peerCtx for id, creating it if needed.
func (pt *peerTable) Ensure(id NodeID) *peerCtx {
	pt.mu.Lock()
	defer pt.mu.Unlock()
	p, ok := pt.ctxBy[id]
	if !ok {
		p = &peerCtx{
			id:       id,
			cfg:      pt.configFn(id),
			lastSeen: time.Now(),
		}
		pt.ctxBy[id] = p
	}
	return p
}

// Remove drops a peer from the table (e.g. on disconnect).
func (pt *peerTable) Remove(id NodeID) {
	pt.mu.Lock()
	defer pt.mu.Unlock()
	delete(pt.ctxBy, id)
}

// All returns a snapshot of all peer IDs.
func (pt *peerTable) All() []NodeID {
	pt.mu.RLock()
	defer pt.mu.RUnlock()
	out := make([]NodeID, 0, len(pt.ctxBy))
	for id := range pt.ctxBy {
		out = append(out, id)
	}
	return out
}

// TreeEdges returns the subset of peers that are currently tree edges.
func (pt *peerTable) TreeEdges() []NodeID {
	pt.mu.RLock()
	defer pt.mu.RUnlock()
	out := make([]NodeID, 0)
	for id, p := range pt.ctxBy {
		p.mu.RLock()
		if p.isTreeEdge {
			out = append(out, id)
		}
		p.mu.RUnlock()
	}
	return out
}

// NonTreeEdges returns the subset that are NOT tree edges (lazy-push targets).
func (pt *peerTable) NonTreeEdges() []NodeID {
	pt.mu.RLock()
	defer pt.mu.RUnlock()
	out := make([]NodeID, 0)
	for id, p := range pt.ctxBy {
		p.mu.RLock()
		if !p.isTreeEdge {
			out = append(out, id)
		}
		p.mu.RUnlock()
	}
	return out
}

// SetTreeEdge atomically updates a peer's tree-edge flag.
func (pt *peerTable) SetTreeEdge(id NodeID, isEdge bool) {
	p := pt.Ensure(id)
	p.mu.Lock()
	defer p.mu.Unlock()
	p.isTreeEdge = isEdge
}

// Snapshot returns a copy of one peer's PerPeerConfig (for inspection).
func (pt *peerTable) Snapshot(id NodeID) PerPeerConfig {
	pt.mu.RLock()
	defer pt.mu.RUnlock()
	p, ok := pt.ctxBy[id]
	if !ok {
		return pt.configFn(id)
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.cfg
}

// LazyQueueDepth returns the number of pending IHave entries queued to
// this peer. Used by the Plumtrees lazy-push path to apply
// BackpressureMax.
func (pt *peerTable) LazyQueueDepth(id NodeID) int {
	pt.mu.RLock()
	p, ok := pt.ctxBy[id]
	pt.mu.RUnlock()
	if !ok {
		return 0
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.lazyQueue)
}

// EnqueueLazy appends an entry to the peer's lazy-push queue. Returns
// true if accepted, false if the queue is at BackpressureMax and the
// entry should be dropped. Entries older than maxAge are pruned before
// the cap check, so BackpressureMax acts as "max recent IHaves to this
// peer in the maxAge window" — preventing chatter to slow peers while
// letting the queue refill once they catch up.
//
// nowFn lets the simulator drive the prune clock; nil uses time.Now.
func (pt *peerTable) EnqueueLazy(id NodeID, e lazyEntry, maxAge time.Duration, nowFn func() time.Time) bool {
	p := pt.Ensure(id)
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	if nowFn != nil {
		now = nowFn()
	}
	if maxAge > 0 {
		cutoff := now.Add(-maxAge)
		i := 0
		for ; i < len(p.lazyQueue); i++ {
			if !p.lazyQueue[i].queuedAt.Before(cutoff) {
				break
			}
		}
		if i > 0 {
			p.lazyQueue = p.lazyQueue[i:]
		}
	}
	if p.cfg.BackpressureMax > 0 && len(p.lazyQueue) >= p.cfg.BackpressureMax {
		return false
	}
	e.queuedAt = now
	p.lazyQueue = append(p.lazyQueue, e)
	return true
}

// DrainLazy returns and clears all queued lazy entries for the peer.
// Used by the periodic lazy-push flush.
func (pt *peerTable) DrainLazy(id NodeID) []lazyEntry {
	pt.mu.RLock()
	p, ok := pt.ctxBy[id]
	pt.mu.RUnlock()
	if !ok {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	out := p.lazyQueue
	p.lazyQueue = nil
	return out
}

// ConsumeTokens attempts to spend `cost` bytes of bandwidth budget on
// the peer's token bucket. Returns true if granted, false when the
// bucket is exhausted and the caller should drop or defer the send.
// A BandwidthCap of 0 means unlimited — always grants.
//
// nowFn lets the simulator inject virtual time so token refills track
// the simulated clock instead of wall-clock.
func (pt *peerTable) ConsumeTokens(id NodeID, cost int64, nowFn func() time.Time) bool {
	if cost <= 0 {
		return true
	}
	p := pt.Ensure(id)
	p.mu.Lock()
	defer p.mu.Unlock()
	cap := int64(p.cfg.BandwidthCap)
	if cap == 0 {
		return true
	}
	now := time.Now()
	if nowFn != nil {
		now = nowFn()
	}
	if p.lastRefill.IsZero() {
		p.tokens = int64(p.cfg.EgressTokens)
		if p.tokens == 0 {
			p.tokens = cap
		}
		p.lastRefill = now
	}
	elapsed := now.Sub(p.lastRefill)
	if elapsed > 0 {
		add := cap * int64(elapsed) / int64(time.Second)
		if add > 0 {
			p.tokens += add
			if p.tokens > cap {
				p.tokens = cap
			}
			p.lastRefill = now
		}
	}
	if p.tokens < cost {
		return false
	}
	p.tokens -= cost
	return true
}
