// Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
// Queries: licensing@hstles.com

package swarm

import (
	"testing"
	"time"
)

// hlcAt returns an HLC seeded to a fixed wall-millisecond so the injected
// clock in observeAt fully controls the test (NewHLC anchors to real now).
func hlcAt(wallMs int64) *HLC {
	h := &HLC{}
	h.state.Store(packHLC(uint64(wallMs), 0))
	return h
}

func TestHLC_Now_Monotonic(t *testing.T) {
	h := NewHLC()
	prev := h.Now()
	for i := 0; i < 2000; i++ {
		next := h.Now()
		if next <= prev {
			t.Fatalf("Now not monotonic at %d: %d then %d", i, prev, next)
		}
		prev = next
	}
}

// TestHLC_Observe_RejectsFarFutureWall is the security guard: a peer that
// gossips a wall-clock far in the future must NOT ratchet the local HLC
// forward. Before the clamp, observing such a value pushed the wall component
// years ahead, after which Now() could only bump the 16-bit counter (wrapping
// at 65536 events in the same wall ms). The injected clock makes this
// deterministic: the resulting wall must stay at the fixed "now", not the
// far-future value.
func TestHLC_Observe_RejectsFarFutureWall(t *testing.T) {
	const nowMs int64 = 1_700_000_000_000
	h := hlcAt(nowMs)
	farFuture := uint64(nowMs) + uint64((10 * 365 * 24 * time.Hour).Milliseconds())

	h.observeAt(packHLC(farFuture, 0), nowMs)

	gotWall, _ := Decompose(h.state.Load())
	if gotWall > uint64(nowMs)+uint64(observerForwardSkewBudget.Milliseconds()) {
		t.Fatalf("far-future remote ratcheted the HLC: wall=%d, now=%d", gotWall, nowMs)
	}
}

// TestHLC_Observe_AcceptsInBudgetFuture confirms a remote within the
// forward-skew budget still advances the clock (legitimate cross-region skew
// is tolerated, and causality is preserved).
func TestHLC_Observe_AcceptsInBudgetFuture(t *testing.T) {
	const nowMs int64 = 1_700_000_000_000
	h := hlcAt(nowMs)
	inBudget := uint64(nowMs) + uint64(observerForwardSkewBudget.Milliseconds())/2

	h.observeAt(packHLC(inBudget, 0), nowMs)

	gotWall, _ := Decompose(h.state.Load())
	if gotWall != inBudget {
		t.Fatalf("in-budget remote should advance the wall to %d, got %d", inBudget, gotWall)
	}
}

// TestHLC_Observe_LocalExceedsRemote confirms the causality guarantee for an
// in-budget remote: a subsequent local stamp is strictly greater.
func TestHLC_Observe_LocalExceedsRemote(t *testing.T) {
	h := NewHLC()
	remote := h.Now() + (uint64(5) << 16) // 5 ms ahead — within budget
	h.Observe(remote)
	if got := h.Now(); got <= remote {
		t.Fatalf("after Observe(%d), Now()=%d must be greater", remote, got)
	}
}
