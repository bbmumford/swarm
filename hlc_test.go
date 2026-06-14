// Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
// Queries: licensing@hstles.com

package swarm

import (
	"sync"
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

	// The far-future remote is rejected entirely, so the clock stays at now.
	gotWall, _ := Decompose(h.state.Load())
	if gotWall != uint64(nowMs) {
		t.Fatalf("far-future remote must be rejected (clock stays at now): wall=%d, now=%d", gotWall, nowMs)
	}
}

// TestHLC_Observe_BudgetBoundary pins the inclusive `<=` budget edge: a remote
// exactly at now+budget is accepted, one millisecond past it is rejected.
func TestHLC_Observe_BudgetBoundary(t *testing.T) {
	const nowMs int64 = 1_700_000_000_000
	budget := uint64(observerForwardSkewBudget.Milliseconds())

	atEdge := hlcAt(nowMs)
	atEdge.observeAt(packHLC(uint64(nowMs)+budget, 0), nowMs)
	if w, _ := Decompose(atEdge.state.Load()); w != uint64(nowMs)+budget {
		t.Fatalf("remote exactly at the budget edge should be accepted: got %d, want %d", w, uint64(nowMs)+budget)
	}

	pastEdge := hlcAt(nowMs)
	pastEdge.observeAt(packHLC(uint64(nowMs)+budget+1, 0), nowMs)
	if w, _ := Decompose(pastEdge.state.Load()); w != uint64(nowMs) {
		t.Fatalf("remote one ms past the budget should be rejected: got %d, want %d", w, nowMs)
	}
}

// TestHLC_Observe_NeverMovesBackward confirms the monotonic invariant: an
// already-future local wall (a clock that jumped forward then back, or a
// pre-clamp state) is preserved — Observe gates the remote but never pulls the
// clock backward, which would let Now() re-issue used timestamps.
func TestHLC_Observe_NeverMovesBackward(t *testing.T) {
	const nowMs int64 = 1_700_000_000_000
	future := uint64(nowMs) + uint64((24 * time.Hour).Milliseconds())
	h := hlcAt(int64(future))

	h.observeAt(packHLC(uint64(nowMs)+1000, 0), nowMs) // in-budget remote + now, both below cur

	if w, _ := Decompose(h.state.Load()); w != future {
		t.Fatalf("Observe must not move the clock backward: got %d, want %d", w, future)
	}
}

// TestHLC_ConcurrentObserveAndNow makes the -race run meaningful: many
// goroutines hammer Observe + Now concurrently, exercising the CAS retry path.
// Afterwards Now() must still advance monotonically. Run with -race.
func TestHLC_ConcurrentObserveAndNow(t *testing.T) {
	h := NewHLC()
	var wg sync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 5000; i++ {
				if i%2 == 0 {
					h.Observe(h.Now())
				} else {
					_ = h.Now()
				}
			}
		}()
	}
	wg.Wait()

	prev := h.Now()
	for i := 0; i < 100; i++ {
		n := h.Now()
		if n <= prev {
			t.Fatalf("Now not monotonic after contention: %d then %d", prev, n)
		}
		prev = n
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
