// Copyright (c) 2026 Brandon Miller-Mumford.
// Licensed under the MIT License; see LICENSE.

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
// forward. Without the clamp, observing such a value pushes the wall component
// years ahead, and every later stamp is issued from that wall instead of real
// time. The injected clock makes this
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

// TestHLC_Now_CarriesAFullCounterIntoTheWall pins the counter's upper edge: a
// stamp whose 16-bit counter is full (here an in-budget remote adopted by
// Observe) is followed by the first stamp of the next millisecond. Packing
// counter+1 there would drop it to 0 and issue a stamp below the one observed,
// which every slot's highest-HLC-wins merge would then order wrongly.
func TestHLC_Now_CarriesAFullCounterIntoTheWall(t *testing.T) {
	h := NewHLC()
	wall, _ := Decompose(h.Now())
	ahead := wall + 60_000 // one minute ahead: inside the forward-skew budget
	full := packHLC(ahead, 0xFFFF)
	h.Observe(full)

	next := h.Now()
	if next <= full {
		w, c := Decompose(next)
		t.Fatalf("the stamp after a full counter must exceed it: got wall %d counter %d, after wall %d counter 65535", w, c, ahead)
	}
	if w, c := Decompose(next); w != ahead+1 || c != 0 {
		t.Fatalf("a full counter carries into the next millisecond: got wall %d counter %d, want wall %d counter 0", w, c, ahead+1)
	}
}

// TestHLCWithNow_FrozenWallStaysMonotonic issues more stamps than the counter
// holds while the injected wall never moves: each is greater than the last,
// and the stamp after the 65,535th of the millisecond is in the next one.
func TestHLCWithNow_FrozenWallStaysMonotonic(t *testing.T) {
	frozen := time.UnixMilli(1_700_000_000_000)
	h := NewHLCWithNow(func() time.Time { return frozen })
	prev := h.Now()
	for i := 0; i < 70_000; i++ {
		next := h.Now()
		if next <= prev {
			pw, pc := Decompose(prev)
			nw, nc := Decompose(next)
			t.Fatalf("stamp %d not above the one before: wall %d counter %d then wall %d counter %d", i, pw, pc, nw, nc)
		}
		prev = next
	}
	if w, _ := Decompose(prev); w != 1_700_000_000_001 {
		t.Fatalf("70,001 stamps in one frozen millisecond should end in the next one: got wall %d", w)
	}
}

// TestHLCWithNow_ReadsTheInjectedWall checks that Now and Observe both read the
// injected clock: the first stamp is at the injected millisecond, and a remote
// one millisecond past the forward-skew budget of the injected time is
// refused even though real time is years later.
func TestHLCWithNow_ReadsTheInjectedWall(t *testing.T) {
	const nowMs int64 = 1_700_000_000_000
	h := NewHLCWithNow(func() time.Time { return time.UnixMilli(nowMs) })
	if w, c := Decompose(h.Now()); w != uint64(nowMs) || c != 1 {
		t.Fatalf("first stamp of an injected clock: got wall %d counter %d, want wall %d counter 1", w, c, nowMs)
	}
	budget := uint64(observerForwardSkewBudget.Milliseconds())
	h.Observe(packHLC(uint64(nowMs)+budget+1, 0))
	if w, _ := Decompose(h.Now()); w != uint64(nowMs) {
		t.Fatalf("a remote past the budget of the injected wall must be refused: got wall %d, want %d", w, nowMs)
	}
}

// TestPack_IsDecomposesInverse pins the packed layout a package converting its
// own stamps relies on.
func TestPack_IsDecomposesInverse(t *testing.T) {
	for _, c := range []struct {
		wall uint64
		ctr  uint16
	}{{0, 0}, {1_700_000_000_000, 0}, {1_700_000_000_000, 0xFFFF}, {1<<48 - 1, 7}} {
		v := Pack(c.wall, c.ctr)
		if v != c.wall<<16|uint64(c.ctr) {
			t.Fatalf("Pack(%d, %d) = %d, want wall<<16|counter", c.wall, c.ctr, v)
		}
		if w, ctr := Decompose(v); w != c.wall || ctr != c.ctr {
			t.Fatalf("Decompose(Pack(%d, %d)) = (%d, %d)", c.wall, c.ctr, w, ctr)
		}
	}
}
