// Copyright (c) 2026 Brandon Miller-Mumford.
// Licensed under the MIT License; see LICENSE.

package swarm

import (
	"sync/atomic"
	"time"
)

// HLC is a Hybrid Logical Clock. It encodes wall-clock-ish ordering with
// a tie-break counter so concurrent events at the same wall time get
// distinct, totally-ordered timestamps.
//
// Encoding: high 48 bits = unix milliseconds, low 16 bits = counter (Pack
// and Decompose). The wall portion wraps every ~8900 years; the counter
// resets each millisecond, and a counter that is full within one
// millisecond carries into the next millisecond, so a stamp never falls
// below the one before it.
//
// HLC.Now() is monotonic — never decreases even if wall clock jumps back.
// Receivers update via HLC.Observe() before stamping local records.
//
// swarm stamps its records with it; packages that keep their own stamp
// format fill that format from an HLC (reach's signed records, minerva's
// CRDT stamps).
type HLC struct {
	state atomic.Uint64
	// now reads the wall clock; nil reads time.Now.
	now func() time.Time
}

// maxCounter is the largest value the 16-bit counter holds.
const maxCounter = 0xFFFF

// NewHLC creates an HLC anchored at the current wall time.
func NewHLC() *HLC {
	return NewHLCWithNow(nil)
}

// NewHLCWithNow creates an HLC that reads its wall clock from now (nil reads
// time.Now), anchored at now's current time. Now and Observe both read it, so
// a caller that injects a clock (reach's Clock, a test that freezes or rewinds
// the wall) gets the same stamps and the same forward-skew bound as one on the
// real clock.
func NewHLCWithNow(now func() time.Time) *HLC {
	h := &HLC{now: now}
	h.state.Store(packHLC(h.wallMs(), 0))
	return h
}

// wallMs is the wall clock in unix milliseconds.
func (h *HLC) wallMs() uint64 {
	if h.now == nil {
		return uint64(time.Now().UnixMilli())
	}
	return uint64(h.now().UnixMilli())
}

// Now returns the next monotonic HLC value, advancing both the wall and
// counter components as needed.
func (h *HLC) Now() uint64 {
	for {
		cur := h.state.Load()
		curWall, curCtr := unpackHLC(cur)
		nowWall := h.wallMs()

		var nextWall, nextCtr uint64
		switch {
		case nowWall > curWall:
			nextWall = nowWall
			nextCtr = 0
		case curCtr < maxCounter:
			nextWall = curWall
			nextCtr = curCtr + 1
		default:
			// The counter is full for this millisecond: packing curCtr+1
			// would drop it to 0 and return a stamp below cur, so the
			// stamp moves to the next millisecond instead.
			nextWall = curWall + 1
			nextCtr = 0
		}
		next := packHLC(nextWall, nextCtr)
		if h.state.CompareAndSwap(cur, next) {
			return next
		}
	}
}

// Observe updates the HLC after seeing a remote timestamp. Ensures local
// future stamps are strictly greater than the observed value.
func (h *HLC) Observe(remote uint64) {
	h.observeAt(remote, int64(h.wallMs()))
}

// observeAt is Observe with the wall clock injected (nowMs), so the
// forward-skew clamp is testable without stubbing time.
//
// The remote wall component is only allowed to advance the local clock when
// it is within observerForwardSkewBudget of nowMs. A peer that gossips a
// far-future wall time — malicious, or badly clock-skewed — must not ratchet
// the local HLC permanently forward: once the wall component is pushed years
// ahead, Now() can never advance the wall again (now stays below it), so
// every later stamp is issued from that far-future wall instead of real time,
// and every node that observes one of those stamps is pushed the same way.
// Gating the remote against the same forward-skew budget the attestation path
// uses (crdt.go) closes that vector while still tolerating legitimate
// cross-region clock skew.
func (h *HLC) observeAt(remote uint64, nowMs int64) {
	skewMs := uint64(observerForwardSkewBudget.Milliseconds())
	nowWall := uint64(nowMs)
	for {
		cur := h.state.Load()
		curWall, curCtr := unpackHLC(cur)
		remoteWall, remoteCtr := unpackHLC(remote)

		// Pick max of (cur, now) and — only when in budget — remote.
		maxWall := curWall
		maxCtr := curCtr
		if remoteWall <= nowWall+skewMs {
			if remoteWall > maxWall || (remoteWall == maxWall && remoteCtr > maxCtr) {
				maxWall = remoteWall
				maxCtr = remoteCtr
			}
		}
		if nowWall > maxWall {
			maxWall = nowWall
			maxCtr = 0
		}
		// We don't bump counter here — that's Now()'s job.

		next := packHLC(maxWall, maxCtr)
		if h.state.CompareAndSwap(cur, next) {
			return
		}
	}
}

// Decompose returns (wallMillis, counter) for the given HLC value.
func Decompose(h uint64) (wallMillis uint64, counter uint16) {
	w, c := unpackHLC(h)
	return w, uint16(c)
}

// Pack returns the HLC value for (wallMillis, counter), the inverse of
// Decompose. A package that carries the clock in its own format converts a
// stamp it receives with Pack before passing it to Observe.
func Pack(wallMillis uint64, counter uint16) uint64 {
	return packHLC(wallMillis, uint64(counter))
}

func packHLC(wall, ctr uint64) uint64 {
	return (wall << 16) | (ctr & 0xFFFF)
}

func unpackHLC(h uint64) (wall, ctr uint64) {
	return h >> 16, h & 0xFFFF
}
