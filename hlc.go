// Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
// Queries: licensing@hstles.com

package swarm

import (
	"sync/atomic"
	"time"
)

// HLC is a Hybrid Logical Clock. It encodes wall-clock-ish ordering with
// a tie-break counter so concurrent events at the same wall time get
// distinct, totally-ordered timestamps.
//
// Encoding: high 48 bits = unix milliseconds, low 16 bits = counter.
// Wraps every ~8900 years for the wall portion; counter resets every ms.
//
// HLC.Now() is monotonic — never decreases even if wall clock jumps back.
// Receivers update via HLC.Observe() before stamping local records.
type HLC struct {
	state atomic.Uint64
}

// NewHLC creates an HLC anchored at the current wall time.
func NewHLC() *HLC {
	h := &HLC{}
	h.state.Store(packHLC(uint64(time.Now().UnixMilli()), 0))
	return h
}

// Now returns the next monotonic HLC value, advancing both the wall and
// counter components as needed.
func (h *HLC) Now() uint64 {
	for {
		cur := h.state.Load()
		curWall, curCtr := unpackHLC(cur)
		nowWall := uint64(time.Now().UnixMilli())

		var nextWall, nextCtr uint64
		if nowWall > curWall {
			nextWall = nowWall
			nextCtr = 0
		} else {
			nextWall = curWall
			nextCtr = curCtr + 1
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
	for {
		cur := h.state.Load()
		curWall, curCtr := unpackHLC(cur)
		remoteWall, remoteCtr := unpackHLC(remote)
		nowWall := uint64(time.Now().UnixMilli())

		// Pick max of (cur, remote, now)
		maxWall := curWall
		maxCtr := curCtr
		if remoteWall > maxWall || (remoteWall == maxWall && remoteCtr > maxCtr) {
			maxWall = remoteWall
			maxCtr = remoteCtr
		}
		if nowWall > maxWall {
			maxWall = nowWall
			maxCtr = 0
		} else if nowWall == maxWall {
			// Counter stays as max
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

func packHLC(wall, ctr uint64) uint64 {
	return (wall << 16) | (ctr & 0xFFFF)
}

func unpackHLC(h uint64) (wall, ctr uint64) {
	return h >> 16, h & 0xFFFF
}
