// Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
// Queries: licensing@hstles.com

package swarm

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"sync/atomic"
	"time"
)

// inboundGate centralises every pre-store admission check for records that
// arrive off the wire (eager push, graft replies, merkle ranges). It runs
// AFTER signature verification and BEFORE store.Apply — nothing an
// unauthorized or malformed record can do reaches the CRDT.
//
// Checks, in order (cheapest first):
//  0. key length      — MaxKeyBytes, a CORRECTNESS bound rather than a
//     resource policy: signableBytes length-prefixes Key with a u16, so a
//     longer key would truncate its own length and let two distinct keys
//     share one canonical byte string (a signature collision, hence a
//     record-relocation primitive). Never relax this.
//  1. body size       — Config.MaxRecordBytes (local Publish already
//     enforced it; pre-hardening the inbound paths did not)
//  2. clock skew      — the record's HLC wall part may not sit more than
//     Config.MaxClockSkew ahead of local wall-now; the CRDT winner
//     comparison consumes the RAW remote HLC, so this is the only thing
//     standing between one far-future stamp and a permanently-pinned slot
//  3. key binding     — optional NodeID == hex(PubKey) enforcement
//     (owner records bind NodeID; attestations bind ObserverNodeID)
//  4. TrustCheck      — the application's injected policy hook
//
// Rejections are counted per reason for observability.
type inboundGate struct {
	maxBytes   int
	maxSkew    time.Duration
	binding    bool
	trustCheck func(Record) error
	nowFn      func() time.Time

	rejectedSize    atomic.Uint64
	rejectedSkew    atomic.Uint64
	rejectedBinding atomic.Uint64
	rejectedTrust   atomic.Uint64
}

// MaxKeyBytes bounds Record.Key. It is fixed by the canonical signing
// encoding, not by policy: signableBytes writes a u16 length prefix, so a
// key at or beyond 1<<16 bytes would wrap its own length and two distinct
// keys could produce identical signable bytes. Enforced on both the local
// Publish path and every inbound path.
const MaxKeyBytes = 1<<16 - 1

// DefaultMaxKeysPerNodePerTopic bounds how many slots one node may occupy on
// a single topic when Config.MaxKeysPerNodePerTopic is unset.
//
// 4096 is deliberately generous against every use composite keys were added
// for — a latency observation per fleet peer, a record per content holding —
// while still requiring 16 distinct nodes to exhaust the 65536-slot default
// topic budget. Before composite keys that budget was implicitly per-node
// (one node, one slot); this keeps a single node from consuming it alone.
const DefaultMaxKeysPerNodePerTopic = 4096

var (
	errGateTooLarge  = errors.New("swarm: inbound record body exceeds maximum size")
	errGateSkew      = errors.New("swarm: inbound record HLC too far in the future")
	errGateBinding   = errors.New("swarm: record NodeID does not bind to its public key")
	errGateKeyTooLong = errors.New("swarm: record key exceeds MaxKeyBytes")
)

func newInboundGate(cfg Config) *inboundGate {
	maxSkew := cfg.MaxClockSkew
	if maxSkew <= 0 {
		maxSkew = 10 * time.Minute
	}
	return &inboundGate{
		maxBytes:   cfg.MaxRecordBytes,
		maxSkew:    maxSkew,
		binding:    cfg.RequireNodeKeyBinding,
		trustCheck: cfg.TrustCheck,
		// The skew comparison MUST run in the HLC's clock domain, which is
		// the REAL wall clock (HLC.Now stamps time.Now regardless of
		// Config.NowFn). Using cfg.NowFn here would compare real-time HLC
		// stamps against the simulator's virtual clock and reject every
		// record as far-future — exactly the failure the deterministic
		// convergence suite caught.
		nowFn: time.Now,
	}
}

// Admit returns nil when r may proceed to store.Apply.
func (g *inboundGate) Admit(r Record) error {
	// Unconditional — MaxKeyBytes is an encoding invariant, so unlike the
	// caps below it is never disabled by a zero-valued config.
	if len(r.Key) > MaxKeyBytes {
		g.rejectedSize.Add(1)
		return errGateKeyTooLong
	}

	if g.maxBytes > 0 && len(r.Body) > g.maxBytes {
		g.rejectedSize.Add(1)
		return errGateTooLarge
	}

	wallMs, _ := Decompose(r.HLC)
	if wallMs > uint64(g.nowFn().UnixMilli())+uint64(g.maxSkew.Milliseconds()) {
		g.rejectedSkew.Add(1)
		return errGateSkew
	}

	if g.binding {
		// Owner records bind NodeID↔PubKey; attestations bind the OBSERVER
		// (their PubKey signed the record; the target NodeID is the claim).
		bindID := r.NodeID
		if r.IsObserverAttestation() {
			bindID = r.ObserverNodeID
		}
		if len(r.PubKey) != ed25519.PublicKeySize ||
			bindID != nodeIDFromPub(ed25519.PublicKey(r.PubKey)) {
			g.rejectedBinding.Add(1)
			return errGateBinding
		}
	}

	if g.trustCheck != nil {
		if err := g.trustCheck(r); err != nil {
			g.rejectedTrust.Add(1)
			return fmt.Errorf("swarm: trust check rejected record: %w", err)
		}
	}
	return nil
}

// Rejections reports the per-reason rejection counters
// (size, skew, binding, trust).
func (g *inboundGate) Rejections() (size, skew, binding, trust uint64) {
	return g.rejectedSize.Load(), g.rejectedSkew.Load(),
		g.rejectedBinding.Load(), g.rejectedTrust.Load()
}

// cloneRecord returns a copy of r whose byte slices are independent of the
// original. Used at every boundary where store-owned bytes would otherwise
// leak to (or from) application code: Publish input, Get/TopicRecords
// output, subscriber delivery, and the OnAccepted stream.
func cloneRecord(r Record) Record {
	if r.Body != nil {
		r.Body = append([]byte(nil), r.Body...)
	}
	if r.Sig != nil {
		r.Sig = append([]byte(nil), r.Sig...)
	}
	if r.PubKey != nil {
		r.PubKey = append([]byte(nil), r.PubKey...)
	}
	return r
}
