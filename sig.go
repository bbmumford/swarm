// Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
// Queries: licensing@hstles.com

package swarm

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
)

// signableBytes returns the canonical byte form of a Record used as the
// signature input. Excludes Sig (because Sig is what we're producing).
//
// Layout:
//   topic_len:u16 || topic || node_id || hlc:u64 || tombstone:u8 ||
//   body_len:u32 || body || pub_key ||
//   observer_node_id_len:u16 || observer_node_id || observed_at_ms:i64 ||
//   [ key_len:u16 || key ]      <- emitted ONLY when Key != ""
//
// PubKey is included so a forger cannot rebind a valid sig to a different
// PubKey claim (which would otherwise let a publisher impersonate any
// peer by swapping the pubkey on a record they intercepted).
//
// ObserverNodeID + ObservedAtUnixMs are appended after the legacy payload
// so an owner-signed record (ObserverNodeID="", ObservedAtUnixMs=0)
// produces a signature payload whose suffix is two zero bytes (empty
// observer_node_id_len) plus 8 zero bytes (observed_at_ms=0) — the
// canonical bytes uniquely encode whether the record is owner-authored
// or observer-attested. An observer cannot strip these fields and
// resubmit as owner-authored without invalidating Sig (the byte layout
// differs even when both suffix fields are empty/zero — the encoding is
// always written by the signer).
//
// Key is appended LAST and CONDITIONALLY — the two-byte length prefix and
// the key bytes are emitted only when Key != "". This is deliberate and is
// the opposite of the observer-field choice above: appending it
// unconditionally would add two zero bytes to every record and invalidate
// every signature in the fleet, forcing a coordinated fresh-mesh redeploy.
// Emitting nothing for Key == "" makes the canonical bytes of every
// pre-composite-key record BYTE-IDENTICAL to what they were, so no signed
// record ever stops verifying.
//
// The conditional suffix is still unambiguous, which is what makes it safe:
// topic and body are length-prefixed and node_id / pub_key are fixed-length,
// so the legacy layout has a determined end. A keyed record's bytes are a
// legacy prefix plus extra trailing bytes and therefore cannot collide with
// any legacy record's bytes. Both substitutions are caught because the
// verifier recomputes this encoding from the record it actually received:
// re-labelling a keyless record with a key appends a suffix the signer never
// signed, and stripping a key removes one the signer did — either way Sig
// fails. That closes record relocation, e.g. promoting one peer-scoped
// latency observation into the node's canonical keyless slot.
//
// This is a STABLE serialization independent of proto wire format —
// signature validity does not depend on protobuf encoding quirks.
func signableBytes(r Record) []byte {
	topic := []byte(r.Topic)
	observer := []byte(r.ObserverNodeID)
	key := []byte(r.Key)
	n := 2 + len(topic) + len(r.NodeID) + 8 + 1 + 4 + len(r.Body) + len(r.PubKey) +
		2 + len(observer) + 8
	if len(key) > 0 {
		n += 2 + len(key)
	}
	buf := make([]byte, 0, n)

	var tlen [2]byte
	binary.BigEndian.PutUint16(tlen[:], uint16(len(topic)))
	buf = append(buf, tlen[:]...)
	buf = append(buf, topic...)

	buf = append(buf, []byte(r.NodeID)...)

	var hlcb [8]byte
	binary.BigEndian.PutUint64(hlcb[:], r.HLC)
	buf = append(buf, hlcb[:]...)

	if r.Tombstone {
		buf = append(buf, 1)
	} else {
		buf = append(buf, 0)
	}

	var blen [4]byte
	binary.BigEndian.PutUint32(blen[:], uint32(len(r.Body)))
	buf = append(buf, blen[:]...)
	buf = append(buf, r.Body...)

	buf = append(buf, r.PubKey...)

	var olen [2]byte
	binary.BigEndian.PutUint16(olen[:], uint16(len(observer)))
	buf = append(buf, olen[:]...)
	buf = append(buf, observer...)

	var oat [8]byte
	binary.BigEndian.PutUint64(oat[:], uint64(r.ObservedAtUnixMs))
	buf = append(buf, oat[:]...)

	// Conditional composite-key suffix — see the layout note above. Nothing
	// is emitted for Key == "", which is what keeps every pre-existing
	// signature valid.
	if len(key) > 0 {
		var klen [2]byte
		binary.BigEndian.PutUint16(klen[:], uint16(len(key)))
		buf = append(buf, klen[:]...)
		buf = append(buf, key...)
	}

	return buf
}

// signRecord stamps r.PubKey from priv and sets r.Sig = Ed25519 signature
// over signableBytes(r) using priv. After signRecord returns, the record
// carries everything a remote verifier needs (PubKey + Sig).
func signRecord(r *Record, priv ed25519.PrivateKey) {
	if pub, ok := priv.Public().(ed25519.PublicKey); ok {
		r.PubKey = append(r.PubKey[:0], pub...)
	}
	r.Sig = ed25519.Sign(priv, signableBytes(*r))
}

// verifyRecord returns true if r.Sig is a valid Ed25519 signature by pub
// over signableBytes(r). Callers pass the public key directly (typically
// r.PubKey, after sanity-checking its length).
func verifyRecord(r Record, pub ed25519.PublicKey) bool {
	if len(r.Sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(pub, signableBytes(r), r.Sig)
}

// signableManifestBytes returns the canonical byte form of a Manifest
// used as its signature input. Excludes Sig. The layout is independent
// of proto wire-format ordering so verification is stable across proto
// encoder changes.
//
//	blob_hash || total_size:u64 || chunk_size:u32 ||
//	chunks_count:u32 || (chunks[i] for i in [0,chunks_count)) ||
//	filename_len:u16 || filename || mime_len:u16 || mime ||
//	published_at:i64 || publisher_len:u16 || publisher
func signableManifestBytes(m manifestSig) []byte {
	buf := make([]byte, 0, 64+len(m.Chunks)*32+len(m.Filename)+len(m.Mime)+len(m.Publisher))
	buf = append(buf, m.BlobHash...)

	var sz [8]byte
	binary.BigEndian.PutUint64(sz[:], m.TotalSize)
	buf = append(buf, sz[:]...)

	var cs [4]byte
	binary.BigEndian.PutUint32(cs[:], m.ChunkSize)
	buf = append(buf, cs[:]...)

	var cn [4]byte
	binary.BigEndian.PutUint32(cn[:], uint32(len(m.Chunks)))
	buf = append(buf, cn[:]...)
	for _, c := range m.Chunks {
		buf = append(buf, c...)
	}

	var fnl [2]byte
	binary.BigEndian.PutUint16(fnl[:], uint16(len(m.Filename)))
	buf = append(buf, fnl[:]...)
	buf = append(buf, m.Filename...)

	var mnl [2]byte
	binary.BigEndian.PutUint16(mnl[:], uint16(len(m.Mime)))
	buf = append(buf, mnl[:]...)
	buf = append(buf, m.Mime...)

	var pa [8]byte
	binary.BigEndian.PutUint64(pa[:], uint64(m.PublishedAt))
	buf = append(buf, pa[:]...)

	var pl [2]byte
	binary.BigEndian.PutUint16(pl[:], uint16(len(m.Publisher)))
	buf = append(buf, pl[:]...)
	buf = append(buf, m.Publisher...)

	return buf
}

// manifestSig is the projected field set used for canonical signing.
// Keeping the struct decoupled from the proto type lets sig.go avoid a
// proto import and lets tests build manifest signatures without going
// through proto.Marshal.
type manifestSig struct {
	BlobHash    []byte
	TotalSize   uint64
	ChunkSize   uint32
	Chunks      [][]byte
	Filename    string
	Mime        string
	PublishedAt int64
	Publisher   []byte
}

// pubFromNodeID extracts the Ed25519 public key embedded in a NodeID. The
// NodeID encoding is hex(pubkey) — 64 chars for a 32-byte key.
func pubFromNodeID(id NodeID) (ed25519.PublicKey, bool) {
	s := string(id)
	if len(s) != 2*ed25519.PublicKeySize {
		return nil, false
	}
	pub := make([]byte, ed25519.PublicKeySize)
	for i := 0; i < ed25519.PublicKeySize; i++ {
		hi, ok1 := hexNibble(s[2*i])
		lo, ok2 := hexNibble(s[2*i+1])
		if !ok1 || !ok2 {
			return nil, false
		}
		pub[i] = (hi << 4) | lo
	}
	return pub, true
}

// nodeIDFromPub returns the NodeID encoding for a public key.
func nodeIDFromPub(pub ed25519.PublicKey) NodeID {
	const hex = "0123456789abcdef"
	out := make([]byte, 2*len(pub))
	for i, b := range pub {
		out[2*i] = hex[b>>4]
		out[2*i+1] = hex[b&0x0f]
	}
	return NodeID(out)
}

func hexNibble(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	default:
		return 0, false
	}
}

// VerifyRecord reports whether r carries a valid owner signature, binding the
// signature to the NodeID that claims the slot.
//
// 🔑 THIS IS THE PACKAGE'S ONLY EXPORTED WAY TO CHECK A RECORD, AND IT IS
// DELIBERATELY STRICTER THAN THE INTERNAL PATH.
//
// The internal call sites (merkle.go, plumtrees.go) verify with
// ed25519.PublicKey(rec.PubKey) — the key the RECORD ITSELF SUPPLIES. That
// establishes the record is internally consistent and NOTHING about who sent
// it: an attacker signs with their own key and writes any NodeID they like
// into the slot. Closing that is what RequireNodeKeyBinding is for, and it is
// off by default.
//
// An exported verifier cannot depend on a gate the caller may not have wired,
// so this one derives the key FROM THE NODEID (the NodeID encoding is
// hex(pubkey)) and the bind therefore holds BY CONSTRUCTION. A record signed
// by one keypair while claiming another node's slot fails here even when the
// internal path accepts it.
//
// Fails closed in every ambiguous case: an unparseable NodeID cannot be bound
// to a key and is UNVERIFIABLE, which is never the same as verified; and a
// PubKey field disagreeing with the NodeID is rejected rather than resolved in
// favour of either.
//
// It exists because preserving a signature is not the same as being able to
// check one: the directory projection carries Signature/PubKey/Body
// byte-identically, and before this every consumer outside the package held a
// valid signature it had no way to verify — forcing it to trust the relaying
// node, which the Phase-0.5 plan explicitly rejects ("observer facts remain
// explicitly third-party attestations").
func VerifyRecord(r Record) bool {
	pub, ok := pubFromNodeID(r.NodeID)
	if !ok {
		return false
	}
	if len(r.PubKey) != 0 && !bytes.Equal(r.PubKey, pub) {
		return false
	}
	return verifyRecord(r, pub)
}
