// Copyright (c) 2026 Brandon Miller-Mumford.
// Licensed under the MIT License; see LICENSE.

package swarm

import (
	"crypto/ed25519"
	"encoding/binary"

	"github.com/ORBTR/aether"
)

// signableBytes returns the canonical byte form of a Record used as the
// signature input. Excludes Sig (because Sig is what we're producing).
//
// Layout:
//
//	topic_len:u16 || topic || node_id || hlc:u64 || tombstone:u8 ||
//	body_len:u32 || body || pub_key ||
//	observer_node_id_len:u16 || observer_node_id || observed_at_ms:i64 ||
//	[ key_len:u16 || key ]      <- emitted ONLY when Key != ""
//	[ "BCST" ]                  <- emitted ONLY when Broadcast
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
	if r.Broadcast {
		n += len(broadcastSuffix)
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

	// Conditional broadcast suffix, emitted only for Record.Broadcast, so a
	// stored record's bytes stay as they were. It cannot be read as a key
	// suffix: that would put the suffix's first two bytes (0x4243) in the key
	// length, and fewer bytes follow.
	if r.Broadcast {
		buf = append(buf, broadcastSuffix...)
	}

	return buf
}

// broadcastSuffix ends the signable bytes of a broadcast (Record.Broadcast).
var broadcastSuffix = []byte("BCST")

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

// nodeIDFromPub returns the NodeID of a public key: its aether NodeID, the
// identity every mesh session proves, so a record's slot names the node the
// transport authenticated. A key of the wrong size has none (""), and binds
// to no NodeID.
func nodeIDFromPub(pub ed25519.PublicKey) NodeID {
	id, err := aether.NewNodeID(pub)
	if err != nil {
		return ""
	}
	return NodeID(id)
}

// nodeIDBindsKey reports whether id is the NodeID of pub. The aether NodeID
// is a one-way digest of the key, so a record proves its NodeID only by
// carrying the key it was signed with.
func nodeIDBindsKey(id NodeID, pub []byte) bool {
	if len(pub) != ed25519.PublicKeySize || id == "" {
		return false
	}
	return id == nodeIDFromPub(ed25519.PublicKey(pub))
}

// recordBindsKey reports whether r's signing key, r.PubKey, is the key of the
// identity r is written under: NodeID for an owner record, ObserverNodeID for
// an observer attestation (whose NodeID is the subject it reports on).
func recordBindsKey(r Record) bool {
	bindID := r.NodeID
	if r.IsObserverAttestation() {
		bindID = r.ObserverNodeID
	}
	return nodeIDBindsKey(bindID, r.PubKey)
}

// VerifyRecord reports whether r carries a valid signature by the identity it
// is written under: r.PubKey must be the key of r.NodeID (of ObserverNodeID for
// an observer attestation, recordBindsKey) and r.Sig a signature by that key
// over the record. It is the check the inbound gate applies before
// TrustCheck, exported for a consumer holding a record a relay handed it,
// which must check the signature itself rather than trust the relay.
//
// Fails closed in every ambiguous case: a record without its key, or whose key
// is not its identity's, is unverifiable, which is never the same as verified.
func VerifyRecord(r Record) bool {
	if !recordBindsKey(r) {
		return false
	}
	return verifyRecord(r, ed25519.PublicKey(r.PubKey))
}
