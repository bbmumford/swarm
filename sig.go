// Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
// Queries: licensing@hstles.com

package swarm

import (
	"crypto/ed25519"
	"encoding/binary"
)

// signableBytes returns the canonical byte form of a Record used as the
// signature input. Excludes Sig (because Sig is what we're producing).
//
// Layout:
//   topic_len:u16 || topic || node_id || hlc:u64 || tombstone:u8 || body_len:u32 || body
//
// This is a STABLE serialization independent of proto wire format —
// signature validity does not depend on protobuf encoding quirks.
func signableBytes(r Record) []byte {
	topic := []byte(r.Topic)
	buf := make([]byte, 0, 2+len(topic)+len(r.NodeID)+8+1+4+len(r.Body))

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

	return buf
}

// signRecord sets r.Sig = Ed25519 signature over signableBytes(r) using priv.
func signRecord(r *Record, priv ed25519.PrivateKey) {
	r.Sig = ed25519.Sign(priv, signableBytes(*r))
}

// verifyRecord returns true if r.Sig is a valid Ed25519 signature by pub
// (which must be NodeID-derived) over signableBytes(r).
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
