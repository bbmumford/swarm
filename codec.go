// Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
// Queries: licensing@hstles.com

package swarm

import (
	"crypto/sha256"
	"fmt"

	pb "github.com/bbmumford/swarm/proto/pb"
	"google.golang.org/protobuf/proto"
)

// encodeFrame serializes a Plumtrees frame to bytes. The wire format is
// the proto-buffer encoding of pb.Frame.
func encodeFrame(f *pb.Frame) ([]byte, error) {
	return proto.Marshal(f)
}

// decodeFrame parses a Frame from bytes.
func decodeFrame(b []byte) (*pb.Frame, error) {
	var f pb.Frame
	if err := proto.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("swarm: decode frame: %w", err)
	}
	return &f, nil
}

// recordToProto converts an in-memory Record to the wire-format pb.Record.
func recordToProto(r Record) *pb.Record {
	return &pb.Record{
		Topic:     string(r.Topic),
		NodeId:    []byte(r.NodeID),
		Hlc:       r.HLC,
		Body:      r.Body,
		Tombstone: r.Tombstone,
		Sig:       r.Sig,
		PubKey:    r.PubKey,
	}
}

// recordFromProto converts a wire-format pb.Record to an in-memory Record.
func recordFromProto(p *pb.Record) Record {
	return Record{
		Topic:     Topic(p.Topic),
		NodeID:    NodeID(p.NodeId),
		HLC:       p.Hlc,
		Body:      p.Body,
		Tombstone: p.Tombstone,
		Sig:       p.Sig,
		PubKey:    p.PubKey,
	}
}

// bodyHash returns SHA256(r.Body) for use in IHave announcements.
func bodyHash(r Record) [32]byte {
	return sha256.Sum256(r.Body)
}

// ---------- Frame constructors ----------

func frameEagerPush(r Record, ttl uint32) *pb.Frame {
	return &pb.Frame{
		Kind: &pb.Frame_Eager{
			Eager: &pb.EagerPush{
				Record: recordToProto(r),
				Ttl:    ttl,
			},
		},
	}
}

func frameIHave(topic Topic, nodeID NodeID, hlc uint64, h [32]byte) *pb.Frame {
	return &pb.Frame{
		Kind: &pb.Frame_Ihave{
			Ihave: &pb.IHave{
				Topic:    string(topic),
				NodeId:   []byte(nodeID),
				Hlc:      hlc,
				BodyHash: h[:],
			},
		},
	}
}

func frameGraft(topic Topic, nodeID NodeID, hlc uint64) *pb.Frame {
	return &pb.Frame{
		Kind: &pb.Frame_Graft{
			Graft: &pb.Graft{
				Topic:  string(topic),
				NodeId: []byte(nodeID),
				Hlc:    hlc,
			},
		},
	}
}

func framePrune(topic Topic) *pb.Frame {
	return &pb.Frame{
		Kind: &pb.Frame_Prune{
			Prune: &pb.Prune{
				Topic: string(topic),
			},
		},
	}
}

func frameKeepalive() *pb.Frame {
	return &pb.Frame{
		Kind: &pb.Frame_Keepalive{Keepalive: &pb.Keepalive{}},
	}
}
