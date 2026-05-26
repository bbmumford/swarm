// Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
// Queries: licensing@hstles.com

package swarm

import (
	"context"
	"crypto/ed25519"
	"time"
)


// NodeID is an opaque per-peer identifier (Ed25519 public key hex-encoded).
type NodeID string

// Topic is a tenant- and network-scoped topic identifier.
// Conventions:
//   - Fleet: "fleet.peer", "fleet.latency", "fleet.anchor-snapshot"
//   - Agent: "agent.peer.<tenantID>.<networkID>", "agent.policy.<tenantID>", etc.
type Topic string

// Role classifies a node's tree-edge preferences and topic-publish duties.
type Role uint8

const (
	RoleLeaf Role = iota
	RoleEdge
	RoleRelay
	RoleAnchor
)

// Record is the signed envelope carried over the swarm. Body is opaque to the
// transport layer; consumers register topic types that decode Body.
type Record struct {
	Topic     Topic
	NodeID    NodeID
	HLC       uint64 // hybrid logical clock
	Body      []byte
	Tombstone bool
	Sig       []byte // Ed25519 over (Topic || NodeID || HLC || Body || Tombstone)
}

// Subscriber is invoked for every Record applied to the local store.
// The subscriber MUST NOT block; expensive work must be done off the swarm
// goroutine.
type Subscriber func(r Record) error

// Config configures a Node instance. See PerPeerConfig for per-peer knobs.
type Config struct {
	NodeID  NodeID
	PrivKey ed25519.PrivateKey

	// PerPeerConfig is consulted on every per-peer state transition.
	// Default: returns DefaultPerPeerConfig.
	PerPeerConfig func(NodeID) PerPeerConfig

	// OnPaused is invoked when the resource governor pauses swarm activity.
	// Fleet endpoints leave this nil (no pause path).
	OnPaused func()

	// OnResumed is invoked after Pause+Resume completes.
	OnResumed func()

	// MaxRecordBytes caps a single signed Record body. Default: 16 KB.
	MaxRecordBytes int

	// Tree fan-out target (Plumtrees). Default: 4.
	TreeDegree int

	// GraftDelay is the grace window after seeing an IHave before pulling
	// the announced record via GRAFT. Default 200ms.
	GraftDelay time.Duration

	// MerkleProbeInterval controls anti-entropy probe cadence per topic.
	// Default 60s. Lower values converge faster under loss at the cost of
	// extra protocol traffic.
	MerkleProbeInterval time.Duration

	// NowFn returns the current time. Production uses time.Now (the default);
	// the deterministic simulator injects a virtual-time function. The
	// engine reads time only through this function — no direct time.Now()
	// calls in the protocol path.
	NowFn func() time.Time

	// DisableBackgroundTicker disables the in-process wall-clock ticker.
	// Used by the simulator, which drives Node.Tick directly. Default false
	// (production wires the wall-clock ticker).
	DisableBackgroundTicker bool
}

// PerPeerConfig captures per-peer adaptive state. Returned by Config.PerPeerConfig.
type PerPeerConfig struct {
	// AdaptiveInterval base period for delta-state diff to this peer.
	AdaptiveInterval time.Duration

	// BackpressureMax: drop the lazy queue to this peer when it exceeds N entries.
	BackpressureMax int

	// BandwidthCap in bytes/sec. Zero = unlimited.
	BandwidthCap uint64

	// EgressTokens is the initial token-bucket size; refilled at BandwidthCap rate.
	EgressTokens uint64

	// PriorityClass influences tree-edge selection.
	PriorityClass uint8
}

// DefaultPerPeerConfig returns sensible defaults for a fleet endpoint.
func DefaultPerPeerConfig() PerPeerConfig {
	return PerPeerConfig{
		AdaptiveInterval: 5 * time.Second,
		BackpressureMax:  256,
		BandwidthCap:     0,
		EgressTokens:     0,
		PriorityClass:    0,
	}
}

// Node is the public Swarm API. One instance per fabric per process.
type Node interface {
	// Start runs the swarm engine until ctx is cancelled.
	Start(ctx context.Context) error

	// Stop shuts down the engine and flushes outstanding state. Idempotent.
	Stop() error

	// Subscribe registers a callback for records on the given topic.
	// The callback is invoked on every applied record (including tombstones).
	Subscribe(topic Topic, sub Subscriber) (Unsubscribe, error)

	// Publish creates and signs a Record with the configured key, then
	// broadcasts it via Plumtrees + lazy push. HLC is assigned by the Node.
	Publish(topic Topic, body []byte) error

	// PublishTombstone publishes a tombstone for the (topic, node) pair.
	PublishTombstone(topic Topic) error

	// SetRole atomically updates this Node's role. Triggers tree-edge
	// rebalance + topic-publish duty changes. Idempotent.
	SetRole(role Role) error

	// SetTenant rebinds this Node to a tenant. Pre-tenant records are
	// tombstoned; self records republish under the tenant-scoped topic.
	SetTenant(tenantID string) error

	// Pause halts non-correctness-critical work (lazy push, merkle probes,
	// route advertisements). Eager-push records continue to apply. The
	// caller is responsible for sequencing Pause/Resume pairs.
	Pause() error

	// Resume restores normal cadence.
	Resume() error

	// PerPeerConfig returns the live config for a peer (for inspection/test).
	PerPeerConfig(peerID NodeID) PerPeerConfig

	// ContentTopic returns the singleton content-addressed topic interface.
	// See content.go for the API.
	ContentTopic() ContentTopic

	// Tick drives the engine's periodic work (graft timer, anti-entropy
	// probes, etc.) using the given "now" timestamp. Production callers
	// can ignore this — the in-process background ticker calls it
	// automatically. Used by the simulator to drive virtual time.
	Tick(now time.Time)
}

// Unsubscribe removes a previously-registered Subscriber.
type Unsubscribe func()

// New is implemented in node.go.
