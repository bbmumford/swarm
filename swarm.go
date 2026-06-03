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
//
// NodeID is an opaque identifier chosen by the application — when the
// application's NodeID encoding is a non-reversible derivation of the
// public key (e.g. a fingerprint), the verifier cannot recover the public
// key from NodeID alone. PubKey carries the raw 32-byte Ed25519 public
// key used to verify Sig; the verifier compares Sig against PubKey
// directly. Topic owners that want NodeID ↔ PubKey binding enforce it
// at the topic layer after Sig is verified.
//
// Observer-tombstone semantics: when Tombstone is true AND ObserverNodeID
// is non-empty, this record is an ATTESTATION by ObserverNodeID that the
// (Topic, NodeID) owner is dead. PubKey/Sig in that case prove the
// ObserverNodeID signed the record (NOT the owner). Consumers gate on
// K-of-N distinct ObserverNodeIDs accumulated within a corroboration
// window before applying the effective tombstone — see recordStore.Apply.
// When Tombstone is true and ObserverNodeID is empty, this is the
// classical owner-signed tombstone and applies immediately.
type Record struct {
	Topic     Topic
	NodeID    NodeID
	HLC       uint64 // hybrid logical clock
	Body      []byte
	Tombstone bool
	PubKey    []byte // raw 32-byte Ed25519 public key for Sig verification
	Sig       []byte // Ed25519 over signableBytes(Record); see sig.go

	// ObserverNodeID — when set, this record is an observer-signed
	// attestation that (Topic, NodeID)'s owner is dead. Empty for
	// owner-signed records.
	ObserverNodeID NodeID
	// ObservedAtUnixMs — observer's wall-clock at the moment death was
	// declared. Used by the corroboration-window gate; an attestation
	// older than corroborationWindow is ignored. Zero for owner-signed
	// records.
	ObservedAtUnixMs int64
}

// IsObserverAttestation reports whether r is an observer-signed
// attestation (vs an owner-signed record or classical tombstone).
func (r Record) IsObserverAttestation() bool {
	return r.Tombstone && r.ObserverNodeID != ""
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

// Defaults for the observer-tombstone (N-of-M witness) gate.
//
// Apply only counts as "K distinct observers" when each attestation's
// ObservedAtUnixMs is within DefaultObserverCorroborationWindow of every
// other attestation in the count. Attestations older than the window are
// pruned. DefaultObserverQuorum K must be >= 2 (anything less is no
// quorum at all); production values are tuned so a single rogue anchor
// cannot evict a live peer, but K live anchors observing the same death
// converge within one corroboration window.
//
// observerForwardSkewBudget caps how far into the future an attestation's
// ObservedAtUnixMs is allowed to be relative to the receiver's wall
// clock. The prune window is anchored on the NEWEST attestation in the
// set; without a forward-skew bound a single rogue observer (or one
// with a forward-skewed clock) could post ObservedAtUnixMs = now + 1h
// and make that the prune anchor, evicting every honest in-window
// attestation. 2x the corroboration window leaves room for legitimate
// clock skew (10 min default) while still bounding the attack.
const (
	DefaultObserverQuorum              = 2
	DefaultObserverCorroborationWindow = 5 * time.Minute
	observerForwardSkewBudget          = 2 * DefaultObserverCorroborationWindow
)

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
	// The signing key is this node's own private key, so the tombstone is
	// owner-authored and applies immediately on every consumer.
	PublishTombstone(topic Topic) error

	// PublishObserverTombstone publishes an observer-signed attestation
	// that the (topic, target) owner is dead. The attestation alone does
	// NOT evict the target's record — consumers gate on K-of-N distinct
	// observer attestations accumulated within a corroboration window
	// before applying the effective tombstone (see DefaultObserverQuorum).
	// Combined with the v1 anchor-role gate (callers SHOULD only invoke
	// this from peers whose Role is RoleAnchor), this makes the death-
	// detection signal resistant to single-node corruption or Sybil
	// attestation. A wrongly-evicted live peer is auto-restored by the
	// CRDT once it republishes its own PeerRecord with a higher HLC.
	PublishObserverTombstone(topic Topic, target NodeID) error

	// SetObserverRoleCheck wires an application-layer trust gate for
	// observer attestations. The gate is called with the attesting peer's
	// claimed NodeID and Sig-verified PubKey and must return true only
	// when the (NodeID, PubKey) binding maps to a trusted observer (e.g.
	// a known anchor in HSTLES's role_table). Without the gate any peer
	// can mint attestations; with the gate set, only anchor-owned key
	// pairs count toward the K-of-N quorum.
	SetObserverRoleCheck(fn func(observer NodeID, pubKey []byte) bool)

	// SetRole atomically updates this Node's role. Triggers tree-edge
	// rebalance + topic-publish duty changes. Idempotent.
	SetRole(role Role) error

	// SelfRole returns the role this Node has been configured to play.
	// Bypasses the RoleTable (which depends on this node's own
	// PeerRecord having round-tripped via gossip). Use this for any
	// "am I an anchor" check that must succeed during the boot window
	// before the first PeerRecord gossip echo arrives. Returns RoleLeaf
	// before any SetRole call (the zero-value default).
	SelfRole() Role

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

	// ProbePeer triggers an immediate Merkle anti-entropy probe to the
	// specified peer across every topic this node owns records for. Use
	// this when a session is freshly established to catch up the new peer
	// in O(log N) hashes instead of waiting for the periodic Tick() loop
	// to land on them. Safe to call concurrently; safe to call when peer
	// is unknown (silently no-ops).
	ProbePeer(peer NodeID)
}

// Unsubscribe removes a previously-registered Subscriber.
type Unsubscribe func()

// New is implemented in node.go.
