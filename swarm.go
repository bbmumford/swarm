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

	// Key sub-divides a node's slot on a topic. The store is keyed by
	// (Topic, NodeID, Key), so one node may hold many records on one
	// topic — the latency observations it has for each distinct peer,
	// the content hashes it holds, and so on. Each (Topic, NodeID, Key)
	// converges independently under the same HLC-max rule.
	//
	// Key == "" is the classical single-slot-per-node form and remains
	// the default: a publisher that never sets Key sees exactly the
	// pre-composite-key behaviour, and its signable bytes are unchanged
	// (see signableBytes — the key suffix is emitted only when Key is
	// non-empty, so no existing signature is invalidated).
	//
	// Key is covered by Sig. Moving a record between keys — or stripping
	// the key to make a per-peer observation look like the node's single
	// canonical record — invalidates the signature.
	Key string

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
//
// 🛑 That rule is not advisory politeness — Subscribe's return time depends on
// it. Records arriving while Subscribe is replaying are queued and drained
// before live delivery resumes (see subGate), so Subscribe returns once the
// subscriber has caught up with arrivals. A subscriber that outruns the
// publish rate — an in-memory index update, which is what every in-tree
// subscriber is — makes that a few microseconds. A subscriber that BLOCKS
// inverts the relationship and couples Subscribe to the topic's publish rate.
// MEASURED (@Z-345): a deliberately slow 2ms subscriber against a topic
// published for 3s returned from Subscribe after 5,695ms instead of 123ms.
//
// If Subscribe is slow, the subscriber is violating this contract; that is the
// thing to fix, not the gate.
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

	// ── Inbound trust / resource hardening (Phase-0.5 release blockers) ──

	// TrustCheck, when non-nil, runs on every signature-verified inbound
	// record BEFORE it can mutate the store (eager push, graft reply, and
	// merkle range paths). Return a non-nil error to reject the record.
	// This is the swarm-side enforcement point for an application
	// TrustPolicy (NodeID↔key binding beyond the hex scheme, tenant/topic
	// authorization, role entitlement, revocation). nil = accept (the
	// pre-hardening behaviour).
	TrustCheck func(Record) error

	// RequireNodeKeyBinding, when true, rejects any inbound owner record
	// whose NodeID is not the canonical hex encoding of its embedded
	// PubKey, and any observer attestation whose ObserverNodeID does not
	// bind to its PubKey the same way. Deployments whose NodeIDs follow
	// nodeIDFromPub (the default when Config.NodeID is left empty) should
	// set this — it closes "any keypair can claim any NodeID" at the
	// store boundary. Off by default for NodeID schemes that are not
	// reversible to a key (fingerprints); those wire TrustCheck instead.
	RequireNodeKeyBinding bool

	// MaxClockSkew bounds how far ahead of the local wall clock an inbound
	// record's HLC may sit before it is rejected. The HLC.Observe clamp
	// only protects the LOCAL clock — the CRDT winner comparison uses the
	// raw remote HLC, so without this gate one far-future-stamped record
	// permanently pins its (topic,node) slot. Default 10m.
	MaxClockSkew time.Duration

	// MaxTopics caps the number of distinct topics the store accepts.
	// Records for new topics beyond the cap are rejected (never evict —
	// eviction is an attack amplifier). Default 4096.
	MaxTopics int

	// MaxRecordsPerTopic caps distinct (topic,node) slots per topic.
	// Default 65536.
	MaxRecordsPerTopic int

	// MaxKeysPerNodePerTopic caps how many slots ONE node may occupy on a
	// single topic. Default: DefaultMaxKeysPerNodePerTopic.
	//
	// This bound exists only because of composite keys and closes the
	// amplification they introduce. Before Record.Key a node could hold
	// exactly one slot per topic, so MaxRecordsPerTopic was implicitly a
	// per-node bound too; with keys, one node could otherwise open every
	// slot in the topic's budget and crowd out every honest peer.
	// Enforcement is reject-new, never evict-old — evicting under pressure
	// would hand an attacker the very thing the cap denies.
	MaxKeysPerNodePerTopic int

	// MaxAttestationsPerTarget caps distinct observers accumulated per
	// tombstone target. Default 64.
	MaxAttestationsPerTarget int

	// MaxPendingIHaves caps the lazy-push missing-record tracker. Beyond
	// the cap new IHave announcements are dropped (anti-entropy still
	// recovers the records). Default 4096.
	MaxPendingIHaves int

	// OnAccepted, when non-nil, fires after EVERY accepted store change —
	// local publishes, remote eager/graft/merkle applies, and quorum-
	// crossed observer events — with a defensively-copied record. This is
	// the accepted-change stream a projection/journal layer (loom
	// LiveDirectory / DurableJournal) consumes; watermarking is the
	// consumer's concern. Called synchronously on the apply path: keep it
	// O(1) and non-blocking (hand off to a channel/queue).
	OnAccepted func(Record)

	// TopicTTL, when non-nil, returns the retention for records on a
	// topic (0 = retain forever, the default). The background ticker
	// reaps live records whose HLC wall-clock age exceeds the TTL, and
	// tombstones at 2× the TTL (tombstones must outlive the live records
	// they supersede or deletes resurrect via anti-entropy). Durable
	// checkpoint-governed retention lives in the journal layer above —
	// this is the in-memory bound.
	TopicTTL func(Topic) time.Duration
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
	//
	// On return the subscriber has seen the topic's current state (replay,
	// tombstones included) followed in order by anything that arrived during
	// that replay — no gap, no duplicate, no interleaving.
	//
	// 🛑 THAT SERIALISATION COVERS THE REPLAY→LIVE TRANSITION ONLY. Once the
	// transition completes, deliver() releases its lock before invoking the
	// subscriber, so STEADY-STATE DELIVERY IS CONCURRENT: several publishers
	// enter the callback at once. MEASURED (@Z-346): 6 concurrent publishers
	// → 6 concurrent entries, post-transition.
	//
	// ⇒ A subscriber MUST be safe for concurrent entry. It is not a mutex.
	// (loom's AddressTable and RoleTable both carry their own RWMutex and are
	// correct under this; a new subscriber that assumes serial delivery
	// because the transition is serial would be wrong.)
	//
	// ⚠ Return time is therefore bounded by the SUBSCRIBER, not by the store:
	// see Subscriber's MUST-NOT-BLOCK contract. Callers that invoke this from
	// a synchronous constructor on a startup path (loom's NewAddressTable /
	// NewRoleTable / bridgeReachFromSwarm all do, on `fleet.peer`) inherit
	// that bound.
	Subscribe(topic Topic, sub Subscriber) (Unsubscribe, error)

	// Publish creates and signs a Record with the configured key, then
	// broadcasts it via Plumtrees + lazy push. HLC is assigned by the Node.
	// Publishes into this node's classical single slot on the topic —
	// equivalent to PublishKeyed(topic, "", body).
	Publish(topic Topic, body []byte) error

	// PublishKeyed publishes into one of this node's per-key slots on a
	// topic (Record.Key), so a node can hold many records there: a latency
	// observation per observed peer, a record per content hash it serves.
	// Each (topic, node, key) converges independently under HLC-max.
	//
	// key "" is the classical single slot, so PublishKeyed(t, "", b) and
	// Publish(t, b) are the same operation. key may not exceed MaxKeyBytes.
	PublishKeyed(topic Topic, key string, body []byte) error

	// PublishKeyedTombstone retires one of this node's per-key slots. The
	// tombstone is owner-authored, so it applies immediately on every
	// consumer — the composite-key counterpart of PublishTombstone.
	PublishKeyedTombstone(topic Topic, key string) error

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

	// Get returns the current record for (topic, node) and whether one
	// exists. This is the production read API over the convergence store
	// — a stable, exported alternative to the test-only InternalStore.
	// A tombstoned or expired record is reported as not-present.
	// Reads the node's classical single slot: Get == GetKeyed(…, "").
	Get(topic Topic, node NodeID) (Record, bool)

	// GetKeyed returns one per-key slot of a node on a topic. key "" is the
	// classical single slot.
	GetKeyed(topic Topic, node NodeID, key string) (Record, bool)

	// NodeRecords returns every live record a node holds on a topic, in
	// canonical (NodeID, Key) order — the composite-key read. Use it where
	// a node contributes a SET of facts to one topic (its latency
	// observations, its content holdings) rather than a single value.
	NodeRecords(topic Topic, node NodeID) []Record

	// TopicRecords returns a snapshot of every live record on a topic.
	// Consumers build typed, tenant-scoped projections (members, reach,
	// roles) on top of this — it is the query surface that lets the swarm
	// store back a directory the way ledger's DirectoryCache used to.
	TopicRecords(topic Topic) []Record

	// Topics returns every topic the store currently holds records for.
	Topics() []Topic

	// SetObserverQuorum tunes the observer-tombstone gate: k distinct
	// anchors must corroborate a death within window w before it
	// synthesises a tombstone. k must be >= 2 (below that is no quorum).
	// Defaults are DefaultObserverQuorum / DefaultObserverCorroborationWindow.
	SetObserverQuorum(k int, w time.Duration)

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
