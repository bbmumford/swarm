# swarm

swarm spreads small signed records across a mesh of nodes and keeps every
node's copy converging. A node publishes a record on a topic; swarm pushes it
along a spanning tree of peers (Plumtrees: eager push on tree edges, lazy
`IHAVE` announcements elsewhere, `GRAFT` and `PRUNE` to repair the tree), stores
it in a per-topic delta-state CRDT, and runs Merkle anti-entropy so that nodes
which missed a message catch up.

swarm does not open connections. The caller supplies a `Transport` (send to a
peer, broadcast, the current peers, and callbacks for received messages and for
peers joining and leaving) and joins it to a node with `Wire`.

What a node stores and how copies converge:

- **Records.** A `Record` carries its topic, the publishing NodeID, an optional
  `Key`, a hybrid logical clock stamp, a body (16 KB at most by default), a
  tombstone flag, the publisher's Ed25519 public key and its signature over a
  fixed byte layout of all of those. Each topic holds one slot per
  (NodeID, Key); a node that never sets `Key` holds one slot per topic.
- **Merge.** A slot keeps the record with the highest clock stamp, ties broken
  by the signature bytes, so any two stores merge to the same result in either
  order. Tombstones override live records.
- **Observer tombstones.** Other nodes can attest that a node has gone silent.
  When enough distinct observers attest within a window
  (`SetObserverQuorum`), each store tombstones every slot that node holds on the
  topic. `SetObserverRoleCheck` decides which observers count.
- **Inbound checks.** A node's NodeID is the aether NodeID of its Ed25519 key.
  Every inbound record must be signed by the key it carries, and its NodeID
  (an observer attestation's `ObserverNodeID`) must be that key's NodeID.
  `TrustCheck` is required (`New` returns `ErrNoTrustCheck` without it): it
  runs on every proved record before the record can change the store, and
  decides partition, topic and role admission. Observer attestations are
  admitted only once `SetObserverRoleCheck` sets a gate. Stamps more than
  `MaxClockSkew` (default 10 minutes) ahead of the local clock are refused, and
  the store refuses new topics, slots and per-node keys past `MaxTopics`,
  `MaxRecordsPerTopic` and `MaxKeysPerNodePerTopic` rather than evicting.
- **Per-peer pacing.** `PerPeerConfig` gives each peer its own adaptive
  interval, backpressure limit, bandwidth cap and priority class.
- **Roles, partitions and pausing.** `SetRole` changes the node's role and
  rebalances its tree edges (anchor peers are preferred as edges),
  `SetPartition` tombstones the node's records and republishes them under a new
  partition, and `Pause`/`Resume` stop and restart non-essential work under
  host pressure.
- **Content.** `ContentTopic` announces and fetches content-addressed blobs,
  whole or in chunks, behind a signed manifest (`BuildSignedManifest`,
  `ChunkBlob`).

## Use

```sh
go get github.com/bbmumford/swarm
```

```go
n, err := swarm.New(swarm.Config{
	NodeID:     id,   // the aether NodeID of priv's public key
	PrivKey:    priv,
	TreeDegree: 4,
	TrustCheck: trust, // func(swarm.Record) error: admit or refuse each proved record
})
if err != nil {
	return err
}
if err := swarm.Wire(n, transport); err != nil { // transport implements swarm.Transport
	return err
}
go n.Start(ctx)

unsub, _ := n.Subscribe("fleet.peer", func(r swarm.Record) error {
	// r is verified and has won its slot's merge
	return nil
})
defer unsub()

_ = n.Publish("fleet.peer", body)
rec, ok := n.Get("fleet.peer", someNode)
```

`TopicRecords`, `NodeRecords` and `GetKeyed` read the store; `PublishKeyed`,
`PublishTombstone`, `PublishKeyedTombstone` and `PublishObserverTombstone`
write it. `HLC` is the hybrid logical clock the records use, and
`VerifyRecord` checks a record's signature and its NodeID binding on its own. `topics.go` names the
topics the device agents use (`AgentPolicyTopic`, `AgentHealthTopic` and the
rest, each scoped by partition).

| package | what it holds |
|---|---|
| `swarm` | `Node`, `New`, `Wire`, `Config`, `Record`, `Topic`, `Transport`, `HLC`, `ContentTopic` |
| `swarm/proto/pb` | the protobuf messages generated from `proto/*.proto`: peer records, content adverts and fetches, and the device agents' topic payloads |
| `swarm/sim` | a deterministic network simulator that drives nodes on virtual time (`Config.NowFn`, `DisableBackgroundTicker`, `Node.Tick`), used by the tests |
| `swarm/swarmtest` | `AcceptAll` and `AcceptAllObservers`, the trust gates for tests that trust every proved node |

## Dependencies

- `github.com/ORBTR/aether`: `NewNodeID`, the NodeID every record binds to.
- `google.golang.org/protobuf`, for `proto/pb`.

## Used by

Importers in the ORBTR estate:

- `github.com/bbmumford/loom/node` and `github.com/bbmumford/loom/directory`:
  loom builds the platform mesh's swarm node over an aether transport.
- `github.com/ORBTR/agent/internal/core/wire` and
  `github.com/ORBTR/agent/internal/core/edge`: the device agent's mesh.
- `github.com/ORBTR/constellation/domain/storage/storage/meshxport` and
  `github.com/ORBTR/constellation/domain/identity/trust/partitionkeys`
  (`proto/pb` only).
- `github.com/ORBTR/node.orbtr.io`.
- `github.com/ORBTR/orb/internal/mesh`, `internal/control`, `internal/dispatch`,
  `internal/trust` and `cmd/orb-satellite`: the local inference cluster's state.

## Platforms and build

Pure Go, no cgo and no build tags. The module's `go` directive is 1.25.0.

## Licence

MIT. Copyright (c) 2026 Brandon Miller-Mumford. The full text is in
[LICENSE](LICENSE).

## Contributing

[AGENTS.md](AGENTS.md) holds the repository's two rules, for people and coding
agents alike: no temporary documents in the repository, and conventional commit
messages that stand on their own. [CLAUDE.md](CLAUDE.md) imports it for Claude
Code.
