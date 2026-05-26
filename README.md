# swarm

Plumtrees-based propagation engine with δ-CRDT storage and Merkle anti-entropy.
Propagation substrate for the HSTLES fleet mesh and the ORBTR agent mesh.

## Capabilities

- **Plumtrees epidemic broadcast** — tree-based eager push + lazy IHAVE announcements + GRAFT/PRUNE for partial-tree healing
- **δ-CRDT records** — per-topic delta-state CRDT with deterministic merge
- **Merkle anti-entropy** — periodic root comparison + range reconciliation for drift recovery
- **PerPeerConfig** — per-peer adaptive interval, backpressure, RTT, bandwidth-cap state owned by swarm
- **Role-aware tree-edge selection** — anchor-role peers preferred for tree edges
- **Tenant-scoped topics** — per-tenant + per-network subscriber filtering
- **Pause/Resume** — resource-governor integration; pause non-correctness-critical work under host pressure
- **ContentTopic** — content-addressed pull (single-blob + chunked file transfer) for signed+hash-addressed artifact distribution

## Topics

Topics are tenant- and network-scoped strings. The unified PeerRecord lives on `fleet.peer` (fleet) or `agent.peer.<tenantID>.<networkID>` (agent).


