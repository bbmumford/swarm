// Copyright (c) 2026 Brandon Miller-Mumford.
// Licensed under the MIT License; see LICENSE.

// Package swarm is a Plumtrees-based propagation engine with delta-state CRDT
// storage and Merkle anti-entropy. It is the propagation substrate for both
// the HSTLES fleet mesh and the ORBTR agent mesh.
//
// The package exposes a single Node type whose API surface covers:
//   - Subscribe/Publish on partition-scoped topics
//   - PerPeerConfig: per-peer adaptive interval + backpressure + bandwidth cap
//   - SetRole: runtime role change with tree-edge rebalance
//   - SetPartition: partition rebind with tombstone-and-republish
//   - Pause/Resume: resource-governor integration
//   - ContentTopic: content-addressed pull (single + chunked) for signed
//     hash-addressed artifact distribution
//
// All consumer wiring is via the Node interface; the package owns no global
// state and is safe for multiple instances per process (e.g. one fleet Node
// plus one agent Node within the same binary if needed).
package swarm
