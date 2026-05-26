// Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
// Queries: licensing@hstles.com

// Package swarm is a Plumtrees-based propagation engine with delta-state CRDT
// storage and Merkle anti-entropy. It is the propagation substrate for both
// the HSTLES fleet mesh and the ORBTR agent mesh.
//
// The package exposes a single Node type whose API surface covers:
//   - Subscribe/Publish on tenant-scoped topics
//   - PerPeerConfig: per-peer adaptive interval + backpressure + RTT state
//   - SetRole: runtime role change with tree-edge rebalance
//   - SetTenant: tenant rebind with tombstone-and-republish
//   - Pause/Resume: resource-governor integration
//   - ContentTopic: content-addressed pull (single + chunked) for signed
//     hash-addressed artifact distribution
//
// All consumer wiring is via the Node interface; the package owns no global
// state and is safe for multiple instances per process (e.g. one fleet Node
// plus one agent Node within the same binary if needed).
package swarm
