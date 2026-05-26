// Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
// Queries: licensing@hstles.com

// Package sim provides a deterministic network simulator for the swarm
// engine. It is the test bed for the swarm core, role/tenant/pause hooks,
// ContentTopic + chunked transfer, distributed-state topics, and edge
// roles.
//
// The simulator runs a virtual clock — no time.Sleep, no real network.
// Tests assert convergence within N virtual ticks rather than wall-clock
// seconds. This makes tests both fast and deterministic across CI.
//
// Topology is configurable: a Mesh holds N Nodes connected by Edges with
// per-edge latency, loss, and bandwidth. Frames sent between Nodes are
// scheduled on the virtual clock and delivered by Step.
package sim
