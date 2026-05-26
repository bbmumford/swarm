// Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
// Queries: licensing@hstles.com

package swarm

// Transport is the byte-level send/receive interface that the swarm Node
// uses to talk to peers. Consumers wire this to their actual mesh transport
// (aether, WebSocket, etc.); the simulator wires it to a deterministic mesh.
//
// All calls are non-blocking — Send queues for delivery; the Transport
// drives Receive() from its own goroutine.
type Transport interface {
	// LocalID returns the NodeID this transport represents.
	LocalID() NodeID

	// Send queues a Frame for delivery to a single peer. Returns nil if
	// queued successfully (delivery is best-effort and asynchronous).
	Send(to NodeID, frame []byte) error

	// Broadcast queues a Frame for delivery to all currently-connected peers.
	Broadcast(frame []byte) error

	// Peers returns the current set of connected peer NodeIDs.
	Peers() []NodeID

	// OnReceive registers a callback invoked on every incoming frame.
	// Called from the transport's goroutine — the callback should not block.
	OnReceive(fn func(from NodeID, frame []byte))

	// OnPeerJoin registers a callback invoked when a new peer becomes
	// reachable.
	OnPeerJoin(fn func(id NodeID))

	// OnPeerLeave registers a callback invoked when a peer becomes
	// unreachable (disconnect, timeout, etc.).
	OnPeerLeave(fn func(id NodeID))
}
