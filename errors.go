// Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
// Queries: licensing@hstles.com

package swarm

import "errors"

var (
	// ErrNotImplemented is returned by ContentTopic methods while the
	// chunked content layer is not yet wired in.
	ErrNotImplemented = errors.New("swarm: not implemented")

	// ErrInvalidConfig is returned by New() if Config is structurally invalid.
	ErrInvalidConfig = errors.New("swarm: invalid config")

	// ErrNoHolders is returned by ContentTopic.Fetch when no peer claims
	// to hold the requested hash and broadcast lookup also returns empty.
	ErrNoHolders = errors.New("swarm: no holders for content hash")

	// ErrHashMismatch is returned when fetched bytes do not match the
	// requested SHA256 hash.
	ErrHashMismatch = errors.New("swarm: fetched content hash mismatch")

	// ErrTooLarge is returned when a single Record body exceeds Config.MaxRecordBytes.
	ErrTooLarge = errors.New("swarm: record body exceeds maximum size")

	// ErrTenantNotSet is returned when an agent operation is attempted
	// before SetTenant has been called.
	ErrTenantNotSet = errors.New("swarm: tenant not set")

	// ErrPaused is returned by Publish-style calls while the engine is paused.
	ErrPaused = errors.New("swarm: engine paused")

	// ErrStopped is returned after Stop has been called.
	ErrStopped = errors.New("swarm: engine stopped")

	// ErrAlreadyStarted is returned by Start when the node is already
	// running. A second Start would spawn a duplicate ticker goroutine and
	// orphan the first one's cancel func.
	ErrAlreadyStarted = errors.New("swarm: already started")

	// ErrAlreadyWired is returned by Wire when the node already has a
	// transport. Re-wiring would silently discard plumtree/merkle state
	// and leave the old transport's callbacks dangling.
	ErrAlreadyWired = errors.New("swarm: already wired")
)
