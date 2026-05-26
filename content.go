// Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
// Queries: licensing@hstles.com

package swarm

import (
	"context"
	"io"
)

// ContentTopic provides content-addressed pull of signed+hash-addressed
// artifacts. It supports two flavours: single-blob Fetch and chunked
// FetchBlob with manifest + parallel chunk fetching + resume.
//
// All artifact types in the fleet ride this primitive: scripts,
// PolicyBundles, DNS blocklists, admin-uploaded files, TUF binaries +
// metadata, YARA/CAPA/Sigma rules, print drivers, key rotation envelopes,
// vouchers, FIM baselines, OSquery packs.
type ContentTopic interface {
	// SetProvider registers the local content provider (Has/Read/Size).
	// Called by consumers that publish content (e.g. admin asset store).
	SetProvider(p ContentProvider) error

	// Announce publishes a signed advert claiming this node holds hash.
	Announce(hash [32]byte) error

	// Withdraw publishes a tombstone advert for hash.
	Withdraw(hash [32]byte) error

	// Holders returns the current advert set for hash (peers who claim
	// to hold it). May be empty if no adverts received yet.
	Holders(hash [32]byte) []NodeID

	// Fetch retrieves a single-blob content by hash.
	// Looks up holders, RTT-sorts, fans out in parallel to first 2,
	// SHA256-verifies, returns the bytes. If no holders are known,
	// broadcasts a content.locate.<hash> query first.
	Fetch(ctx context.Context, hash [32]byte) ([]byte, error)

	// FetchBlob retrieves a chunked content blob by its top-level
	// BlobHash. Internally:
	//   1. Fetches the signed Manifest
	//   2. Verifies signature + that BlobHash matches its declared chunks
	//   3. Fans out parallel ContentTopic.Fetch calls for each chunk
	//      (concurrency bounded by Config.MaxParallelChunks, default 4)
	//   4. Resumes from local cache if some chunks already held
	//   5. Reassembles into out; verifies total SHA256(reassembled) == BlobHash
	//   6. Calls progress after each chunk
	FetchBlob(ctx context.Context, blobHash [32]byte, out io.Writer, progress ProgressFunc) error
}

// ContentProvider is the local content-fetch interface. Holders register
// a provider so the FetchBlob receiver can serve chunks from local storage.
type ContentProvider interface {
	// Has reports whether this node currently holds the content.
	Has(hash [32]byte) bool

	// Read returns the content bytes if held.
	Read(hash [32]byte) ([]byte, error)

	// Size returns the byte size if held (cheaper than Read for advert sizing).
	Size(hash [32]byte) (uint32, bool)
}

// ProgressFunc reports cumulative bytes received during a FetchBlob.
// Called after each chunk completes. Nil is OK (no progress reporting).
type ProgressFunc func(received, total uint64)
