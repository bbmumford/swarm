// Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
// Queries: licensing@hstles.com

package sim

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/bbmumford/swarm"
)

// memContentProvider is an in-memory ContentProvider for tests.
type memContentProvider struct {
	mu     sync.RWMutex
	blobs  map[[32]byte][]byte
}

func newMemContentProvider() *memContentProvider {
	return &memContentProvider{blobs: make(map[[32]byte][]byte)}
}

func (m *memContentProvider) Put(body []byte) [32]byte {
	hash := sha256.Sum256(body)
	m.mu.Lock()
	m.blobs[hash] = body
	m.mu.Unlock()
	return hash
}

func (m *memContentProvider) Has(hash [32]byte) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.blobs[hash]
	return ok
}

func (m *memContentProvider) Read(hash [32]byte) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	body, ok := m.blobs[hash]
	if !ok {
		return nil, errors.New("not held")
	}
	return body, nil
}

func (m *memContentProvider) Size(hash [32]byte) (uint32, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	body, ok := m.blobs[hash]
	if !ok {
		return 0, false
	}
	return uint32(len(body)), true
}

// TestContentTopicFetch verifies a fetcher can pull bytes from a holder
// via the point-to-point ContentFetchRequest/Response path.
func TestContentTopicFetch(t *testing.T) {
	const numNodes = 4
	mesh := NewMesh(11)

	ids := make([]NodeID, numNodes)
	nodes := make([]*SwarmNode, numNodes)
	for i := 0; i < numNodes; i++ {
		ids[i] = NodeID(fmt.Sprintf("n%02d", i))
	}
	for i, id := range ids {
		peers := make([]NodeID, 0, numNodes-1)
		for _, p := range ids {
			if p != id {
				peers = append(peers, p)
			}
		}
		nodes[i] = NewSwarmNode(id, peers)
		mesh.AddNode(nodes[i])
	}
	for i, n := range nodes {
		for j, peer := range nodes {
			if i == j {
				continue
			}
			n.tport.RegisterPeer(ids[j], peer.SwarmNodeID())
		}
	}
	mesh.FullMesh(5, 2, 0)

	// Node 0 holds and announces a blob.
	provider := newMemContentProvider()
	body := []byte("the quick brown fox jumps over the lazy dog")
	hash := provider.Put(body)

	if err := nodes[0].node.ContentTopic().SetProvider(provider); err != nil {
		t.Fatalf("set provider: %v", err)
	}
	if err := nodes[0].node.ContentTopic().Announce(hash); err != nil {
		t.Fatalf("announce: %v", err)
	}

	// Wait for the advert to propagate to node 1.
	_, err := mesh.Run(500, func(*Mesh) bool {
		holders := nodes[1].node.ContentTopic().Holders(hash)
		for _, h := range holders {
			if h == nodes[0].SwarmNodeID() {
				return true
			}
		}
		return false
	})
	if err != nil {
		t.Fatalf("advert did not propagate: %v", err)
	}

	// Fire Fetch in a goroutine — Mesh.Run drives the message exchange.
	fetchDone := make(chan struct{})
	var fetched []byte
	var fetchErr error
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		fetched, fetchErr = nodes[1].node.ContentTopic().Fetch(ctx, hash)
		close(fetchDone)
	}()

	// Drive ticks until the fetch resolves or we exhaust the budget.
	// Yield to the fetch goroutine each loop so its Send hits the
	// transport's outbound queue before the next mesh tick drains it.
	_, err = mesh.Run(2000, func(*Mesh) bool {
		runtime.Gosched()
		select {
		case <-fetchDone:
			return true
		default:
			return false
		}
	})
	if err != nil {
		t.Fatalf("fetch did not complete in budget: %v", err)
	}

	if fetchErr != nil {
		t.Fatalf("fetch: %v", fetchErr)
	}
	if string(fetched) != string(body) {
		t.Errorf("fetched %q, want %q", fetched, body)
	}

	for _, n := range nodes {
		n.Stop()
	}

	_ = swarm.ErrNoHolders
}

// TestContentTopicFetchBlob verifies the chunked-blob path:
// build+sign manifest, announce, peer FetchBlob reassembles + verifies.
func TestContentTopicFetchBlob(t *testing.T) {
	const numNodes = 3
	mesh := NewMesh(17)

	ids := make([]NodeID, numNodes)
	nodes := make([]*SwarmNode, numNodes)
	for i := 0; i < numNodes; i++ {
		ids[i] = NodeID(fmt.Sprintf("n%02d", i))
	}
	for i, id := range ids {
		peers := make([]NodeID, 0, numNodes-1)
		for _, p := range ids {
			if p != id {
				peers = append(peers, p)
			}
		}
		nodes[i] = NewSwarmNode(id, peers)
		mesh.AddNode(nodes[i])
	}
	for i, n := range nodes {
		for j, peer := range nodes {
			if i == j {
				continue
			}
			n.tport.RegisterPeer(ids[j], peer.SwarmNodeID())
		}
	}
	mesh.FullMesh(5, 2, 0)

	// Build a 3.5-chunk body (3 full + 1 partial) so chunk boundary +
	// last-chunk-shorter behaviour both exercise.
	body := make([]byte, 1024*3+512)
	for i := range body {
		body[i] = byte(i & 0xff)
	}
	const chunkSize = uint32(1024)

	priv := nodes[0].Priv()
	manifestBytes, manifestHash, chunkHashes, chunks, err := swarm.BuildSignedManifest(
		body, chunkSize, "blob.bin", "application/octet-stream", priv,
	)
	if err != nil {
		t.Fatalf("build manifest: %v", err)
	}

	// Node 0's provider holds the manifest + every chunk.
	provider := newMemContentProvider()
	provider.PutHash(manifestHash, manifestBytes)
	for i, h := range chunkHashes {
		provider.PutHash(h, chunks[i])
	}

	if err := nodes[0].node.ContentTopic().SetProvider(provider); err != nil {
		t.Fatalf("set provider: %v", err)
	}
	if err := nodes[0].node.ContentTopic().Announce(manifestHash); err != nil {
		t.Fatalf("announce manifest: %v", err)
	}
	for _, h := range chunkHashes {
		if err := nodes[0].node.ContentTopic().Announce(h); err != nil {
			t.Fatalf("announce chunk: %v", err)
		}
	}

	// Wait for the manifest advert to reach node 1.
	_, err = mesh.Run(500, func(*Mesh) bool {
		holders := nodes[1].node.ContentTopic().Holders(manifestHash)
		for _, h := range holders {
			if h == nodes[0].SwarmNodeID() {
				return true
			}
		}
		return false
	})
	if err != nil {
		t.Fatalf("manifest advert did not propagate: %v", err)
	}

	// Wait for chunk adverts too — otherwise FetchBlob's inner Fetch
	// calls hit ErrNoHolders on the chunks.
	_, err = mesh.Run(500, func(*Mesh) bool {
		for _, h := range chunkHashes {
			holders := nodes[1].node.ContentTopic().Holders(h)
			has := false
			for _, holder := range holders {
				if holder == nodes[0].SwarmNodeID() {
					has = true
					break
				}
			}
			if !has {
				return false
			}
		}
		return true
	})
	if err != nil {
		t.Fatalf("chunk adverts did not propagate: %v", err)
	}

	// FetchBlob from node 1.
	var reassembled blockingBuffer
	var progressCalls int
	fetchDone := make(chan struct{})
	var fetchErr error
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		fetchErr = nodes[1].node.ContentTopic().FetchBlob(ctx, manifestHash, &reassembled, func(received, total uint64) {
			progressCalls++
		})
		close(fetchDone)
	}()

	_, err = mesh.Run(5000, func(*Mesh) bool {
		runtime.Gosched()
		select {
		case <-fetchDone:
			return true
		default:
			return false
		}
	})
	if err != nil {
		t.Fatalf("fetchblob did not complete: %v", err)
	}
	if fetchErr != nil {
		t.Fatalf("fetchblob: %v", fetchErr)
	}

	got := reassembled.Bytes()
	if len(got) != len(body) {
		t.Fatalf("reassembled length = %d, want %d", len(got), len(body))
	}
	for i := range body {
		if got[i] != body[i] {
			t.Fatalf("reassembled diverged at byte %d: got %d, want %d", i, got[i], body[i])
		}
	}
	if progressCalls != len(chunkHashes) {
		t.Errorf("progress calls = %d, want %d", progressCalls, len(chunkHashes))
	}

	for _, n := range nodes {
		n.Stop()
	}
}

// blockingBuffer is a tiny bytes.Buffer wrapper with a mutex so the
// fetch goroutine + test goroutine can race-safely read/write.
type blockingBuffer struct {
	mu  sync.Mutex
	buf []byte
}

func (b *blockingBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buf = append(b.buf, p...)
	return len(p), nil
}

func (b *blockingBuffer) Bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]byte, len(b.buf))
	copy(out, b.buf)
	return out
}

// PutHash stores body under a caller-supplied hash. Used in tests that
// pre-compute hashes (manifests + chunks) before storing.
func (m *memContentProvider) PutHash(hash [32]byte, body []byte) {
	m.mu.Lock()
	m.blobs[hash] = body
	m.mu.Unlock()
}

// TestContentTopicFetch_NoHolders verifies Fetch returns ErrNoHolders
// when nobody has advertised the hash.
func TestContentTopicFetch_NoHolders(t *testing.T) {
	mesh := NewMesh(13)
	n := NewSwarmNode("solo", nil)
	mesh.AddNode(n)

	hash := sha256.Sum256([]byte("nobody-has-this"))

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	_, err := n.node.ContentTopic().Fetch(ctx, hash)
	if !errors.Is(err, swarm.ErrNoHolders) {
		t.Errorf("expected ErrNoHolders, got %v", err)
	}
	n.Stop()
}
