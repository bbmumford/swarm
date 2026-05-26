// Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
// Queries: licensing@hstles.com

package swarm

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"time"

	pb "github.com/bbmumford/swarm/proto/pb"
	"google.golang.org/protobuf/proto"
)

// topicContentAdvert is the swarm topic carrying ContentAdvert records
// for the fleet fabric. Agent-fabric ContentTopic instances use
// AgentContentAdvertTopic(tenantID) — selected per SwarmIntegration in
// the agent layer.
const topicContentAdvert = FleetContentAdvertTopic

// fetchTimeoutDefault is the default deadline for a Fetch RPC if the
// caller's context has none.
const fetchTimeoutDefault = 15 * time.Second

// contentTopicImpl implements ContentTopic. Announce publishes a signed
// ContentAdvert onto a swarm topic; Holders queries an in-memory index
// built from received adverts. Fetch issues a point-to-point
// ContentFetchRequest to a holder and awaits the paired
// ContentFetchResponse via correlation through pending.
type contentTopicImpl struct {
	node     *nodeImpl
	provider ContentProvider

	mu        sync.RWMutex
	holders   map[[32]byte]map[NodeID]int64 // hash -> nodeID -> expires_at unix ns
	advertTTL time.Duration

	subOnce sync.Once
	unsub   Unsubscribe

	// In-flight Fetch correlation. Each Fetch allocates a request ID, an
	// entry in pending, and waits on its channel for the matching
	// ContentFetchResponse to arrive. The channel itself is taken from
	// chanPool so a burst of concurrent Fetch calls doesn't allocate a
	// fresh channel per RPC — under load this is the difference
	// between a few-MB working set and a steady drip of GC pressure.
	pendingMu sync.Mutex
	pending   map[uint64]chan *pb.ContentFetchResponse
	reqCount  atomic.Uint64
	chanPool  sync.Pool
}

func newContentTopic(n *nodeImpl) *contentTopicImpl {
	c := &contentTopicImpl{
		node:      n,
		holders:   make(map[[32]byte]map[NodeID]int64),
		advertTTL: 6 * time.Hour,
		pending:   make(map[uint64]chan *pb.ContentFetchResponse),
	}
	c.chanPool.New = func() any {
		return make(chan *pb.ContentFetchResponse, 1)
	}
	c.ensureSubscribed()
	return c
}

// ensureSubscribed installs the advert-topic subscriber. Called once at
// construction; idempotent.
func (c *contentTopicImpl) ensureSubscribed() {
	c.subOnce.Do(func() {
		unsub, err := c.node.Subscribe(topicContentAdvert, c.onAdvertRecord)
		if err != nil {
			return
		}
		c.unsub = unsub
	})
}

func (c *contentTopicImpl) SetProvider(p ContentProvider) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.provider = p
	return nil
}

// Announce publishes a signed advert claiming this node holds hash. The
// advert carries the node's NodeID + expiry timestamp; receivers index
// the (hash, holder) tuple until expiry. Re-Announce extends expiry.
func (c *contentTopicImpl) Announce(hash [32]byte) error {
	c.ensureSubscribed()

	c.mu.RLock()
	provider := c.provider
	advertTTL := c.advertTTL
	c.mu.RUnlock()

	var size uint32
	if provider != nil {
		if s, ok := provider.Size(hash); ok {
			size = s
		}
	}

	expiresAt := time.Now().Add(advertTTL).UnixNano()
	advert := &pb.ContentAdvert{
		Hash:      hash[:],
		Holder:    []byte(c.node.id),
		ExpiresAt: expiresAt,
		Size:      size,
	}
	body, err := proto.Marshal(advert)
	if err != nil {
		return err
	}
	return c.node.Publish(topicContentAdvert, body)
}

// Withdraw publishes a tombstone advert (Size=0, ExpiresAt=now) so peers
// remove this holder from their index promptly.
func (c *contentTopicImpl) Withdraw(hash [32]byte) error {
	advert := &pb.ContentAdvert{
		Hash:      hash[:],
		Holder:    []byte(c.node.id),
		ExpiresAt: time.Now().UnixNano() - 1, // already expired
		Size:      0,
	}
	body, err := proto.Marshal(advert)
	if err != nil {
		return err
	}
	return c.node.Publish(topicContentAdvert, body)
}

// Holders returns the set of NodeIDs that currently claim to hold the
// content with the given hash. Returns an empty slice if no holders
// advertised, or if all known adverts have expired.
func (c *contentTopicImpl) Holders(hash [32]byte) []NodeID {
	c.ensureSubscribed()

	c.mu.Lock()
	defer c.mu.Unlock()
	m, ok := c.holders[hash]
	if !ok {
		return nil
	}
	now := time.Now().UnixNano()
	out := make([]NodeID, 0, len(m))
	for id, exp := range m {
		if exp <= now {
			delete(m, id)
			continue
		}
		out = append(out, id)
	}
	if len(m) == 0 {
		delete(c.holders, hash)
	}
	return out
}

// Fetch retrieves a single-blob content by hash. Picks a holder from
// the local advert index, issues a point-to-point ContentFetchRequest,
// awaits the paired response on a correlation channel, and SHA256-
// verifies the returned body against the requested hash before
// returning. Returns ErrNoHolders when no holders are known and
// ErrHashMismatch if a holder returns bytes that don't match the hash.
func (c *contentTopicImpl) Fetch(ctx context.Context, hash [32]byte) ([]byte, error) {
	holders := c.Holders(hash)
	if len(holders) == 0 {
		return nil, ErrNoHolders
	}

	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, fetchTimeoutDefault)
		defer cancel()
	}

	var lastErr error
	for _, holder := range holders {
		if holder == c.node.id {
			// Local-hold short-circuit — provider may be wired.
			c.mu.RLock()
			provider := c.provider
			c.mu.RUnlock()
			if provider != nil && provider.Has(hash) {
				body, err := provider.Read(hash)
				if err == nil && verifyContentHash(hash, body) {
					return body, nil
				}
			}
			continue
		}

		body, err := c.requestFromHolder(ctx, holder, hash)
		if err == nil && verifyContentHash(hash, body) {
			return body, nil
		}
		if err != nil {
			lastErr = err
		} else {
			lastErr = ErrHashMismatch
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}

	if lastErr != nil {
		return nil, lastErr
	}
	return nil, ErrNoHolders
}

// requestFromHolder dispatches a single ContentFetchRequest to holder
// and blocks on the correlated response. Cancellation drains pending
// without leaking the channel.
func (c *contentTopicImpl) requestFromHolder(ctx context.Context, holder NodeID, hash [32]byte) ([]byte, error) {
	tport := c.node.tport
	if tport == nil {
		return nil, ErrNotImplemented
	}

	reqID := c.reqCount.Add(1)
	ch := c.chanPool.Get().(chan *pb.ContentFetchResponse)

	c.pendingMu.Lock()
	c.pending[reqID] = ch
	c.pendingMu.Unlock()

	defer func() {
		c.pendingMu.Lock()
		delete(c.pending, reqID)
		c.pendingMu.Unlock()
		// Drain any stale value before returning to the pool so the
		// next Get() sees a fresh buffered channel.
		select {
		case <-ch:
		default:
		}
		c.chanPool.Put(ch)
	}()

	frame := &pb.Frame{Kind: &pb.Frame_FetchReq{FetchReq: &pb.ContentFetchRequest{
		RequestId: reqID,
		Hash:      hash[:],
	}}}
	raw, err := proto.Marshal(frame)
	if err != nil {
		return nil, err
	}
	if err := tport.Send(holder, raw); err != nil {
		return nil, err
	}

	select {
	case resp := <-ch:
		if resp.Error != "" {
			return nil, errors.New(resp.Error)
		}
		return resp.Body, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// handleFetchRequest serves an incoming ContentFetchRequest from peer
// from. Looks up the local provider, sends a paired response carrying
// the bytes or an error string. Always responds — even on miss — so the
// originator's wait doesn't hit its deadline.
func (c *contentTopicImpl) handleFetchRequest(from NodeID, req *pb.ContentFetchRequest) {
	tport := c.node.tport
	if tport == nil {
		return
	}

	resp := &pb.ContentFetchResponse{RequestId: req.RequestId}
	if len(req.Hash) != 32 {
		resp.Error = "invalid hash length"
	} else {
		c.mu.RLock()
		provider := c.provider
		c.mu.RUnlock()

		if provider == nil {
			resp.Error = "no local provider"
		} else {
			var hash [32]byte
			copy(hash[:], req.Hash)
			if !provider.Has(hash) {
				resp.Error = "not held"
			} else {
				body, err := provider.Read(hash)
				if err != nil {
					resp.Error = err.Error()
				} else {
					resp.Body = body
				}
			}
		}
	}

	frame := &pb.Frame{Kind: &pb.Frame_FetchResp{FetchResp: resp}}
	raw, err := proto.Marshal(frame)
	if err != nil {
		return
	}
	_ = tport.Send(from, raw)
}

// handleFetchResponse routes an incoming response to the waiting Fetch
// goroutine via the pending channel keyed by request_id. Stale or
// unknown responses are silently dropped.
func (c *contentTopicImpl) handleFetchResponse(_ NodeID, resp *pb.ContentFetchResponse) {
	c.pendingMu.Lock()
	ch, ok := c.pending[resp.RequestId]
	c.pendingMu.Unlock()
	if !ok {
		return
	}
	select {
	case ch <- resp:
	default:
		// Buffer full — caller already timed out.
	}
}

// FetchBlob retrieves a chunked content blob addressed by the SHA256 of
// its serialized Manifest. The flow is:
//
//  1. Fetch the Manifest bytes via single-blob Fetch(manifestHash) and
//     decode them.
//  2. Verify the manifest's Ed25519 signature against the publisher's
//     public key (NodeID == hex(public key)) and reject if invalid.
//  3. Walk manifest.Chunks in order, fetching each by hash via Fetch.
//     The local provider short-circuits as a chunk cache when already
//     held.
//  4. Stream every chunk into out, calling progress after each one with
//     cumulative bytes / total.
//  5. After the final chunk, verify the reassembled stream's running
//     SHA256 matches manifest.BlobHash and return an error if it
//     diverges so callers don't write a corrupted reassembly.
//
// Concurrency: chunks are serialized for now — the streaming write into
// out makes parallel decoding awkward without an intermediate buffer.
// A parallel-with-reorder buffer is a straight optimization to add once
// it's needed.
func (c *contentTopicImpl) FetchBlob(ctx context.Context, manifestHash [32]byte, out io.Writer, progress ProgressFunc) error {
	if out == nil {
		return errors.New("swarm: FetchBlob requires non-nil out writer")
	}

	manifestBody, err := c.Fetch(ctx, manifestHash)
	if err != nil {
		return err
	}

	manifest := &pb.Manifest{}
	if err := proto.Unmarshal(manifestBody, manifest); err != nil {
		return errors.New("swarm: malformed manifest body")
	}
	if !verifyManifestSig(manifest) {
		return errors.New("swarm: manifest signature verification failed")
	}
	if len(manifest.BlobHash) != 32 {
		return errors.New("swarm: manifest blob_hash length invalid")
	}

	hasher := sha256.New()
	var received uint64
	for _, chunkHashBytes := range manifest.Chunks {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if len(chunkHashBytes) != 32 {
			return errors.New("swarm: manifest chunk hash length invalid")
		}
		var chunkHash [32]byte
		copy(chunkHash[:], chunkHashBytes)

		body, err := c.Fetch(ctx, chunkHash)
		if err != nil {
			return err
		}
		if _, err := hasher.Write(body); err != nil {
			return err
		}
		if _, err := out.Write(body); err != nil {
			return err
		}
		received += uint64(len(body))
		if progress != nil {
			progress(received, manifest.TotalSize)
		}
	}

	var sum [32]byte
	hasher.Sum(sum[:0])
	var expected [32]byte
	copy(expected[:], manifest.BlobHash)
	if sum != expected {
		return ErrHashMismatch
	}
	return nil
}

// onAdvertRecord is the subscriber callback for the content advert
// topic. Decodes the advert, indexes the (hash, holder) tuple, and
// schedules its expiry per the carried ExpiresAt field.
func (c *contentTopicImpl) onAdvertRecord(r Record) error {
	if r.Tombstone {
		return nil
	}
	advert := &pb.ContentAdvert{}
	if err := proto.Unmarshal(r.Body, advert); err != nil {
		return nil
	}
	if len(advert.Hash) != 32 {
		return nil
	}
	var hash [32]byte
	copy(hash[:], advert.Hash)
	holder := NodeID(advert.Holder)
	if holder == "" {
		holder = r.NodeID
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if advert.ExpiresAt <= time.Now().UnixNano() {
		// Tombstone-shaped withdrawal
		if m, ok := c.holders[hash]; ok {
			delete(m, holder)
			if len(m) == 0 {
				delete(c.holders, hash)
			}
		}
		return nil
	}

	m, ok := c.holders[hash]
	if !ok {
		m = make(map[NodeID]int64)
		c.holders[hash] = m
	}
	m[holder] = advert.ExpiresAt
	return nil
}

// verifyContentHash reports whether sha256(body) equals hash.
func verifyContentHash(hash [32]byte, body []byte) bool {
	actual := sha256.Sum256(body)
	return actual == hash
}

// verifyManifestSig validates the manifest's Ed25519 signature against
// the publisher's public key (derived from the Publisher NodeID).
// Returns false on any malformed input — the caller treats a false
// return as an unsigned manifest and rejects it.
func verifyManifestSig(m *pb.Manifest) bool {
	if m == nil || len(m.Sig) == 0 {
		return false
	}
	pub, ok := pubFromNodeID(NodeID(m.Publisher))
	if !ok {
		return false
	}
	signable := signableManifestBytes(manifestSig{
		BlobHash:    m.BlobHash,
		TotalSize:   m.TotalSize,
		ChunkSize:   m.ChunkSize,
		Chunks:      m.Chunks,
		Filename:    m.Filename,
		Mime:        m.Mime,
		PublishedAt: m.PublishedAt,
		Publisher:   m.Publisher,
	})
	return ed25519.Verify(pub, signable, m.Sig)
}
