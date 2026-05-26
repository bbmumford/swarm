// Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
// Queries: licensing@hstles.com

package swarm

import (
	"crypto/ed25519"
	"crypto/sha256"
	"time"

	pb "github.com/bbmumford/swarm/proto/pb"
	"google.golang.org/protobuf/proto"
)

// ChunkBlob splits body into fixed-size chunks and returns each chunk's
// SHA256 hash in order. The last chunk may be smaller than chunkSize.
// chunkSize must be > 0.
func ChunkBlob(body []byte, chunkSize uint32) ([][32]byte, [][]byte) {
	if chunkSize == 0 {
		return nil, nil
	}
	n := len(body)
	count := (n + int(chunkSize) - 1) / int(chunkSize)
	hashes := make([][32]byte, 0, count)
	chunks := make([][]byte, 0, count)
	for i := 0; i < n; i += int(chunkSize) {
		end := i + int(chunkSize)
		if end > n {
			end = n
		}
		c := body[i:end]
		hashes = append(hashes, sha256.Sum256(c))
		chunks = append(chunks, c)
	}
	return hashes, chunks
}

// BuildSignedManifest constructs a Manifest for body, splits it into
// chunks of chunkSize bytes, and signs the manifest with priv. Returns
// the signed manifest bytes, the manifest's SHA256 (used as its
// content-address — pass to ContentTopic.Announce + FetchBlob), the
// chunk hashes, and the chunk bodies (which the publisher must store
// in its ContentProvider so peers can pull them).
func BuildSignedManifest(body []byte, chunkSize uint32, filename, mime string, priv ed25519.PrivateKey) (manifestBytes []byte, manifestHash [32]byte, chunkHashes [][32]byte, chunks [][]byte, err error) {
	if chunkSize == 0 {
		chunkSize = 1 << 20 // 1 MB default
	}
	chunkHashes, chunks = ChunkBlob(body, chunkSize)

	blobHash := sha256.Sum256(body)
	pub, _ := priv.Public().(ed25519.PublicKey)
	publisher := nodeIDFromPub(pub)

	chunkHashBytes := make([][]byte, len(chunkHashes))
	for i := range chunkHashes {
		h := chunkHashes[i]
		chunkHashBytes[i] = h[:]
	}

	manifest := &pb.Manifest{
		BlobHash:    blobHash[:],
		TotalSize:   uint64(len(body)),
		ChunkSize:   chunkSize,
		Chunks:      chunkHashBytes,
		Filename:    filename,
		Mime:        mime,
		PublishedAt: time.Now().UnixNano(),
		Publisher:   []byte(publisher),
	}
	signable := signableManifestBytes(manifestSig{
		BlobHash:    manifest.BlobHash,
		TotalSize:   manifest.TotalSize,
		ChunkSize:   manifest.ChunkSize,
		Chunks:      manifest.Chunks,
		Filename:    manifest.Filename,
		Mime:        manifest.Mime,
		PublishedAt: manifest.PublishedAt,
		Publisher:   manifest.Publisher,
	})
	manifest.Sig = ed25519.Sign(priv, signable)

	manifestBytes, err = proto.Marshal(manifest)
	if err != nil {
		return nil, [32]byte{}, nil, nil, err
	}
	manifestHash = sha256.Sum256(manifestBytes)
	return manifestBytes, manifestHash, chunkHashes, chunks, nil
}
