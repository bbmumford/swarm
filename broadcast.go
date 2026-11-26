// Copyright (c) 2026 Brandon Miller-Mumford.
// Licensed under the MIT License; see LICENSE.

package swarm

import "sync"

// maxSeenBroadcasts bounds seenBroadcasts.
const maxSeenBroadcasts = 2048

// broadcastKey names one broadcast: its origin's signed (topic, node, HLC).
type broadcastKey struct {
	topic Topic
	node  NodeID
	hlc   uint64
}

// seenBroadcasts is the bounded set of broadcasts a node has delivered: at
// most maxSeenBroadcasts keys, the oldest forgotten first. A copy that arrives
// after its key was forgotten is delivered again, so the bound sets how long
// duplicates are suppressed, never what is stored.
type seenBroadcasts struct {
	mu    sync.Mutex
	set   map[broadcastKey]struct{}
	order []broadcastKey
	next  int
}

// add records k and reports whether it was new.
func (s *seenBroadcasts) add(k broadcastKey) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.set == nil {
		s.set = make(map[broadcastKey]struct{})
	}
	if _, ok := s.set[k]; ok {
		return false
	}
	if len(s.order) < maxSeenBroadcasts {
		s.order = append(s.order, k)
	} else {
		delete(s.set, s.order[s.next])
		s.order[s.next] = k
		s.next = (s.next + 1) % maxSeenBroadcasts
	}
	s.set[k] = struct{}{}
	return true
}

// handleBroadcast takes a broadcast (Record.Broadcast) that has passed the
// signature and inbound checks: the first copy is handed to the Node's
// subscribers and forwarded to the other tree edges while ttl allows, and
// later copies are dropped. Nothing is stored or announced, and the sender is
// neither promoted nor pruned: a broadcast has no repair path, so it rides the
// tree that stored records shape, and pruning on its duplicates would cut
// edges those records rely on.
func (e *plumtreesEngine) handleBroadcast(from NodeID, r Record, ttl uint32) {
	if !e.broadcasts.add(broadcastKey{r.Topic, r.NodeID, r.HLC}) {
		return
	}
	if e.onBroadcast != nil {
		e.onBroadcast(r)
	}
	if ttl > 1 {
		e.pushBroadcast(from, r, ttl-1)
	}
}

// pushBroadcast sends r to every tree edge but except, promoting edges up to
// treeTarget first (bestTreeEdges) so that a node with no edges yet still
// forwards.
func (e *plumtreesEngine) pushBroadcast(except NodeID, r Record, ttl uint32) {
	frame, err := encodeFrame(frameEagerPush(r, ttl))
	if err != nil {
		return
	}
	for _, edge := range e.bestTreeEdges() {
		if edge != except {
			_ = e.tport.Send(edge, frame)
		}
	}
}

// Broadcast implements Broadcaster: the message is signed, marked seen so its
// echoes are dropped, delivered to this node's own subscribers and pushed to
// the tree edges with the full eager hop budget.
func (n *nodeImpl) Broadcast(topic Topic, body []byte) error {
	if n.stopped.Load() {
		return ErrStopped
	}
	if len(body) > n.cfg.MaxRecordBytes {
		return ErrTooLarge
	}
	r := Record{
		Topic:     topic,
		NodeID:    n.id,
		HLC:       n.hlc.Now(),
		Body:      append([]byte(nil), body...),
		Broadcast: true,
	}
	signRecord(&r, n.priv)
	n.plum.broadcasts.add(broadcastKey{r.Topic, r.NodeID, r.HLC})
	n.deliverToSubs(cloneRecord(r))
	n.plum.pushBroadcast("", r, n.plum.eagerTTL)
	return nil
}
