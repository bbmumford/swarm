// Copyright (c) 2026 Brandon Miller-Mumford.
// Licensed under the MIT License; see LICENSE.

package swarm

import (
	"fmt"
	"sort"
	"testing"
)

// treeEngine builds a Plumtree engine for self with the given peers known and
// none yet a tree edge.
func treeEngine(self NodeID, peers []NodeID, degree int, cfg func(NodeID) PerPeerConfig) *plumtreesEngine {
	pt := newPeerTable(cfg)
	for _, p := range peers {
		pt.Ensure(p)
	}
	return newPlumtrees(self, newRecordStore(), pt, nil, nil, degree, nil, 0)
}

func members(n int) []NodeID {
	out := make([]NodeID, n)
	for i := range out {
		out[i] = NodeID(fmt.Sprintf("n%02d", i))
	}
	return out
}

func without(ids []NodeID, self NodeID) []NodeID {
	var out []NodeID
	for _, id := range ids {
		if id != self {
			out = append(out, id)
		}
	}
	return out
}

func sortedIDs(ids []NodeID) []NodeID {
	out := append([]NodeID(nil), ids...)
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// TestBestTreeEdgesAreTheCubeNeighbours: of eight members, n05 (position 101)
// has cube neighbours n04 (100), n07 (111) and n01 (001); with four tree
// edges the fourth is the nearest other position, n06 (110). A tree seeded
// from the lowest NodeIDs instead (n00 to n03) leaves n05's eager pushes
// circling one corner of the cube.
func TestBestTreeEdgesAreTheCubeNeighbours(t *testing.T) {
	all := members(8)
	e := treeEngine("n05", without(all, "n05"), 4, nil)
	got := sortedIDs(e.bestTreeEdges())
	want := []NodeID{"n01", "n04", "n06", "n07"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("tree edges of n05 among 8: got %v, want the cube neighbours n01 n04 n07 and the nearest other n06", got)
	}
}

// TestTreeSeedsEveryDimensionOfALargeCube: with 40 members the cube has six
// dimensions; a tree of only TreeDegree (4) edges would leave the eager graph
// in blocks no eager push crosses, so every dimension's neighbour is seeded.
func TestTreeSeedsEveryDimensionOfALargeCube(t *testing.T) {
	all := members(40)
	self := NodeID("n09") // position 9 = 001001
	e := treeEngine(self, without(all, self), 4, nil)
	edges := map[NodeID]bool{}
	for _, id := range e.bestTreeEdges() {
		edges[id] = true
	}
	if len(edges) != 6 {
		t.Fatalf("tree edges among 40 members: got %d, want 6 (one per dimension)", len(edges))
	}
	for d := 0; d < 6; d++ {
		pos := 9 ^ (1 << d)
		if pos >= 40 {
			continue
		}
		if id := NodeID(fmt.Sprintf("n%02d", pos)); !edges[id] {
			t.Fatalf("dimension %d neighbour %s is not a tree edge: %v", d, id, edges)
		}
	}
}

// TestTreeEdgesKeepPriorityFirst: a peer of a higher PriorityClass (an anchor,
// an edge service) is seeded before every cube neighbour.
func TestTreeEdgesKeepPriorityFirst(t *testing.T) {
	all := members(8)
	cfg := func(id NodeID) PerPeerConfig {
		c := DefaultPerPeerConfig()
		if id == "n00" {
			c.PriorityClass = c.PriorityClass + 1
		}
		return c
	}
	e := treeEngine("n05", without(all, "n05"), 4, cfg)
	got := sortedIDs(e.bestTreeEdges())
	want := []NodeID{"n00", "n01", "n04", "n07"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("tree edges with n00 prioritised: got %v, want %v", got, want)
	}
}

// TestHypercubeRank pins the order: cube neighbours by dimension, then the
// others by XOR distance.
func TestHypercubeRank(t *testing.T) {
	r := hypercubeRank("n05", without(members(8), "n05"))
	order := []NodeID{"n04", "n07", "n01", "n06", "n00", "n03", "n02"}
	for i := 1; i < len(order); i++ {
		if r[order[i-1]] >= r[order[i]] {
			t.Fatalf("rank of %s (%d) should be below %s (%d)", order[i-1], r[order[i-1]], order[i], r[order[i]])
		}
	}
	if hypercubeDims(1) != 0 || hypercubeDims(2) != 1 || hypercubeDims(8) != 3 || hypercubeDims(9) != 4 {
		t.Fatalf("hypercubeDims: %d %d %d %d", hypercubeDims(1), hypercubeDims(2), hypercubeDims(8), hypercubeDims(9))
	}
}
