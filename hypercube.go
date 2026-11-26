// Copyright (c) 2026 Brandon Miller-Mumford.
// Licensed under the MIT License; see LICENSE.

package swarm

import (
	"math/bits"
	"sort"
)

// hypercubeDims is the dimension count of a hypercube holding n members:
// ceil(log2 n), and 0 for one member or none.
func hypercubeDims(n int) int {
	if n <= 1 {
		return 0
	}
	return bits.Len(uint(n - 1))
}

// hypercubeRank ranks peers for the eager tree (bestTreeEdges). The members,
// self and every peer, are sorted by NodeID and each takes its index as its
// hypercube position, which every node holding the same member set computes
// alike. A peer whose position differs from self's in exactly one bit, a
// dimension neighbour, ranks by that bit, lowest dimension first; every other
// peer ranks after all of them, nearest position (by XOR distance) first.
// Seeding the tree in this order makes a node's eager edges its cube edges, so
// while the tree holds an eager push reaches every member in at most
// hypercubeDims hops, and Plumtree's prunes then thin the cube to a tree.
func hypercubeRank(self NodeID, peers []NodeID) map[NodeID]int {
	members := make([]NodeID, 0, len(peers)+1)
	members = append(members, self)
	for _, p := range peers {
		if p != self {
			members = append(members, p)
		}
	}
	sort.Slice(members, func(i, j int) bool { return members[i] < members[j] })
	selfPos := sort.Search(len(members), func(i int) bool { return members[i] >= self })
	dims := hypercubeDims(len(members))
	rank := make(map[NodeID]int, len(members)-1)
	for pos, id := range members {
		if pos == selfPos {
			continue
		}
		x := uint(pos ^ selfPos)
		if bits.OnesCount(x) == 1 {
			rank[id] = bits.TrailingZeros(x)
		} else {
			rank[id] = dims + int(x)
		}
	}
	return rank
}
