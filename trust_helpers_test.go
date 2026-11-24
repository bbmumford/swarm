// Copyright (c) 2026 Brandon Miller-Mumford.
// Licensed under the MIT License; see LICENSE.

package swarm

// acceptAllRecords is the TrustCheck a test gives a node that trusts every
// node whose record binds to its key. swarmtest.AcceptAll is the same check
// for tests outside this package, which cannot import it from here.
func acceptAllRecords(Record) error { return nil }

// acceptAllObservers is the observer gate a test gives a store or node that
// counts every attestation, as swarmtest.AcceptAllObservers does.
func acceptAllObservers(NodeID, []byte, NodeID) bool { return true }
