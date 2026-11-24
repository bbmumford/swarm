// Copyright (c) 2026 Brandon Miller-Mumford.
// Licensed under the MIT License; see LICENSE.

// Package swarmtest holds the trust seams a test hands a swarm node when it
// trusts every node that proves its key. swarm.New requires a TrustCheck and an
// unset observer gate admits no attestation, so a production node always states
// its own policy; these two state "trust every proved node", which only a test
// may mean.
package swarmtest

import "github.com/bbmumford/swarm"

// AcceptAll is a swarm.Config.TrustCheck that admits every record the inbound
// gate has already bound to its signing key, on every topic.
func AcceptAll(swarm.Record) error { return nil }

// AcceptAllObservers is an observer gate (swarm.Node.SetObserverRoleCheck) that
// admits every attestation whose observer the inbound gate has bound to its key.
func AcceptAllObservers(swarm.NodeID, []byte, swarm.NodeID) bool { return true }
