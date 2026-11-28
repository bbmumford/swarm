# Changelog

## [0.3.0](https://github.com/bbmumford/swarm/compare/v0.2.0...v0.3.0) (2026-11-28)


### Features

* anti-entropy repairs a large topic by IBLT set difference, moving only the records that differ ([53dbc40](https://github.com/bbmumford/swarm/commit/53dbc406f9f62a3ca89f3f789fb66c8ef39dd260))
* the eager tree is seeded along hypercube dimensions, a topic can have its own merge rule, and a node can broadcast messages that are never stored ([37614a1](https://github.com/bbmumford/swarm/commit/37614a17e9ac6c4ebe15b38a2d976cb7061e992f))


### Bug Fixes

* a node stopped while Start is still setting up returns from Start, and Stop no longer races Start's WaitGroup Add ([dd40257](https://github.com/bbmumford/swarm/commit/dd40257b68a9cfd9d9337a29ccc4ad34ae7b8f48))
* anti-entropy skips the records it already holds before checking their signatures, so repeated ranges cannot starve the missing ones ([a0085f0](https://github.com/bbmumford/swarm/commit/a0085f0a982b7f6e773ebcb1dcc66c7ea4e35a3e))

## [0.2.0](https://github.com/bbmumford/swarm/compare/v0.1.0...v0.2.0) (2026-11-26)


### Features

* an HLC can read an injected wall clock, and a full counter carries into the next millisecond ([888e15a](https://github.com/bbmumford/swarm/commit/888e15a6c8b4492cd77f5c6774f467e87dc0bbfc))

## [0.1.0](https://github.com/bbmumford/swarm/compare/v0.0.9...v0.1.0) (2026-11-25)


### ⚠ BREAKING CHANGES

* swarm.New fails with ErrNoTrustCheck unless Config.TrustCheck is set, and observer attestations are refused until SetObserverRoleCheck sets a gate.
* Config.RequireNodeKeyBinding is removed; the binding always holds. A node's default NodeID, and the NodeID every record must carry, is the aether NodeID of its key.

### Bug Fixes

* a node's NodeID is its aether NodeID, and every inbound record must bind to the key that signed it ([354ae4f](https://github.com/bbmumford/swarm/commit/354ae4f28a84db6235b10488c7425e5bb1b8aa55))
* a record repaired by a Merkle range starts a rumor, and the periodic probe reaches tree-edge peers ([d1fccbe](https://github.com/bbmumford/swarm/commit/d1fccbe82b8ac42536fb54ad2a6b0b422572ce18))
* go.mod requires aether v0.0.118, the release holding the aether code this module builds against ([a0e66cf](https://github.com/bbmumford/swarm/commit/a0e66cf1441d851723a719a68decddeae4692848))
* New requires a TrustCheck, and a node with no observer gate admits no attestation ([cdb88d3](https://github.com/bbmumford/swarm/commit/cdb88d349d59ed7fead66dc4f075edf9486e1b82))
