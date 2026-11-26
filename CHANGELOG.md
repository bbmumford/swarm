# Changelog

## [0.1.0](https://github.com/bbmumford/swarm/compare/v0.0.9...v0.1.0) (2026-11-25)


### ⚠ BREAKING CHANGES

* swarm.New fails with ErrNoTrustCheck unless Config.TrustCheck is set, and observer attestations are refused until SetObserverRoleCheck sets a gate.
* Config.RequireNodeKeyBinding is removed; the binding always holds. A node's default NodeID, and the NodeID every record must carry, is the aether NodeID of its key.

### Bug Fixes

* a node's NodeID is its aether NodeID, and every inbound record must bind to the key that signed it ([354ae4f](https://github.com/bbmumford/swarm/commit/354ae4f28a84db6235b10488c7425e5bb1b8aa55))
* a record repaired by a Merkle range starts a rumor, and the periodic probe reaches tree-edge peers ([d1fccbe](https://github.com/bbmumford/swarm/commit/d1fccbe82b8ac42536fb54ad2a6b0b422572ce18))
* go.mod requires aether v0.0.118, the release holding the aether code this module builds against ([a0e66cf](https://github.com/bbmumford/swarm/commit/a0e66cf1441d851723a719a68decddeae4692848))
* New requires a TrustCheck, and a node with no observer gate admits no attestation ([cdb88d3](https://github.com/bbmumford/swarm/commit/cdb88d349d59ed7fead66dc4f075edf9486e1b82))
