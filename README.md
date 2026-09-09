# Coins + GSR v1 Bridge

Research implementation of a proof-authorized Coins bridge for Bitcoin Script
Restoration. The bridge uses OP_TX to enforce one stable Taproot program and a
trailing caboose that commits to changing account state.

The first milestone is deliberately bounded: three fixed accounts, two deposits
per collection, one signed Coins transfer and one withdrawal per settlement.
Bitcoin miner fees and new cabooses are funded by separate sponsor inputs.

No bridge signing key or mock verifier is part of the accepted bridge path.
This repository is not yet implemented or validated; current status and exact
acceptance gates are in [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md).

## Documents

- [Protocol](docs/protocol.md): canonical formats and enforced transaction rules.
- [Security boundaries](docs/security.md): what Bitcoin, the proof, and the host
  each establish.
- [Source lock](sources.lock.json): exact reference revisions and license status.

## Development rule

Commits are ordered by one reviewable purpose and include their focused tests.
Historical results from sibling prototypes are baselines only. The README will
claim a working lifecycle only after actual proofs are mined and independently
reproduced on a pinned GSR backend.
