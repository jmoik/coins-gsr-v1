# Coins + GSR v1 Bridge

Research implementation of a proof-authorized Coins bridge for Bitcoin Script
Restoration. The bridge uses OP_TX to enforce one stable Taproot program and a
trailing caboose that commits to changing account state.

The first milestone is deliberately bounded: three fixed accounts, two deposits
per collection, one signed Coins transfer and one withdrawal per settlement.
Bitcoin miner fees and new cabooses are funded by separate sponsor inputs.

No bridge signing key or mock verifier is part of the accepted bridge path.
The bounded v1 lifecycle is implemented and was validated on GSR regtest with
three real SP1 Groth16 proofs. See [the measured result](results/v1.md) and the
exact acceptance gates in [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md).

## Verified lifecycle

```text
uncredited deposits -> proved collection -> proved transfer + withdrawal
                    -> proved post-settlement collection
```

The stable Taproot output program remains unchanged. Account state lives in the
trailing caboose, while OP_TX binds lineage, deposits, backing, payout, and the
proof statement to each actual Bitcoin transaction.

Run the cheap retained-artifact checks:

```bash
python3 tests/check_vectors.py
python3 tests/check_deployment.py fixtures/v1
scripts/check-sources.sh
```

Replay the complete proof-authorized regtest with the pinned GSR Core build:

```bash
COINS_GSR_VERIFIER=$PWD/fixtures/v1/collection-1/script.json \
COINS_GSR_PROOF_FIXTURES=$PWD/fixtures/v1 \
python3 tests/feature_bridge.py \
  --configfile=../../core/gsr/gsr-full/build/test/config.ini \
  --tmpdir=/private/tmp/coins-gsr-v1-replay
```

Proof generation is intentionally separate and expensive. Use
`scripts/lifecycle.py --help`; commands refuse to overwrite prior artifacts.

## Documents

- [Protocol](docs/protocol.md): canonical formats and enforced transaction rules.
- [Security boundaries](docs/security.md): what Bitcoin, the proof, and the host
  each establish.
- [Source lock](sources.lock.json): exact reference revisions and license status.
- [Retained deployment](fixtures/v1/): inputs, proofs, verifier witnesses, and hashes.
- [Verified result](results/v1.md): transactions, costs, timings, and limitations.

## Development rule

Commits are ordered by one reviewable purpose and include their focused tests.
Historical results from sibling prototypes remain baselines only.
