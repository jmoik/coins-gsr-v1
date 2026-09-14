# Coins + GSR v1 Bridge

## What We Built

This repository contains a bounded, proof-authorized Bitcoin bridge prototype.
It connects Bitcoin custody to a three-account Coins state machine using Script
Restoration, OP_TX, UTXO linearization, a changing state caboose, and genuine
SP1 Groth16 proofs. The complete lifecycle was mined on a dedicated GSR regtest.
There is no bridge signing key, hidden Taproot key path, or mock-verifier fallback
in an accepted bridge transition.

```text
Bitcoin deposits ──► proved collection ──► Coins balances
                                              │
                               signed transfer + withdrawal
                                              │
                                              ▼
Bitcoin payout ◄── proved settlement ◄── updated Coins balances
                                              │
                                   proved later collection
```

## Bitcoin Construction

The bridge is a unique chain of head UTXOs. Output 0 always carries the same
two-leaf, NUMS-key Taproot program. Changing account state is committed in the
last output, a 330-sat P2WSH “caboose.” The state contains the fixed account root
and, after genesis, the actual genesis txid as the bridge identity.

OP_TX binds every proof to the real transaction: current and spent amounts,
scripts, input/output roles, parent and grandparent lineage, bridge identity,
old caboose root, successor root, deposits, payout, and backing. A copied program
or state cannot create another valid bridge origin. A competing transition makes
an existing proof stale, but deposits remain usable because they commit to the
stable bridge identity rather than a particular head.

The fixed v1 transactions are:

- Genesis: funding → 1,000-sat reserve bridge + caboose.
- Collection: bridge + two deposits + sponsor → successor + sponsor change +
  caboose.
- Settlement: bridge + sponsor → successor + recipient payout + sponsor change
  + caboose.
- Refund: an uncollected depositor can immediately spend through their BIP340
  refund path without bridge cooperation.

The sponsor pays miner fees and each new caboose. The invariant is:

```text
bridge value = 1,000-sat reserve + sum of all account balances
```

## Proven State Machine

The SP1 guest supports two actions:

1. `COLLECT_TWO` authenticates two ordered deposit UTXOs, credits their exact
   values to their committed accounts, and preserves every other balance/nonce.
2. `TRANSFER_WITHDRAW` validates one native Coins transfer, a bridge-scoped
   transfer authorization, its fee credit, and one signed withdrawal. It debits
   the withdrawing account, increments nonces, and binds the exact Bitcoin payout.

The proof statement includes the bridge identity and head, old/new account roots,
old/new backing, and all action-specific deposit or payout data. Script rebuilds
these public values from OP_TX-authenticated transaction data, checks both caboose
roots, and executes the fixed verifier. The prover cannot substitute roots,
transactions, recipients, amounts, or the verification key.

## Implemented Lifecycle and Evidence

The retained run completed:

```text
genesis → collect two deposits → transfer and withdraw
        → collect two later deposits
```

It used three real proofs; all proof-authorized spends entered blocks. A separate
owner refund succeeded. Mutation tests rejected altered proofs, statements,
deposits, forwarding, payouts, destinations, outputs, roots, and stale heads.
Invalidate/reconsider tests restored the correct state.

| Action | Transaction weight | Proof | Bridge witness | Verifier varops | Mempool validation |
| --- | ---: | ---: | ---: | ---: | ---: |
| Collection 1 | 342,448 WU | 356 B | 338,847 B | 3.334B | 0.138–0.255 s |
| Settlement | 337,323 WU | 356 B | 336,262 B | 3.348B | 0.138–0.255 s |
| Collection 2 | 343,124 WU | 356 B | 339,201 B | 3.343B | 0.138–0.255 s |

The common pure-GSR verifier is 76,400 bytes. Proof generation took minutes to
hours on the test machine and is not suitable for a mobile prover. The separate
five-field-opcode verifier research is substantially smaller and faster, but is
not part of this retained v1 deployment.

## Reproduce the Retained Deployment

Run the inexpensive artifact checks:

```bash
python3 tests/check_vectors.py
python3 tests/check_deployment.py fixtures/v1
scripts/check-sources.sh
```

Replay the proof-authorized lifecycle with the pinned GSR Core build:

```bash
COINS_GSR_VERIFIER=$PWD/fixtures/v1/collection-1/script.json \
COINS_GSR_PROOF_FIXTURES=$PWD/fixtures/v1 \
python3 tests/feature_bridge.py \
  --configfile=../../core/gsr/gsr-full/build/test/config.ini \
  --tmpdir=/private/tmp/coins-gsr-v1-replay
```

Proof generation is intentionally separate and expensive. Run
`scripts/lifecycle.py --help`; lifecycle commands refuse to overwrite existing
artifacts.

## Enforcement Boundary

- Bitcoin enforces lineage, unique state succession, exact custody accounting,
  deposit binding, payout binding, proof execution, and transaction validity.
- The proof enforces Coins signatures, nonces, balances, deposit credits,
  transfer fees, withdrawal authorization, and old-to-new account state.
- A host supplies complete state openings, constructs proofs/transactions, pays
  fees, publishes data, and follows the validated Bitcoin chain. It has no key
  that can bypass the covenant or proof.

## What v1 Does Not Solve

This is not yet a production L2 or Glass Coins. It has three fixed accounts,
two deposits per collection, one transfer/withdrawal per settlement, public
deposits and payouts, and a fixed P2TR withdrawal destination. It provides no
general batching, privacy, decentralized data availability, mobile proving,
forced exit for already-collected balances, inclusion guarantee, production
setup ceremony, or migration mechanism. Uncollected deposits have unilateral
refunds; collected balances still require state data and a prover.

## Repository Guide

- [Protocol](docs/protocol.md): canonical formats and enforced transaction rules.
- [Security boundaries](docs/security.md): what Bitcoin, the proof, and the host
  each establish.
- [Implementation plan](IMPLEMENTATION_PLAN.md): completed milestones and gates.
- [Source lock](sources.lock.json): exact reference revisions and license status.
- [Retained deployment](fixtures/v1/): inputs, proofs, verifier witnesses, and hashes.
- [Verified result](results/v1.md): transactions, costs, timings, and limitations.

Commits are ordered by one reviewable purpose and include their focused tests.
Historical results from sibling prototypes remain baselines only.
