# Security and Enforcement Boundaries

This project composes three checks. None substitutes for another.

| Claim | Bitcoin Script | ZK relation | Host / observer |
| --- | --- | --- | --- |
| Correct bridge lineage | Enforces parent/grandparent authentication and stable successor | Binds claimed identity and head | Tracks expected genesis and validated chain |
| Correct account transition | Binds old/new caboose roots to the proof | Checks roots, signatures, nonces, balances and action | Supplies state opening; verifies it matches root |
| Correct deposit credit | Binds spent deposit programs, recipients and values | Credits exact bound records | Finds deposits and constructs transaction |
| Correct withdrawal | Binds actual payout and reduced backing | Checks authorization and debit | Submits proof; cannot change payout |
| Transaction validity | Consensus and GSR resource rules | Not established | Full node validates block/mempool |
| Latest/unspent state | Prevents confirmed double spend | Not established | Validated chain and UTXO view |
| Data availability | Not established | Not established | State/proof data must remain available |
| Progress and inclusion | Not guaranteed | Not guaranteed | Permissionless participants may prove/submit |

## Required invariants

- All Taproot spending paths enforce the same lineage, accounting, and real-proof
  checks; the internal key has no known discrete logarithm.
- A copied stable program or copied state is not accepted as the intended bridge.
- The old root comes from the authenticated parent caboose, not the prover.
- The new root, deposits, payout and backing are bound to actual transaction data.
- The verification key and program identity are deployment constants, never
  chosen by the proof witness.
- Mock verifier fixtures use separate development commands and cannot satisfy the
  accepted deployment path.
- Every input/output has one exhaustive role. Unknown extras fail.
- Cache use never changes consensus resource charges.

## Known limitations

The prototype assumes the chosen SP1/Groth16 construction and its setup/deployment
process are sound. It does not establish production ceremony security. The GSR
rules and OP_TX are experimental.

Anyone with the complete state may construct proofs, but proving may be expensive.
Permissionless validity does not guarantee publication, fee payment, or timely
withdrawals. If state data is withheld, already-collected users have no defined
unilateral exit in v1. Immediate refunds protect only uncollected deposits.

The fixed account set and fixed action sizes are conformance boundaries, not
scalability claims. No privacy is added: deposits, payouts, and the bridge UTXO
remain public. Glass Coins, batching and a decentralized DA layer are separate
future protocols.

The three account secrets (`11`, `12`, and `13` as BN254 scalars) and all Bitcoin
refund secrets are public deterministic regtest fixtures. They demonstrate that
the proof checks genuine Coins signatures; they provide no user authentication
or secrecy outside this isolated deployment. They are not a bridge authority:
knowing them cannot bypass lineage, backing, or proof verification.

## Review rule

Every negative test must identify the guard it reaches. Native verification,
Script evaluation, mempool acceptance and consensus block acceptance are reported
separately. Historical logs never count as a current rerun.
