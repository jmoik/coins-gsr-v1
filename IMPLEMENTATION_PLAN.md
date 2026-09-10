# Coins + GSR v1 — Implementation Plan

Status: bounded v1 implemented and validated on 2026-09-10. All ten milestone
purposes below are complete; exact evidence and remaining limitations are in
`results/v1.md`.

## 1. Outcome and scope

Build one reproducible, proof-authorized Bitcoin bridge prototype connecting
OP_TX UTXO linearization to a bounded Coins account state machine.

The demonstration must start with uncredited Bitcoin funds, collect real
deposits, prove the corresponding account credits, validate a genuinely signed
Coins transfer and withdrawal, and pay Bitcoin to the authorized destination.
Every bridge transition preserves the same Taproot program at output 0. State
changes live in the trailing caboose, not inside the program.

This is a research implementation on GSR regtest, not a production L2. It must
have no bridge signing authority, hidden key-path bypass, mock verifier fallback,
or host-only authorization presented as Bitcoin enforcement. It still depends
on proof-system assumptions, available state data, proving resources, transaction
inclusion, and the experimental GSR consensus rules.

### First complete milestone

- Three fixed accounts: Alice, Bob, and the Coins transfer-fee recipient.
- Fixed, distinct, validated account keys; zero issued balances at genesis.
- Exactly two deposits per collection, credited to registered accounts.
- One native Coins transfer followed by one withdrawal per settlement proof.
- Separate sponsor funding for miner fees and the new caboose.
- Pending deposits remain collectible across legitimate bridge-head changes and
  have an immediate owner-signature refund path.
- Command-line workflow and dedicated regtest; no web UI in this milestone.

Arbitrary account creation, general Coins journals, variable-size batches,
standalone transfer publication, and production data availability are not implied
by this bounded relation. Follow-ups belong in root `TODO.md`.

## 2. Existing work to reuse

Paths below are relative to `/Users/julian/Code/bitcoin`.

| Source | Reuse | Do not inherit |
| --- | --- | --- |
| `utxo-linearization-v0.1.0-en/bip-utxo-linearization.md` | Genesis identity, stable program, trailing caboose, ancestry checks | CAT/Schnorr introspection, grinding, unexplained removal of resource bounds |
| `projects/utxo-linearization-op-tx/` | Minimal OP_TX construction and ancestry mutation tests | Fixed one-input transition layout or vault-funded fees |
| `zk/coins-gsr-bridge-op-tx/` | Persistent deposits, refunds, exact recipient binding, lifecycle lessons | Test withdrawal key, anchor-based identity, history hash as account root, output-1 state placement |
| `projects/groth16/tools/coins-sp1/` | Real Coins relation, SP1 wrapper, GSR verifier adapter, actual-proof tests | Prefunded account fixture, root-in-Taproot rewrite, stale README status |
| `zk/coins/` | Native account/signature/transfer semantics | A claim that this bounded integration implements the entire Coins protocol |

The September 7 proof-withdrawal milestone is retained evidence, not validation
of this new composition. Its guest relation, root format, and transaction binding
change here, so its saved proof cannot authorize the new bridge.

The new repository remains independent. Import only required source with origin,
revision, local patch, and license records. Pin external dependencies; do not
depend on the current contents of dirty sibling checkouts or their absolute paths.
Leave all existing prototypes untouched.

## 3. Design decisions and recommendations

Already agreed: stable program; caboose state; OP_TX introspection; real proof
authorization; separate clean repository; small, structured commits.

The following are proposed v1 choices. Freeze them in the protocol document
before generating a deployment or expensive proofs.

### State, identity, and initialization

Use the draft's exact envelope: `UTXOLIN`, version 1, phase, optional 32-byte
genesis ID, and 32-byte account root. GENESIS is 41 bytes; ACTIVE is 73 bytes.
The identity is the raw txid bytes of the actual genesis transaction, not an
anchor outpoint or a caller-provided label.

Retain the draft's P2WSH caboose format. Fix its four-byte randomizer to zero:
OP_TX does not need Schnorr grinding. Start with a deployment-fixed 330-satoshi
caboose. Every successor creates a new one; the old one is not spent. This burns
value and creates an unspendable P2WSH output that is not visibly OP_RETURN to
the UTXO database. Record this cost explicitly; simplifying the container is a
separate decision, not a hidden change to the draft.

Use a small, fixed, non-issued backing reserve, initially proposed as 1,000
satoshis. Genesis holds only this reserve; all three account balances and nonces
start at zero. The reserve stays in the bridge even when all issued balances
are withdrawn. Genesis funding pays for its own fee and caboose.

**Avoid the genesis self-reference:** the initial account root must not hash the
genesis ID. Define one domain-separated account encoding independent of that ID
for both phases. Bind identity in the envelope and every proof statement instead.
Do not put a hash of the final Taproot program or deployment manifest into the
guest in a way that makes the verification key depend on its own output program.

The account encoding includes ordered IDs, canonical public keys, balances, and
nonces. Use a versioned, fixed three-account encoding rather than introducing a
Merkle tree before variable account support is required. The old journal root
and old SP1 root are not interchangeable with this root.

### Deposits and signatures

Prefer deposits addressed to `(expected program, expected genesis ID)`, not an
exact head outpoint. This supersedes the September 7 head-bound/refund-and-recreate
proposal for this project. It costs additional identity authentication but avoids
making every pending deposit stale after another legitimate update.

Each deposit commits to its registered recipient ID/key binding and refund key.
The collection path independently checks the actual main input and authenticated
new caboose identity. It relies on the co-spent, exact main program to enforce
lineage; a matching address or unbound witness state is insufficient. The refund
path requires the owner's normal Bitcoin signature and does not require bridge
cooperation. Refund fees may reduce the returned deposit amount.

Retain genuine Coins signature verification and transfer arithmetic. Before
freezing the relation, settle cross-instance signature replay: the existing
native transfer message does not visibly include the bridge identity. A proof
bound to an identity does not retroactively make that signature identity-bound.
Recommended safe baseline: retain the native signature and add a bridge-scoped
signed authorization for the exact transfer. Withdrawal authorization already
needs explicit network/domain, identity, account, nonce, amount, and destination.
Document the additional verification cost. Omitting the extra authorization
requires an explicit narrower replay assumption, not an implicit shortcut.

## 4. Transaction layouts and money rules

These fixed layouts keep parsing, roles, and proof binding small. All amounts
are satoshis. Account fees are transfers between accounts, not miner fees.

| Transaction | Inputs in order | Outputs in order |
| --- | --- | --- |
| Genesis | Prepared funding input | Reserve at stable program; caboose |
| Collect two deposits | Bridge; deposit A; deposit B; sponsor | Successor bridge; sponsor change; caboose |
| Transfer and withdraw | Bridge; sponsor | Successor bridge; recipient payout; sponsor change; caboose |
| Deposit refund | Deposit, optionally separate fee funding | Owner-chosen signature-authorized refund outputs |

Main input index and spent main-output index must both be zero. Every transition
has exactly one main input and one successor using the exact program. Every
other input/output must match its assigned role; extra entries fail. Payout and
sponsor outputs initially use native P2TR and cannot duplicate the bridge or
designated caboose scripts. Sponsor inputs must be approved non-main inputs.

For protocol transactions, fix version 2, locktime 0, empty scriptSigs, native
SegWit inputs, and sequence `0xfffffffd`. Define each allowed funding/ancestor
template explicitly. Do not constrain unrelated transactions beyond what is
actually reflected or spent by the protocol. Annex behavior is fixed per
protocol script path; unrecognized witnesses must not change branch selection.

Enforce in Script and independently in the host model:

```text
collection: new backing = old backing + deposit A + deposit B
withdrawal: new backing = old backing - payout
both:       sponsor input = sponsor change + miner fee + new caboose value
state:      backing = reserve + sum(all three account balances)
```

Require positive collected deposits/payouts, valid money ranges, no underflow or
overflow, and spendable sponsor change under the selected test policy. The proof
checks the state/backing equation using amounts authenticated by Script. Miner
fees must never silently come out of issued balances or the reserve.

## 5. Enforcement boundaries

### Bitcoin covenant

OP_TX reads actual current transaction fields and spent outputs. Constant,
reviewable selectors must match the pinned Core implementation; do not copy
historical selector hex. The current local BIP uses a six-byte selector with
scope operands, which differs from earlier drafts in this conversation. Pin
compatible BIP and Core revisions before importing scripts. Never accept an
unvalidated spender-controlled selector that could trigger upgrade success.

Authenticate the parent transaction against the actual bridge input outpoint,
and its predecessor against the parent's input-0 outpoint. Check the actual
predecessor script to distinguish genesis from continuation. Authenticate the
old state through the parent's trailing caboose; enforce the new caboose through
actual outputs. OP_TX does not eliminate these ancestry checks.

For genesis, validate the fixed initial root, reserve, funding shape and phase,
then assign the actual genesis txid. For continuation, require ACTIVE state and
preserve that identity. A copied program with a copied ACTIVE state must not
create an alternate entry point.

Use one auditable NUMS Taproot construction. Every bridge spending branch must
perform identity, state, accounting, and real proof checks. No emergency key,
upgrade leaf, or mock-success path belongs in the deployed program.

### Proof relation

Use one guest with two explicitly tagged actions:

1. `COLLECT_TWO`: credit exactly the two actual deposit amounts to their bound
   registered recipients; preserve other balances, keys, and nonces.
2. `TRANSFER_WITHDRAW`: validate the native Coins transfer, bridge authorization,
   fee credit, nonces and balances, then the signed withdrawal and its debit.

Both recompute old/new account roots and verify backing consistency. Genesis
starts from the fixed zero-account state, not arbitrary witness balances. Do
not accept deposit credits based merely on JSON records: Script binds the proof
records to the UTXOs consumed by this very transaction.

Freeze exact public-value bytes in a versioned specification and golden vectors:

- Protocol/network domain and action tag.
- Expected bridge identity and actual spent bridge outpoint.
- Old/new account roots and old/new backing amounts.
- For collection: ordered deposit outpoints, values and canonical recipient
  bindings authenticated against the actual deposit programs.
- For settlement: exact transfer/authorization digest, withdrawal request digest,
  payout value and destination script.

Use exact action-specific lengths and reject trailing bytes. Script constructs
or validates these bytes from authenticated context, recomputes SP1's public
values digest, and passes it to the actual verifier. A prover-supplied digest or
verification key is not an authority.

Binding the bridge outpoint makes an already-proven transition stale after a
competing update. Rebuild and reprove against the winning head. Deposits remain
collectible; already-generated proofs do not automatically remain usable.

### Deposit-program authentication

The main program must check that each deposited amount credits the recipient
committed by the actual spent deposit script. Prefer authenticating its revealed
canonical leaf through the actual spent Taproot commitment, using the pinned
GSR branch's available primitives. OP_TWEAKADD may still be needed here even
though successor-program reconstruction is removed. Determine and test the
smallest correct construction before claiming it is unnecessary.

A recipient prefix supplied by the witness is insufficient. Reconstruct the
complete allowed deposit program, including refund and collection paths and
the internal-key construction; reject alternate leaves or substitutions.

### Proof deployment

Reuse the SP1 SHA256 wrapper and GSR-only Groth16 verifier, with pinned toolchain,
guest ELF, verification key, recursion constants, and compiler configuration.
Independently derive the deployment manifest before accepting fixture exports.
Rebuild the guest and regenerate proofs because the relation has changed.

Keep the public-values digest and proof nonce as real runtime inputs. Preserve
strict canonical scalar/point decoding and actual Script hint validation. No
new field or native pairing opcode is assumed. List restored, macro, OP_TX and
any companion-opcode dependencies separately, with their actual uses.

## 6. Data, concurrency, and recovery

Build a minimal local state store, not a second full journal implementation.
Store the account snapshot, action data/signatures, state openings, transactions,
proof references, block anchors and pending deposits. Verify snapshots against
the authenticated root before using them. Do not label pending or merely proven
actions as confirmed credits or payouts.

A full-node-backed observer tracks the expected identity's current unspent head.
On a competing spend, discard the stale transaction/proof and rebase. On a
reorganization, roll back the corresponding account/head checkpoint and deposit
status before preparing another proof. Test refund-versus-collection conflicts:
only one spend can confirm, and an orphaned collection creates no durable credit.

Export a complete replay bundle so another process can validate and continue
the bounded state without a privileged operator key. This demonstrates portable
local recovery, not a decentralized data-availability protocol. Missing state
data can still halt proving and withdrawals. Refunds protect uncollected
deposits; they are not an escape path for funds already credited inside the bridge.

## 7. Repository structure

Create only directories actually needed by a milestone:

```text
README.md                    scope, quick start, current verified status
IMPLEMENTATION_PLAN.md       this plan and milestone progress
TODO.md                      deferred work; never committed without request
docs/protocol.md             canonical bytes, rules, witness layout, limits
docs/security.md             assumptions and enforcement/check matrix
sources.lock.json            source revisions, licenses and patch hashes
crates/protocol/             shared Rust types, codecs and native state rules
crates/prover-host/          deployment derivation, proof generation/verification
guest/                      pinned SP1 program using shared protocol rules
script/                     focused covenant builder and verifier adapter
tests/                      unit vectors, differential checks and regtest driver
fixtures/                   small vectors and retained bounded proof artifacts
scripts/                    setup/check/prove/demo/evidence entry points
results/                    selected reproducible evidence and concise report
```

Use Rust for the shared account relation and prover integration. Start with the
smallest existing Script-builder language that works with the verifier export
(the minimal linearization builder is Python); avoid porting it merely to unify
languages. Share byte vectors between languages and compare independent encoders.
No new general-purpose Script compiler, SDK, or selector package is in scope.

Keep build trees, toolchain downloads, private keys, datadirs and large temporary
logs ignored. Retain only explicit public regtest keys. Pin and document how to
obtain any large artifact not included in Git, with a hash and reproducible build
recipe. Verify source licenses before copying code; do not assume the unassigned
draft supplies a redistribution license for all referenced material.

## 8. Implementation milestones and commit sequence

Each commit should be understandable alone, include its focused tests, and state
what was actually run. No history rewriting or unrelated repository changes.
The order below is a dependency order, not a promise that each stage fits one
commit. Split large stages into these named purposes without leaving a deployable
bridge that accidentally accepts a stub verifier.

| Stage / suggested commit | Deliverable and completion gate |
| --- | --- |
| 1. `docs: define the bounded Coins GSR bridge protocol` | Resolve the decisions in section 3; write complete encoding, layouts, enforcement matrix and threat boundaries. Include this plan and source provenance. |
| 2. `build: pin bridge and proof toolchains` | Clean dependency setup, lockfiles, artifact manifest, Core/BIP compatibility check. Replay the old proof on its matching pinned backend as a separate baseline; never reinterpret it as a new bridge proof. |
| 3. `feat: add canonical bridge state and transition model` | Shared codecs, fixed account rules, genesis root, both action variants, public-value serialization and independent vectors. Catch identity/root cycles before generating a key. |
| 4. `feat: implement OP_TX caboose linearization` | Port minimal ancestry checks and new layouts; prove stable program and copied-origin rejection. Isolated linearization tests only; no deployable bridge with unchecked application state. |
| 5. `feat: bind persistent deposits and refunds` | Canonical deposit program, recipient authentication, full-value collection rules and immediate refunds. Verify identity survives a head update. Any binding-only harness is explicitly separate from deployment. |
| 6. `feat: prove deposit credits and Coins settlements` | Both guest actions, actual signatures, replay rules and deployment derivation. Generate and independently verify new deposit and settlement proofs. No prefunded fixture shortcut. |
| 7. `feat: enforce proof-authorized bridge transitions` | Compose lineage, deposit/payout binding and real GSR verifier. Old root comes from the caboose; successor program stays unchanged. Mine a real deposit collection and settlement. |
| 8. `feat: add the reproducible bridge lifecycle CLI` | Genesis, deposit, refund, prove, submit and inspect commands; minimal persisted state, head tracking, restart/reorg handling and export bundle. Commands must not silently regenerate expensive proofs. |
| 9. `test: cover bridge attacks and state recovery` | Integrated mutation suite, competing updates, cross-instance attacks and replay, cold/warm cache validation parity where relevant, missing/mismatched artifact hard failures. |
| 10. `docs: record the verified v1 bridge result` | Reproduction from a clean setup, full transaction evidence and measurement report, dependency/opcode inventory, and precise limitations. |

Steps 3–5 can use deterministic binding-only fixtures for development, but these
must have visibly separate entry points and cannot generate a production-shaped
deployment manifest. The project's successful bridge demonstration requires
steps 6–10 with real proofs.

## 9. Test and acceptance plan

### Cheap tests on each relevant commit

- Canonical state, transaction and public-value encodings: lengths, byte order,
  noncanonical CompactSize, truncation, trailing bytes and numeric boundaries.
- Account state: wrong signatures/keys, infinity and invalid points, replayed
  nonces, insufficient funds, checked arithmetic and preserved untouched fields.
- Cross-language vectors and native-model/Script agreement on binding failures.
- Fixed selectors and witness stack layout checked against the pinned backend.
- Formatting, JSON parsing, source-manifest checks and `git diff --check`.

### Focused adversarial Bitcoin cases

Each case must reach its intended guard: keep other fields valid and retain the
rejection reason. Avoid many mutations that only exercise the same early parser.

| Boundary | Discriminating tests |
| --- | --- |
| Identity | Copied P + copied ACTIVE state; wrong genesis ID; false parent/grandparent; nonzero bridge prevout index; GENESIS/ACTIVE confusion |
| Continuity | Missing/duplicate/changed successor; wrong caboose position/value/hash; alternate bridge leaf/key path; unsupported auxiliary role |
| Deposits | Correct collection after a head change; wrong bridge; changed recipient with matching witness claim; alternate deposit program; partial forwarding; unknown account; refund/collection conflict |
| Proof binding | Correct proof with consistently changed roots, action, identity, outpoint, deposit record, payout amount or destination; modified proof/hint; mismatched deployment key |
| Accounting | Overcredit, overwithdrawal, account-fee omission, sponsor costs charged to bridge, reserve withdrawal and arithmetic boundaries |
| Resources | Exact accepted bound and one-above for reflected data, stack/element usage and budget; reject creating an unspendable successor due to next-spend reflection limits |
| Recovery | Restart from export; stale proof after competing update; rollback after reorg; never confirm both refund and collection |

### Real-proof end-to-end gates

1. Independently reproduce the existing proof baseline with matching deployment
   artifacts. Report incompatibilities rather than patching dirty sources.
2. Create a new zero-issued genesis and two real deposits. Generate a new
   `COLLECT_TWO` proof; native verification and actual GSR block validation must
   succeed, and confirmed balances must equal the deposits.
3. Produce the genuine Coins transfer and withdrawal signatures. Generate the
   new settlement proof; mine the exact payout and check reduced backing,
   updated account balances/nonces, stable program and updated caboose.
4. Exercise another collection against the ACTIVE successor with a newly bound
   proof. This covers continuation without resetting to a prefunded fixture.
5. Reuse valid proofs in targeted false statements and confirm rejection in the
   actual composed Bitcoin spend, not just in the native model.
6. Demonstrate restart/replay and refund on a dedicated regtest. For concurrency
   tests, distinguish node double-spend rejection from a covenant/proof failure.

Saved valid proofs make routine checks cheap. Full proving is an explicit slow
target, with recorded CPU/memory settings and resumable artifact directories.
One historical bounded proof took approximately 54 minutes; do not describe that
as this new relation's proving time or launch repeated jobs without reporting cost.

Use the Bitcoin Core testing workflow when building/testing the backend. Run
focused GSR functional tests on the pinned build; full Core suites are required
if Core changes become separately authorized, not as an excuse to expand this
standalone project. Final evidence must distinguish mempool policy from consensus
block acceptance. If policy rejects an otherwise valid prototype, retain and
explain that result rather than silently relaxing it.

## 10. Resource and evidence requirements

Replace the draft's CAT-specific 520-byte reflection bound with explicit,
deployment-fixed limits derived from these layouts and the pinned GSR rules.
Bound current transactions, both ancestors, reconstructed hash inputs, proof
witnesses and all intermediate stack values. Enforce constraints when creating
the successor as well as when spending it. Large witnesses do not by themselves
make non-witness parent transactions large, but both must be measured separately.

Record for collection and withdrawal separately:

- Complete serialized transaction, txid, block anchor and successor outpoint.
- Full transaction weight/vsize; Script bytes; proof/hint/ancestry/state witness
  bytes, separating the small curve proof from its much larger execution witness.
- Actual total varops and available transaction budget, including all inputs,
  covenant work, hashing, verifier work and final checks. If instrumentation only
  measures a fragment, label it and do not claim an exact full-transaction total.
- Full validation time with repeated runs and the measurement boundary stated;
  native proof verification, Script evaluation and block validation are distinct.
- Proof generation time, peak memory, machine, thread count and toolchain.
- Source revisions and selected patch hashes, binary and deployment hashes,
  artifact hashes, commands and positive/negative test results.

Do not rely on unmetered replay or padding that conceals a budget failure. If
the complete transaction exceeds its real budget or another consensus limit,
stop at that gate, report the smallest failing construction, and seek a scoped
design decision. Do not silently add a native verifier opcode or alter varops.

## 11. Completion and remaining claims

The project is complete at this scope when a clean setup reproduces a real
deposit-to-withdrawal lifecycle, with authenticated identity, correct issuance
and payouts, no privileged bridge key, adversarial tests, and retained evidence.

The final report must separately state what is enforced by Bitcoin, what is
proved by the guest, and what still depends on off-chain services or assumptions.
It must not claim Glass Coins privacy, unrestricted account/batch support,
guaranteed exits, production trusted-setup security, decentralized publication,
or mobile-friendly proving. Those are later research questions, not hidden
acceptance criteria for v1.
