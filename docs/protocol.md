# Bounded Bridge Protocol

Status: implemented bounded-regtest protocol. Byte-level choices are covered by
the retained vectors and proof-authorized lifecycle in `fixtures/v1`.

## Deployment constants

A deployment fixes the GSR Core and BIP revisions, complete NUMS Taproot program
`P`, proof deployment identity, three ordered account public keys, caboose value
`c = 330 sat`, and unissued reserve `r = 1,000 sat`.

The retained bounded-regtest deployment has:

```text
guest ELF SHA256   3b0a8aba36a0ced4b6a3ef658d45e61ae4bcfbcc283276d0814e70302cc84473
SP1 program key    0000688ca06f69f806f59cc453716875b5fdb1adc964919592d90feae78e6e56
SP1 Groth16 VK     0e78f4db7a6771a3a6a7d9c3b0de6fe73d58781368967a7fe84d87aefffec896
zero account root  1f18ff4555c14b881530ed0f0758734d1a11ea1dce8ded843f076314d14e6825
P scriptPubKey     512005177fa3de9c3040fd0e6bbc2c27df8c33da505edcbd95608b0fa21a0e443fd1
```

`P` has two `0xc2` leaves under the fixed NUMS internal key: an 81,417-byte
collection program and a 78,505-byte settlement program. Both append the same
76,400-byte verifier. There is no known key-path secret.

The bridge instance identity is the raw 32-byte txid of its genesis transaction.
The identity is stored in ACTIVE state and proof statements, not in the stable
program. Explorer-format txid strings are reversed only at display boundaries.

## State

All fixed integers are little-endian. Constants are literal bytes.

```text
StateGenesis = "UTXOLIN" || 0x01 || 0x00 || account_root             # 41 bytes
StateActive  = "UTXOLIN" || 0x01 || 0x01 || genesis_txid || account_root
                                                                    # 73 bytes
```

The account root is independent of the genesis txid, avoiding a circular genesis
construction:

```text
AccountRoot = SHA256(
  "coins-gsr-v1/accounts\0" ||
  for id in 0..2:
    u32_le(id) || canonical_account_key || u64_le(balance) || u32_le(nonce)
)
```

The key encoding and its exact length are frozen when the Coins dependency is
imported. Keys are deployment constants, pairwise distinct, canonically encoded,
and non-infinity. Genesis balances and nonces are zero.

The caboose follows the linearization draft with randomizer zero:

```text
state_hash = SHA256(State)
witness_script = OP_RETURN PUSH36(state_hash || 0x00000000)
caboose_spk = P2WSH(witness_script)
```

It is the unique last output and has value `c`. Its old output is never spent by
the state chain.

## Common transaction rules

Protocol transactions use version 2, locktime 0, native SegWit inputs with empty
scriptSigs, and sequence `0xfffffffd`. The main input is exactly input 0, spends
vout 0, and the sole successor is exactly output 0 with script `P`. All other
inputs and outputs have an explicit action-specific role. Extra or duplicate
roles fail.

The main program uses constant, version-zero OP_TX selectors. Spender-controlled
selectors are forbidden because a reserved OP_TX selector version may terminate
successfully under upgrade semantics.

Every transition authenticates:

1. Actual current fields and spent outputs through OP_TX.
2. The supplied parent transaction against input 0's actual prevout txid.
3. The supplied grandparent against the parent's input-0 prevout txid.
4. The predecessor script to select GENESIS or ACTIVE validation.
5. The old state through the parent's trailing caboose.
6. The new state through the current transaction's trailing caboose.

Genesis has one prepared funding input outside the main-program set, creates
`P` at output 0 with value `r`, and creates a GENESIS caboose. Its first spend
validates genesis and writes the actual genesis txid into ACTIVE state. An ACTIVE
transition preserves the identity byte for byte. A copied `P + ACTIVE` output
cannot pass the genesis branch.

## Deposits

A canonical deposit program commits to:

- protocol version and expected `P`;
- expected genesis txid;
- registered recipient account ID and its deployment-fixed key;
- depositor refund x-only key.

It has exactly two paths. Collection requires a joint spend with the authentic
bridge transition and reveals enough data to reconstruct and authenticate the
complete deposit Taproot output. Refund requires the depositor's signature and
does not require bridge cooperation. No timeout is required. Refund transaction
fees may reduce its output.

Collection has exactly four inputs and three outputs:

```text
inputs:  bridge, deposit A, deposit B, sponsor
outputs: successor bridge, sponsor change, caboose
```

Deposits are ordered by serialized outpoint. Their values are positive, their
outpoints differ, and their recipient IDs are valid. The bridge increases by
their exact total. The proof credits exactly those values to the bound accounts.
Because a deposit commits to lineage identity rather than a head outpoint, it
remains collectible after another valid bridge transition.

## Transfer and withdrawal

Settlement has exactly two inputs and four outputs:

```text
inputs:  bridge, sponsor
outputs: successor bridge, recipient payout, sponsor change, caboose
```

The proof validates one native Coins transfer from account 0 to account 1 and
credits its declared Coins fee to account 2. It additionally validates a
bridge-scoped signature by account 0 over:

```text
"coins-gsr-v1/transfer-auth/regtest\0" ||
genesis_txid || SHA256(native_coins_signing_message)
```

The proof then validates account 1's signed withdrawal:

```text
"coins-gsr-v1/withdrawal/regtest\0" ||
genesis_txid || u32_le(account_id=1) || u32_le(nonce) ||
u64_le(amount) || CompactSize(len(destination_spk)) || destination_spk
```

The initial implementation permits only a 34-byte native P2TR destination.
Amount is positive, at most the post-transfer account-1 balance, and is debited
while its nonce increments. Output 1 must be the exact destination and amount.

## Money invariant

At every state:

```text
bridge_value = r + balance[0] + balance[1] + balance[2]
```

For collection, the successor bridge equals old bridge plus both deposits. For
settlement, it equals old bridge minus the payout. The sponsor pays the exact
miner fee, new caboose, and any sponsor change. No issued balance or reserve can
be converted silently into a miner fee.

All arithmetic is checked over Bitcoin money ranges. The proof checks balances
and backing; Script binds its public values to actual amounts and outputs.

## Proof statement

The serialized statement starts with
`"coins-gsr-v1/statement/regtest\0"`, followed by `u8 version = 1`, an action
byte, genesis txid, actual bridge prevout (`txid || u32_le(vout)`), old root, new
root, old backing, and new backing.

Collection then contains two ordered records:

```text
prevout || u64_le(value) || u32_le(recipient_id) || account_key
```

Settlement instead contains the native transfer-message hash, scoped-transfer
authorization hash, withdrawal-request hash, payout amount, and destination
script using canonical CompactSize framing.

Action-specific lengths are exact; trailing bytes fail. The SP1 wrapper proves
the SHA256 digest of these public values. The bridge Script constructs or checks
the same bytes from authenticated transaction data before executing the fixed
GSR verifier.

## Witness layout

The GSR verifier witness is deepest and retains its generator-defined order.
Its second item from the bottom is the normalized little-endian SP1 statement
digest scalar. The covenant prefix verifies that scalar against the supplied
public-value bytes, consumes every application item, and leaves the original
verifier stack unchanged.

```text
collection input 0:
  verifier_stack..., parent, ancestor, old_state, new_state, bridge_id,
  recipient_a, refund_key_a, recipient_b, refund_key_b, public_values,
  collection_leaf, control_block

settlement input 0:
  verifier_stack..., parent, ancestor, old_state, new_state, bridge_id,
  public_values, settlement_leaf, control_block

deposit collection input:
  parent, old_state, false, deposit_leaf, control_block

deposit refund input:
  BIP340_signature, true, deposit_leaf, control_block
```

`parent` and `ancestor` are serialized without witness. The prefix authenticates
them against actual OP_TX prevouts before trusting their state or program bytes.
The application cannot supply selectors: every six-byte selector is a constant
in the leaves.

## Reorganizations and concurrency

A proof is bound to an exact bridge head and becomes stale if a competing update
wins. Rebuild and reprove against the winning head. Deposits remain collectible
because their identity is stable. Confirmed account state changes only with the
corresponding confirmed Bitcoin transition and rolls back with a reorganization.
