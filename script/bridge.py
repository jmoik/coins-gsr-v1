"""Proof-authorized bridge leaves for the bounded Coins + GSR v1 protocol."""

from test_framework.script import CScript, taproot_construct

from script.deposit import (
    _authenticate_deposit,
    _check_collection_transaction,
    _check_settlement_transaction,
    _collection_context,
    _is_size,
)
from script.linearization import (
    AMOUNTS,
    ANNEX,
    CABOOSE_VALUE,
    CURRENT_INDEX,
    LEAF_VERSION,
    MAGIC,
    MINER_FEE,
    NUMS_INTERNAL_KEY,
    OP_EQUALVERIFY,
    OP_HASH256,
    OP_LEFT,
    OP_NUMEQUALVERIFY,
    OP_SHA256,
    OP_SUB,
    OP_SWAP,
    OUTPUTS,
    PREVOUTS,
    SCRIPT_SIGS,
    SEQUENCES,
    SPKS,
    STATE_VERSION,
    TX_SHAPE,
    Builder,
    _check_one_input_two_output,
    _make_caboose,
)


STATEMENT_DOMAIN = b"coins-gsr-v1/statement/regtest\0"
COLLECTION_STATEMENT_SIZE = 341
SETTLEMENT_STATEMENT_SIZE = 320

OP_DEPTH = 0x74
OP_NIP = 0x77
OP_OVER = 0x78
OP_PICK = 0x79
OP_SUBSTR = 0x7F
OP_SIZE = 0x82
OP_AND = 0x84
OP_ADD = 0x93
OP_NUMEQUAL = 0x9C


def account_root(account_keys: list[bytes], balances=(0, 0, 0), nonces=(0, 0, 0)) -> bytes:
    if len(account_keys) != 3 or any(len(key) != 32 for key in account_keys):
        raise ValueError("three compressed account keys are required")
    import hashlib

    digest = hashlib.sha256()
    digest.update(b"coins-gsr-v1/accounts\0")
    for account_id, (key, balance, nonce) in enumerate(
        zip(account_keys, balances, nonces, strict=True)
    ):
        digest.update(account_id.to_bytes(4, "little"))
        digest.update(key)
        digest.update(balance.to_bytes(8, "little"))
        digest.update(nonce.to_bytes(4, "little"))
    return digest.digest()


def _check_parent_output(
    builder: Builder,
    amount_offset: int,
    spk_offset: int,
    caboose_value_offset: int,
    caboose_spk_offset: int,
    sponsor_spk_offset: int | None,
    sponsor_spk: bytes,
) -> None:
    builder.slice("parent", amount_offset, 8)
    builder.slice("amounts", 0, 8)
    builder.op(OP_EQUALVERIFY, 2, 0)
    builder.slice("parent", spk_offset, 34)
    builder.get("program_spk")
    builder.op(OP_EQUALVERIFY, 2, 0)
    builder.equal_slice("parent", caboose_value_offset, CABOOSE_VALUE.to_bytes(8, "little"))
    _make_caboose(builder, "old_state", "old_caboose")
    builder.slice("parent", caboose_spk_offset, 34)
    builder.get("old_caboose")
    builder.op(OP_EQUALVERIFY, 2, 0)
    if sponsor_spk_offset is not None:
        builder.equal_slice("parent", sponsor_spk_offset, sponsor_spk)


def _authenticate_transition_ancestor(builder: Builder) -> None:
    builder.get("ancestor")
    builder.op(OP_HASH256, 1, 1)
    builder.slice("parent", 5, 32)
    builder.op(OP_EQUALVERIFY, 2, 0)
    builder.equal_slice("parent", 37, bytes(4))
    _is_size(builder, "ancestor", 303)

    def collection(branch: Builder) -> None:
        _check_collection_transaction(branch, "ancestor")
        branch.slice("ancestor", 179, 34)
        branch.get("program_spk")
        branch.op(OP_EQUALVERIFY, 2, 0)

    def genesis_or_settlement(branch: Builder) -> None:
        _is_size(branch, "ancestor", 264)

        def settlement(inner: Builder) -> None:
            _check_settlement_transaction(inner, "ancestor")
            inner.slice("ancestor", 97, 34)
            inner.get("program_spk")
            inner.op(OP_EQUALVERIFY, 2, 0)

        def genesis(inner: Builder) -> None:
            _check_one_input_two_output(inner, "ancestor")
            inner.slice("ancestor", 56, 34)
            inner.get("program_spk")
            inner.op(OP_EQUALVERIFY, 2, 0)

        branch.branch(settlement, genesis)

    builder.branch(collection, genesis_or_settlement)


def _authenticate_parent(
    builder: Builder, sponsor_spk: bytes, genesis_root: bytes
) -> None:
    builder.get("parent")
    builder.op(OP_HASH256, 1, 1)
    builder.slice("prevouts", 0, 32)
    builder.op(OP_EQUALVERIFY, 2, 0)
    builder.equal_slice("prevouts", 32, bytes(4))
    _is_size(builder, "parent", 137)

    def genesis(branch: Builder) -> None:
        _check_one_input_two_output(branch, "parent")
        _check_parent_output(branch, 47, 56, 90, 99, None, sponsor_spk)
        branch.get("ancestor")
        branch.op(OP_HASH256, 1, 1)
        branch.slice("parent", 5, 32)
        branch.op(OP_EQUALVERIFY, 2, 0)
        branch.equal_slice("parent", 37, bytes(4))
        _check_one_input_two_output(branch, "ancestor")
        branch.equal_slice("ancestor", 56, sponsor_spk)
        branch.require_size("old_state", 41)
        branch.equal_slice("old_state", 0, MAGIC + bytes([STATE_VERSION, 0]))
        branch.equal_slice("old_state", 9, genesis_root)
        branch.get("parent")
        branch.op(OP_HASH256, 1, 1)
        branch.get("bridge_id")
        branch.op(OP_EQUALVERIFY, 2, 0)
        branch.slice("old_state", 9, 32)
        branch.name("old_root")

    def continuation(branch: Builder) -> None:
        _is_size(branch, "parent", 303)

        def collection(inner: Builder) -> None:
            _check_collection_transaction(inner, "parent")
            _check_parent_output(inner, 170, 179, 256, 265, 222, sponsor_spk)

        def settlement(inner: Builder) -> None:
            _check_settlement_transaction(inner, "parent")
            _check_parent_output(inner, 88, 97, 217, 226, 183, sponsor_spk)

        branch.branch(collection, settlement)
        _authenticate_transition_ancestor(branch)
        branch.require_size("old_state", 73)
        branch.equal_slice("old_state", 0, MAGIC + bytes([STATE_VERSION, 1]))
        branch.slice("old_state", 9, 32)
        branch.get("bridge_id")
        branch.op(OP_EQUALVERIFY, 2, 0)
        branch.slice("old_state", 41, 32)
        branch.name("old_root")

    builder.branch(genesis, continuation)
    builder.require_size("new_state", 73)
    builder.equal_slice("new_state", 0, MAGIC + bytes([STATE_VERSION, 1]))
    builder.slice("new_state", 9, 32)
    builder.get("bridge_id")
    builder.op(OP_EQUALVERIFY, 2, 0)


def _statement_slice(builder: Builder, offset: int, size: int) -> None:
    builder.slice("public_values", offset, size)


def _statement_header(builder: Builder, size: int, action: int) -> None:
    builder.require_size("public_values", size)
    builder.equal_slice("public_values", 0, STATEMENT_DOMAIN + bytes([1, action]))
    _statement_slice(builder, 33, 32)
    builder.get("bridge_id")
    builder.op(OP_EQUALVERIFY, 2, 0)
    _statement_slice(builder, 65, 36)
    builder.slice("prevouts", 0, 36)
    builder.op(OP_EQUALVERIFY, 2, 0)
    _statement_slice(builder, 101, 32)
    builder.get("old_root")
    builder.op(OP_EQUALVERIFY, 2, 0)
    _statement_slice(builder, 133, 32)
    builder.slice("new_state", 41, 32)
    builder.op(OP_EQUALVERIFY, 2, 0)
    _statement_slice(builder, 165, 8)
    builder.slice("amounts", 0, 8)
    builder.op(OP_EQUALVERIFY, 2, 0)


def _calculated_collection_backing(builder: Builder) -> None:
    builder.slice("amounts", 0, 8)
    builder.slice("amounts", 8, 8)
    builder.op(OP_ADD, 2, 1)
    builder.slice("amounts", 16, 8)
    builder.op(OP_ADD, 2, 1)
    builder.fixed_width(8)


def _select_account_key(builder: Builder, id_name: str, account_keys: list[bytes]) -> None:
    builder.get(id_name)
    builder.number(0)
    builder.op(OP_NUMEQUAL, 2, 1)

    def zero(branch: Builder) -> None:
        branch.push(account_keys[0])

    def nonzero(branch: Builder) -> None:
        branch.get(id_name)
        branch.number(1)
        branch.op(OP_NUMEQUAL, 2, 1)

        def one(inner: Builder) -> None:
            inner.push(account_keys[1])

        def two(inner: Builder) -> None:
            inner.get(id_name)
            inner.number(2)
            inner.op(OP_NUMEQUALVERIFY, 2, 0)
            inner.push(account_keys[2])

        branch.branch(one, two)

    builder.branch(zero, nonzero)


def _bind_collection_statement(builder: Builder, account_keys: list[bytes]) -> None:
    _statement_header(builder, COLLECTION_STATEMENT_SIZE, 1)
    _statement_slice(builder, 173, 8)
    _calculated_collection_backing(builder)
    builder.op(OP_EQUALVERIFY, 2, 0)
    for index, (recipient, record_offset) in enumerate(
        (("recipient_a", 181), ("recipient_b", 261)), start=1
    ):
        _statement_slice(builder, record_offset, 36)
        builder.slice("prevouts", index * 36, 36)
        builder.op(OP_EQUALVERIFY, 2, 0)
        _statement_slice(builder, record_offset + 36, 8)
        builder.slice("amounts", index * 8, 8)
        builder.op(OP_EQUALVERIFY, 2, 0)
        _statement_slice(builder, record_offset + 44, 4)
        builder.get(recipient)
        builder.fixed_width(4)
        builder.op(OP_EQUALVERIFY, 2, 0)
        _statement_slice(builder, record_offset + 48, 32)
        _select_account_key(builder, recipient, account_keys)
        builder.op(OP_EQUALVERIFY, 2, 0)


def _bind_settlement_statement(builder: Builder) -> None:
    _statement_header(builder, SETTLEMENT_STATEMENT_SIZE, 2)
    _statement_slice(builder, 173, 8)
    builder.slice("amounts", 0, 8)
    _statement_slice(builder, 277, 8)
    builder.op(OP_SUB, 2, 1)
    builder.fixed_width(8)
    builder.op(OP_EQUALVERIFY, 2, 0)
    builder.equal_slice("public_values", 285, b"\x22")


def _bind_statement_digest(builder: Builder) -> None:
    """Bind SHA256(public values) to SP1's second Groth16 public input."""
    builder.get("public_values")
    builder.op(OP_SHA256, 1, 1)
    builder.push(bytes([0x1F]) + bytes([0xFF]) * 31)
    builder.op(OP_AND, 2, 1)
    builder.push(b"")
    for index in reversed(range(32)):
        builder.op(OP_OVER, 0, 1)
        builder.number(index)
        builder.number(1)
        builder.op(OP_SUBSTR, 3, 1)
        builder.cat()
    builder.op(OP_NIP, 2, 1)
    builder.op(OP_DEPTH, 0, 1)
    builder.number(2)
    builder.op(OP_SUB, 2, 1)
    builder.op(OP_PICK, 1, 1)
    builder.op(OP_SIZE, 0, 1)
    builder.number(32)
    builder.op(OP_SWAP, 2, 2)
    builder.op(OP_SUB, 2, 1)
    builder.push(bytes(32))
    builder.op(OP_SWAP, 2, 2)
    builder.op(OP_LEFT, 2, 1)
    builder.cat()
    builder.op(OP_EQUALVERIFY, 2, 0)


def _expected_collection_outputs(builder: Builder, sponsor_spk: bytes) -> None:
    _make_caboose(builder, "new_state", "new_caboose")
    _calculated_collection_backing(builder)
    builder.push(b"\x22")
    builder.cat()
    builder.get("program_spk")
    builder.cat()
    builder.slice("amounts", 24, 8)
    builder.number(MINER_FEE + CABOOSE_VALUE)
    builder.op(OP_SUB, 2, 1)
    builder.fixed_width(8)
    builder.push(b"\x22")
    builder.cat()
    builder.push(sponsor_spk)
    builder.cat()
    builder.cat()
    builder.push(CABOOSE_VALUE.to_bytes(8, "little") + b"\x22")
    builder.cat()
    builder.get("new_caboose")
    builder.cat()
    builder.name("expected_outputs")
    builder.tx(OUTPUTS)
    builder.get("expected_outputs")
    builder.op(OP_EQUALVERIFY, 2, 0)


def _settlement_context(builder: Builder, sponsor_spk: bytes) -> None:
    builder.tx(TX_SHAPE)
    builder.push(bytes.fromhex("02000000000000000200000004000000"))
    builder.op(OP_EQUALVERIFY, 2, 0)
    builder.tx(SEQUENCES)
    builder.push(b"\xfd\xff\xff\xff" * 2)
    builder.op(OP_EQUALVERIFY, 2, 0)
    builder.tx(SCRIPT_SIGS)
    builder.push(bytes(2))
    builder.op(OP_EQUALVERIFY, 2, 0)
    builder.tx(ANNEX)
    builder.push(b"")
    builder.op(OP_EQUALVERIFY, 2, 0)
    for name, selector in (("prevouts", PREVOUTS), ("amounts", AMOUNTS), ("spks", SPKS)):
        builder.tx(selector)
        builder.name(name)
    builder.require_size("prevouts", 72)
    builder.equal_slice("prevouts", 32, bytes(4))
    builder.require_size("amounts", 16)
    builder.require_size("spks", 70)
    builder.equal_slice("spks", 0, b"\x22")
    builder.slice("spks", 1, 34)
    builder.name("program_spk")
    builder.equal_slice("spks", 35, b"\x22" + sponsor_spk)
    builder.tx(CURRENT_INDEX)
    builder.number(0)
    builder.op(OP_NUMEQUALVERIFY, 2, 0)


def _expected_settlement_outputs(builder: Builder, sponsor_spk: bytes) -> None:
    _make_caboose(builder, "new_state", "new_caboose")
    builder.slice("amounts", 0, 8)
    _statement_slice(builder, 277, 8)
    builder.op(OP_SUB, 2, 1)
    builder.fixed_width(8)
    builder.push(b"\x22")
    builder.cat()
    builder.get("program_spk")
    builder.cat()
    _statement_slice(builder, 277, 8)
    builder.push(b"\x22")
    builder.cat()
    _statement_slice(builder, 286, 34)
    builder.cat()
    builder.cat()
    builder.slice("amounts", 8, 8)
    builder.number(MINER_FEE + CABOOSE_VALUE)
    builder.op(OP_SUB, 2, 1)
    builder.fixed_width(8)
    builder.push(b"\x22")
    builder.cat()
    builder.push(sponsor_spk)
    builder.cat()
    builder.cat()
    builder.push(CABOOSE_VALUE.to_bytes(8, "little") + b"\x22")
    builder.cat()
    builder.get("new_caboose")
    builder.cat()
    builder.name("expected_outputs")
    builder.tx(OUTPUTS)
    builder.get("expected_outputs")
    builder.op(OP_EQUALVERIFY, 2, 0)


def build_collection_program(
    verifier: bytes, sponsor_spk: bytes, account_keys: list[bytes], genesis_root: bytes
) -> bytes:
    if not verifier or len(sponsor_spk) != 34 or len(genesis_root) != 32:
        raise ValueError("invalid deployment constants")
    builder = Builder(
        [
            "parent",
            "ancestor",
            "old_state",
            "new_state",
            "bridge_id",
            "recipient_a",
            "refund_a",
            "recipient_b",
            "refund_b",
            "public_values",
        ]
    )
    _collection_context(builder, sponsor_spk)
    builder.tx(CURRENT_INDEX)
    builder.number(0)
    builder.op(OP_NUMEQUALVERIFY, 2, 0)
    builder.require_size("bridge_id", 32)
    _expected_collection_outputs(builder, sponsor_spk)
    _authenticate_deposit(builder, 1, "recipient_a", "refund_a", account_keys)
    _authenticate_deposit(builder, 2, "recipient_b", "refund_b", account_keys)
    _authenticate_parent(builder, sponsor_spk, genesis_root)
    _bind_collection_statement(builder, account_keys)
    _bind_statement_digest(builder)
    return builder.finish_prefix() + verifier


def build_settlement_program(
    verifier: bytes, sponsor_spk: bytes, genesis_root: bytes
) -> bytes:
    if not verifier or len(sponsor_spk) != 34 or len(genesis_root) != 32:
        raise ValueError("invalid deployment constants")
    builder = Builder(
        ["parent", "ancestor", "old_state", "new_state", "bridge_id", "public_values"]
    )
    _settlement_context(builder, sponsor_spk)
    builder.require_size("bridge_id", 32)
    _expected_settlement_outputs(builder, sponsor_spk)
    _authenticate_parent(builder, sponsor_spk, genesis_root)
    _bind_settlement_statement(builder)
    _bind_statement_digest(builder)
    return builder.finish_prefix() + verifier


def bridge_taproot(collection_program: bytes, settlement_program: bytes):
    return taproot_construct(
        NUMS_INTERNAL_KEY,
        [
            ("collection", CScript(collection_program), LEAF_VERSION),
            ("settlement", CScript(settlement_program), LEAF_VERSION),
        ],
    )


def control_block(taproot, leaf: str) -> bytes:
    selected = taproot.leaves[leaf]
    return bytes([LEAF_VERSION | taproot.negflag]) + taproot.internal_pubkey + selected.merklebranch
