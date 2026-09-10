"""Persistent identity-bound deposits and a collection-only bridge program."""

from test_framework.messages import ser_compact_size
from test_framework.script import CScript, taproot_construct

from script.linearization import (
    AMOUNTS,
    ANNEX,
    CABOOSE_VALUE,
    CURRENT_INDEX,
    LEAF_VERSION,
    MAGIC,
    MINER_FEE,
    NUMS_INTERNAL_KEY,
    OP_DROP,
    OP_ELSE,
    OP_ENDIF,
    OP_EQUALVERIFY,
    OP_HASH256,
    OP_IF,
    OP_NUMEQUAL,
    OP_NUMEQUALVERIFY,
    OP_SHA256,
    OP_SIZE,
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
    sha256,
)


OP_VERIFY = 0x69
OP_TOALTSTACK = 0x6B
OP_FROMALTSTACK = 0x6C
OP_CAT = 0x7E
OP_ADD = 0x93
OP_SUB = 0x94
OP_WITHIN = 0xA5
OP_CHECKSIG = 0xAC
OP_TWEAKADD = 0xBE


def _tag_prefix(tag: str) -> bytes:
    digest = sha256(tag.encode())
    return digest + digest


def _equal_number_byte(builder: Builder, name: str, offset: int, value: int) -> None:
    builder.slice(name, offset, 1)
    builder.number(value)
    builder.op(OP_NUMEQUALVERIFY, 2, 0)


def _is_size(builder: Builder, name: str, size: int) -> None:
    builder.get(name)
    builder.op(OP_SIZE, 0, 1)
    builder.number(size)
    builder.op(OP_NUMEQUAL, 2, 1)
    builder.op(OP_SWAP, 2, 2)
    builder.op(OP_DROP, 1, 0)


def _check_collection_transaction(builder: Builder, name: str) -> None:
    builder.require_size(name, 303)
    builder.equal_slice(name, 0, b"\x02\x00\x00\x00\x04")
    for input_index in range(4):
        builder.equal_slice(name, 41 + 41 * input_index, b"\x00\xfd\xff\xff\xff")
    _equal_number_byte(builder, name, 169, 3)
    for offset in (178, 221, 264):
        builder.equal_slice(name, offset, b"\x22")
    builder.equal_slice(name, 299, bytes(4))


def _check_settlement_transaction(builder: Builder, name: str) -> None:
    builder.get(name)
    builder.op(OP_SIZE, 0, 1)
    builder.number(264)
    builder.op(OP_EQUALVERIFY, 2, 0)
    builder.op(OP_DROP, 1, 0)
    builder.equal_slice(name, 0, b"\x02\x00\x00\x00\x02")
    for offset in (41, 82):
        builder.equal_slice(name, offset, b"\x00\xfd\xff\xff\xff")
    _equal_number_byte(builder, name, 87, 4)
    for offset in (96, 139, 182, 225):
        builder.equal_slice(name, offset, b"\x22")
    builder.equal_slice(name, 260, bytes(4))


def _collection_context(builder: Builder, sponsor_spk: bytes) -> None:
    builder.tx(TX_SHAPE)
    builder.push(bytes.fromhex("02000000000000000400000003000000"))
    builder.op(OP_EQUALVERIFY, 2, 0)
    builder.tx(SEQUENCES)
    builder.push(b"\xfd\xff\xff\xff" * 4)
    builder.op(OP_EQUALVERIFY, 2, 0)
    builder.tx(SCRIPT_SIGS)
    builder.push(bytes(4))
    builder.op(OP_EQUALVERIFY, 2, 0)
    builder.tx(ANNEX)
    builder.push(b"")
    builder.op(OP_EQUALVERIFY, 2, 0)
    for name, selector in (("prevouts", PREVOUTS), ("amounts", AMOUNTS), ("spks", SPKS)):
        builder.tx(selector)
        builder.name(name)

    builder.require_size("prevouts", 144)
    builder.equal_slice("prevouts", 32, bytes(4))
    builder.require_size("amounts", 32)
    builder.require_size("spks", 140)
    for offset in (0, 35, 70, 105):
        builder.equal_slice("spks", offset, b"\x22")
    builder.slice("spks", 1, 34)
    builder.name("program_spk")
    builder.equal_slice("spks", 106, sponsor_spk)


def _check_parent_output(
    builder: Builder,
    amount_offset: int,
    spk_offset: int,
    caboose_value_offset: int,
    caboose_spk_offset: int,
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


def _authenticate_parent(builder: Builder, sponsor_spk: bytes, require_new_state: bool) -> None:
    builder.get("parent")
    builder.op(OP_HASH256, 1, 1)
    builder.slice("prevouts", 0, 32)
    builder.op(OP_EQUALVERIFY, 2, 0)
    _is_size(builder, "parent", 303)

    def continuation(branch: Builder) -> None:
        _check_collection_transaction(branch, "parent")
        _check_parent_output(branch, 170, 179, 256, 265)
        branch.equal_slice("parent", 222, sponsor_spk)
        branch.get("ancestor")
        branch.op(OP_HASH256, 1, 1)
        branch.slice("parent", 5, 32)
        branch.op(OP_EQUALVERIFY, 2, 0)
        branch.equal_slice("parent", 37, bytes(4))
        _is_size(branch, "ancestor", 303)

        def prior_collection(inner: Builder) -> None:
            _check_collection_transaction(inner, "ancestor")
            inner.slice("ancestor", 179, 34)
            inner.get("program_spk")
            inner.op(OP_EQUALVERIFY, 2, 0)

        def prior_genesis(inner: Builder) -> None:
            _check_one_input_two_output(inner, "ancestor")
            inner.slice("ancestor", 56, 34)
            inner.get("program_spk")
            inner.op(OP_EQUALVERIFY, 2, 0)

        branch.branch(prior_collection, prior_genesis)
        branch.require_size("old_state", 73)
        branch.equal_slice("old_state", 0, MAGIC + bytes([STATE_VERSION, 1]))
        branch.slice("old_state", 9, 32)
        branch.get("bridge_id")
        branch.op(OP_EQUALVERIFY, 2, 0)
        if require_new_state:
            branch.require_size("new_state", 73)
            branch.equal_slice("new_state", 0, MAGIC + bytes([STATE_VERSION, 1]))
            branch.slice("new_state", 9, 32)
            branch.get("bridge_id")
            branch.op(OP_EQUALVERIFY, 2, 0)

    def genesis(branch: Builder) -> None:
        _check_one_input_two_output(branch, "parent")
        _check_parent_output(branch, 47, 56, 90, 99)
        branch.get("ancestor")
        branch.op(OP_HASH256, 1, 1)
        branch.slice("parent", 5, 32)
        branch.op(OP_EQUALVERIFY, 2, 0)
        branch.equal_slice("parent", 37, bytes(4))
        _check_one_input_two_output(branch, "ancestor")
        branch.equal_slice("ancestor", 56, sponsor_spk)
        branch.require_size("old_state", 41)
        branch.equal_slice("old_state", 0, MAGIC + bytes([STATE_VERSION, 0]))
        branch.get("parent")
        branch.op(OP_HASH256, 1, 1)
        branch.get("bridge_id")
        branch.op(OP_EQUALVERIFY, 2, 0)
        if require_new_state:
            branch.require_size("new_state", 73)
            branch.equal_slice("new_state", 0, MAGIC + bytes([STATE_VERSION, 1]))
            branch.slice("new_state", 9, 32)
            branch.get("bridge_id")
            branch.op(OP_EQUALVERIFY, 2, 0)

    builder.branch(continuation, genesis)


def _expected_collection_outputs(builder: Builder, sponsor_spk: bytes) -> None:
    _make_caboose(builder, "new_state", "new_caboose")
    builder.slice("amounts", 0, 8)
    builder.slice("amounts", 8, 8)
    builder.op(OP_ADD, 2, 1)
    builder.slice("amounts", 16, 8)
    builder.op(OP_ADD, 2, 1)
    builder.fixed_width(8)
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


def _deposit_collection_body() -> bytes:
    builder = Builder(
        ["parent", "old_state", "program_spk", "bridge_id", "account_key", "recipient_id"]
    )
    builder.require_size("program_spk", 34)
    builder.require_size("bridge_id", 32)
    builder.require_size("account_key", 32)
    builder.require_size("recipient_id", 4)

    builder.tx(TX_SHAPE)
    builder.push(bytes.fromhex("02000000000000000400000003000000"))
    builder.op(OP_EQUALVERIFY, 2, 0)
    builder.tx(SEQUENCES)
    builder.push(b"\xfd\xff\xff\xff" * 4)
    builder.op(OP_EQUALVERIFY, 2, 0)
    builder.tx(SCRIPT_SIGS)
    builder.push(bytes(4))
    builder.op(OP_EQUALVERIFY, 2, 0)
    builder.tx(ANNEX)
    builder.push(b"")
    builder.op(OP_EQUALVERIFY, 2, 0)
    for name, selector in (("prevouts", PREVOUTS), ("amounts", AMOUNTS), ("spks", SPKS)):
        builder.tx(selector)
        builder.name(name)
    builder.require_size("prevouts", 144)
    builder.equal_slice("prevouts", 32, bytes(4))
    builder.require_size("amounts", 32)
    builder.require_size("spks", 140)
    builder.equal_slice("spks", 0, b"\x22")
    builder.slice("spks", 1, 34)
    builder.get("program_spk")
    builder.op(OP_EQUALVERIFY, 2, 0)
    builder.tx(CURRENT_INDEX)
    builder.number(1)
    builder.number(3)
    builder.op(OP_WITHIN, 3, 1)
    builder.op(OP_VERIFY, 1, 0)

    builder.get("parent")
    builder.op(OP_HASH256, 1, 1)
    builder.slice("prevouts", 0, 32)
    builder.op(OP_EQUALVERIFY, 2, 0)
    _is_size(builder, "parent", 137)

    def active(branch: Builder) -> None:
        _is_size(branch, "parent", 303)

        def collection(inner: Builder) -> None:
            _check_collection_transaction(inner, "parent")
            _check_parent_output(inner, 170, 179, 256, 265)

        def settlement(inner: Builder) -> None:
            _check_settlement_transaction(inner, "parent")
            _check_parent_output(inner, 88, 97, 217, 226)

        branch.branch(collection, settlement)
        branch.require_size("old_state", 73)
        branch.equal_slice("old_state", 0, MAGIC + bytes([STATE_VERSION, 1]))
        branch.slice("old_state", 9, 32)
        branch.get("bridge_id")
        branch.op(OP_EQUALVERIFY, 2, 0)

    def genesis(branch: Builder) -> None:
        _check_one_input_two_output(branch, "parent")
        _check_parent_output(branch, 47, 56, 90, 99)
        branch.require_size("old_state", 41)
        branch.equal_slice("old_state", 0, MAGIC + bytes([STATE_VERSION, 0]))
        branch.get("parent")
        branch.op(OP_HASH256, 1, 1)
        branch.get("bridge_id")
        branch.op(OP_EQUALVERIFY, 2, 0)

    builder.branch(genesis, active)
    return builder.finish()


def _deposit_fixed_parts(recipient_id: int, account_key: bytes) -> tuple[bytes, bytes]:
    if not 0 <= recipient_id < 3 or len(account_key) != 32:
        raise ValueError("invalid deposit recipient")
    prefix = bytearray()
    prefix.extend(bytes(CScript([recipient_id.to_bytes(4, "little")])))
    prefix.append(OP_TOALTSTACK)
    prefix.extend(bytes(CScript([account_key])))
    prefix.append(OP_TOALTSTACK)
    cleanup = bytes([OP_FROMALTSTACK, OP_DROP]) * 4
    before_refund = bytes(prefix) + b"\x20"  # next field is bridge_id
    after_refund = bytes(
        [
            OP_CHECKSIG,
            OP_ELSE,
            OP_FROMALTSTACK,
            OP_FROMALTSTACK,
            OP_FROMALTSTACK,
            OP_FROMALTSTACK,
        ]
    ) + _deposit_collection_body() + bytes([OP_ENDIF])
    middle = bytes([OP_TOALTSTACK, 0x22])  # program_spk push follows
    branch = bytes([OP_TOALTSTACK, OP_IF]) + cleanup + b"\x20"  # refund key push follows
    return before_refund, middle + branch, after_refund


def deposit_leaf(
    program_spk: bytes,
    bridge_id: bytes,
    recipient_id: int,
    account_key: bytes,
    refund_key: bytes,
) -> bytes:
    if len(program_spk) != 34 or len(bridge_id) != 32 or len(refund_key) != 32:
        raise ValueError("invalid deposit deployment metadata")
    before_bridge, between, after_refund = _deposit_fixed_parts(recipient_id, account_key)
    return (
        before_bridge
        + bridge_id
        + between[:2]
        + program_spk
        + between[2:]
        + refund_key
        + after_refund
    )


def deposit_taproot(leaf: bytes):
    return taproot_construct(NUMS_INTERNAL_KEY, [("spend", CScript(leaf), LEAF_VERSION)])


def _choose_recipient_prefix(
    builder: Builder, id_name: str, account_keys: list[bytes]
) -> tuple[list[bytes], bytes, bytes]:
    parts = [_deposit_fixed_parts(index, key) for index, key in enumerate(account_keys)]
    if any(part[1:] != parts[0][1:] for part in parts[1:]):
        raise AssertionError("deposit template varies outside recipient prefix")

    builder.get(id_name)
    builder.number(0)
    builder.op(OP_NUMEQUAL, 2, 1)

    def zero(branch: Builder) -> None:
        branch.push(parts[0][0])

    def nonzero(branch: Builder) -> None:
        branch.get(id_name)
        branch.number(1)
        branch.op(OP_NUMEQUAL, 2, 1)

        def one(inner: Builder) -> None:
            inner.push(parts[1][0])

        def two(inner: Builder) -> None:
            inner.get(id_name)
            inner.number(2)
            inner.op(OP_NUMEQUALVERIFY, 2, 0)
            inner.push(parts[2][0])

        branch.branch(one, two)

    builder.branch(zero, nonzero)
    return parts[0]


def _authenticate_deposit(
    builder: Builder,
    input_index: int,
    id_name: str,
    refund_name: str,
    account_keys: list[bytes],
) -> None:
    _, between, after_refund = _choose_recipient_prefix(builder, id_name, account_keys)
    builder.get("bridge_id")
    builder.cat()
    builder.push(between[:2])
    builder.cat()
    builder.get("program_spk")
    builder.cat()
    builder.push(between[2:])
    builder.cat()
    builder.get(refund_name)
    builder.require_size(refund_name, 32)
    builder.cat()
    builder.push(after_refund)
    builder.cat()
    builder.name("deposit_leaf")

    leaf_size = len(deposit_leaf(bytes(34), bytes(32), 0, account_keys[0], bytes(32)))
    builder.push(_tag_prefix("TapLeaf") + bytes([LEAF_VERSION]) + ser_compact_size(leaf_size))
    builder.get("deposit_leaf")
    builder.cat()
    builder.op(OP_SHA256, 1, 1)
    builder.push(_tag_prefix("TapTweak") + NUMS_INTERNAL_KEY)
    builder.op(OP_SWAP, 2, 2)
    builder.cat()
    builder.op(OP_SHA256, 1, 1)
    builder.push(NUMS_INTERNAL_KEY)
    builder.op(OP_TWEAKADD, 2, 1)
    builder.push(b"\x22\x51\x20")
    builder.op(OP_SWAP, 2, 2)
    builder.cat()
    builder.slice("spks", input_index * 35, 35)
    builder.op(OP_EQUALVERIFY, 2, 0)


def build_collection_test_program(sponsor_spk: bytes, account_keys: list[bytes]) -> bytes:
    """Collection bridge with an explicit Boolean proof stub; not deployable."""
    if len(sponsor_spk) != 34 or len(account_keys) != 3:
        raise ValueError("invalid deployment constants")
    if any(len(key) != 32 for key in account_keys):
        raise ValueError("account keys must be 32 bytes")

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
            "proof_ok",
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
    _authenticate_parent(builder, sponsor_spk, require_new_state=True)
    builder.get("proof_ok")
    builder.number(1)
    builder.op(OP_NUMEQUALVERIFY, 2, 0)
    return builder.finish()
