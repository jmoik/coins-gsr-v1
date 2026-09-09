"""OP_TX caboose-linearization prefix and host-side encoders.

`build_binding_test_program` appends an explicit Boolean development stub. It is
not the proof-authorized deployment program.
"""

import hashlib

from test_framework.script import CScript


LEAF_VERSION = 0xC2
NUMS_INTERNAL_KEY = bytes.fromhex(
    "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"
)
MAGIC = b"UTXOLIN"
STATE_VERSION = 1
RESERVE = 1_000
CABOOSE_VALUE = 330
MINER_FEE = 10_000

OP_IF = 0x63
OP_ELSE = 0x67
OP_ENDIF = 0x68
OP_DROP = 0x75
OP_PICK = 0x79
OP_SWAP = 0x7C
OP_CAT = 0x7E
OP_SUBSTR = 0x7F
OP_LEFT = 0x80
OP_SIZE = 0x82
OP_EQUAL = 0x87
OP_EQUALVERIFY = 0x88
OP_SUB = 0x94
OP_NUMEQUAL = 0x9C
OP_NUMEQUALVERIFY = 0x9D
OP_SHA256 = 0xA8
OP_HASH256 = 0xAA
OP_TX = 0xBD

# OP_TX v0 selectors pinned by sources.lock.json. Collection scopes are ALL.
TX_SHAPE = bytes.fromhex("005700000000")
PREVOUTS = bytes.fromhex("000100200300")
AMOUNTS = bytes.fromhex("000100200400")
SPKS = bytes.fromhex("000100200800")
SCRIPT_SIGS = bytes.fromhex("000100201000")
SEQUENCES = bytes.fromhex("000100202000")
CURRENT_INDEX = bytes.fromhex("000101000000")
ANNEX = bytes.fromhex("000002000000")
OUTPUTS = bytes.fromhex("000100020003")


def sha256(value: bytes) -> bytes:
    return hashlib.sha256(value).digest()


def hash256(value: bytes) -> bytes:
    return sha256(sha256(value))


def encode_genesis_state(root: bytes) -> bytes:
    if len(root) != 32:
        raise ValueError("account root must be 32 bytes")
    return MAGIC + bytes([STATE_VERSION, 0]) + root


def encode_active_state(bridge_id: bytes, root: bytes) -> bytes:
    if len(bridge_id) != 32 or len(root) != 32:
        raise ValueError("bridge identity and account root must be 32 bytes")
    return MAGIC + bytes([STATE_VERSION, 1]) + bridge_id + root


def caboose_script_pubkey(state: bytes) -> CScript:
    witness_script = b"\x6a\x24" + sha256(state) + bytes(4)
    return CScript(b"\x00\x20" + sha256(witness_script))


class Builder:
    def __init__(self, names: list[str]):
        self.code = bytearray()
        self.names = list(names)

    def push(self, value: bytes) -> None:
        self.code.extend(bytes(CScript([value])))
        self.names.append("")

    def number(self, value: int) -> None:
        self.code.extend(bytes(CScript([value])))
        self.names.append("")

    def op(self, opcode: int, inputs: int, outputs: int) -> None:
        if len(self.names) < inputs:
            raise AssertionError(f"builder stack underflow at {opcode:02x}")
        del self.names[len(self.names) - inputs :]
        self.code.append(opcode)
        self.names.extend([""] * outputs)

    def name(self, name: str) -> None:
        self.names[-1] = name

    def get(self, name: str) -> None:
        position = max(index for index, item in enumerate(self.names) if item == name)
        self.number(len(self.names) - 1 - position)
        self.op(OP_PICK, 1, 1)

    def slice(self, name: str, start: int, length: int) -> None:
        self.get(name)
        self.number(start)
        self.number(length)
        self.op(OP_SUBSTR, 3, 1)

    def equal_slice(self, name: str, start: int, expected: bytes) -> None:
        self.slice(name, start, len(expected))
        self.push(expected)
        self.op(OP_EQUALVERIFY, 2, 0)

    def require_size(self, name: str, length: int) -> None:
        self.get(name)
        self.op(OP_SIZE, 0, 1)
        self.number(length)
        self.op(OP_NUMEQUALVERIFY, 2, 0)
        self.op(OP_DROP, 1, 0)

    def cat(self) -> None:
        self.op(OP_CAT, 2, 1)

    def fixed_width(self, width: int) -> None:
        self.push(bytes(width))
        self.cat()
        self.number(width)
        self.op(OP_LEFT, 2, 1)

    def tx(self, selector: bytes) -> None:
        self.push(selector)
        self.op(OP_TX, 1, 1)

    def branch(self, yes, no) -> None:
        self.op(OP_IF, 1, 0)
        before = list(self.names)
        yes(self)
        after = list(self.names)
        self.code.append(OP_ELSE)
        self.names = before
        no(self)
        if self.names != after:
            raise AssertionError("branch stack mismatch")
        self.code.append(OP_ENDIF)

    def finish(self) -> bytes:
        while self.names:
            self.op(OP_DROP, 1, 0)
        self.number(1)
        return bytes(self.code)


def _make_caboose(builder: Builder, state_name: str, result_name: str) -> None:
    builder.get(state_name)
    builder.op(OP_SHA256, 1, 1)
    builder.push(b"\x6a\x24")
    builder.op(OP_SWAP, 2, 2)
    builder.cat()
    builder.push(bytes(4))
    builder.cat()
    builder.op(OP_SHA256, 1, 1)
    builder.push(b"\x00\x20")
    builder.op(OP_SWAP, 2, 2)
    builder.cat()
    builder.name(result_name)


def _check_common_transaction(builder: Builder, name: str, size: int) -> None:
    builder.require_size(name, size)
    builder.equal_slice(name, 0, b"\x02\x00\x00\x00")
    builder.equal_slice(name, size - 4, bytes(4))


def _check_one_input_two_output(builder: Builder, name: str) -> None:
    _check_common_transaction(builder, name, 137)
    for offset, expected in (
        (0, b"\x02\x00\x00\x00\x01"),
        (41, b"\x00\xfd\xff\xff\xff\x02"),
        (55, b"\x22"),
        (98, b"\x22"),
    ):
        builder.equal_slice(name, offset, expected)


def _check_two_input_three_output(builder: Builder, name: str) -> None:
    _check_common_transaction(builder, name, 221)
    for offset, expected in (
        (0, b"\x02\x00\x00\x00\x02"),
        (41, b"\x00\xfd\xff\xff\xff"),
        (82, b"\x00\xfd\xff\xff\xff\x03"),
        (96, b"\x22"),
        (139, b"\x22"),
        (182, b"\x22"),
    ):
        builder.equal_slice(name, offset, expected)


def _check_current_context(builder: Builder, sponsor_spk: bytes) -> None:
    builder.tx(TX_SHAPE)
    builder.push(bytes.fromhex("02000000000000000200000003000000"))
    builder.op(OP_EQUALVERIFY, 2, 0)
    builder.tx(SEQUENCES)
    builder.push(b"\xfd\xff\xff\xff" * 2)
    builder.op(OP_EQUALVERIFY, 2, 0)
    builder.tx(SCRIPT_SIGS)
    builder.push(b"\x00\x00")
    builder.op(OP_EQUALVERIFY, 2, 0)
    builder.tx(ANNEX)
    builder.push(b"")
    builder.op(OP_EQUALVERIFY, 2, 0)
    for name, selector in (("prevouts", PREVOUTS), ("amounts", AMOUNTS), ("spks", SPKS)):
        builder.tx(selector)
        builder.name(name)
    builder.tx(CURRENT_INDEX)
    builder.number(0)
    builder.op(OP_NUMEQUALVERIFY, 2, 0)

    builder.require_size("prevouts", 72)
    builder.equal_slice("prevouts", 32, bytes(4))
    builder.require_size("amounts", 16)
    builder.require_size("spks", 70)
    builder.equal_slice("spks", 0, b"\x22")
    builder.slice("spks", 1, 34)
    builder.name("program_spk")
    builder.equal_slice("spks", 35, b"\x22" + sponsor_spk)


def _check_outputs(builder: Builder, sponsor_spk: bytes) -> None:
    _make_caboose(builder, "new_state", "new_caboose")
    builder.slice("amounts", 0, 8)
    builder.name("bridge_amount")
    builder.get("bridge_amount")
    builder.push(b"\x22")
    builder.cat()
    builder.get("program_spk")
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


def _check_parent_output(builder: Builder, amount_offset: int, spk_offset: int) -> None:
    builder.slice("parent", amount_offset, 8)
    builder.get("bridge_amount")
    builder.op(OP_EQUALVERIFY, 2, 0)
    builder.slice("parent", spk_offset, 34)
    builder.get("program_spk")
    builder.op(OP_EQUALVERIFY, 2, 0)


def _check_parent_caboose(builder: Builder, value_offset: int, spk_offset: int) -> None:
    builder.equal_slice("parent", value_offset, CABOOSE_VALUE.to_bytes(8, "little"))
    _make_caboose(builder, "old_state", "old_caboose")
    builder.slice("parent", spk_offset, 34)
    builder.get("old_caboose")
    builder.op(OP_EQUALVERIFY, 2, 0)


def _authenticate_ancestor(builder: Builder, expected_spk: bytes) -> None:
    builder.get("ancestor")
    builder.op(OP_HASH256, 1, 1)
    builder.slice("parent", 5, 32)
    builder.op(OP_EQUALVERIFY, 2, 0)
    builder.equal_slice("parent", 37, bytes(4))

    builder.get("ancestor")
    builder.op(OP_SIZE, 0, 1)
    builder.number(221)
    builder.op(OP_NUMEQUAL, 2, 1)
    builder.op(OP_SWAP, 2, 2)
    builder.op(OP_DROP, 1, 0)

    def transition_ancestor(branch: Builder) -> None:
        _check_two_input_three_output(branch, "ancestor")
        branch.equal_slice("ancestor", 97, expected_spk)

    def genesis_or_funding_ancestor(branch: Builder) -> None:
        _check_one_input_two_output(branch, "ancestor")
        branch.equal_slice("ancestor", 56, expected_spk)

    builder.branch(transition_ancestor, genesis_or_funding_ancestor)


def build_binding_test_program(sponsor_spk: bytes) -> bytes:
    """Build the linearization program with an explicit witness Boolean stub."""
    if len(sponsor_spk) != 34:
        raise ValueError("sponsor scriptPubKey must be 34 bytes")
    builder = Builder(["parent", "ancestor", "old_state", "new_state", "proof_ok"])
    _check_current_context(builder, sponsor_spk)
    _check_outputs(builder, sponsor_spk)

    builder.get("parent")
    builder.op(OP_HASH256, 1, 1)
    builder.slice("prevouts", 0, 32)
    builder.op(OP_EQUALVERIFY, 2, 0)

    builder.get("parent")
    builder.op(OP_SIZE, 0, 1)
    builder.number(221)
    builder.op(OP_NUMEQUAL, 2, 1)
    builder.op(OP_SWAP, 2, 2)
    builder.op(OP_DROP, 1, 0)

    def genesis(branch: Builder) -> None:
        _check_one_input_two_output(branch, "parent")
        _check_parent_output(branch, 47, 56)
        _check_parent_caboose(branch, 90, 99)
        _authenticate_ancestor(branch, sponsor_spk)

    # Continuation needs the authenticated predecessor output to be the exact
    # stable program. It is dynamic, so handle it without the constant helper.
    def continuation_with_dynamic_program(branch: Builder) -> None:
        _check_two_input_three_output(branch, "parent")
        _check_parent_output(branch, 88, 97)
        branch.equal_slice("parent", 140, sponsor_spk)
        _check_parent_caboose(branch, 174, 183)
        branch.get("ancestor")
        branch.op(OP_HASH256, 1, 1)
        branch.slice("parent", 5, 32)
        branch.op(OP_EQUALVERIFY, 2, 0)
        branch.equal_slice("parent", 37, bytes(4))
        branch.get("ancestor")
        branch.op(OP_SIZE, 0, 1)
        branch.number(221)
        branch.op(OP_NUMEQUAL, 2, 1)
        branch.op(OP_SWAP, 2, 2)
        branch.op(OP_DROP, 1, 0)

        def prior_transition(inner: Builder) -> None:
            _check_two_input_three_output(inner, "ancestor")
            inner.slice("ancestor", 97, 34)
            inner.get("program_spk")
            inner.op(OP_EQUALVERIFY, 2, 0)

        def prior_genesis(inner: Builder) -> None:
            _check_one_input_two_output(inner, "ancestor")
            inner.slice("ancestor", 56, 34)
            inner.get("program_spk")
            inner.op(OP_EQUALVERIFY, 2, 0)

        branch.branch(prior_transition, prior_genesis)
        branch.require_size("old_state", 73)
        branch.require_size("new_state", 73)
        branch.equal_slice("old_state", 0, MAGIC + bytes([STATE_VERSION, 1]))
        branch.equal_slice("new_state", 0, MAGIC + bytes([STATE_VERSION, 1]))
        branch.slice("old_state", 9, 32)
        branch.slice("new_state", 9, 32)
        branch.op(OP_EQUALVERIFY, 2, 0)

    def genesis_with_identity(branch: Builder) -> None:
        genesis(branch)
        branch.require_size("old_state", 41)
        branch.require_size("new_state", 73)
        branch.equal_slice("old_state", 0, MAGIC + bytes([STATE_VERSION, 0]))
        branch.equal_slice("new_state", 0, MAGIC + bytes([STATE_VERSION, 1]))
        branch.get("parent")
        branch.op(OP_HASH256, 1, 1)
        branch.slice("new_state", 9, 32)
        branch.op(OP_EQUALVERIFY, 2, 0)

    builder.branch(continuation_with_dynamic_program, genesis_with_identity)
    builder.get("proof_ok")
    builder.number(1)
    builder.op(OP_NUMEQUALVERIFY, 2, 0)
    return builder.finish()
