#!/usr/bin/env python3
"""Persistent deposit, collection binding, and immediate refund tests."""

import copy
import os
import sys
from pathlib import Path

CORE = Path(os.environ.get("GSR_CORE_PATH", "/Users/julian/Code/bitcoin/core/gsr/gsr-full"))
sys.path.insert(0, str(CORE / "test/functional"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from script.deposit import build_collection_test_program, deposit_leaf, deposit_taproot
from script.linearization import (
    CABOOSE_VALUE,
    LEAF_VERSION,
    MINER_FEE,
    NUMS_INTERNAL_KEY,
    RESERVE,
    caboose_script_pubkey,
    encode_active_state,
    encode_genesis_state,
    hash256,
)
from test_framework.key import compute_xonly_pubkey, sign_schnorr
from test_framework.messages import COutPoint, CTransaction, CTxIn, CTxInWitness, CTxOut, tx_from_hex
from test_framework.script import CScript, OP_1, TaprootSignatureHash, taproot_construct
from test_framework.script_util import script_to_p2wsh_script
from test_framework.test_framework import BitcoinTestFramework
from test_framework.wallet import NodeSigner


SPONSOR_SCRIPT = CScript([OP_1])
SPONSOR_SPK = script_to_p2wsh_script(SPONSOR_SCRIPT)
ACCOUNT_KEYS = [
    bytes.fromhex(value)
    for value in (
        "ef493dfc801fb7a82cc12ae97f478224b8cdee518680a89d1809b037557014aa",
        "51c82b00d1b7c09fb02665f3e4d95af76601048d11b4c99aabd18c1c472cd3a5",
        "3f2ff530e029b508e46914b4fdc3b8f8179f67653409560ff1a4a7c88c6fe885",
    )
]


def tx_outpoint(tx: CTransaction, index: int = 0) -> COutPoint:
    return COutPoint(int.from_bytes(hash256(tx.serialize_without_witness()), "little"), index)


def control_block(tap) -> bytes:
    return (
        bytes([LEAF_VERSION | tap.negflag])
        + tap.internal_pubkey
        + tap.leaves["spend"].merklebranch
    )


def script_number(value: int) -> bytes:
    if value == 0:
        return b""
    return value.to_bytes((value.bit_length() + 7) // 8, "little")


class DepositTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-vbparams=script_restoration:0:3999999999", "-acceptnonstdtxn=1"]]

    def activate(self):
        deployment = self.nodes[0].getdeploymentinfo()["deployments"]["script_restoration"]
        while deployment["bip9"]["status"] != "active":
            self.generate(self.nodes[0], 144 - self.nodes[0].getblockcount() % 144)
            deployment = self.nodes[0].getdeploymentinfo()["deployments"]["script_restoration"]

    def publish(self, tx):
        self.nodes[0].sendrawtransaction(tx.serialize().hex(), 0)
        self.generate(self.nodes[0], 1)

    def accepted(self, tx, label):
        result = self.nodes[0].testmempoolaccept([tx.serialize().hex()], maxfeerate=0)[0]
        assert result["allowed"], f"{label}: {result}"

    def rejected(self, tx, label, script_failure=True):
        result = self.nodes[0].testmempoolaccept([tx.serialize().hex()], maxfeerate=0)[0]
        assert not result["allowed"], f"{label}: unexpectedly accepted"
        if script_failure:
            assert "script-verify-flag-failed" in result.get("reject-reason", ""), result

    def fund_output(self, amount, script_pubkey):
        coin = next(
            coin
            for coin in self.signer.listunspent()
            if int(coin["amount"] * 100_000_000) > amount + MINER_FEE
        )
        total = int(coin["amount"] * 100_000_000)
        tx = CTransaction()
        tx.vin = [
            CTxIn(COutPoint(int(coin["txid"], 16), coin["vout"]), nSequence=0xFFFFFFFD)
        ]
        tx.vout = [
            CTxOut(amount, script_pubkey),
            CTxOut(total - amount - MINER_FEE, SPONSOR_SPK),
        ]
        signed = self.signer.signrawtransaction(tx.serialize().hex(), [coin])
        assert signed["complete"]
        tx = tx_from_hex(signed["hex"])
        assert len(tx.serialize_without_witness()) == 137
        self.publish(tx)
        return tx

    def genesis(self, funding, state):
        tx = CTransaction()
        tx.vin = [CTxIn(tx_outpoint(funding), nSequence=0xFFFFFFFD)]
        tx.vout = [
            CTxOut(RESERVE, self.bridge.scriptPubKey),
            CTxOut(CABOOSE_VALUE, caboose_script_pubkey(state)),
        ]
        tx.wit.vtxinwit = [CTxInWitness()]
        tx.wit.vtxinwit[0].scriptWitness.stack = [bytes(SPONSOR_SCRIPT)]
        assert len(tx.serialize_without_witness()) == 137
        self.publish(tx)
        return tx

    def make_deposit(self, bridge_id, recipient_id, refund_secret, amount):
        refund_key = compute_xonly_pubkey(refund_secret)[0]
        leaf = CScript(
            deposit_leaf(
                bytes(self.bridge.scriptPubKey),
                bridge_id,
                recipient_id,
                ACCOUNT_KEYS[recipient_id],
                refund_key,
            )
        )
        tap = deposit_taproot(bytes(leaf))
        funding = self.fund_output(amount, tap.scriptPubKey)
        return {
            "funding": funding,
            "outpoint": tx_outpoint(funding),
            "output": funding.vout[0],
            "recipient_id": recipient_id,
            "refund_secret": refund_secret,
            "refund_key": refund_key,
            "leaf": leaf,
            "tap": tap,
        }

    def collect(self, parent, ancestor, old_state, new_state, bridge_id, deposits):
        sponsor = self.fund_output(100_000, SPONSOR_SPK)
        tx = CTransaction()
        tx.vin = [
            CTxIn(tx_outpoint(parent), nSequence=0xFFFFFFFD),
            CTxIn(deposits[0]["outpoint"], nSequence=0xFFFFFFFD),
            CTxIn(deposits[1]["outpoint"], nSequence=0xFFFFFFFD),
            CTxIn(tx_outpoint(sponsor), nSequence=0xFFFFFFFD),
        ]
        bridge_value = parent.vout[0].nValue + sum(d["output"].nValue for d in deposits)
        tx.vout = [
            CTxOut(bridge_value, self.bridge.scriptPubKey),
            CTxOut(sponsor.vout[0].nValue - MINER_FEE - CABOOSE_VALUE, SPONSOR_SPK),
            CTxOut(CABOOSE_VALUE, caboose_script_pubkey(new_state)),
        ]
        tx.wit.vtxinwit = [CTxInWitness() for _ in tx.vin]
        main_stack = [
            parent.serialize_without_witness(),
            ancestor.serialize_without_witness(),
            old_state,
            new_state,
            bridge_id,
        ]
        for deposit in deposits:
            main_stack.extend(
                [script_number(deposit["recipient_id"]), deposit["refund_key"]]
            )
        main_stack.append(b"\x01")
        tx.wit.vtxinwit[0].scriptWitness.stack = main_stack + [
            self.bridge_script,
            control_block(self.bridge),
        ]
        for input_index, deposit in enumerate(deposits, start=1):
            tx.wit.vtxinwit[input_index].scriptWitness.stack = [
                parent.serialize_without_witness(),
                old_state,
                b"",
                bytes(deposit["leaf"]),
                control_block(deposit["tap"]),
            ]
        tx.wit.vtxinwit[3].scriptWitness.stack = [bytes(SPONSOR_SCRIPT)]
        assert len(tx.serialize_without_witness()) == 303
        return tx

    def refund(self, deposit, secret=None):
        tx = CTransaction()
        tx.vin = [CTxIn(deposit["outpoint"], nSequence=0xFFFFFFFD)]
        tx.vout = [CTxOut(deposit["output"].nValue - MINER_FEE, SPONSOR_SPK)]
        signature_hash = TaprootSignatureHash(
            tx,
            [deposit["output"]],
            0,
            0,
            scriptpath=True,
            leaf_script=deposit["leaf"],
            leaf_ver=LEAF_VERSION,
            codeseparator_pos=0xFFFFFFFF,
        )
        signature = sign_schnorr(secret or deposit["refund_secret"], signature_hash)
        tx.wit.vtxinwit = [CTxInWitness()]
        tx.wit.vtxinwit[0].scriptWitness.stack = [
            signature,
            b"\x01",
            bytes(deposit["leaf"]),
            control_block(deposit["tap"]),
        ]
        return tx

    def run_test(self):
        self.signer = NodeSigner(self.nodes[0])
        self.generatetoaddress(
            self.nodes[0], 101, self.signer.getnewaddress(address_type="bech32")[2]
        )
        self.activate()
        self.bridge_script = CScript(
            build_collection_test_program(bytes(SPONSOR_SPK), ACCOUNT_KEYS)
        )
        self.bridge = taproot_construct(
            NUMS_INTERNAL_KEY, [("spend", self.bridge_script, LEAF_VERSION)]
        )

        genesis_funding = self.fund_output(RESERVE + CABOOSE_VALUE + MINER_FEE, SPONSOR_SPK)
        state0 = encode_genesis_state(bytes.fromhex("10" * 32))
        genesis = self.genesis(genesis_funding, state0)
        bridge_id = tx_outpoint(genesis).serialize()[:32]

        pending = [
            self.make_deposit(bridge_id, 0, (21).to_bytes(32, "big"), 20_000),
            self.make_deposit(bridge_id, 1, (22).to_bytes(32, "big"), 30_000),
        ]
        first_pair = [
            self.make_deposit(bridge_id, 0, (31).to_bytes(32, "big"), 40_000),
            self.make_deposit(bridge_id, 2, (32).to_bytes(32, "big"), 50_000),
        ]
        state1 = encode_active_state(bridge_id, bytes.fromhex("20" * 32))
        first = self.collect(genesis, genesis_funding, state0, state1, bridge_id, first_pair)
        self.accepted(first, "first collection")
        self.publish(first)

        state2 = encode_active_state(bridge_id, bytes.fromhex("30" * 32))
        rebased = self.collect(first, genesis, state1, state2, bridge_id, pending)
        self.accepted(rebased, "deposits survive a legitimate head change")

        bad = copy.deepcopy(rebased)
        bad.wit.vtxinwit[0].scriptWitness.stack[5] = b"\x01"
        self.rejected(bad, "substituted recipient metadata")
        bad = copy.deepcopy(rebased)
        bad.vout[0].nValue -= 1
        self.rejected(bad, "partial deposit forwarding")
        bad = copy.deepcopy(rebased)
        bad.wit.vtxinwit[0].scriptWitness.stack[4] = bytes.fromhex("99" * 32)
        self.rejected(bad, "wrong bridge identity")

        self.publish(rebased)

        refundable = self.make_deposit(
            bridge_id, 1, (41).to_bytes(32, "big"), 25_000
        )
        refund = self.refund(refundable)
        self.accepted(refund, "immediate owner refund")
        wrong_refund = self.refund(refundable, (42).to_bytes(32, "big"))
        self.rejected(wrong_refund, "wrong refund key")
        self.publish(refund)

        race_pair = [
            self.make_deposit(bridge_id, 0, (51).to_bytes(32, "big"), 22_000),
            self.make_deposit(bridge_id, 2, (52).to_bytes(32, "big"), 23_000),
        ]
        state3 = encode_active_state(bridge_id, bytes.fromhex("40" * 32))
        racing_collection = self.collect(rebased, first, state2, state3, bridge_id, race_pair)
        self.accepted(racing_collection, "collection competing with refund")
        racing_refund = self.refund(race_pair[0])
        self.accepted(racing_refund, "refund competing with collection")
        self.publish(racing_refund)
        self.rejected(racing_collection, "confirmed refund prevents collection", script_failure=False)

        self.log.info("persistent deposit and refund tests passed")


if __name__ == "__main__":
    DepositTest(__file__).main()
