#!/usr/bin/env python3
"""Focused OP_TX linearization test using the explicit development proof stub."""

import copy
import json
import os
import sys
from pathlib import Path

CORE = Path(os.environ.get("GSR_CORE_PATH", "/Users/julian/Code/bitcoin/core/gsr/gsr-full"))
sys.path.insert(0, str(CORE / "test/functional"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from script.linearization import (
    CABOOSE_VALUE,
    LEAF_VERSION,
    MINER_FEE,
    NUMS_INTERNAL_KEY,
    RESERVE,
    build_binding_test_program,
    caboose_script_pubkey,
    encode_active_state,
    encode_genesis_state,
    hash256,
)
from test_framework.key import sign_schnorr
from test_framework.messages import COutPoint, CTransaction, CTxIn, CTxInWitness, CTxOut, tx_from_hex
from test_framework.script import CScript, OP_1, TaprootSignatureHash, taproot_construct
from test_framework.script_util import script_to_p2wsh_script
from test_framework.test_framework import BitcoinTestFramework
from test_framework.wallet import NodeSigner


SPONSOR_SCRIPT = CScript([OP_1])
SPONSOR_SPK = script_to_p2wsh_script(SPONSOR_SCRIPT)


def tx_outpoint(tx: CTransaction, index: int = 0) -> COutPoint:
    return COutPoint(int.from_bytes(hash256(tx.serialize_without_witness()), "little"), index)


def control_block(tap) -> bytes:
    return (
        bytes([LEAF_VERSION | tap.negflag])
        + tap.internal_pubkey
        + tap.leaves["spend"].merklebranch
    )


class LinearizationTest(BitcoinTestFramework):
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

    def allowed(self, tx, label):
        result = self.nodes[0].testmempoolaccept([tx.serialize().hex()], maxfeerate=0)[0]
        assert result["allowed"], f"{label}: {result}"
        self.cases.append({"case": label, "allowed": True})

    def rejected(self, tx, label, script_failure=True):
        result = self.nodes[0].testmempoolaccept([tx.serialize().hex()], maxfeerate=0)[0]
        assert not result["allowed"], f"{label}: unexpectedly accepted"
        reason = result.get("reject-reason", "")
        if script_failure:
            assert "script-verify-flag-failed" in reason, f"{label}: wrong rejection: {result}"
        self.cases.append({"case": label, "allowed": False, "reason": reason})

    def funding_tx(self, amount):
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
            CTxOut(amount, SPONSOR_SPK),
            CTxOut(total - amount - MINER_FEE, SPONSOR_SPK),
        ]
        signed = self.signer.signrawtransaction(tx.serialize().hex(), [coin])
        assert signed["complete"]
        tx = tx_from_hex(signed["hex"])
        assert len(tx.serialize_without_witness()) == 137
        self.publish(tx)
        return tx

    def genesis_tx(self, funding, state):
        tx = CTransaction()
        tx.vin = [CTxIn(tx_outpoint(funding), nSequence=0xFFFFFFFD)]
        tx.vout = [
            CTxOut(RESERVE, self.tap.scriptPubKey),
            CTxOut(CABOOSE_VALUE, caboose_script_pubkey(state)),
        ]
        tx.wit.vtxinwit = [CTxInWitness()]
        tx.wit.vtxinwit[0].scriptWitness.stack = [bytes(SPONSOR_SCRIPT)]
        assert funding.vout[0].nValue - RESERVE - CABOOSE_VALUE == MINER_FEE
        assert len(tx.serialize_without_witness()) == 137
        self.publish(tx)
        return tx

    def transition(self, parent, ancestor, sponsor_outpoint, sponsor_value, old_state, new_state, proof_ok=b"\x01"):
        tx = CTransaction()
        tx.vin = [
            CTxIn(tx_outpoint(parent), nSequence=0xFFFFFFFD),
            CTxIn(sponsor_outpoint, nSequence=0xFFFFFFFD),
        ]
        tx.vout = [
            CTxOut(parent.vout[0].nValue, self.tap.scriptPubKey),
            CTxOut(sponsor_value - MINER_FEE - CABOOSE_VALUE, SPONSOR_SPK),
            CTxOut(CABOOSE_VALUE, caboose_script_pubkey(new_state)),
        ]
        tx.wit.vtxinwit = [CTxInWitness(), CTxInWitness()]
        tx.wit.vtxinwit[0].scriptWitness.stack = [
            parent.serialize_without_witness(),
            ancestor.serialize_without_witness(),
            old_state,
            new_state,
            proof_ok,
            self.script,
            control_block(self.tap),
        ]
        tx.wit.vtxinwit[1].scriptWitness.stack = [bytes(SPONSOR_SCRIPT)]
        assert len(tx.serialize_without_witness()) == 221
        return tx

    def run_test(self):
        self.signer = NodeSigner(self.nodes[0])
        self.cases = []
        self.generatetoaddress(
            self.nodes[0], 101, self.signer.getnewaddress(address_type="bech32")[2]
        )
        self.activate()
        self.script = CScript(build_binding_test_program(bytes(SPONSOR_SPK)))
        self.tap = taproot_construct(
            NUMS_INTERNAL_KEY, [("spend", self.script, LEAF_VERSION)]
        )

        funding = self.funding_tx(RESERVE + CABOOSE_VALUE + MINER_FEE)
        sponsor = self.funding_tx(100_000)
        root0 = bytes.fromhex("10" * 32)
        state0 = encode_genesis_state(root0)
        genesis = self.genesis_tx(funding, state0)
        bridge_id = tx_outpoint(genesis).serialize()[:32]
        state1 = encode_active_state(bridge_id, bytes.fromhex("20" * 32))
        first = self.transition(genesis, funding, tx_outpoint(sponsor), sponsor.vout[0].nValue, state0, state1)

        for witness_index, label in (
            (0, "forged parent"),
            (1, "forged ancestor"),
            (2, "forged old state"),
            (3, "forged new state"),
        ):
            bad = copy.deepcopy(first)
            value = bytearray(bad.wit.vtxinwit[0].scriptWitness.stack[witness_index])
            value[0] ^= 1
            bad.wit.vtxinwit[0].scriptWitness.stack[witness_index] = bytes(value)
            self.rejected(bad, label)

        bad = copy.deepcopy(first)
        bad.wit.vtxinwit[0].scriptWitness.stack[4] = b""
        self.rejected(bad, "development proof stub is false")
        bad = copy.deepcopy(first)
        bad.vout[0].nValue -= 1
        self.rejected(bad, "changed bridge value")
        bad = copy.deepcopy(first)
        bad.vout[1].nValue -= 1
        self.rejected(bad, "changed sponsor value")
        bad = copy.deepcopy(first)
        bad.vout[2].scriptPubKey = caboose_script_pubkey(state0)
        self.rejected(bad, "changed caboose")

        keypath = copy.deepcopy(first)
        message = TaprootSignatureHash(keypath, [genesis.vout[0], sponsor.vout[0]], 0, 0)
        keypath.wit.vtxinwit[0].scriptWitness.stack = [
            sign_schnorr((123).to_bytes(32, "big"), message)
        ]
        self.rejected(keypath, "known test key cannot bypass script path")

        counterfeit_funding = self.funding_tx(RESERVE + CABOOSE_VALUE + MINER_FEE)
        counterfeit_sponsor = self.funding_tx(100_000)
        counterfeit_state = encode_active_state(bridge_id, bytes.fromhex("40" * 32))
        counterfeit = self.genesis_tx(counterfeit_funding, counterfeit_state)
        copied_origin = self.transition(
            counterfeit,
            counterfeit_funding,
            tx_outpoint(counterfeit_sponsor),
            counterfeit_sponsor.vout[0].nValue,
            counterfeit_state,
            encode_active_state(bridge_id, bytes.fromhex("41" * 32)),
        )
        self.rejected(copied_origin, "copied program and active state have no valid origin")

        self.allowed(first, "genesis to active")
        self.publish(first)
        state2 = encode_active_state(bridge_id, bytes.fromhex("30" * 32))
        second = self.transition(
            first,
            genesis,
            tx_outpoint(first, 1),
            first.vout[1].nValue,
            state1,
            state2,
        )
        self.allowed(second, "active continuation")

        copied = bytearray(state2)
        copied[9] ^= 1
        bad = self.transition(
            first,
            genesis,
            tx_outpoint(first, 1),
            first.vout[1].nValue,
            state1,
            bytes(copied),
        )
        self.rejected(bad, "changed propagated identity")
        self.publish(second)

        result = {
            "scope": "linearization binding only; Boolean proof stub is not deployable",
            "program_script_bytes": len(self.script),
            "program_scriptpubkey": self.tap.scriptPubKey.hex(),
            "scriptpubkey_stable": all(
                tx.vout[0].scriptPubKey == self.tap.scriptPubKey
                for tx in (genesis, first, second)
            ),
            "genesis_id": bridge_id.hex(),
            "txids": [f"{tx_outpoint(tx).hash:064x}" for tx in (genesis, first, second)],
            "cases": self.cases,
        }
        output = Path(
            os.environ.get("COINS_GSR_RESULT", str(Path(self.options.tmpdir) / "result.json"))
        )
        output.write_text(json.dumps(result, indent=2) + "\n")
        self.log.info("OP_TX caboose linearization binding test passed")


if __name__ == "__main__":
    LinearizationTest(__file__).main()
