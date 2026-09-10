#!/usr/bin/env python3
"""Deterministic preparation and proof-authorized bridge lifecycle on GSR regtest."""

import copy
import hashlib
import json
import os
import sys
import time
from pathlib import Path

CORE = Path(os.environ.get("GSR_CORE_PATH", "/Users/julian/Code/bitcoin/core/gsr/gsr-full"))
sys.path.insert(0, str(CORE / "test/functional"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from script.bridge import (
    account_root,
    bridge_taproot,
    build_collection_program,
    build_settlement_program,
    control_block,
)
from script.deposit import deposit_leaf, deposit_taproot
from script.linearization import (
    CABOOSE_VALUE,
    MINER_FEE,
    RESERVE,
    caboose_script_pubkey,
    encode_active_state,
    encode_genesis_state,
    hash256,
)
from test_framework.messages import (
    COIN,
    COutPoint,
    CTransaction,
    CTxIn,
    CTxInWitness,
    CTxOut,
)
from test_framework.key import compute_xonly_pubkey, sign_schnorr
from test_framework.script import CScript, OP_1, OP_DROP, TaprootSignatureHash
from test_framework.script_util import script_to_p2wsh_script
from test_framework.test_framework import BitcoinTestFramework


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
DESTINATION_SPK = CScript(b"\x51\x20" + bytes.fromhex("77" * 32))
MOCKTIME = 1_700_000_000


def tx_outpoint(tx: CTransaction, index: int = 0) -> COutPoint:
    return COutPoint(int.from_bytes(hash256(tx.serialize_without_witness()), "little"), index)


def raw_txid(outpoint: COutPoint) -> bytes:
    return outpoint.serialize()[:32]


def script_number(value: int) -> bytes:
    if value == 0:
        return b""
    return value.to_bytes((value.bit_length() + 7) // 8, "little")


def encode_outpoint(value: dict) -> bytes:
    return bytes.fromhex(value["txid"]) + value["vout"].to_bytes(4, "little")


def statement_prefix(request: dict, action: int, old_root: bytes, new_root: bytes) -> bytes:
    old_backing = RESERVE + sum(request["old_balances"])
    if action == 1:
        new_backing = old_backing + sum(deposit["value"] for deposit in request["deposits"])
    else:
        new_backing = old_backing - request["withdrawal_amount"]
    return (
        b"coins-gsr-v1/statement/regtest\0"
        + bytes([1, action])
        + bytes.fromhex(request["bridge_id"])
        + encode_outpoint(request["bridge_prevout"])
        + old_root
        + new_root
        + old_backing.to_bytes(8, "little")
        + new_backing.to_bytes(8, "little")
    )


def binding_only_statement(request: dict, new_balances: tuple[int, int, int], new_nonces) -> bytes:
    old_root = account_root(
        ACCOUNT_KEYS, tuple(request["old_balances"]), tuple(request["old_nonces"])
    )
    new_root = account_root(ACCOUNT_KEYS, new_balances, new_nonces)
    if request["action"] == "collect":
        value = bytearray(statement_prefix(request, 1, old_root, new_root))
        for deposit in request["deposits"]:
            value.extend(encode_outpoint(deposit["outpoint"]))
            value.extend(deposit["value"].to_bytes(8, "little"))
            value.extend(deposit["recipient_id"].to_bytes(4, "little"))
            value.extend(ACCOUNT_KEYS[deposit["recipient_id"]])
        return bytes(value)
    value = bytearray(statement_prefix(request, 2, old_root, new_root))
    value.extend(bytes(96))  # Proof-only native, scoped, and withdrawal message hashes.
    value.extend(request["withdrawal_amount"].to_bytes(8, "little"))
    destination = bytes.fromhex(request["withdrawal_destination"])
    value.append(len(destination))
    value.extend(destination)
    return bytes(value)


def binding_only_artifact(values: bytes, verifier: bytes) -> dict:
    digest = bytearray(hashlib.sha256(values).digest())
    digest[0] &= 0x1F
    scalar = bytes(reversed(digest)).rstrip(b"\0")
    return {
        "status": "binding-only-not-proof-authorized",
        "script": verifier.hex(),
        "stack": ["", scalar.hex(), ""],
        "public_values": values.hex(),
    }


def set_statement_digest(stack: list[bytes], values: bytes) -> None:
    digest = bytearray(hashlib.sha256(values).digest())
    digest[0] &= 0x1F
    stack[1] = bytes(reversed(digest)).rstrip(b"\0")


class BridgeLifecycleTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-vbparams=script_restoration:0:3999999999", "-acceptnonstdtxn=1"]]

    def mine(self, count=1):
        return self.generatetodescriptor(
            self.nodes[0], count, f"raw({bytes(SPONSOR_SPK).hex()})"
        )

    def activate(self):
        deployment = self.nodes[0].getdeploymentinfo()["deployments"]["script_restoration"]
        while deployment["bip9"]["status"] != "active":
            self.mine(144 - self.nodes[0].getblockcount() % 144)
            deployment = self.nodes[0].getdeploymentinfo()["deployments"]["script_restoration"]

    def publish(self, tx: CTransaction):
        self.nodes[0].sendrawtransaction(tx.serialize().hex(), 0)
        block = self.mine()[0]
        txid = f"{tx_outpoint(tx).hash:064x}"
        assert txid in self.nodes[0].getblock(block)["tx"]
        return block

    def accepted(self, tx: CTransaction, label: str, runs: int = 1):
        timings = []
        for _ in range(runs):
            started = time.perf_counter()
            result = self.nodes[0].testmempoolaccept([tx.serialize().hex()], maxfeerate=0)[0]
            timings.append(time.perf_counter() - started)
            assert result["allowed"], f"{label}: {result}"
        return timings

    def rejected(self, tx: CTransaction, label: str):
        result = self.nodes[0].testmempoolaccept([tx.serialize().hex()], maxfeerate=0)[0]
        assert not result["allowed"], f"{label}: unexpectedly accepted"

    def funding(self, block: str, amount: int, script_pubkey: bytes) -> CTransaction:
        coinbase = self.nodes[0].getblock(block, 2)["tx"][0]
        total = int(coinbase["vout"][0]["value"] * COIN)
        tx = CTransaction()
        tx.version = 2
        tx.nLockTime = 0
        tx.vin = [
            CTxIn(COutPoint(int(coinbase["txid"], 16), 0), nSequence=0xFFFFFFFD)
        ]
        tx.vout = [
            CTxOut(amount, CScript(script_pubkey)),
            CTxOut(total - amount - MINER_FEE, SPONSOR_SPK),
        ]
        tx.wit.vtxinwit = [CTxInWitness()]
        tx.wit.vtxinwit[0].scriptWitness.stack = [bytes(SPONSOR_SCRIPT)]
        assert len(tx.serialize_without_witness()) == 137
        self.publish(tx)
        return tx

    def genesis(self, funding: CTransaction, state: bytes) -> CTransaction:
        tx = CTransaction()
        tx.version = 2
        tx.nLockTime = 0
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

    def make_deposit(
        self, block: str, bridge_id: bytes, recipient_id: int, refund_byte: int, amount: int
    ) -> dict:
        refund_secret = refund_byte.to_bytes(32, "big")
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
        taproot = deposit_taproot(bytes(leaf))
        funding = self.funding(block, amount, bytes(taproot.scriptPubKey))
        return {
            "funding": funding,
            "outpoint": tx_outpoint(funding),
            "output": funding.vout[0],
            "recipient_id": recipient_id,
            "refund_secret": refund_secret,
            "refund_key": refund_key,
            "leaf": leaf,
            "taproot": taproot,
        }

    def collect_tx(
        self,
        parent: CTransaction,
        deposits: list[dict],
        sponsor: CTransaction,
        new_state: bytes,
    ) -> CTransaction:
        deposits = sorted(deposits, key=lambda deposit: deposit["outpoint"].serialize())
        tx = CTransaction()
        tx.version = 2
        tx.nLockTime = 0
        tx.vin = [
            CTxIn(tx_outpoint(parent), nSequence=0xFFFFFFFD),
            *(CTxIn(deposit["outpoint"], nSequence=0xFFFFFFFD) for deposit in deposits),
            CTxIn(tx_outpoint(sponsor), nSequence=0xFFFFFFFD),
        ]
        new_backing = parent.vout[0].nValue + sum(
            deposit["output"].nValue for deposit in deposits
        )
        tx.vout = [
            CTxOut(new_backing, self.bridge.scriptPubKey),
            CTxOut(sponsor.vout[0].nValue - MINER_FEE - CABOOSE_VALUE, SPONSOR_SPK),
            CTxOut(CABOOSE_VALUE, caboose_script_pubkey(new_state)),
        ]
        assert len(tx.serialize_without_witness()) == 303
        return tx

    def refund_tx(self, deposit: dict) -> CTransaction:
        tx = CTransaction()
        tx.version = 2
        tx.nLockTime = 0
        tx.vin = [CTxIn(deposit["outpoint"], nSequence=0xFFFFFFFD)]
        tx.vout = [CTxOut(deposit["output"].nValue - MINER_FEE, SPONSOR_SPK)]
        signature_hash = TaprootSignatureHash(
            tx,
            [deposit["output"]],
            0,
            0,
            scriptpath=True,
            leaf_script=deposit["leaf"],
            leaf_ver=0xC2,
            codeseparator_pos=0xFFFFFFFF,
        )
        signature = sign_schnorr(deposit["refund_secret"], signature_hash)
        tx.wit.vtxinwit = [CTxInWitness()]
        tx.wit.vtxinwit[0].scriptWitness.stack = [
            signature,
            b"\x01",
            bytes(deposit["leaf"]),
            bytes([0xC2 | deposit["taproot"].negflag])
            + deposit["taproot"].internal_pubkey
            + deposit["taproot"].leaves["spend"].merklebranch,
        ]
        return tx

    def settlement_tx(
        self,
        parent: CTransaction,
        sponsor: CTransaction,
        new_state: bytes,
        payout: int,
    ) -> CTransaction:
        tx = CTransaction()
        tx.version = 2
        tx.nLockTime = 0
        tx.vin = [
            CTxIn(tx_outpoint(parent), nSequence=0xFFFFFFFD),
            CTxIn(tx_outpoint(sponsor), nSequence=0xFFFFFFFD),
        ]
        tx.vout = [
            CTxOut(parent.vout[0].nValue - payout, self.bridge.scriptPubKey),
            CTxOut(payout, DESTINATION_SPK),
            CTxOut(sponsor.vout[0].nValue - MINER_FEE - CABOOSE_VALUE, SPONSOR_SPK),
            CTxOut(CABOOSE_VALUE, caboose_script_pubkey(new_state)),
        ]
        assert len(tx.serialize_without_witness()) == 264
        return tx

    @staticmethod
    def collection_request(
        bridge_id: bytes,
        parent: CTransaction,
        balances: list[int],
        nonces: list[int],
        deposits: list[dict],
    ) -> dict:
        deposits = sorted(deposits, key=lambda deposit: deposit["outpoint"].serialize())
        return {
            "action": "collect",
            "bridge_id": bridge_id.hex(),
            "bridge_prevout": {"txid": raw_txid(tx_outpoint(parent)).hex(), "vout": 0},
            "old_balances": balances,
            "old_nonces": nonces,
            "deposits": [
                {
                    "outpoint": {
                        "txid": raw_txid(deposit["outpoint"]).hex(),
                        "vout": deposit["outpoint"].n,
                    },
                    "value": deposit["output"].nValue,
                    "recipient_id": deposit["recipient_id"],
                }
                for deposit in deposits
            ],
        }

    @staticmethod
    def settlement_request(bridge_id: bytes, parent: CTransaction) -> dict:
        return {
            "action": "transfer_withdraw",
            "bridge_id": bridge_id.hex(),
            "bridge_prevout": {"txid": raw_txid(tx_outpoint(parent)).hex(), "vout": 0},
            "old_balances": [120_000, 80_000, 0],
            "old_nonces": [0, 0, 0],
            "transfer_amount": 50_000,
            "transfer_fee": 1,
            "withdrawal_nonce": 0,
            "withdrawal_amount": 60_000,
            "withdrawal_destination": bytes(DESTINATION_SPK).hex(),
        }

    def attach_collection_witness(
        self,
        tx: CTransaction,
        parent: CTransaction,
        ancestor: CTransaction,
        old_state: bytes,
        new_state: bytes,
        bridge_id: bytes,
        deposits: list[dict],
        artifact: dict,
    ) -> None:
        deposits = sorted(deposits, key=lambda deposit: deposit["outpoint"].serialize())
        proof_stack = [bytes.fromhex(item) for item in artifact["stack"]]
        tx.wit.vtxinwit = [CTxInWitness() for _ in tx.vin]
        tx.wit.vtxinwit[0].scriptWitness.stack = proof_stack + [
            parent.serialize_without_witness(),
            ancestor.serialize_without_witness(),
            old_state,
            new_state,
            bridge_id,
            script_number(deposits[0]["recipient_id"]),
            deposits[0]["refund_key"],
            script_number(deposits[1]["recipient_id"]),
            deposits[1]["refund_key"],
            bytes.fromhex(artifact["public_values"]),
            self.collection_program,
            control_block(self.bridge, "collection"),
        ]
        for index, deposit in enumerate(deposits, start=1):
            tx.wit.vtxinwit[index].scriptWitness.stack = [
                parent.serialize_without_witness(),
                old_state,
                b"",
                bytes(deposit["leaf"]),
                bytes([0xC2 | deposit["taproot"].negflag])
                + deposit["taproot"].internal_pubkey
                + deposit["taproot"].leaves["spend"].merklebranch,
            ]
        tx.wit.vtxinwit[3].scriptWitness.stack = [bytes(SPONSOR_SCRIPT)]

    def attach_settlement_witness(
        self,
        tx: CTransaction,
        parent: CTransaction,
        ancestor: CTransaction,
        old_state: bytes,
        new_state: bytes,
        bridge_id: bytes,
        artifact: dict,
    ) -> None:
        proof_stack = [bytes.fromhex(item) for item in artifact["stack"]]
        tx.wit.vtxinwit = [CTxInWitness(), CTxInWitness()]
        tx.wit.vtxinwit[0].scriptWitness.stack = proof_stack + [
            parent.serialize_without_witness(),
            ancestor.serialize_without_witness(),
            old_state,
            new_state,
            bridge_id,
            bytes.fromhex(artifact["public_values"]),
            self.settlement_program,
            control_block(self.bridge, "settlement"),
        ]
        tx.wit.vtxinwit[1].scriptWitness.stack = [bytes(SPONSOR_SCRIPT)]

    @staticmethod
    def load_proof(fixtures: Path, name: str, request: dict, verifier: bytes) -> dict:
        bundle = json.loads((fixtures / name / "input.json").read_text())
        assert bundle["request"] == request
        verified = json.loads((fixtures / name / "verified.json").read_text())
        artifact = json.loads((fixtures / name / "script.json").read_text())
        assert artifact["status"] == "arithmetic-only-not-a-bridge-lock"
        assert bytes.fromhex(artifact["script"]) == verifier
        assert bytes.fromhex(artifact["public_values"]) == bytes(
            bundle["transition"]["statement"]
        )
        assert verified["public_values"] == artifact["public_values"]
        artifact["compact_proof_bytes"] = verified["proof_bytes"]
        artifact["proving_seconds"] = verified["proving_seconds"]
        return artifact

    def run_test(self):
        binding_only = os.environ.get("COINS_GSR_BINDING_ONLY") == "1"
        if binding_only:
            verifier = bytes(CScript([OP_DROP, OP_DROP, OP_DROP, 1]))
        else:
            verifier_path = Path(os.environ["COINS_GSR_VERIFIER"])
            verifier_artifact = json.loads(verifier_path.read_text())
            verifier = bytes.fromhex(verifier_artifact["script"])
        genesis_root = account_root(ACCOUNT_KEYS)
        self.collection_program = build_collection_program(
            verifier, bytes(SPONSOR_SPK), ACCOUNT_KEYS, genesis_root
        )
        self.settlement_program = build_settlement_program(
            verifier, bytes(SPONSOR_SPK), genesis_root
        )
        self.bridge = bridge_taproot(self.collection_program, self.settlement_program)

        self.nodes[0].setmocktime(MOCKTIME)
        coinbase_blocks = self.mine(12)
        self.activate()
        if self.nodes[0].getblockcount() < 112:
            self.mine(112 - self.nodes[0].getblockcount())

        genesis_funding = self.funding(
            coinbase_blocks[0], RESERVE + CABOOSE_VALUE + MINER_FEE, bytes(SPONSOR_SPK)
        )
        state0 = encode_genesis_state(genesis_root)
        genesis = self.genesis(genesis_funding, state0)
        bridge_id = raw_txid(tx_outpoint(genesis))

        deposits1 = [
            self.make_deposit(coinbase_blocks[1], bridge_id, 0, 0x31, 120_000),
            self.make_deposit(coinbase_blocks[2], bridge_id, 1, 0x32, 80_000),
        ]
        sponsor1 = self.funding(coinbase_blocks[3], 100_000, bytes(SPONSOR_SPK))
        sponsor2 = self.funding(coinbase_blocks[4], 100_000, bytes(SPONSOR_SPK))
        deposits2 = [
            self.make_deposit(coinbase_blocks[5], bridge_id, 0, 0x41, 20_000),
            self.make_deposit(coinbase_blocks[6], bridge_id, 2, 0x42, 30_000),
        ]
        sponsor3 = self.funding(coinbase_blocks[7], 100_000, bytes(SPONSOR_SPK))
        refundable = self.make_deposit(coinbase_blocks[8], bridge_id, 1, 0x51, 25_000)
        refund = self.refund_tx(refundable)
        self.accepted(refund, "immediate owner refund")
        self.publish(refund)
        stale_sponsor = self.funding(coinbase_blocks[9], 100_000, bytes(SPONSOR_SPK))

        state1 = encode_active_state(bridge_id, account_root(ACCOUNT_KEYS, (120_000, 80_000, 0)))
        collection1 = self.collect_tx(genesis, deposits1, sponsor1, state1)
        state2 = encode_active_state(
            bridge_id,
            account_root(ACCOUNT_KEYS, (69_999, 70_000, 1), (1, 1, 0)),
        )
        settlement = self.settlement_tx(collection1, sponsor2, state2, 60_000)
        state3 = encode_active_state(
            bridge_id,
            account_root(ACCOUNT_KEYS, (89_999, 70_000, 30_001), (1, 1, 0)),
        )
        collection2 = self.collect_tx(settlement, deposits2, sponsor3, state3)

        requests = {
            "collection-1": self.collection_request(
                bridge_id, genesis, [0, 0, 0], [0, 0, 0], deposits1
            ),
            "settlement": self.settlement_request(bridge_id, collection1),
            "collection-2": self.collection_request(
                bridge_id,
                settlement,
                [69_999, 70_000, 1],
                [1, 1, 0],
                deposits2,
            ),
        }
        scenario = {
            "status": "deterministic-proof-inputs-not-yet-mined",
            "bridge_script_pubkey": bytes(self.bridge.scriptPubKey).hex(),
            "collection_script_bytes": len(self.collection_program),
            "settlement_script_bytes": len(self.settlement_program),
            "genesis_root": genesis_root.hex(),
            "bridge_id": bridge_id.hex(),
            "refund_txid": f"{tx_outpoint(refund).hash:064x}",
            "requests": requests,
            "transactions": {
                "genesis": genesis.serialize_without_witness().hex(),
                "collection-1": collection1.serialize_without_witness().hex(),
                "settlement": settlement.serialize_without_witness().hex(),
                "collection-2": collection2.serialize_without_witness().hex(),
            },
        }
        scenario_output = os.environ.get("COINS_GSR_SCENARIO_OUTPUT")
        if scenario_output:
            output = Path(scenario_output)
            assert not output.exists()
            output.write_text(json.dumps(scenario, indent=2) + "\n")

        if binding_only:
            artifact1 = binding_only_artifact(
                binding_only_statement(requests["collection-1"], (120_000, 80_000, 0), (0, 0, 0)),
                verifier,
            )
            artifact2 = binding_only_artifact(
                binding_only_statement(requests["settlement"], (69_999, 70_000, 1), (1, 1, 0)),
                verifier,
            )
            artifact3 = binding_only_artifact(
                binding_only_statement(requests["collection-2"], (89_999, 70_000, 30_001), (1, 1, 0)),
                verifier,
            )
        fixtures_value = os.environ.get("COINS_GSR_PROOF_FIXTURES")
        if not fixtures_value:
            if binding_only:
                pass
            else:
                self.log.info("prepared deterministic proof inputs; no proof fixtures requested")
                return
        if not binding_only:
            fixtures = Path(fixtures_value)
            artifact1 = self.load_proof(
                fixtures, "collection-1", requests["collection-1"], verifier
            )
            artifact2 = self.load_proof(fixtures, "settlement", requests["settlement"], verifier)
            artifact3 = self.load_proof(
                fixtures, "collection-2", requests["collection-2"], verifier
            )

        self.attach_collection_witness(
            collection1, genesis, genesis_funding, state0, state1, bridge_id, deposits1, artifact1
        )
        validation_seconds = {}
        validation_seconds["collection-1"] = self.accepted(
            collection1, "proof-authorized initial collection", runs=3
        )
        bad = copy.deepcopy(collection1)
        changed_values = bytearray(bad.wit.vtxinwit[0].scriptWitness.stack[-3])
        changed_values[0] ^= 1
        bad.wit.vtxinwit[0].scriptWitness.stack[-3] = bytes(changed_values)
        self.rejected(bad, "changed collection public values")
        bad = copy.deepcopy(collection1)
        bad.vout[0].nValue -= 1
        self.rejected(bad, "partial deposit forwarding")
        bad = copy.deepcopy(collection1)
        bad.wit.vtxinwit[0].scriptWitness.stack[-7] = b"\x02"
        self.rejected(bad, "substituted deposit recipient")
        bad = copy.deepcopy(collection1)
        changed_state = bytearray(bad.wit.vtxinwit[0].scriptWitness.stack[-9])
        changed_state[-1] ^= 1
        bad.wit.vtxinwit[0].scriptWitness.stack[-9] = bytes(changed_state)
        self.rejected(bad, "new-state witness does not match caboose")
        if not binding_only:
            bad = copy.deepcopy(collection1)
            proof_item = bytearray(bad.wit.vtxinwit[0].scriptWitness.stack[3])
            proof_item[0] ^= 1
            bad.wit.vtxinwit[0].scriptWitness.stack[3] = bytes(proof_item)
            self.rejected(bad, "altered collection proof point")
        block1 = self.publish(collection1)

        self.attach_settlement_witness(
            settlement, collection1, genesis, state1, state2, bridge_id, artifact2
        )
        validation_seconds["settlement"] = self.accepted(
            settlement, "proof-authorized transfer and withdrawal", runs=3
        )
        bad = copy.deepcopy(settlement)
        bad.vout[1].nValue += 1
        bad.vout[0].nValue -= 1
        self.rejected(bad, "changed payout")
        bad = copy.deepcopy(settlement)
        bad.vout[1].scriptPubKey = SPONSOR_SPK
        self.rejected(bad, "changed payout destination")
        bad = copy.deepcopy(settlement)
        bad.vout.append(CTxOut(0, SPONSOR_SPK))
        self.rejected(bad, "extra settlement output")
        if not binding_only:
            bad = copy.deepcopy(settlement)
            values = bytearray(bad.wit.vtxinwit[0].scriptWitness.stack[-3])
            values[181] ^= 1
            bad.wit.vtxinwit[0].scriptWitness.stack[-3] = bytes(values)
            set_statement_digest(bad.wit.vtxinwit[0].scriptWitness.stack, values)
            self.rejected(bad, "old proof with consistently changed proof-only message hash")
        block2 = self.publish(settlement)

        self.attach_collection_witness(
            collection2, settlement, collection1, state2, state3, bridge_id, deposits2, artifact3
        )
        validation_seconds["collection-2"] = self.accepted(
            collection2, "proof-authorized collection after settlement", runs=3
        )
        block3 = self.publish(collection2)
        final_txid = f"{tx_outpoint(collection2).hash:064x}"
        final_utxo = self.nodes[0].gettxout(final_txid, 0)
        assert final_utxo is not None and final_utxo["confirmations"] >= 1
        assert int(final_utxo["value"] * COIN) == 191_000

        stale = self.settlement_tx(collection2, stale_sponsor, state2, 60_000)
        self.attach_settlement_witness(
            stale, collection2, settlement, state3, state2, bridge_id, artifact2
        )
        self.rejected(stale, "proof bound to the old bridge head")

        self.nodes[0].invalidateblock(block3)
        settlement_txid = f"{tx_outpoint(settlement).hash:064x}"
        assert self.nodes[0].gettxout(settlement_txid, 0, False) is not None
        self.nodes[0].reconsiderblock(block3)
        assert self.nodes[0].gettxout(final_txid, 0, False) is not None
        self.nodes[0].invalidateblock(block2)
        collection_txid = f"{tx_outpoint(collection1).hash:064x}"
        assert self.nodes[0].gettxout(collection_txid, 0, False) is not None
        self.nodes[0].reconsiderblock(block2)
        assert self.nodes[0].gettxout(final_txid, 0, False) is not None

        weights = {
            "collection-1": self.nodes[0].decoderawtransaction(collection1.serialize().hex())[
                "weight"
            ],
            "settlement": self.nodes[0].decoderawtransaction(settlement.serialize().hex())[
                "weight"
            ],
            "collection-2": self.nodes[0].decoderawtransaction(collection2.serialize().hex())[
                "weight"
            ],
        }
        result = {
            **scenario,
            "status": (
                "binding-only-lifecycle-mined"
                if binding_only
                else "proof-authorized-lifecycle-mined"
            ),
            "blocks": [block1, block2, block3],
            "final_outpoint": f"{final_txid}:0",
            "balances": [89_999, 70_000, 30_001],
            "nonces": [1, 1, 0],
            "backing": 191_000,
            "weights": weights,
            "testmempoolaccept_seconds": validation_seconds,
            "proof_transactions": {
                "collection-1": collection1.serialize().hex(),
                "settlement": settlement.serialize().hex(),
                "collection-2": collection2.serialize().hex(),
            },
            "proof_transaction_ids": {
                "collection-1": f"{tx_outpoint(collection1).hash:064x}",
                "settlement": f"{tx_outpoint(settlement).hash:064x}",
                "collection-2": final_txid,
            },
        }
        if not binding_only:
            result["proof_metrics"] = {}
            for name, tx, artifact, program in (
                ("collection-1", collection1, artifact1, self.collection_program),
                ("settlement", settlement, artifact2, self.settlement_program),
                ("collection-2", collection2, artifact3, self.collection_program),
            ):
                result["proof_metrics"][name] = {
                    "compact_groth16_proof_bytes": artifact["compact_proof_bytes"],
                    "proving_seconds": artifact["proving_seconds"],
                    "verifier_script_bytes": len(verifier),
                    "bridge_leaf_bytes": len(program),
                    "verifier_stack_items": len(artifact["stack"]),
                    "verifier_stack_payload_bytes": sum(
                        len(bytes.fromhex(item)) for item in artifact["stack"]
                    ),
                    "public_values_bytes": len(bytes.fromhex(artifact["public_values"])),
                    "bridge_input_serialized_witness_bytes": len(tx.wit.vtxinwit[0].serialize()),
                    "arithmetic_only_varops": artifact["measured_varops"],
                    "transaction_varops_budget": weights[name] * 10_000,
                }
        result_path = Path(self.options.tmpdir) / "bridge-result.json"
        result_path.write_text(json.dumps(result, indent=2) + "\n")
        evidence = os.environ.get("COINS_GSR_RESULT_OUTPUT")
        if evidence:
            output = Path(evidence)
            assert not output.exists()
            output.write_bytes(result_path.read_bytes())
        self.log.info(
            "binding-only bridge lifecycle passed"
            if binding_only
            else "proof-authorized bridge lifecycle passed"
        )


if __name__ == "__main__":
    BridgeLifecycleTest(__file__).main()
