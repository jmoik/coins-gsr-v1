#!/usr/bin/env python3
"""Cheap cross-language and artifact-integrity checks for the retained deployment."""

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path

CORE = Path(os.environ.get("GSR_CORE_PATH", "/Users/julian/Code/bitcoin/core/gsr/gsr-full"))
sys.path.insert(0, str(CORE / "test/functional"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from script.bridge import (
    account_root,
    bridge_taproot,
    build_collection_program,
    build_settlement_program,
)
from test_framework.messages import tx_from_hex
from test_framework.script import CScript, OP_1
from test_framework.script_util import script_to_p2wsh_script


ACTIONS = ("collection-1", "settlement", "collection-2")
ACCOUNT_KEYS = [
    bytes.fromhex(value)
    for value in (
        "ef493dfc801fb7a82cc12ae97f478224b8cdee518680a89d1809b037557014aa",
        "51c82b00d1b7c09fb02665f3e4d95af76601048d11b4c99aabd18c1c472cd3a5",
        "3f2ff530e029b508e46914b4fdc3b8f8179f67653409560ff1a4a7c88c6fe885",
    )
]


def load(path: Path):
    return json.loads(path.read_text())


def raw_txid(raw: str) -> str:
    tx = tx_from_hex(raw)
    return hashlib.sha256(hashlib.sha256(tx.serialize_without_witness()).digest()).digest().hex()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixtures", nargs="?", type=Path, default=Path("fixtures/v1"))
    args = parser.parse_args()
    root = args.fixtures.resolve()
    scenario = load(root / "scenario.json")
    deployment = load(root / "deployment.json")
    expected_key = deployment["program_key_be"]
    expected_vk = deployment["groth16_vk_sha256"]
    verifier = None

    for name in ACTIONS:
        bundle = load(root / name / "input.json")
        verified = load(root / name / "verified.json")
        script = load(root / name / "script.json")
        assert bundle["request"] == scenario["requests"][name]
        statement = bytes(bundle["transition"]["statement"])
        assert bytes.fromhex(verified["public_values"]) == statement
        assert bytes.fromhex(script["public_values"]) == statement
        assert verified["program_key_be"] == expected_key
        assert verified["groth16_vk_sha256"] == expected_vk
        candidate = bytes.fromhex(script["script"])
        verifier = candidate if verifier is None else verifier
        assert candidate == verifier

    sponsor = bytes(script_to_p2wsh_script(CScript([OP_1])))
    genesis_root = account_root(ACCOUNT_KEYS)
    collection = build_collection_program(verifier, sponsor, ACCOUNT_KEYS, genesis_root)
    settlement = build_settlement_program(verifier, sponsor, genesis_root)
    bridge = bridge_taproot(collection, settlement)
    assert genesis_root.hex() == scenario["genesis_root"]
    assert bytes(bridge.scriptPubKey).hex() == scenario["bridge_script_pubkey"]
    assert len(collection) == scenario["collection_script_bytes"]
    assert len(settlement) == scenario["settlement_script_bytes"]

    transactions = scenario["transactions"]
    assert raw_txid(transactions["genesis"]) == scenario["bridge_id"]
    assert raw_txid(transactions["genesis"]) == scenario["requests"]["collection-1"][
        "bridge_prevout"
    ]["txid"]
    assert raw_txid(transactions["collection-1"]) == scenario["requests"]["settlement"][
        "bridge_prevout"
    ]["txid"]
    assert raw_txid(transactions["settlement"]) == scenario["requests"]["collection-2"][
        "bridge_prevout"
    ]["txid"]

    for line in (root / "SHA256SUMS").read_text().splitlines():
        expected, relative = line.split(maxsplit=1)
        relative = relative.lstrip("*")
        assert hashlib.sha256((root / relative).read_bytes()).hexdigest() == expected
    print("deployment, statements, scripts, transaction lineage, and fixture hashes match")


if __name__ == "__main__":
    main()
