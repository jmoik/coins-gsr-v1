#!/usr/bin/env python3
import hashlib
import json
import pathlib
import struct


ROOT_DOMAIN = b"coins-gsr-v1/accounts\0"
STATE_PREFIX = b"UTXOLIN\x01"
STATEMENT_DOMAIN = b"coins-gsr-v1/statement/regtest\0"


def sha256(value: bytes) -> bytes:
    return hashlib.sha256(value).digest()


def caboose(state: bytes) -> bytes:
    witness_script = b"\x6a\x24" + sha256(state) + b"\x00" * 4
    return b"\x00\x20" + sha256(witness_script)


def check(case: dict) -> None:
    keys = [bytes.fromhex(value) for value in case["keys"]]
    bridge_id = bytes.fromhex(case["bridge_id"])
    assert len(keys) == 3 and all(len(key) == 32 for key in keys)
    assert len(bridge_id) == 32

    preimage = bytearray(ROOT_DOMAIN)
    for account_id, (key, balance, nonce) in enumerate(
        zip(keys, case["balances"], case["nonces"], strict=True)
    ):
        preimage += struct.pack("<I", account_id)
        preimage += key
        preimage += struct.pack("<Q", balance)
        preimage += struct.pack("<I", nonce)
    root = sha256(preimage)
    genesis = STATE_PREFIX + b"\x00" + root
    active = STATE_PREFIX + b"\x01" + bridge_id + root

    assert root.hex() == case["account_root"]
    assert genesis.hex() == case["genesis_state"]
    assert active.hex() == case["active_state"]
    assert caboose(genesis).hex() == case["genesis_caboose_spk"]
    assert caboose(active).hex() == case["active_caboose_spk"]

    new_balances = [case["balances"][0] + 5000, case["balances"][1] + 6000, 7]
    new_preimage = bytearray(ROOT_DOMAIN)
    for account_id, (key, balance, nonce) in enumerate(
        zip(keys, new_balances, case["nonces"], strict=True)
    ):
        new_preimage += struct.pack("<I", account_id)
        new_preimage += key
        new_preimage += struct.pack("<Q", balance)
        new_preimage += struct.pack("<I", nonce)
    new_root = sha256(new_preimage)
    statement = bytearray(STATEMENT_DOMAIN + b"\x01\x01")
    statement += bridge_id
    statement += b"\x31" * 32 + struct.pack("<I", 0)
    statement += root + new_root
    statement += struct.pack("<Q", 201007) + struct.pack("<Q", 212007)
    statement += b"\x41" * 32 + struct.pack("<I", 1)
    statement += struct.pack("<Q", 5000) + struct.pack("<I", 0) + keys[0]
    statement += b"\x52" * 32 + struct.pack("<I", 2)
    statement += struct.pack("<Q", 6000) + struct.pack("<I", 1) + keys[1]
    assert statement.hex() == case["collection_statement"]


def main() -> None:
    path = pathlib.Path(__file__).with_name("protocol_vectors.json")
    cases = json.loads(path.read_text())
    for case in cases:
        check(case)
    print(f"checked {len(cases)} protocol vector(s)")


if __name__ == "__main__":
    main()
