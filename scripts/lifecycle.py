#!/usr/bin/env python3
"""Reproducible command-line workflow for the bounded regtest lifecycle."""

import argparse
import hashlib
import json
import os
import subprocess
import sys
import uuid
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ACTIONS = ("collection-1", "settlement", "collection-2")
DEFAULT_CORE = Path("/Users/julian/Code/bitcoin/core/gsr/gsr-full")
ELF = ROOT / "guest/target/elf-compilation/riscv64im-succinct-zkvm-elf/release/coins-gsr-guest"
HOST = ROOT / "crates/prover-host/target/release/coins-gsr-prover-host"


def run(command, *, env=None):
    subprocess.run([str(value) for value in command], cwd=ROOT, env=env, check=True)


def load(path: Path):
    try:
        return json.loads(path.read_text())
    except FileNotFoundError as error:
        raise SystemExit(f"missing lifecycle artifact: {path}") from error


def write(path: Path, value):
    temporary = path.with_suffix(path.suffix + ".new")
    temporary.write_text(json.dumps(value, indent=2) + "\n")
    temporary.replace(path)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_command(core: Path, tmpdir: Path):
    return [
        sys.executable,
        ROOT / "tests/feature_bridge.py",
        f"--configfile={core / 'build/test/config.ini'}",
        f"--tmpdir={tmpdir}",
    ]


def genesis(args):
    work = args.work.resolve()
    if work.exists():
        raise SystemExit(f"refusing to overwrite {work}")
    work.mkdir(parents=True)
    (work / "inputs").mkdir()
    run([HOST, "prepare", ELF, work / "deployment"])
    scenario = work / "scenario.json"
    env = os.environ.copy()
    env["COINS_GSR_VERIFIER"] = str(args.verifier.resolve())
    env["COINS_GSR_SCENARIO_OUTPUT"] = str(scenario)
    tmpdir = Path("/private/tmp") / f"coins-gsr-prepare-{uuid.uuid4().hex}"
    run(test_command(args.core, tmpdir), env=env)
    value = load(scenario)
    for name in ACTIONS:
        directory = work / "inputs" / name
        directory.mkdir()
        request = directory / "request.json"
        write(request, value["requests"][name])
        run([HOST, "derive", request, directory / "input.json"])
    write(
        work / "state.json",
        {
            "status": "prepared-not-confirmed",
            "bridge_id": value["bridge_id"],
            "bridge_script_pubkey": value["bridge_script_pubkey"],
            "scenario_sha256": digest(scenario),
            "proofs": {name: "missing" for name in ACTIONS},
        },
    )
    print(f"prepared deterministic genesis and proof inputs in {work}")


def deposit(args):
    scenario = load(args.work / "scenario.json")
    for batch in ("collection-1", "collection-2"):
        for item in scenario["requests"][batch]["deposits"]:
            point = item["outpoint"]
            print(
                f"{batch}: {point['txid']}:{point['vout']} -> account "
                f"{item['recipient_id']}, {item['value']} sat"
            )


def refund(args):
    env = os.environ.copy()
    env["COINS_GSR_BINDING_ONLY"] = "1"
    tmpdir = Path("/private/tmp") / f"coins-gsr-refund-{uuid.uuid4().hex}"
    run(test_command(args.core, tmpdir), env=env)
    print("owner-signature refund and all binding-only transitions passed on fresh regtest")


def prove(args):
    work = args.work.resolve()
    proof_root = work / "proofs"
    script_root = work / "scripts"
    if proof_root.exists() or script_root.exists() or (work / "fixtures").exists():
        raise SystemExit("refusing to overwrite existing proof, script, or fixture artifacts")
    proof_root.mkdir()
    script_root.mkdir()
    deployment = work / "deployment/deployment.json"
    for name in ACTIONS:
        input_path = work / "inputs" / name / "input.json"
        proof_path = proof_root / name
        run([ROOT / "scripts/prove-input.sh", args.patched_host, input_path, proof_path])
        run([HOST, "verify", input_path, ELF, proof_path])
        run(
            [
                ROOT / "scripts/build-verifier-artifact.sh",
                proof_path / "verified.json",
                deployment,
                script_root / f"{name}.json",
            ]
        )
    fixtures = work / "fixtures"
    run(
        [
            ROOT / "scripts/package-fixtures.sh",
            work / "scenario.json",
            deployment,
            work / "inputs",
            proof_root,
            script_root,
            fixtures,
        ]
    )
    state = load(work / "state.json")
    state["status"] = "proved-not-submitted"
    state["proofs"] = {
        name: digest(fixtures / name / "proof.bin") for name in ACTIONS
    }
    write(work / "state.json", state)
    print(f"verified and packaged all three proofs in {fixtures}")


def submit(args):
    work = args.work.resolve()
    fixtures = work / "fixtures"
    result = work / "result.json"
    if result.exists():
        raise SystemExit("refusing to overwrite an existing lifecycle result")
    env = os.environ.copy()
    env["COINS_GSR_VERIFIER"] = str(fixtures / "collection-1/script.json")
    env["COINS_GSR_PROOF_FIXTURES"] = str(fixtures)
    env["COINS_GSR_RESULT_OUTPUT"] = str(result)
    tmpdir = Path("/private/tmp") / f"coins-gsr-submit-{uuid.uuid4().hex}"
    run(test_command(args.core, tmpdir), env=env)
    state = load(work / "state.json")
    evidence = load(result)
    state.update(
        status="proof-authorized-lifecycle-mined",
        final_outpoint=evidence["final_outpoint"],
        result_sha256=digest(result),
    )
    write(work / "state.json", state)
    print(f"mined proof-authorized lifecycle; final head {evidence['final_outpoint']}")


def inspect(args):
    state = load(args.work / "state.json")
    print(json.dumps(state, indent=2))
    if state["status"] == "proof-authorized-lifecycle-mined":
        result = load(args.work / "result.json")
        print(
            f"balances={result['balances']} nonces={result['nonces']} "
            f"backing={result['backing']} sat"
        )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--core", type=Path, default=DEFAULT_CORE)
    commands = parser.add_subparsers(dest="command", required=True)
    command = commands.add_parser("genesis", help="freeze deployment and deterministic chain inputs")
    command.add_argument("--verifier", type=Path, required=True)
    command.set_defaults(function=genesis)
    command = commands.add_parser("deposit", help="list the bound pending deposits")
    command.set_defaults(function=deposit)
    command = commands.add_parser("refund", help="replay owner refund and binding checks")
    command.set_defaults(function=refund)
    command = commands.add_parser("prove", help="generate, verify, and package all real proofs")
    command.add_argument("--patched-host", type=Path, required=True)
    command.set_defaults(function=prove)
    command = commands.add_parser("submit", help="recreate and mine the proof-authorized lifecycle")
    command.set_defaults(function=submit)
    command = commands.add_parser("inspect", help="show persisted lifecycle status")
    command.set_defaults(function=inspect)
    args = parser.parse_args()
    args.function(args)


if __name__ == "__main__":
    main()
