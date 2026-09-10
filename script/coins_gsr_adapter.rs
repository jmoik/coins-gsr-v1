//! Generate and replay a GSR verifier from an independently checked SP1 proof.

use super::{
    fixtures::DeterministicGroth16Fixture,
    host::{G1Affine, G2Affine},
    verifier::Groth16Replay,
};
use crate::test_util::{bytes_hex, eval_gsr_with_cpp_raw, hex_bytes};
use bitcoin::hashes::{Hash, sha256};
use num_bigint::BigUint;
use serde_json::{Value, json};

const MAX_TRANSACTION_VAROPS_BUDGET: u64 = 4_000_000 * 10_000;

fn bytes(value: &Value) -> Vec<u8> {
    hex_bytes(value.as_str().expect("hex field"))
}

fn point(value: &Value) -> Vec<Vec<u8>> {
    value
        .as_array()
        .expect("point array")
        .iter()
        .map(bytes)
        .collect()
}

#[test]
#[ignore = "requires an independently verified Coins/SP1 proof"]
fn coins_gsr_proof_accepts_gsr_script() {
    let proof_path = std::env::var("COINS_GSR_PROOF").expect("set COINS_GSR_PROOF");
    let manifest_path =
        std::env::var("COINS_GSR_DEPLOYMENT").expect("set COINS_GSR_DEPLOYMENT");
    let output = std::env::var("COINS_GSR_SCRIPT_OUTPUT").expect("set output path");
    assert!(!std::path::Path::new(&output).exists(), "refuse to overwrite");
    let data: Value = serde_json::from_slice(&std::fs::read(&proof_path).unwrap()).unwrap();
    let manifest: Value =
        serde_json::from_slice(&std::fs::read(&manifest_path).unwrap()).unwrap();
    assert_eq!(manifest["status"], "bounded-regtest-deployment");
    assert_eq!(manifest["sp1_version"], "6.0.1");
    assert_eq!(manifest["program_key_be"], data["program_key_be"]);
    assert_eq!(manifest["groth16_vk_sha256"], data["groth16_vk_sha256"]);
    assert_eq!(data["public_values_hash_mode"], "sha256-top-three-bits-cleared");

    let folded = &data["folded_arkworks"];
    let key = &manifest["folded_key"];
    assert_eq!(folded["encoding"], "canonical-unsigned-little-endian-hex");
    for name in ["ic0", "ic1", "ic2", "alpha", "beta", "gamma", "delta"] {
        assert_eq!(folded[name], key[name]);
    }
    let fixture = DeterministicGroth16Fixture {
        input0: 0,
        input1: 0,
        invalid_input1: 1,
        ic0: G1Affine::from_stack(&point(&key["ic0"])),
        ic1: G1Affine::from_stack(&point(&key["ic1"])),
        ic2: G1Affine::from_stack(&point(&key["ic2"])),
        alpha: G1Affine::from_stack(&point(&key["alpha"])),
        beta: G2Affine::from_stack(&point(&key["beta"])),
        gamma: G2Affine::from_stack(&point(&key["gamma"])),
        delta: G2Affine::from_stack(&point(&key["delta"])),
        proof_a: G1Affine::from_stack(&point(&folded["proof_a"])),
        proof_b: G2Affine::from_stack(&point(&folded["proof_b"])),
        proof_c: G1Affine::from_stack(&point(&folded["proof_c"])),
    };
    let input0 = BigUint::from_bytes_le(&bytes(&folded["input0"]));
    let input1 = BigUint::from_bytes_le(&bytes(&folded["input1"]));
    let values = bytes(&data["public_values"]);
    let mut digest = sha256::Hash::hash(&values).to_byte_array();
    digest[0] &= 0x1f;
    assert_eq!(input0, BigUint::from_bytes_be(&digest));

    let report = Groth16Replay::default().verify_fixture_inputs_with_fused_residue_report(
        &fixture,
        input0.clone(),
        input1.clone(),
    );
    assert!(report.accepted);
    let artifact = report.monolithic_artifact(&fixture, input0, input1);
    let macros = super::stats::compile_monolithic_flat_macros(artifact.script.as_bytes());
    let estimated_weight = artifact.estimated_tx_weight - artifact.script_bytes + macros.script.len();
    assert!(estimated_weight <= 4_000_000, "verifier alone exceeds block weight");
    // This fragment is not a standalone transaction, so its estimated weight is
    // not its consensus budget. Measure under the protocol maximum here; the
    // composed bridge test supplies the exact transaction-weight-derived budget.
    let result = eval_gsr_with_cpp_raw(
        macros.script.clone(),
        artifact.witness_stack.clone(),
        MAX_TRANSACTION_VAROPS_BUDGET,
    );
    assert!(result.success, "{result:?}");
    assert!(result.stack_after.is_empty());

    let output_value = json!({
        "status": "arithmetic-only-not-a-bridge-lock",
        "script": bytes_hex(macros.script.as_bytes()),
        "script_sha256": bytes_hex(&sha256::Hash::hash(macros.script.as_bytes()).to_byte_array()),
        "stack": artifact.witness_stack.iter().map(|item| bytes_hex(item)).collect::<Vec<_>>(),
        "estimated_weight": estimated_weight,
        "measured_varops": MAX_TRANSACTION_VAROPS_BUDGET - result.varops_budget_remaining.unwrap(),
        "statement_digest_stack_index": 1,
        "proof_nonce_stack_index": 2,
        "public_values": data["public_values"],
    });
    std::fs::write(output, serde_json::to_vec_pretty(&output_value).unwrap()).unwrap();
}
