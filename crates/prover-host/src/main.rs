mod ark_adapter;
mod wrapper;

use coins_crypto::sign;
use coins_gsr_protocol::{
    Account, AccountState, Collection, Deposit, OutPoint, ProofInput, Settlement, Transition,
    apply_collection, apply_settlement, fixtures, scoped_transfer_message, validate_proof_input,
    withdrawal_message,
};
use coins_types::{NATIVE_TOKEN_ID, Transaction};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use sp1_sdk::{
    Elf, HashableKey, ProvingKey, SP1Stdin,
    blocking::{ProveRequest, Prover, ProverClient},
};

#[derive(Deserialize)]
struct ScenarioOutPoint {
    txid: String,
    vout: u32,
}

#[derive(Deserialize)]
struct ScenarioDeposit {
    outpoint: ScenarioOutPoint,
    value: u64,
    recipient_id: u32,
}

#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
enum Scenario {
    Collect {
        bridge_id: String,
        bridge_prevout: ScenarioOutPoint,
        old_balances: [u64; 3],
        old_nonces: [u32; 3],
        deposits: [ScenarioDeposit; 2],
    },
    TransferWithdraw {
        bridge_id: String,
        bridge_prevout: ScenarioOutPoint,
        old_balances: [u64; 3],
        old_nonces: [u32; 3],
        transfer_amount: u32,
        transfer_fee: u8,
        withdrawal_nonce: u32,
        withdrawal_amount: u64,
        withdrawal_destination: String,
    },
}

#[derive(serde::Serialize, serde::Deserialize)]
struct ScenarioBundle {
    request: serde_json::Value,
    proof_input: ProofInput,
    transition: ScenarioTransition,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct ScenarioTransition {
    new_state: AccountState,
    old_root: [u8; 32],
    new_root: [u8; 32],
    new_backing: u64,
    statement: Vec<u8>,
}

impl From<Transition> for ScenarioTransition {
    fn from(value: Transition) -> Self {
        Self {
            new_state: value.new_state,
            old_root: value.old_root,
            new_root: value.new_root,
            new_backing: value.new_backing,
            statement: value.statement,
        }
    }
}

fn bytes32(value: &str, name: &str) -> Result<[u8; 32], String> {
    hex::decode(value)
        .map_err(|_| format!("invalid {name} hex"))?
        .try_into()
        .map_err(|_| format!("{name} must be 32 bytes"))
}

fn outpoint(value: ScenarioOutPoint) -> Result<OutPoint, String> {
    Ok(OutPoint {
        txid: bytes32(&value.txid, "outpoint txid")?,
        vout: value.vout,
    })
}

fn fixture_state(balances: [u64; 3], nonces: [u32; 3]) -> AccountState {
    let (_, keys) = fixtures::keys();
    AccountState {
        accounts: std::array::from_fn(|index| Account {
            key: keys[index],
            balance: balances[index],
            nonce: nonces[index],
        }),
    }
}

struct SettlementTerms {
    transfer_amount: u32,
    transfer_fee: u8,
    withdrawal_nonce: u32,
    withdrawal_amount: u64,
    withdrawal_destination: Vec<u8>,
}

fn signed_settlement(
    bridge_id: [u8; 32],
    bridge_prevout: OutPoint,
    old_state: AccountState,
    terms: SettlementTerms,
) -> Settlement {
    let (secrets, public) = fixtures::keys();
    let transfer = Transaction {
        sender_id: 0,
        recipient_pk: public[1],
        token_id: NATIVE_TOKEN_ID,
        amount: terms.transfer_amount,
        fee: terms.transfer_fee,
    };
    let native_message = transfer.message_to_sign(old_state.accounts[0].nonce);
    let withdrawal = withdrawal_message(
        &bridge_id,
        terms.withdrawal_nonce,
        terms.withdrawal_amount,
        &terms.withdrawal_destination,
    )
    .expect("valid bounded withdrawal");
    Settlement {
        bridge_id,
        bridge_prevout,
        old_backing: old_state.backing().expect("bounded fixture backing"),
        old_state,
        transfer,
        transfer_signature: sign(&secrets[0], &native_message),
        scoped_transfer_signature: sign(
            &secrets[0],
            &scoped_transfer_message(&bridge_id, &native_message),
        ),
        withdrawal_nonce: terms.withdrawal_nonce,
        withdrawal_amount: terms.withdrawal_amount,
        withdrawal_destination: terms.withdrawal_destination,
        withdrawal_signature: sign(&secrets[1], &withdrawal),
    }
}

fn scenario(value: Scenario) -> Result<ScenarioBundle, String> {
    let (proof_input, transition) = match value {
        Scenario::Collect {
            bridge_id,
            bridge_prevout,
            old_balances,
            old_nonces,
            deposits,
        } => {
            let old_state = fixture_state(old_balances, old_nonces);
            let [deposit_a, deposit_b] = deposits;
            let deposit = |deposit: ScenarioDeposit| {
                Ok::<_, String>(Deposit {
                    outpoint: outpoint(deposit.outpoint)?,
                    value: deposit.value,
                    recipient_id: deposit.recipient_id,
                })
            };
            let collection = Collection {
                bridge_id: bytes32(&bridge_id, "bridge id")?,
                bridge_prevout: outpoint(bridge_prevout)?,
                old_backing: old_state.backing().map_err(|error| format!("{error:?}"))?,
                old_state,
                deposits: [deposit(deposit_a)?, deposit(deposit_b)?],
            };
            let transition = apply_collection(&collection).map_err(|error| format!("{error:?}"))?;
            (ProofInput::Collect(collection), transition)
        }
        Scenario::TransferWithdraw {
            bridge_id,
            bridge_prevout,
            old_balances,
            old_nonces,
            transfer_amount,
            transfer_fee,
            withdrawal_nonce,
            withdrawal_amount,
            withdrawal_destination,
        } => {
            let settlement = signed_settlement(
                bytes32(&bridge_id, "bridge id")?,
                outpoint(bridge_prevout)?,
                fixture_state(old_balances, old_nonces),
                SettlementTerms {
                    transfer_amount,
                    transfer_fee,
                    withdrawal_nonce,
                    withdrawal_amount,
                    withdrawal_destination: hex::decode(withdrawal_destination)
                        .map_err(|_| "invalid withdrawal destination hex")?,
                },
            );
            let transition = apply_settlement(&settlement).map_err(|error| format!("{error:?}"))?;
            (ProofInput::TransferWithdraw(settlement), transition)
        }
    };
    Ok(ScenarioBundle {
        request: serde_json::Value::Null,
        proof_input,
        transition: transition.into(),
    })
}

fn load_input(path: &str) -> Result<ProofInput, Box<dyn std::error::Error>> {
    let bytes = std::fs::read(path)?;
    if let Ok(bundle) = serde_json::from_slice::<ScenarioBundle>(&bytes) {
        return Ok(bundle.proof_input);
    }
    Ok(serde_json::from_slice(&bytes)?)
}

fn action(input: &ProofInput) -> &'static str {
    match input {
        ProofInput::Collect(_) => "collect",
        ProofInput::TransferWithdraw(_) => "settle",
    }
}

fn check_release_artifacts() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("SP1_CIRCUIT_MODE").is_ok_and(|mode| mode != "release") {
        return Err("proof generation requires pinned release circuits".into());
    }
    let directory = sp1_prover::build::groth16_circuit_artifacts_dir()?;
    for name in ["groth16_circuit.bin", "groth16_pk.bin", "groth16_vk.bin"] {
        if std::fs::metadata(directory.join(name)).map_or(true, |file| !file.is_file()) {
            return Err(format!(
                "missing Groth16 artifact: {}",
                directory.join(name).display()
            )
            .into());
        }
    }
    if std::fs::read(directory.join("groth16_vk.bin"))? != *sp1_verifier::GROTH16_VK_BYTES {
        return Err("installed Groth16 verification key differs from SP1 6.0.1".into());
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    sp1_sdk::utils::setup_logger();
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().is_some_and(|command| command == "derive") {
        if args.len() != 3 {
            return Err("usage: coins-gsr-prover-host derive REQUEST_JSON NEW_BUNDLE_JSON".into());
        }
        let output = std::path::Path::new(&args[2]);
        if output.exists() {
            return Err("scenario bundle already exists".into());
        }
        let request: serde_json::Value = serde_json::from_slice(&std::fs::read(&args[1])?)?;
        let mut bundle = scenario(serde_json::from_value(request.clone())?)?;
        bundle.request = request;
        std::fs::write(output, serde_json::to_vec_pretty(&bundle)?)?;
        return Ok(());
    }
    if args.first().is_some_and(|command| command == "prepare") {
        if args.len() != 3 {
            return Err("usage: coins-gsr-prover-host prepare PROGRAM_ELF NEW_ARTIFACT_DIR".into());
        }
        let elf_bytes = std::fs::read(&args[1])?;
        let elf_hash = hex::encode(Sha256::digest(&elf_bytes));
        let client = ProverClient::builder().cpu().build();
        let artifact_dir = std::path::Path::new(&args[2]);
        if artifact_dir.exists() {
            return Err("artifact directory already exists".into());
        }
        let proving_key = client.setup(Elf::from(elf_bytes))?;
        let encoded = proving_key.verifying_key().bytes32();
        let key: [u8; 32] = hex::decode(encoded.strip_prefix("0x").ok_or("program key prefix")?)?
            .try_into()
            .map_err(|_| "program key width")?;
        std::fs::create_dir(artifact_dir)?;
        std::fs::write(
            artifact_dir.join("deployment.json"),
            serde_json::to_vec_pretty(&serde_json::json!({
                "status": "bounded-regtest-deployment",
                "sp1_version": "6.0.1",
                "elf_sha256": elf_hash,
                "program_key_be": hex::encode(key),
                "groth16_vk_sha256": hex::encode(Sha256::digest(*sp1_verifier::GROTH16_VK_BYTES)),
                "folded_key": ark_adapter::deployment_key(&key)?,
            }))?,
        )?;
        return Ok(());
    }
    if args.len() != 4 || !["execute", "prove", "verify"].contains(&args[0].as_str()) {
        return Err(
            "usage: coins-gsr-prover-host execute|prove|verify INPUT_JSON PROGRAM_ELF ARTIFACT_DIR"
                .into(),
        );
    }
    let command = &args[0];
    if command == "prove" {
        check_release_artifacts()?;
    }
    let input = load_input(&args[1])?;
    let expected = validate_proof_input(&input).map_err(|error| format!("{error:?}"))?;
    let elf_bytes = std::fs::read(&args[2])?;
    let elf_hash = hex::encode(Sha256::digest(&elf_bytes));
    let elf = Elf::from(elf_bytes);
    let artifact_dir = std::path::Path::new(&args[3]);
    let client = ProverClient::builder().cpu().build();

    let mut stdin = SP1Stdin::new();
    stdin.write(&input);
    let (public_values, report) = client.execute(elf.clone(), stdin.clone()).run()?;
    if report.exit_code != 0 || public_values.as_slice() != expected {
        return Err("guest execution did not produce the canonical statement".into());
    }
    println!("guest instructions: {}", report.total_instruction_count());
    if command == "execute" {
        return Ok(());
    }

    let proving_key = client.setup(elf)?;
    let key_string = proving_key.verifying_key().bytes32();
    let key: [u8; 32] = hex::decode(key_string.strip_prefix("0x").ok_or("program key prefix")?)?
        .try_into()
        .map_err(|_| "program key width")?;
    let proof_path = artifact_dir.join("proof.bin");
    let (proof, proving_seconds) = if command == "verify" {
        (sp1_sdk::SP1ProofWithPublicValues::load(&proof_path)?, None)
    } else {
        if artifact_dir.exists() {
            return Err("artifact directory already exists".into());
        }
        let started = std::time::Instant::now();
        let proof = client.prove(&proving_key, stdin).groth16().run()?;
        let elapsed = started.elapsed().as_secs_f64();
        std::fs::create_dir(artifact_dir)?;
        proof.save(&proof_path)?;
        (proof, Some(elapsed))
    };
    if !matches!(&proof.proof, sp1_sdk::SP1Proof::Groth16(_)) {
        return Err("expected a Groth16 proof".into());
    }
    client.verify(&proof, proving_key.verifying_key(), None)?;
    if proof.public_values.as_slice() != expected {
        return Err("proof public values differ from canonical statement".into());
    }
    let encoded = proof.bytes();
    wrapper::verify(&encoded, &expected, &key)?;
    let mut wrong_values = expected.clone();
    wrong_values[0] ^= 1;
    let mut altered = proof.clone();
    altered.public_values = sp1_sdk::SP1PublicValues::from(&wrong_values);
    if client
        .verify(&altered, proving_key.verifying_key(), None)
        .is_ok()
        || wrapper::verify(&encoded, &wrong_values, &key).is_ok()
    {
        return Err("changed public values accepted".into());
    }
    let mut corrupted = encoded.clone();
    *corrupted.last_mut().ok_or("empty proof")? ^= 1;
    if wrapper::verify(&corrupted, &expected, &key).is_ok() {
        return Err("corrupted proof accepted".into());
    }
    let mut wrong_key = key;
    wrong_key[31] ^= 1;
    if wrapper::verify(&encoded, &expected, &wrong_key).is_ok() {
        return Err("wrong program key accepted".into());
    }
    let recorded_seconds = proving_seconds.or_else(|| {
        std::fs::read(artifact_dir.join("verified.json"))
            .ok()
            .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
            .and_then(|value| value["proving_seconds"].as_f64())
    });
    std::fs::write(
        artifact_dir.join("verified.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "action": action(&input),
            "elf_sha256": elf_hash,
            "program_key_be": hex::encode(key),
            "groth16_vk_sha256": hex::encode(Sha256::digest(*sp1_verifier::GROTH16_VK_BYTES)),
            "public_values": hex::encode(&expected),
            "proof_bytes": proof.bytes().len(),
            "execution_instructions": report.total_instruction_count(),
            "proving_seconds": recorded_seconds,
            "public_values_hash_mode": "sha256-top-three-bits-cleared",
            "folded_arkworks": ark_adapter::export(&encoded, &expected, &key)?,
        }))?,
    )?;
    println!("real Groth16 proof verified");
    Ok(())
}
