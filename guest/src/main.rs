#![no_main]
sp1_zkvm::entrypoint!(main);

pub fn main() {
    let input = sp1_zkvm::io::read::<coins_gsr_protocol::ProofInput>();
    let statement =
        coins_gsr_protocol::validate_proof_input(&input).expect("invalid bridge transition");
    sp1_zkvm::io::commit_slice(&statement);
}
