use sha2::{Digest, Sha256};

pub const ENCODED_PROOF_LEN: usize = 4 + 96 + 256;
const FR_MODULUS_BE: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x01,
];

pub struct Wrapper<'a> {
    pub inputs_be: [[u8; 32]; 5],
    pub raw_proof: &'a [u8],
}

pub fn decode<'a>(
    proof: &'a [u8],
    values: &[u8],
    program_key: &[u8; 32],
) -> Result<Wrapper<'a>, &'static str> {
    if proof.len() != ENCODED_PROOF_LEN {
        return Err("expected exactly 356 proof bytes");
    }
    let vk_hash = Sha256::digest(*sp1_verifier::GROTH16_VK_BYTES);
    if proof[..4] != vk_hash[..4] {
        return Err("wrong wrapper key prefix");
    }
    if proof[4..36] != [0_u8; 32] {
        return Err("guest did not succeed");
    }
    if proof[36..68] != *sp1_verifier::VK_ROOT_BYTES {
        return Err("wrong recursion key root");
    }
    let inputs_be = [
        *program_key,
        sp1_verifier::hash_public_inputs(values),
        [0; 32],
        *sp1_verifier::VK_ROOT_BYTES,
        proof[68..100].try_into().unwrap(),
    ];
    if inputs_be.iter().any(|scalar| *scalar >= FR_MODULUS_BE) {
        return Err("noncanonical scalar");
    }
    Ok(Wrapper {
        inputs_be,
        raw_proof: &proof[100..],
    })
}

pub fn verify(proof: &[u8], values: &[u8], program_key: &[u8; 32]) -> Result<(), String> {
    let wrapper = decode(proof, values, program_key)?;
    sp1_verifier::Groth16Verifier::verify_gnark_proof(
        wrapper.raw_proof,
        &wrapper.inputs_be,
        &sp1_verifier::GROTH16_VK_BYTES,
    )
    .map_err(|error| format!("{error:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn envelope() -> Vec<u8> {
        let mut proof = vec![0; ENCODED_PROOF_LEN];
        proof[..4].copy_from_slice(&Sha256::digest(*sp1_verifier::GROTH16_VK_BYTES)[..4]);
        proof[36..68].copy_from_slice(&*sp1_verifier::VK_ROOT_BYTES);
        proof
    }

    #[test]
    fn strict_envelope_is_not_itself_a_proof() {
        let proof = envelope();
        let key = [1; 32];
        let wrapper = decode(&proof, b"statement", &key).unwrap();
        assert_eq!(wrapper.inputs_be[0], key);
        assert_eq!(
            wrapper.inputs_be[1],
            sp1_verifier::hash_public_inputs(b"statement")
        );
        assert!(verify(&proof, b"statement", &key).is_err());
    }

    #[test]
    fn malformed_envelopes_fail() {
        let proof = envelope();
        for length in 0..proof.len() {
            assert!(decode(&proof[..length], b"", &[1; 32]).is_err());
        }
        for index in [0, 4, 36] {
            let mut bad = proof.clone();
            bad[index] ^= 1;
            assert!(decode(&bad, b"", &[1; 32]).is_err());
        }
        let mut extra = proof.clone();
        extra.push(0);
        assert!(decode(&extra, b"", &[1; 32]).is_err());
        let mut noncanonical = proof;
        noncanonical[68..100].copy_from_slice(&FR_MODULUS_BE);
        assert!(decode(&noncanonical, b"", &[1; 32]).is_err());
        assert!(decode(&envelope(), b"", &FR_MODULUS_BE).is_err());
    }
}
