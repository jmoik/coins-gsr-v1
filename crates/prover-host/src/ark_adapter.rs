//! Independent Arkworks verification and constant folding for Script export.

use ark_bn254::{Bn254, Fr, G1Affine, G2Affine};
use ark_ec::AffineRepr;
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::{Groth16, prepare_verifying_key};
use serde_json::{Value, json};
use sp1_verifier::{load_ark_groth16_verifying_key_from_bytes, load_ark_proof_from_bytes};

fn field<F: PrimeField>(value: F) -> String {
    let mut bytes = value.into_bigint().to_bytes_le();
    while bytes.last() == Some(&0) {
        bytes.pop();
    }
    hex::encode(bytes)
}

fn g1(point: G1Affine) -> [String; 2] {
    [field(point.x), field(point.y)]
}

fn g2(point: G2Affine) -> [String; 4] {
    [
        field(point.x.c0),
        field(point.x.c1),
        field(point.y.c0),
        field(point.y.c1),
    ]
}

/// Derive the constants that may be fixed before accepting any proof artifact.
pub fn deployment_key(program: &[u8; 32]) -> Result<Value, String> {
    let vk = load_ark_groth16_verifying_key_from_bytes(&sp1_verifier::GROTH16_VK_BYTES)
        .map_err(|error| error.to_string())?;
    if vk.gamma_abc_g1.len() != 6 {
        return Err("wrong public-input count".into());
    }
    let scalar = Fr::from_be_bytes_mod_order(program);
    if scalar.into_bigint().to_bytes_be().as_slice() != program {
        return Err("noncanonical program-key scalar".into());
    }
    let root = Fr::from_be_bytes_mod_order(&*sp1_verifier::VK_ROOT_BYTES);
    let inputs = &vk.gamma_abc_g1;
    let fixed: G1Affine = (inputs[0] + inputs[1] * scalar + inputs[4] * root).into();
    if fixed.is_zero() {
        return Err("infinite folded key".into());
    }
    Ok(json!({
        "ic0": g1(fixed), "ic1": g1(inputs[2]), "ic2": g1(inputs[5]),
        "alpha": g1(vk.alpha_g1), "beta": g2(vk.beta_g2),
        "gamma": g2(vk.gamma_g2), "delta": g2(vk.delta_g2),
    }))
}

pub fn export(proof: &[u8], values: &[u8], program: &[u8; 32]) -> Result<Value, String> {
    let wrapper = crate::wrapper::decode(proof, values, program)?;
    let vk = load_ark_groth16_verifying_key_from_bytes(&sp1_verifier::GROTH16_VK_BYTES)
        .map_err(|error| error.to_string())?;
    let proof = load_ark_proof_from_bytes(wrapper.raw_proof).map_err(|error| error.to_string())?;
    if vk.gamma_abc_g1.len() != 6
        || vk
            .gamma_abc_g1
            .iter()
            .chain([&vk.alpha_g1, &proof.a, &proof.c])
            .any(|point| {
                point.is_zero()
                    || !point.is_on_curve()
                    || !point.is_in_correct_subgroup_assuming_on_curve()
            })
        || [&vk.beta_g2, &vk.gamma_g2, &vk.delta_g2, &proof.b]
            .into_iter()
            .any(|point| {
                point.is_zero()
                    || !point.is_on_curve()
                    || !point.is_in_correct_subgroup_assuming_on_curve()
            })
    {
        return Err("invalid verification-key or proof point".into());
    }

    let scalars = wrapper
        .inputs_be
        .map(|value| Fr::from_be_bytes_mod_order(&value));
    if !Groth16::<Bn254>::verify_proof(&prepare_verifying_key(&vk), &proof, &scalars)
        .map_err(|error| error.to_string())?
    {
        return Err("independent Arkworks verification failed".into());
    }

    let inputs = &vk.gamma_abc_g1;
    let mut reduced = vk.clone();
    reduced.gamma_abc_g1 = vec![
        (inputs[0] + inputs[1] * scalars[0] + inputs[4] * scalars[3]).into(),
        inputs[2],
        inputs[5],
    ];
    if reduced.gamma_abc_g1[0].is_zero()
        || !Groth16::<Bn254>::verify_proof(
            &prepare_verifying_key(&reduced),
            &proof,
            &[scalars[1], scalars[4]],
        )
        .map_err(|error| error.to_string())?
    {
        return Err("folded verification failed".into());
    }

    Ok(json!({
        "encoding": "canonical-unsigned-little-endian-hex",
        "input0": field(scalars[1]), "input1": field(scalars[4]),
        "ic0": g1(reduced.gamma_abc_g1[0]), "ic1": g1(reduced.gamma_abc_g1[1]),
        "ic2": g1(reduced.gamma_abc_g1[2]), "alpha": g1(reduced.alpha_g1),
        "beta": g2(reduced.beta_g2), "gamma": g2(reduced.gamma_g2),
        "delta": g2(reduced.delta_g2), "proof_a": g1(proof.a),
        "proof_b": g2(proof.b), "proof_c": g1(proof.c),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deployment_key_is_canonical_and_has_five_inputs() {
        assert!(deployment_key(&[0xff; 32]).is_err());
        assert!(deployment_key(&[1; 32]).is_ok());
        let vk =
            load_ark_groth16_verifying_key_from_bytes(&sp1_verifier::GROTH16_VK_BYTES).unwrap();
        assert_eq!(vk.gamma_abc_g1.len(), 6);
    }
}
