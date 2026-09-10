//! SP1-only BN254 pairing adapter for the pinned Coins BLS relation.

use ark_ff::{BigInteger, PrimeField};
use coins_crypto::G1;
use substrate_bn::{AffineG1, AffineG2, Fq, Fq2, Group, Gt};

pub fn verify_decoded_signature(pk: &G1, message: &[u8], signature: ark_bn254::G2Affine) -> bool {
    let Some(pk) = pk.to_affine() else {
        return false;
    };
    let message_point = bn254_hash2curve::hash2g2::HashToG2(
        message,
        b"QUUX-V01-CS02-with-BN254G2_XMD:SHA-256_SVDW_RO_",
    );
    substrate_bn::pairing_batch(&[
        (substrate_bn::G1::one(), g2(signature)),
        (-g1(pk), g2(message_point)),
    ]) == Gt::one()
}

fn fq(value: ark_bn254::Fq) -> Fq {
    Fq::from_slice(&value.into_bigint().to_bytes_be()).expect("canonical BN254 coordinate")
}

fn g1(point: ark_bn254::G1Affine) -> substrate_bn::G1 {
    if point.infinity {
        return substrate_bn::G1::zero();
    }
    AffineG1::new(fq(point.x), fq(point.y))
        .expect("Coins-validated G1")
        .into()
}

fn g2(point: ark_bn254::G2Affine) -> substrate_bn::G2 {
    if point.infinity {
        return substrate_bn::G2::zero();
    }
    AffineG2::new(
        Fq2::new(fq(point.x.c0), fq(point.x.c1)),
        Fq2::new(fq(point.y.c0), fq(point.y.c1)),
    )
    .expect("Coins-validated G2")
    .into()
}
