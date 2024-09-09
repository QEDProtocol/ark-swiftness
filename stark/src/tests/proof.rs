use crate::{
    fixtures::{config, unsent_commitment, witness},
    types::StarkProof,
};
use starknet_crypto::{Felt};
use swiftness_air::{fixtures::public_input, layout::recursive::Layout};
use swiftness_field::{Fp, SimpleField};
use swiftness_hash::pedersen::PedersenHash;
use swiftness_utils::curve::StarkwareCurve;

#[test]
fn test_stark_proof_fibonacci_verify() {
    let security_bits: Fp = Fp::from_stark_felt(Felt::from_hex_unchecked("0x32"));

    let stark_proof = StarkProof {
        config: config::get::<Fp>(),
        public_input: public_input::get::<Fp>(),
        unsent_commitment: unsent_commitment::get::<Fp>(),
        witness: witness::get::<Fp>(),
    };

    let (program_hash, output_hash) = stark_proof.verify::<StarkwareCurve, Layout>(security_bits).unwrap();
    assert_eq!(
        program_hash,
        Fp::from_stark_felt(Felt::from_hex_unchecked(
            "0x9f6693f4a5610a46b5d71ef573c43bef5f0d111fc1c5e506d509c458a29bae"
        ))
    );
    assert_eq!(
        output_hash,
        PedersenHash::<StarkwareCurve>::hash(
            PedersenHash::<StarkwareCurve>::hash(
                PedersenHash::<StarkwareCurve>::hash(Fp::zero(), Fp::from_stark_felt(Felt::from_hex_unchecked("0xa"))),
                Fp::from_stark_felt(Felt::from_hex_unchecked("0x90"))
            ),
            Fp::two()
        )
    );
}
