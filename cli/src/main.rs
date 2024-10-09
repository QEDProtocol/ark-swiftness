use ark_bls12_381::{Bls12_381, Fr};
use ark_groth16::Groth16;
use ark_r1cs_std::{alloc::AllocVar, fields::nonnative::NonNativeFieldVar};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_snark::{CircuitSpecificSetupSNARK, SNARK};
use ark_std::{
    rand::{RngCore, SeedableRng},
    test_rng,
};
use ark_swiftness_cli::ProofJSON;
use std::path::PathBuf;
use swiftness_field::{Fp, SimpleField};
use swiftness_hash::poseidon::PoseidonHash;
use swiftness_proof_parser::StarkProof;
#[cfg(feature = "dex")]
use swiftness_air::layout::dex::Layout;
#[cfg(feature = "recursive")]
use swiftness_air::layout::recursive::Layout;
#[cfg(feature = "recursive_with_poseidon")]
use swiftness_air::layout::recursive_with_poseidon::Layout;
#[cfg(feature = "small")]
use swiftness_air::layout::small::Layout;
#[cfg(feature = "starknet")]
use swiftness_air::layout::starknet::Layout;
#[cfg(feature = "starknet_with_keccak")]
use swiftness_air::layout::starknet_with_keccak::Layout;

use clap::Parser;
use swiftness_stark::types::StarkProof as StarkProofVerifier;
use swiftness_utils::curve::StarkwareCurve;

#[derive(Parser)]
#[command(author, version, about)]
struct CairoVMVerifier {
    /// Path to proof JSON file
    #[clap(short, long)]
    proof: PathBuf,
}

#[derive(Debug, Clone)]
pub struct StarkProofVerifierCircuit {
    proof: StarkProof,
}

impl ConstraintSynthesizer<Fr> for StarkProofVerifierCircuit
where
    NonNativeFieldVar<Fp, Fr>: PoseidonHash,
{
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let stark_proof_verifier: StarkProofVerifier<NonNativeFieldVar<Fp, Fr>> =
            StarkProofVerifier::<NonNativeFieldVar<Fp, Fr>>::new_witness(cs.clone(), || {
                Ok(self.proof)
            })
            .unwrap();

        let security_bits: NonNativeFieldVar<Fp, Fr> = stark_proof_verifier.config.security_bits();
        let (program_hash, output_hash) = stark_proof_verifier
            .verify::<StarkwareCurve, Layout>(security_bits)
            .unwrap();
        println!(
            "program_hash: {}, output_hash: {}",
            program_hash.get_value(),
            output_hash.get_value()
        );

        Ok(())
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

    let cli = CairoVMVerifier::parse();
    let proof_json = serde_json::from_str::<ProofJSON>(&std::fs::read_to_string(cli.proof)?)?;
    let stark_proof = StarkProof::try_from(proof_json)?;

    let verifier = StarkProofVerifierCircuit { proof: stark_proof.clone() };

    let (pk, vk) = {
        let c = StarkProofVerifierCircuit { proof: stark_proof.clone() };

        Groth16::<Bls12_381>::setup(c, &mut rng).unwrap()
    };

    let pvk = Groth16::<Bls12_381>::process_vk(&vk).unwrap();

    let proof = Groth16::<Bls12_381>::prove(&pk, verifier, &mut rng).unwrap();

    assert!(Groth16::<Bls12_381>::verify_with_processed_vk(&pvk, &[], &proof).unwrap());

    // let stark_proof_verifier: StarkProofVerifier<NonNativeFieldVar<Fp, Fr>> =
    //     parse::<Fp, Fr>(std::fs::read_to_string(cli.proof)?)?;
    // let cs = ConstraintSystem::<Fr>::new_ref();
    // // let stark_proof_verifier =
    // //     StarkProofVerifier::<NonNativeFieldVar<Fp, Fr>>::new_witness(cs.clone(), || Ok(stark_proof))
    // //         .unwrap();
    // let security_bits: NonNativeFieldVar<Fp, Fr> = stark_proof_verifier.config.security_bits();
    // let (program_hash, output_hash) = stark_proof_verifier
    //     .verify::<StarkwareCurve, Layout>(security_bits)
    //     .unwrap();
    // println!(
    //     "program_hash: {}, output_hash: {}",
    //     program_hash.get_value(),
    //     output_hash.get_value()
    // );
    // println!("num_constraints={}", cs.num_constraints());
    // assert!(cs.is_satisfied().unwrap());

    Ok(())
}
