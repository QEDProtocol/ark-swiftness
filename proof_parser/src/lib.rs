mod annotations;
mod builtins;
mod conversion;
mod json_parser;
mod layout;
mod stark_proof;
mod utils;

use crate::{json_parser::ProofJSON, stark_proof::StarkProof};
use std::convert::TryFrom;
extern crate clap;
extern crate num_bigint;
extern crate regex;
extern crate serde;
use ark_ff::PrimeField;
use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar};
use ark_relations::r1cs::ConstraintSystem;
use log::info;
use swiftness_field::SimpleField;
use swiftness_hash::poseidon::PoseidonHash;
use swiftness_stark::types::StarkProof as StarkProofVerifier;

pub fn parse<F: PrimeField + SimpleField + PoseidonHash>(
    input: String,
) -> anyhow::Result<StarkProofVerifier<FpVar<F>>>
where
    FpVar<F>: PoseidonHash,
{
    let proof_json = serde_json::from_str::<ProofJSON>(&input)?;
    let stark_proof = StarkProof::try_from(proof_json)?;
    let cs = ConstraintSystem::<F>::new_ref();
    let stark_proof_verifier: StarkProofVerifier<FpVar<F>> =
        StarkProofVerifier::<FpVar<F>>::new_witness(cs.clone(), || Ok(stark_proof)).unwrap();
    info!("num_constraints={}", cs.num_constraints());
    assert!(cs.is_satisfied().unwrap());
    Ok(stark_proof_verifier)
}

#[cfg(test)]
mod tests {
    use swiftness_field::Fp;

    use super::*;

    #[test]
    fn test_parse() {
        let input = include_str!("../../proofs/recursive/cairo0_example_proof.json");
        let proof_json = serde_json::from_str::<ProofJSON>(input).unwrap();
        let stark_proof = StarkProof::try_from(proof_json).unwrap();
        let _: StarkProofVerifier<Fp> = stark_proof.into();
    }
}
