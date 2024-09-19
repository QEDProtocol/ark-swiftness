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
use ark_r1cs_std::fields::fp::FpVar;
use swiftness_field::SimpleField;
use swiftness_hash::poseidon::PoseidonHash;

pub fn parse<F: PrimeField + SimpleField + PoseidonHash>(
    input: String,
) -> anyhow::Result<StarkProof>
where
    FpVar<F>: PoseidonHash,
{
    let proof_json = serde_json::from_str::<ProofJSON>(&input)?;
    let stark_proof = StarkProof::try_from(proof_json)?;
    Ok(stark_proof)
}

#[cfg(test)]
mod tests {
    use swiftness_field::Fp;
    use swiftness_stark::types::StarkProof as StarkProofVerifier;

    use super::*;

    #[test]
    fn test_parse() {
        let input = include_str!("../../proofs/recursive/cairo0_example_proof.json");
        let proof_json = serde_json::from_str::<ProofJSON>(input).unwrap();
        let stark_proof = StarkProof::try_from(proof_json).unwrap();
        let _: StarkProofVerifier<Fp> = stark_proof.into();
    }
}
