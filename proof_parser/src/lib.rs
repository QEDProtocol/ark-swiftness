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
use swiftness_field::SimpleField;
use swiftness_hash::poseidon::PoseidonHash;
use swiftness_stark::types::StarkProof as StarkProofFromVerifier;

pub fn parse<F: SimpleField + PoseidonHash>(input: String) -> anyhow::Result<StarkProofFromVerifier<F>> {
    let proof_json = serde_json::from_str::<ProofJSON>(&input)?;
    let stark_proof = StarkProof::try_from(proof_json)?;
    let stark_proof_verifier: StarkProofFromVerifier<F> = stark_proof.into();
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
        let _: StarkProofFromVerifier<Fp> = stark_proof.into();
    }
}
