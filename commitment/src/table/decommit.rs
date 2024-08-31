use crate::vector::{decommit::vector_commitment_decommit, types::Query};
use alloc::vec::Vec;
use starknet_crypto::Felt;

// #[cfg(feature = "blake2s")]
// use blake2::Blake2s256;
// #[cfg(feature = "blake2s")]
// use blake2::Digest;
// #[cfg(feature = "keccak")]
// use sha3::Digest;
// #[cfg(feature = "keccak")]
// use sha3::Keccak256;
use swiftness_field::SimpleField;
use swiftness_hash::poseidon::{poseidon_hash_many, Permute};

use super::types::{Commitment, Decommitment, Witness};

pub fn table_decommit<F: SimpleField + Permute>(
    commitment: Commitment<F>,
    queries: &[F],
    decommitment: Decommitment<F>,
    witness: Witness<F>,
) -> Result<(), Error<F>> {
    // An extra layer is added to the height since the table is considered as a layer, which is not
    // included in vector_commitment.config.
    let bottom_layer_depth = commitment.vector_commitment.config.height.clone() + F::one();

    // Determine if the table commitment should use a verifier friendly hash function for the bottom
    // layer. The other layers' hash function will be determined in the vector_commitment logic.
    // let is_bottom_layer_verifier_friendly =
    //     commitment.vector_commitment.config.n_verifier_friendly_commitment_layers
    //         >= bottom_layer_depth;
    let is_bottom_layer_verifier_friendly = true;

    // TODO: may panic
    let n_columns: u32 = commitment
        .config
        .n_columns
        .into_constant()
        .try_into()
        .unwrap();
    if n_columns as usize * queries.len() != decommitment.values.len() {
        return Err(Error::DecommitmentLength);
    }

    // Convert decommitment values to Montgomery form, since the commitment is in that form.
    let montgomery_values: Vec<F> = decommitment
        .values
        .into_iter()
        .map(|v| {
            v * F::from_stark_felt(Felt::from_hex_unchecked(
                "0x7FFFFFFFFFFFDF0FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE1",
            ))
        })
        .collect();

    // Generate queries to the underlying vector commitment.
    let vector_queries = generate_vector_queries(
        queries,
        &montgomery_values,
        n_columns,
        is_bottom_layer_verifier_friendly,
    );

    Ok(vector_commitment_decommit(
        commitment.vector_commitment,
        &vector_queries,
        witness.vector,
    )?)
}

fn generate_vector_queries<F: SimpleField + Permute>(
    queries: &[F],
    values: &[F],
    n_columns: u32,
    is_verifier_friendly: bool,
) -> Vec<Query<F>> {
    let mut vector_queries = Vec::new();
    for i in 0..queries.len() {
        let hash = if n_columns == 1 {
            values[i].clone()
        } else if is_verifier_friendly {
            let slice = &values[(i * n_columns as usize)..((i + 1) * n_columns as usize)];
            poseidon_hash_many(slice)
        } else {
            todo!()
            // let slice = &values[(i * n_columns as usize)..((i + 1) * n_columns as usize)];
            // let mut data = Vec::new();
            // data.extend(slice.iter().flat_map(|x| x.to_bytes_be().to_vec()));
            //
            // #[cfg(feature = "keccak")]
            // let mut hasher = Keccak256::new();
            // #[cfg(feature = "blake2s")]
            // let mut hasher = Blake2s256::new();
            //
            // hasher.update(&data);
            // Felt::from_bytes_be_slice(&hasher.finalize().to_vec().as_slice()[12..32])
        };

        vector_queries.push(Query {
            index: queries[i].clone(),
            value: hash,
        })
    }

    vector_queries
}

#[cfg(feature = "std")]
use thiserror::Error;

#[cfg(feature = "std")]
#[derive(Error, Debug)]
pub enum Error<F: SimpleField> {
    #[error("Invalid decommitment length")]
    DecommitmentLength,

    #[error("Vector Error")]
    Vector(#[from] crate::vector::decommit::Error<F>),
}

#[cfg(not(feature = "std"))]
use thiserror_no_std::Error;

#[cfg(not(feature = "std"))]
#[derive(Error, Debug)]
pub enum Error<F: SimpleField> {
    #[error("Invalid decommitment length")]
    DecommitmentLength,

    #[error("Vector Error")]
    Vector(#[from] crate::vector::decommit::Error<F>),
}
