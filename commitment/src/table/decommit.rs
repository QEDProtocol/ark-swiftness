use crate::vector::{decommit::vector_commitment_decommit, types::Query};
use alloc::vec::Vec;
use starknet_crypto::Felt;

use swiftness_field::SimpleField;
use swiftness_hash::{blake2s::Blake2sHash, keccak::KeccakHash, poseidon::PoseidonHash};

use super::types::{Commitment, Decommitment, Witness};

const MONTGOMERY_R: Felt =
    Felt::from_hex_unchecked("0x7FFFFFFFFFFFDF0FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE1");

pub fn table_decommit<F: SimpleField + PoseidonHash + KeccakHash + Blake2sHash>(
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
    let is_bottom_layer_verifier_friendly = commitment
        .vector_commitment
        .config
        .n_verifier_friendly_commitment_layers
        .gte(&bottom_layer_depth);
    // if n_columns as usize * queries.len() != decommitment.values.len() {
    //     return Err(Error::DecommitmentLength);
    // }
    (commitment.config.n_columns.clone() * &F::from_constant(queries.len()))
        .assert_equal(&F::from_constant(decommitment.values.len()));
    // Convert decommitment values to Montgomery form, since the commitment is in that form.
    let montgomery_values: Vec<F> = decommitment
        .values
        .into_iter()
        .map(|v| v * F::from_stark_felt(MONTGOMERY_R))
        .collect();

    // Generate queries to the underlying vector commitment.
    let vector_queries = generate_vector_queries(
        queries,
        &montgomery_values,
        commitment.config.n_columns.clone(),
        is_bottom_layer_verifier_friendly,
    );

    Ok(vector_commitment_decommit(
        commitment.vector_commitment,
        &vector_queries,
        witness.vector,
    )?)
}

fn generate_vector_queries<F: SimpleField + PoseidonHash + KeccakHash + Blake2sHash>(
    queries: &[F],
    values: &[F],
    n_columns: F,
    is_verifier_friendly: F::BooleanType,
) -> Vec<Query<F>> {
    let mut vector_queries = Vec::new();
    for i in 0..queries.len() {
        let hash = SimpleField::select(&n_columns.is_equal(&F::one()), values[i].clone(), {
            SimpleField::select(
                &is_verifier_friendly,
                {
                    let slice = <F as SimpleField>::slice(
                        &values,
                        &n_columns.mul_by_constant(i),
                        &n_columns.mul_by_constant(i + 1),
                    );
                    PoseidonHash::hash_many(&slice)
                },
                {
                    let slice = <F as SimpleField>::slice(
                        &values,
                        &n_columns.mul_by_constant(i),
                        &n_columns.mul_by_constant(i + 1),
                    );
                    let mut data = Vec::new();
                    data.extend(slice.iter().flat_map(|x| x.to_be_bytes().to_vec()));

                    let final_hash: Vec<<F as SimpleField>::ByteType>;
                    cfg_if::cfg_if! {
                        if #[cfg(feature = "keccak")] {
                            final_hash = <F as PoseidonHash>::hash_out(&data);
                        } else if #[cfg(feature = "blake2s")] {
                            final_hash = <F as PoseidonHash>::hash_out(&data);
                        } else {
                            compile_error!("Either 'keccak' or 'blake2s' feature must be enabled");
                        }
                    }
                    F::from_be_bytes(&final_hash.as_slice()[12..32])
                },
            )
        });

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
