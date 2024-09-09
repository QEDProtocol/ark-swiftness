use alloc::{borrow::ToOwned, vec::Vec};
use swiftness_commitment::table::{
    commit::table_commit,
    config::Config as TableCommitmentConfig,
    decommit::table_decommit,
    types::{Commitment as TableCommitment, Decommitment as TableDecommitment},
};
use swiftness_field::SimpleField;
use swiftness_hash::poseidon::PoseidonHash;
use swiftness_transcript::transcript::Transcript;

use crate::{
    config::Config as FriConfig,
    first_layer::gather_first_layer_queries,
    group::get_fri_group,
    last_layer::verify_last_layer,
    layer::{compute_next_layer, FriLayerComputationParams, FriLayerQuery},
    types::{
        self, Commitment as FriCommitment, Decommitment as FriDecommitment, LayerWitness, Witness,
    },
};

// A FRI phase with N layers starts with a single input layer.
// Afterwards, there are N - 1 inner layers resulting from FRI-folding each preceding layer.
// Each such layer has a separate table commitment, for a total of N - 1 commitments.
// Lastly, there is another FRI-folding resulting in the last FRI layer, that is commited by
// sending the polynomial coefficients, instead of a table commitment.
// Each folding has a step size.
// Illustration:
// InputLayer, no commitment.
//   fold step 0
// InnerLayer 0, Table commitment
//   fold step 1
// ...
// InnerLayer N - 2, Table commitment
//   fold step N - 1
// LastLayer, Polynomial coefficients
//
// N steps.
// N - 1 inner layers.

// Performs FRI commitment phase rounds. Each round reads a commitment on a layer, and sends an
// evaluation point for the next round.
pub fn fri_commit_rounds<F: SimpleField + PoseidonHash>(
    transcript: &mut Transcript<F>,
    n_layers: F,
    configs: Vec<TableCommitmentConfig<F>>,
    unsent_commitments: &[F],
) -> (Vec<TableCommitment<F>>, Vec<F>) {
    let mut commitments = Vec::<TableCommitment<F>>::new();
    let mut eval_points = Vec::<F>::new();

    let len: usize = n_layers.into_constant().try_into().unwrap();
    for i in 0..len {
        // Read commitments.
        commitments.push(table_commit(
            transcript,
            unsent_commitments.get(i).unwrap().clone(),
            configs.get(i).unwrap().clone(),
        ));
        // Send the next eval_points.
        eval_points.push(transcript.random_felt_to_prover());
    }

    (commitments, eval_points)
}

pub fn fri_commit<F: SimpleField + PoseidonHash>(
    transcript: &mut Transcript<F>,
    unsent_commitment: types::UnsentCommitment<F>,
    config: FriConfig<F>,
) -> FriCommitment<F> {
    // TODO: enable this
    // assert!(config.n_layers > F::from(0), "Invalid value");
    let inner_layers = config.inner_layers.clone();

    let (commitments, eval_points) = fri_commit_rounds(
        transcript,
        config.n_layers.clone() - F::one(),
        inner_layers,
        &unsent_commitment.inner_layers,
    );

    // Read last layer coefficients.
    transcript.read_felt_vector_from_prover(&unsent_commitment.last_layer_coefficients);
    let coefficients = unsent_commitment.last_layer_coefficients;

    // TODO: enable
    // assert!(
    //     F::TWO.pow_felt(&config.log_last_layer_degree_bound) == coefficients.len().into(),
    //     "Invalid value"
    // );

    FriCommitment {
        config,
        inner_layers: commitments,
        eval_points,
        last_layer_coefficients: coefficients,
    }
}

fn fri_verify_layers<F: SimpleField + PoseidonHash>(
    fri_group: Vec<F>,
    n_layers: F,
    commitment: Vec<TableCommitment<F>>,
    layer_witness: Vec<LayerWitness<F>>,
    eval_points: Vec<F>,
    step_sizes: Vec<F>,
    mut queries: Vec<FriLayerQuery<F>>,
) -> Vec<FriLayerQuery<F>> {
    let len: usize = n_layers.into_constant().try_into().unwrap();

    for i in 0..len {
        let target_layer_witness = layer_witness.get(i).unwrap();
        let mut target_layer_witness_leaves = target_layer_witness.leaves.to_owned();
        let target_layer_witness_table_withness = target_layer_witness.table_witness.to_owned();
        let target_commitment = commitment.get(i).unwrap().clone();

        // Params.
        let coset_size = F::two().powers_felt(&step_sizes.get(i).unwrap().clone());
        let params = FriLayerComputationParams {
            coset_size,
            fri_group: fri_group.clone(),
            eval_point: eval_points.get(i).unwrap().clone(),
        };

        // Compute next layer queries.
        let (next_queries, verify_indices, verify_y_values) =
            compute_next_layer(&mut queries, &mut target_layer_witness_leaves, params).unwrap();

        // Table decommitment.
        let _ = table_decommit(
            target_commitment,
            &verify_indices,
            TableDecommitment {
                values: verify_y_values,
            },
            target_layer_witness_table_withness,
        );

        queries = next_queries;
    }

    queries
}

// FRI protocol component decommitment.
pub fn fri_verify<F: SimpleField + PoseidonHash>(
    queries: &[F],
    commitment: FriCommitment<F>,
    decommitment: FriDecommitment<F>,
    witness: Witness<F>,
) -> Result<(), Error> {
    if queries.len() != decommitment.values.len() {
        return Err(Error::InvalidLength {
            expected: queries.len(),
            actual: decommitment.values.len(),
        });
    }

    // Compute first FRI layer queries.
    let fri_queries = gather_first_layer_queries(queries, decommitment.values, decommitment.points);

    // Compute fri_group.
    let fri_group = get_fri_group();

    // Verify inner layers.
    let last_queries = fri_verify_layers(
        fri_group,
        commitment.config.n_layers - F::one(),
        commitment.inner_layers,
        witness.layers,
        commitment.eval_points,
        commitment.config.fri_step_sizes[1..commitment.config.fri_step_sizes.len()].to_vec(),
        fri_queries,
    );

    F::from_constant(commitment.last_layer_coefficients.len() as u64)
        .assert_not_equal(&F::two().powers_felt(&commitment.config.log_last_layer_degree_bound));

    // if F::from_constant(commitment.last_layer_coefficients.len() as u64)
    //     != F::two().powers_felt(&commitment.config.log_last_layer_degree_bound)
    // {
    //     return Err(Error::InvalidValue);
    // };

    verify_last_layer(last_queries, commitment.last_layer_coefficients)
        .map_err(|_| Error::LastLayerVerificationError)?;
    Ok(())
}

#[cfg(feature = "std")]
use thiserror::Error;

#[cfg(feature = "std")]
#[derive(Error, Debug)]
pub enum Error {
    #[error("Invalid length: expected {expected}, actual {actual}")]
    InvalidLength { expected: usize, actual: usize },

    #[error("Invalid value")]
    InvalidValue,

    #[error("Last layer verification error")]
    LastLayerVerificationError,
}

#[cfg(not(feature = "std"))]
use thiserror_no_std::Error;

#[cfg(not(feature = "std"))]
#[derive(Error, Debug)]
pub enum Error {
    #[error("Invalid length: expected {expected}, actual {actual}")]
    InvalidLength { expected: usize, actual: usize },

    #[error("Invalid value")]
    InvalidValue,

    #[error("Last layer verification error")]
    LastLayerVerificationError,
}
