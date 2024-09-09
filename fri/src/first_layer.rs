use alloc::vec::Vec;
use starknet_crypto::Felt;
use swiftness_field::SimpleField;
use swiftness_hash::poseidon::PoseidonHash;

use crate::layer::FriLayerQuery;

pub fn gather_first_layer_queries<F: SimpleField + PoseidonHash>(
    queries: &[F],
    evaluations: Vec<F>,
    x_values: Vec<F>,
) -> Vec<FriLayerQuery<F>> {
    let mut fri_queries = Vec::new();

    let field_generator_inverse: F = F::from_stark_felt(Felt::from_hex_unchecked(
        "0x2AAAAAAAAAAAAB0555555555555555555555555555555555555555555555556",
    ));

    for (index, query) in queries.iter().enumerate() {
        // Translate the coset to the homogenous group to have simple FRI equations.
        let shifted_x_value = x_values.get(index).unwrap().clone() * &field_generator_inverse;

        fri_queries.push(FriLayerQuery {
            index: query.clone(),
            y_value: evaluations.get(index).unwrap().clone(),
            x_inv_value: F::one().field_div(&shifted_x_value),
        });
    }

    fri_queries
}
