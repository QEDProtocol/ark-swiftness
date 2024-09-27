use alloc::vec::Vec;

pub struct FriLayerComputationParams<F: SimpleField + PoseidonHash> {
    pub coset_size: F,
    pub fri_group: Vec<F>,
    pub eval_point: F,
}

#[derive(PartialEq, Eq, Debug)]
pub struct FriLayerQuery<F: SimpleField + PoseidonHash> {
    pub index: F,
    pub y_value: F,
    pub x_inv_value: F,
}

// Computes the elements of the coset starting at coset_start_index.
//
// Inputs:
//   - queries: an iterator over the input queries.
//   - sibling_witness: a list of all the query's siblings.
//   - coset_size: the number of elements in the coset.
//   - coset_start_index: the index of the first element of the coset being calculated.
//   - fri_group: holds the group <g> in bit reversed order, where g is the generator of the coset.
//
// Outputs:
//   - coset_elements: the values of the coset elements.
//   - coset_x_inv: x_inv of the first element in the coset. This value is set only if at least one
//     query was consumed by this function.
pub fn compute_coset_elements<F: SimpleField + PoseidonHash>(
    queries: &mut Vec<FriLayerQuery<F>>,
    sibling_witness: &mut Vec<F>,
    coset_size: F,
    coset_start_index: F,
    fri_group: &[F],
) -> (Vec<F>, F) {
    let mut coset_elements = Vec::new();
    let mut coset_x_inv = F::zero();
    for index in F::range(&F::zero(), &coset_size) {
        let q = queries.first();
        // TODO: fix q.unwrap().index == coset_start_index + F::from_constant(index as u64)
        if q.is_some()
            && F::from_boolean(
                q.unwrap()
                    .index
                    .is_equal(&(coset_start_index.clone() + &index)),
            )
            .get_value()
                == F::one().get_value()
        {
            let query: Vec<FriLayerQuery<F>> = queries.drain(0..1).collect();
            coset_elements.push(query[0].y_value.clone());
            coset_x_inv = query[0].x_inv_value.clone() * F::at(fri_group, &index);
        } else {
            let withness: Vec<F> = sibling_witness.drain(0..1).collect();
            coset_elements.push(withness[0].clone());
        }
    }

    (coset_elements, coset_x_inv)
}

// Computes FRI next layer for the given queries. I.e., takes the given i-th layer queries
// and produces queries for layer i+1 (a single query for each coset in the i-th layer).
//
// Inputs:
//   - queries: input queries.
//   - sibling_witness: a list of all the query's siblings.
//   - params: the parameters to use for the layer computation.
//
// Outputs:
//   - next_queries: queries for the next layer.
//   - verify_indices: query indices of the given layer for Merkle verification.
//   - verify_y_values: query y values of the given layer for Merkle verification.
#[allow(clippy::type_complexity)]
pub fn compute_next_layer<F: SimpleField + PoseidonHash>(
    queries: &mut Vec<FriLayerQuery<F>>,
    sibling_witness: &mut Vec<F>,
    params: FriLayerComputationParams<F>,
) -> Result<(Vec<FriLayerQuery<F>>, Vec<F>, Vec<F>), FriError> {
    let mut next_queries = Vec::new();
    let mut verify_indices = Vec::new();
    let mut verify_y_values = Vec::new();

    let coset_size = params.coset_size.clone();
    while !queries.is_empty() {
        let query_index = queries.first().unwrap().index.clone();
        let coset_index = query_index.div_rem(&coset_size).0;

        verify_indices.push(coset_index.clone());

        let (coset_elements, coset_x_inv) = compute_coset_elements(
            queries,
            sibling_witness,
            coset_size.clone(),
            coset_index.clone() * &coset_size,
            &params.fri_group,
        );
        verify_y_values.extend(coset_elements.iter().cloned());

        let fri_formula_res = fri_formula(
            coset_elements,
            params.eval_point.clone(),
            coset_x_inv.clone(),
            coset_size.clone(),
        )?;

        let next_x_inv = coset_x_inv.powers_felt(&params.coset_size);
        next_queries.push(FriLayerQuery {
            index: coset_index,
            y_value: fri_formula_res,
            x_inv_value: next_x_inv,
        });
    }

    Ok((next_queries, verify_indices, verify_y_values))
}

use swiftness_field::SimpleField;
use swiftness_hash::poseidon::PoseidonHash;
use thiserror_no_std::Error;

use crate::formula::fri_formula;

#[derive(Error, Debug)]
pub enum FriError {
    #[error("FRI formula error: {0}")]
    FriFormulaError(#[from] crate::formula::Error),
}
