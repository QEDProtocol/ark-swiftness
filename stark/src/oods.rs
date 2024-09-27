use alloc::vec::Vec;
use swiftness_air::{
    layout::{CompositionPolyEvalError, LayoutTrait},
    public_memory::PublicInput,
    trace,
};
use swiftness_commitment::table;

pub struct OodsEvaluationInfo<F: SimpleField + PoseidonHash> {
    pub oods_values: Vec<F>,
    pub oods_point: F,
    pub trace_generator: F,
    pub constraint_coefficients: Vec<F>,
}

// Checks that the trace and the compostion agree at oods_point, assuming the prover provided us
// with the proper evaluations.
pub fn verify_oods<F: SimpleField + PoseidonHash, Layout: LayoutTrait<F>>(
    oods: &[F],
    interaction_elements: &Layout::InteractionElements,
    public_input: &PublicInput<F>,
    constraint_coefficients: &[F],
    oods_point: &F,
    trace_domain_size: &F,
    trace_generator: &F,
) -> Result<(), OodsVerifyError<F>> {
    let composition_from_trace = Layout::eval_composition_polynomial(
        interaction_elements,
        public_input,
        &oods[0..oods.len() - 2],
        constraint_coefficients,
        oods_point,
        trace_domain_size,
        trace_generator,
    )?;

    // TODO support degree > 2?
    let claimed_composition =
        oods[oods.len() - 2].clone() + oods[oods.len() - 1].clone() * oods_point;

    // assure!(
    //     composition_from_trace == claimed_composition,
    //     OodsVerifyError::EvaluationInvalid {
    //         expected: claimed_composition,
    //         actual: composition_from_trace
    //     }
    // )
    composition_from_trace.assert_equal(&claimed_composition);
    Ok(())
}

use swiftness_field::SimpleField;
use swiftness_hash::poseidon::PoseidonHash;
#[cfg(feature = "std")]
use thiserror::Error;

#[cfg(feature = "std")]
#[derive(Error, Debug)]
pub enum OodsVerifyError<F: SimpleField + PoseidonHash> {
    #[error("oods invalid {expected} - {actual}")]
    EvaluationInvalid { expected: F, actual: F },
    #[error("CompositionPolyEval Error")]
    CompositionPolyEvalError(#[from] CompositionPolyEvalError),
}

#[cfg(not(feature = "std"))]
use thiserror_no_std::Error;

#[cfg(not(feature = "std"))]
#[derive(Error, Debug)]
pub enum OodsVerifyError<F: SimpleField + PoseidonHash> {
    #[error("oods invalid {expected} - {actual}")]
    EvaluationInvalid { expected: F, actual: F },
    #[error("CompositionPolyEval Error")]
    CompositionPolyEvalError(#[from] CompositionPolyEvalError),
}

pub fn eval_oods_boundary_poly_at_points<F: SimpleField + PoseidonHash, Layout: LayoutTrait<F>>(
    n_original_columns: usize,
    n_interaction_columns: usize,
    eval_info: OodsEvaluationInfo<F>,
    points: &[F],
    decommitment: trace::Decommitment<F>,
    composition_decommitment: table::types::Decommitment<F>,
) -> Vec<F> {
    assert!(
        decommitment.original.values.len() == points.len() * n_original_columns,
        "Invalid value"
    );
    assert!(
        decommitment.interaction.values.len() == points.len() * n_interaction_columns,
        "Invalid value"
    );
    assert!(
        composition_decommitment.values.len() == points.len() * Layout::CONSTRAINT_DEGREE,
        "Invalid value"
    );

    let mut evaluations = Vec::with_capacity(points.len());

    for (i, point) in points.iter().enumerate() {
        let mut column_values = Vec::with_capacity(
            n_original_columns + n_interaction_columns + Layout::CONSTRAINT_DEGREE,
        );

        column_values.extend(
            &decommitment.original.values[i * n_original_columns..(i + 1) * n_original_columns],
        );
        column_values.extend(
            &decommitment.interaction.values
                [i * n_interaction_columns..(i + 1) * n_interaction_columns],
        );
        column_values.extend(
            &composition_decommitment.values
                [i * Layout::CONSTRAINT_DEGREE..(i + 1) * Layout::CONSTRAINT_DEGREE],
        );

        evaluations.push(Layout::eval_oods_polynomial(
            &column_values.into_iter().cloned().collect::<Vec<_>>(),
            &eval_info.oods_values,
            &eval_info.constraint_coefficients,
            &point,
            &eval_info.oods_point,
            &eval_info.trace_generator,
        ));
    }

    evaluations
}
