use alloc::vec::Vec;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

const MAX_LAST_LAYER_LOG_DEGREE_BOUND: u64 = 15;
const MAX_FRI_LAYERS: u64 = 15;
const MIN_FRI_LAYERS: u64 = 2;
const MAX_FRI_STEP: u64 = 4;
const MIN_FRI_STEP: u64 = 1;

#[serde_as]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Config<F: SimpleField + PoseidonHash> {
    // Log2 of the size of the input layer to FRI.
    #[cfg_attr(
        feature = "std",
        serde_as(as = "starknet_core::serde::unsigned_field_element::UfeHex")
    )]
    pub log_input_size: F,
    // Number of layers in the FRI. Inner + last layer.
    #[cfg_attr(
        feature = "std",
        serde_as(as = "starknet_core::serde::unsigned_field_element::UfeHex")
    )]
    pub n_layers: F,
    // Array of size n_layers - 1, each entry is a configuration of a table commitment for the
    // corresponding inner layer.
    pub inner_layers: Vec<swiftness_commitment::table::config::Config<F>>,
    // Array of size n_layers, each entry represents the FRI step size,
    // i.e. the number of FRI-foldings between layer i and i+1.
    #[cfg_attr(
        feature = "std",
        serde_as(as = "Vec<starknet_core::serde::unsigned_field_element::UfeHex>")
    )]
    pub fri_step_sizes: Vec<F>,
    #[cfg_attr(
        feature = "std",
        serde_as(as = "starknet_core::serde::unsigned_field_element::UfeHex")
    )]
    pub log_last_layer_degree_bound: F,
}

impl<F: SimpleField + PoseidonHash> Config<F> {
    pub fn validate(
        &self,
        log_n_cosets: F,
        n_verifier_friendly_commitment_layers: F,
    ) -> Result<F, Error<F>> {
        // TODO: enable check
        // if self.n_layers < MIN_FRI_LAYERS.into() || self.n_layers > MAX_FRI_LAYERS.into() {
        //     return Err(Error::OutOfBounds { min: MIN_FRI_LAYERS, max: MAX_FRI_LAYERS });
        // }
        // if self.log_last_layer_degree_bound < Felt::ZERO
        //     || self.log_last_layer_degree_bound > MAX_LAST_LAYER_LOG_DEGREE_BOUND.into()
        // {
        //     return Err(Error::OutOfBounds { min: 0, max: MAX_LAST_LAYER_LOG_DEGREE_BOUND });
        // }
        // if *self.fri_step_sizes.first().ok_or(Error::FirstFriStepInvalid)? != Felt::ZERO {
        //     return Err(Error::FirstFriStepInvalid);
        // }

        let n_layers: usize = self.n_layers.into_biguint().try_into().unwrap();
        let mut sum_of_step_sizes = F::zero();
        let mut log_input_size = self.log_input_size.clone();

        for i in 1..n_layers {
            let fri_step = self.fri_step_sizes[i].clone();
            let table_commitment = &self.inner_layers[i - 1];
            log_input_size -= &fri_step;
            sum_of_step_sizes += &fri_step;

            // TODO: enable check
            // if fri_step < MIN_FRI_STEP.into() || fri_step > MAX_FRI_STEP.into() {
            //     return Err(Error::OutOfBounds { min: MIN_FRI_STEP, max: MAX_FRI_STEP });
            // }
            let expected_n_columns = F::two().powers_felt(&fri_step);
            // if table_commitment.n_columns != expected_n_columns {
            //     return Err(Error::InvalidColumnCount {
            //         expected: expected_n_columns,
            //         actual: table_commitment.n_columns,
            //     });
            // }
            table_commitment.n_columns.assert_equal(&expected_n_columns);
            table_commitment.vector.validate(
                log_input_size.clone(),
                n_verifier_friendly_commitment_layers.clone(),
            )?;
        }

        let log_expected_input_degree = sum_of_step_sizes + &self.log_last_layer_degree_bound;
        // if log_expected_input_degree + log_n_cosets != self.log_input_size {
        //     return Err(Error::LogInputSizeMismatch {
        //         expected: log_expected_input_degree,
        //         actual: self.log_input_size,
        //     });
        // }
        (log_expected_input_degree.clone() + &log_n_cosets).assert_equal(&self.log_input_size);
        Ok(log_expected_input_degree)
    }
}

use swiftness_field::SimpleField;
use swiftness_hash::poseidon::PoseidonHash;
#[cfg(feature = "std")]
use thiserror::Error;

#[cfg(feature = "std")]
#[derive(Error, Debug)]
pub enum Error<F: SimpleField + PoseidonHash> {
    #[error("value out of bounds {min} - {max}")]
    OutOfBounds { min: u64, max: u64 },
    #[error("invalid first fri step")]
    FirstFriStepInvalid,
    #[error("invalid value for column count, expected {expected}, got {actual}")]
    InvalidColumnCount { expected: F, actual: F },
    #[error("log input size mismatch, expected {expected}, got {actual}")]
    LogInputSizeMismatch { expected: F, actual: F },
    #[error("vector validation failed: {0}")]
    VectorValidationFailed(#[from] swiftness_commitment::vector::config::Error<F>),
}

#[cfg(not(feature = "std"))]
use thiserror_no_std::Error;

#[cfg(not(feature = "std"))]
#[derive(Error, Debug)]
pub enum Error<F: SimpleField + PoseidonHash> {
    #[error("value out of bounds {min} - {max}")]
    OutOfBounds { min: u64, max: u64 },
    #[error("invalid first fri step")]
    FirstFriStepInvalid,
    #[error("invalid value for column count, expected {expected}, got {actual}")]
    InvalidColumnCount { expected: F, actual: F },
    #[error("log input size mismatch, expected {expected}, got {actual}")]
    LogInputSizeMismatch { expected: F, actual: F },
    #[error("vector validation failed: {0}")]
    VectorValidationFailed(#[from] swiftness_commitment::vector::config::Error<F>),
}
