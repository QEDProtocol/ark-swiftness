use serde::{Deserialize, Serialize};
use serde_with::serde_as;

#[serde_as]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Config<F: SimpleField + PoseidonHash> {
    #[cfg_attr(
        feature = "std",
        serde_as(as = "starknet_core::serde::unsigned_field_element::UfeHex")
    )]
    pub height: F,
    #[cfg_attr(
        feature = "std",
        serde_as(as = "starknet_core::serde::unsigned_field_element::UfeHex")
    )]
    pub n_verifier_friendly_commitment_layers: F,
}

impl<F: SimpleField + PoseidonHash> Config<F> {
    pub fn validate(
        &self,
        expected_height: F,
        expected_n_verifier_friendly_commitment_layers: F,
    ) -> Result<(), Error<F>> {
        self.height.assert_equal(&expected_height);
        self.n_verifier_friendly_commitment_layers
            .assert_equal(&expected_n_verifier_friendly_commitment_layers);
        Ok(())
    }
}

use swiftness_field::SimpleField;
use swiftness_hash::poseidon::PoseidonHash;
#[cfg(feature = "std")]
use thiserror::Error;

#[cfg(feature = "std")]
#[derive(Error, Debug)]
pub enum Error<F: SimpleField + PoseidonHash> {
    #[error("mismatch value {value} expected {expected}")]
    MisMatch { value: F, expected: F },
}

#[cfg(not(feature = "std"))]
use thiserror_no_std::Error;

#[cfg(not(feature = "std"))]
#[derive(Error, Debug)]
pub enum Error {
    #[error("mismatch value {value} expected {expected}")]
    MisMatch { value: Felt, expected: Felt },
}
