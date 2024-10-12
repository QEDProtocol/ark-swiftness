use crate::layout::LayoutTrait;
use serde::{Deserialize, Serialize};
// use starknet_crypto::Felt;
use swiftness_commitment::vector;

//const MAX_N_COLUMNS: Felt = Felt::from_hex_unchecked("0x80");

// Configuration for the Traces component.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Config<F: SimpleField + PoseidonHash> {
    pub original: swiftness_commitment::table::config::Config<F>,
    pub interaction: swiftness_commitment::table::config::Config<F>,
}

impl<F: SimpleField + PoseidonHash> Config<F> {
    pub fn validate<Layout: LayoutTrait<F>>(
        &self,
        log_eval_domain_size: F,
        n_verifier_friendly_commitment_layers: F,
    ) -> Result<(), Error<F>> {
        // TODO: enable check
        // if self.original.n_columns < Felt::ONE || self.original.n_columns > MAX_N_COLUMNS {
        //     return Err(Error::OutOfBounds { min: Felt::ONE, max: MAX_N_COLUMNS });
        // }
        // if self.interaction.n_columns < Felt::ONE || self.interaction.n_columns > MAX_N_COLUMNS {
        //     return Err(Error::OutOfBounds { min: Felt::ONE, max: MAX_N_COLUMNS });
        // }
        //
        // if self.original.n_columns != Layout::NUM_COLUMNS_FIRST.into() {
        //     return Err(Error::ColumnsNumInvalid);
        // }
        //
        // if self.interaction.n_columns != Layout::NUM_COLUMNS_SECOND.into() {
        //     return Err(Error::ColumnsNumInvalid);
        // }

        Ok(self
            .original
            .vector
            .validate(
                log_eval_domain_size.clone(),
                n_verifier_friendly_commitment_layers.clone(),
            )
            .and(
                self.interaction
                    .vector
                    .validate(log_eval_domain_size, n_verifier_friendly_commitment_layers),
            )?)
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
    OutOfBounds { min: F, max: F },

    #[error("wrong numbers of columns")]
    ColumnsNumInvalid,

    #[error("Vector Error")]
    Vector(#[from] vector::config::Error<F>),
}

#[cfg(not(feature = "std"))]
use thiserror_no_std::Error;

#[cfg(not(feature = "std"))]
#[derive(Error, Debug)]
pub enum Error<F: SimpleField + PoseidonHash> {
    #[error("value out of bounds {min} - {max}")]
    OutOfBounds { min: F, max: F },

    #[error("wrong numbers of columns")]
    ColumnsNumInvalid,

    #[error("Vector Error")]
    Vector(#[from] vector::config::Error<F>),
}
