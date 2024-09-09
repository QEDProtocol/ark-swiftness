use serde::{Deserialize, Serialize};
use serde_with::serde_as;

#[serde_as]
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct StarkConfig<F: SimpleField + PoseidonHash> {
    pub traces: swiftness_air::trace::config::Config<F>,
    pub composition: swiftness_commitment::table::config::Config<F>,
    pub fri: swiftness_fri::config::Config<F>,
    pub proof_of_work: swiftness_pow::config::Config,
    // Log2 of the trace domain size.
    #[cfg_attr(
        feature = "std",
        serde_as(as = "starknet_core::serde::unsigned_field_element::UfeHex")
    )]
    pub log_trace_domain_size: F,
    // Number of queries to the last component, FRI.
    #[cfg_attr(
        feature = "std",
        serde_as(as = "starknet_core::serde::unsigned_field_element::UfeHex")
    )]
    pub n_queries: F,
    // Log2 of the number of cosets composing the evaluation domain, where the coset size is the
    // trace length.
    #[cfg_attr(
        feature = "std",
        serde_as(as = "starknet_core::serde::unsigned_field_element::UfeHex")
    )]
    pub log_n_cosets: F,
    // Number of layers that use a verifier friendly hash in each commitment.
    #[cfg_attr(
        feature = "std",
        serde_as(as = "starknet_core::serde::unsigned_field_element::UfeHex")
    )]
    pub n_verifier_friendly_commitment_layers: F,
}

impl<F: SimpleField + PoseidonHash> StarkConfig<F> {
    pub fn security_bits(&self) -> F {
        self.n_queries.clone() * &self.log_n_cosets + F::from_constant(self.proof_of_work.n_bits as u128)
    }

    pub fn validate<Layout: LayoutTrait<F>>(&self, security_bits: F) -> Result<(), Error<F>> {
        self.proof_of_work.validate()?;

        // assert!(security_bits <= self.security_bits());
        security_bits.assert_lte(&self.security_bits());

        // Validate traces config.
        let log_eval_domain_size = self.log_trace_domain_size.clone() + &self.log_n_cosets;
        self.traces
            .validate::<Layout>(log_eval_domain_size.clone(), self.n_verifier_friendly_commitment_layers.clone())?;

        // Validate composition config.
        self.composition
            .vector
            .validate(log_eval_domain_size, self.n_verifier_friendly_commitment_layers.clone())?;

        // Validate Fri config.
        self.fri.validate(self.log_n_cosets.clone(), self.n_verifier_friendly_commitment_layers.clone())?;
        Ok(())
    }
}

use swiftness_air::layout::LayoutTrait;
use swiftness_commitment::vector;

use swiftness_field::SimpleField;
use swiftness_hash::poseidon::PoseidonHash;
#[cfg(feature = "std")]
use thiserror::Error;

#[cfg(feature = "std")]
#[derive(Error, Debug)]
pub enum Error<F: SimpleField + PoseidonHash> {
    #[error("Vector Error")]
    Vector(#[from] vector::config::Error<F>),
    #[error("Fri Error")]
    Fri(#[from] swiftness_fri::config::Error<F>),
    #[error("Pow Error")]
    Pow(#[from] swiftness_pow::config::Error),
    #[error("Trace Error")]
    Trace(#[from] swiftness_air::trace::config::Error<F>),
}

#[cfg(not(feature = "std"))]
use thiserror_no_std::Error;

#[cfg(not(feature = "std"))]
#[derive(Error, Debug)]
pub enum Error<F: SimpleField  + PoseidonHash> {
    #[error("Vector Error")]
    Vector(#[from] vector::config::Error<F>),
    #[error("Fri Error")]
    Fri(#[from] swiftness_fri::config::Error<F>),
    #[error("Pow Error")]
    Pow(#[from] swiftness_pow::config::Error),
    #[error("Trace Error")]
    Trace(#[from] swiftness_air::trace::config::Error<F>),
}
