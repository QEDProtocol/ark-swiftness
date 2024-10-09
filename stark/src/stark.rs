use crate::{
    commit::stark_commit, queries::generate_queries, types::StarkProof, verify::stark_verify,
};

impl<F: SimpleField + PoseidonHash + Blake2sHash + KeccakHash> StarkProof<F> {
    pub fn verify<P: SWCurveConfig, Layout: LayoutTrait<F>>(
        &self,
        security_bits: F,
    ) -> Result<(F, F), Error<F>>
    where
        F: PedersenHash<P>,
        P::BaseField: PrimeField + SimpleField,
        <P::BaseField as Field>::BasePrimeField: SimpleField,
        FpVar<P::BaseField>:
            FieldVar<P::BaseField, <P::BaseField as Field>::BasePrimeField> + SimpleField,
        for<'a> &'a FpVar<P::BaseField>: FieldOpsBounds<'a, P::BaseField, FpVar<P::BaseField>>,
        <FpVar<P::BaseField> as SimpleField>::BooleanType:
            From<Boolean<<P::BaseField as Field>::BasePrimeField>>,
    {
        info!("Verifying proof");
        self.config.validate::<Layout>(security_bits)?;

        // Validate the public input.
        let stark_domains = StarkDomains::new(
            self.config.log_trace_domain_size.clone(),
            self.config.log_n_cosets.clone(),
        );

        info!("Validating public input");
        Layout::validate_public_input(&self.public_input, &stark_domains)?;

        info!("Computing initial hash seed for Fiat-Shamir transcript");
        let current = std::time::Instant::now();
        // Compute the initial hash seed for the Fiat-Shamir transcript.
        let digest = self.public_input.get_hash();
        debug!(
            "Initial hash seed computed in {} seconds",
            current.elapsed().as_secs_f32()
        );
        debug!(
            "public_input_hash={}",
            hex::encode(digest.get_value().into_bigint().to_bytes_le())
        );
        // Construct the transcript.
        // TODO: is this correct?
        let mut transcript = Transcript::new(digest);

        info!("Committing to the public input");
        // STARK commitment phase.
        let stark_commitment = stark_commit::<F, Layout>(
            &mut transcript,
            &self.public_input,
            &self.unsent_commitment,
            &self.config,
            &stark_domains,
        )?;

        info!("Generating queries");
        // Generate queries.
        let queries = generate_queries(
            &mut transcript,
            self.config.n_queries.clone(),
            stark_domains.eval_domain_size.clone(),
        );

        info!("Verifying proof");
        let current = std::time::Instant::now();
        // STARK verify phase.
        stark_verify::<F, Layout>(
            Layout::NUM_COLUMNS_FIRST,
            Layout::NUM_COLUMNS_SECOND,
            &queries,
            stark_commitment,
            &self.witness,
            &stark_domains,
        )?;
        info!(
            "Proof verified in {} seconds",
            current.elapsed().as_secs_f32()
        );

        info!("verifying public input ");
        Ok(Layout::verify_public_input(&self.public_input)?)
    }
}

use ark_ec::short_weierstrass::SWCurveConfig;
use ark_ff::{BigInteger, Field, PrimeField};
use ark_r1cs_std::{
    fields::{fp::FpVar, FieldOpsBounds, FieldVar},
    prelude::Boolean,
};
use log::{debug, info};
use swiftness_air::{
    domains::StarkDomains,
    layout::{LayoutTrait, PublicInputError},
};
use swiftness_field::SimpleField;
use swiftness_hash::{
    blake2s::Blake2sHash, keccak::KeccakHash, pedersen::PedersenHash, poseidon::PoseidonHash,
};
use swiftness_transcript::transcript::Transcript;

#[cfg(feature = "std")]
use thiserror::Error;

#[cfg(feature = "std")]
#[derive(Error, Debug)]
pub enum Error<F: SimpleField + PoseidonHash> {
    #[error("Vector Error")]
    Validation(#[from] crate::config::Error<F>),

    #[error("PublicInputError Error")]
    PublicInputError(#[from] PublicInputError),

    #[error("Commit Error")]
    Commit(#[from] crate::commit::Error<F>),

    #[error("Verify Error")]
    Verify(#[from] crate::verify::Error<F>),
}

#[cfg(not(feature = "std"))]
use thiserror_no_std::Error;

#[cfg(not(feature = "std"))]
#[derive(Error, Debug)]
pub enum Error<F: SimpleField + PoseidonHash> {
    #[error("Vector Error")]
    Validation(#[from] crate::config::Error),

    #[error("PublicInputError Error")]
    PublicInputError(#[from] PublicInputError),

    #[error("Commit Error")]
    Commit(#[from] crate::commit::Error),

    #[error("Verify Error")]
    Verify(#[from] crate::verify::Error<F>),
}
