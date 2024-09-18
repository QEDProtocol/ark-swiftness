use std::borrow::Borrow;

use ark_ff::PrimeField;
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    fields::fp::FpVar,
};
use ark_relations::r1cs::{Namespace, SynthesisError};
use swiftness_air::{
    public_memory::PublicInput as PublicInputVerifier,
    trace::{
        config::Config as TraceConfigVerifier, Decommitment as TraceDecommitmentVerifier,
        UnsentCommitment as TraceUnsentCommitmentVerifier, Witness as TraceWitnessVerifier,
    },
    types::{AddrValue, Page, SegmentInfo as SegmentInfoVerifier},
};
use swiftness_commitment::{
    table::{
        config::Config as TableConfigVerifier,
        types::{
            Decommitment as TableDecommitmentVerifier, Witness as TableCommitmentWitnessVerifier,
        },
    },
    vector::{
        config::Config as VectorConfigVerifier, types::Witness as VectorCommitmentWitnessVerifier,
    },
};
use swiftness_field::SimpleField;
use swiftness_fri::{
    config::Config as FriConfigVerifier,
    types::{
        LayerWitness, UnsentCommitment as FriUnsentCommitmentVerifier,
        Witness as FriWitnessVerifier,
    },
};
use swiftness_hash::poseidon::PoseidonHash;
use swiftness_pow::{
    config::Config as PowConfigVerifier, pow::UnsentCommitment as PowUnsentCommitmentVerifier,
};
use swiftness_stark::{
    config::StarkConfig as StarkConfigVerifier,
    types::{
        StarkProof as StarkProofVerifier, StarkUnsentCommitment as StarkUnsentCommitmentVerifier,
        StarkWitness as StarkWitnessVerifier,
    },
};

use crate::stark_proof::*;

impl<F: SimpleField + PoseidonHash> From<StarkProof> for StarkProofVerifier<F> {
    fn from(proof: StarkProof) -> Self {
        StarkProofVerifier {
            config: proof.config.into(),
            public_input: proof.public_input.into(),
            unsent_commitment: proof.unsent_commitment.into(),
            witness: proof.witness.into(),
        }
    }
}

impl<F: PrimeField + SimpleField + PoseidonHash> AllocVar<StarkProof, F>
    for StarkProofVerifier<FpVar<F>>
where
    FpVar<F>: PoseidonHash,
{
    fn new_variable<T: Borrow<StarkProof>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        f().and_then(|proof| {
            let ns = cs.into();
            let cs = ns.cs();
            let proof = proof.borrow();

            Ok(StarkProofVerifier {
                config: StarkConfigVerifier::new_variable(cs.clone(), || Ok(&proof.config), mode)?,
                public_input: PublicInputVerifier::new_variable(
                    cs.clone(),
                    || Ok(&proof.public_input),
                    mode,
                )?,
                unsent_commitment: StarkUnsentCommitmentVerifier::new_variable(
                    cs.clone(),
                    || Ok(&proof.unsent_commitment),
                    mode,
                )?,
                witness: StarkWitnessVerifier::new_variable(
                    cs.clone(),
                    || Ok(&proof.witness),
                    mode,
                )?,
            })
        })
    }
}

impl<F: SimpleField + PoseidonHash> From<StarkConfig> for StarkConfigVerifier<F> {
    fn from(config: StarkConfig) -> Self {
        StarkConfigVerifier {
            traces: config.traces.into(),
            composition: config.composition.into(),
            fri: config.fri.into(),
            proof_of_work: config.proof_of_work.into(),
            log_trace_domain_size: F::from_constant(config.log_trace_domain_size),
            n_queries: F::from_constant(config.n_queries),
            log_n_cosets: F::from_constant(config.log_n_cosets),
            n_verifier_friendly_commitment_layers: F::from_constant(
                config.n_verifier_friendly_commitment_layers,
            ),
        }
    }
}

impl<F: PrimeField + SimpleField + PoseidonHash> AllocVar<StarkConfig, F>
    for StarkConfigVerifier<FpVar<F>>
where
    FpVar<F>: PoseidonHash,
{
    fn new_variable<T: Borrow<StarkConfig>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        f().and_then(|config| {
            let ns = cs.into();
            let cs = ns.cs();
            let config = config.borrow();

            Ok(StarkConfigVerifier {
                traces: TraceConfigVerifier::new_variable(cs.clone(), || Ok(&config.traces), mode)?,
                composition: TableConfigVerifier::new_variable(
                    cs.clone(),
                    || Ok(&config.composition),
                    mode,
                )?,
                fri: FriConfigVerifier::new_variable(cs.clone(), || Ok(&config.fri), mode)?,
                proof_of_work: PowConfigVerifier::from(config.proof_of_work.clone()),
                log_trace_domain_size: FpVar::new_variable(
                    cs.clone(),
                    || Ok(F::from_constant(config.log_trace_domain_size)),
                    mode,
                )?,
                n_queries: FpVar::new_variable(
                    cs.clone(),
                    || Ok(F::from_constant(config.n_queries)),
                    mode,
                )?,
                log_n_cosets: FpVar::new_variable(
                    cs.clone(),
                    || Ok(F::from_constant(config.log_n_cosets)),
                    mode,
                )?,
                n_verifier_friendly_commitment_layers: FpVar::new_variable(
                    cs.clone(),
                    || {
                        Ok(F::from_constant(
                            config.n_verifier_friendly_commitment_layers,
                        ))
                    },
                    mode,
                )?,
            })
        })
    }
}

impl From<ProofOfWorkConfig> for PowConfigVerifier {
    fn from(pow: ProofOfWorkConfig) -> Self {
        PowConfigVerifier {
            n_bits: pow.n_bits as u8,
        }
    }
}

impl<F: SimpleField + PoseidonHash> From<FriConfig> for FriConfigVerifier<F> {
    fn from(fri: FriConfig) -> Self {
        FriConfigVerifier {
            log_input_size: F::from_constant(fri.log_input_size),
            n_layers: F::from_constant(fri.n_layers),
            inner_layers: fri.inner_layers.into_iter().map(|x| x.into()).collect(),
            fri_step_sizes: fri
                .fri_step_sizes
                .into_iter()
                .map(|x| F::from_constant(x))
                .collect(),
            log_last_layer_degree_bound: F::from_constant(fri.log_last_layer_degree_bound),
        }
    }
}

impl<F: PrimeField + SimpleField + PoseidonHash> AllocVar<FriConfig, F>
    for FriConfigVerifier<FpVar<F>>
where
    FpVar<F>: PoseidonHash,
{
    fn new_variable<T: Borrow<FriConfig>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        f().and_then(|fri| {
            let ns = cs.into();
            let cs = ns.cs();
            let fri = fri.borrow();

            Ok(FriConfigVerifier {
                log_input_size: FpVar::new_variable(
                    cs.clone(),
                    || Ok(F::from_constant(fri.log_input_size)),
                    mode,
                )?,
                n_layers: FpVar::new_variable(
                    cs.clone(),
                    || Ok(F::from_constant(fri.n_layers)),
                    mode,
                )?,
                inner_layers: fri
                    .inner_layers
                    .iter()
                    .map(|x| TableConfigVerifier::new_variable(cs.clone(), || Ok(x.clone()), mode))
                    .collect::<Result<Vec<_>, _>>()?,
                fri_step_sizes: fri
                    .fri_step_sizes
                    .iter()
                    .map(|x| FpVar::new_variable(cs.clone(), || Ok(F::from_constant(*x)), mode))
                    .collect::<Result<Vec<_>, _>>()?,
                log_last_layer_degree_bound: FpVar::new_variable(
                    cs.clone(),
                    || Ok(F::from_constant(fri.log_last_layer_degree_bound)),
                    mode,
                )?,
            })
        })
    }
}

impl<F: SimpleField + PoseidonHash> From<TracesConfig> for TraceConfigVerifier<F> {
    fn from(traces: TracesConfig) -> Self {
        TraceConfigVerifier {
            original: traces.original.into(),
            interaction: traces.interaction.into(),
        }
    }
}

impl<F: PrimeField + SimpleField + PoseidonHash> AllocVar<TracesConfig, F>
    for TraceConfigVerifier<FpVar<F>>
where
    FpVar<F>: PoseidonHash,
{
    fn new_variable<T: Borrow<TracesConfig>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        f().and_then(|traces| {
            let ns = cs.into();
            let cs = ns.cs();
            let traces = traces.borrow();

            Ok(TraceConfigVerifier {
                original: TableConfigVerifier::new_variable(
                    cs.clone(),
                    || Ok(&traces.original),
                    mode,
                )?,
                interaction: TableConfigVerifier::new_variable(
                    cs.clone(),
                    || Ok(&traces.interaction),
                    mode,
                )?,
            })
        })
    }
}

impl<F: SimpleField + PoseidonHash> From<TableCommitmentConfig> for TableConfigVerifier<F> {
    fn from(config: TableCommitmentConfig) -> Self {
        TableConfigVerifier {
            n_columns: F::from_constant(config.n_columns),
            vector: config.vector.into(),
        }
    }
}

impl<F: PrimeField + SimpleField + PoseidonHash> AllocVar<TableCommitmentConfig, F>
    for TableConfigVerifier<FpVar<F>>
where
    FpVar<F>: PoseidonHash,
{
    fn new_variable<T: Borrow<TableCommitmentConfig>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        f().and_then(|config| {
            let ns = cs.into();
            let cs = ns.cs();
            let config = config.borrow();

            Ok(TableConfigVerifier {
                n_columns: FpVar::new_variable(
                    cs.clone(),
                    || Ok(F::from_constant(config.n_columns)),
                    mode,
                )?,
                vector: VectorConfigVerifier::new_variable(
                    cs.clone(),
                    || Ok(&config.vector),
                    mode,
                )?,
            })
        })
    }
}

impl<F: SimpleField + PoseidonHash> From<VectorCommitmentConfig> for VectorConfigVerifier<F> {
    fn from(vector: VectorCommitmentConfig) -> Self {
        VectorConfigVerifier {
            height: F::from_constant(vector.height),
            n_verifier_friendly_commitment_layers: F::from_constant(
                vector.n_verifier_friendly_commitment_layers,
            ),
        }
    }
}

impl<F: PrimeField + SimpleField + PoseidonHash> AllocVar<VectorCommitmentConfig, F>
    for VectorConfigVerifier<FpVar<F>>
where
    FpVar<F>: PoseidonHash,
{
    fn new_variable<T: Borrow<VectorCommitmentConfig>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        f().and_then(|vector| {
            let ns = cs.into();
            let cs = ns.cs();
            let vector = vector.borrow();

            Ok(VectorConfigVerifier {
                height: FpVar::new_variable(
                    cs.clone(),
                    || Ok(F::from_constant(vector.height)),
                    mode,
                )?,
                n_verifier_friendly_commitment_layers: FpVar::new_variable(
                    cs.clone(),
                    || {
                        Ok(F::from_constant(
                            vector.n_verifier_friendly_commitment_layers,
                        ))
                    },
                    mode,
                )?,
            })
        })
    }
}

// ==================================================================================================

impl<F: SimpleField + PoseidonHash> From<CairoPublicInput> for PublicInputVerifier<F> {
    fn from(public_input: CairoPublicInput) -> Self {
        PublicInputVerifier {
            log_n_steps: F::from_constant(public_input.log_n_steps),
            range_check_min: F::from_constant(public_input.range_check_min),
            range_check_max: F::from_constant(public_input.range_check_max),
            layout: F::from_biguint(public_input.layout),
            dynamic_params: public_input
                .dynamic_params
                .values()
                .map(|x| F::from_biguint(x.clone()))
                .collect(),
            segments: public_input
                .segments
                .into_iter()
                .map(|x| x.into())
                .collect(),
            padding_addr: F::from_constant(public_input.padding_addr),
            padding_value: F::from_biguint(public_input.padding_value),
            main_page: Page(
                public_input
                    .main_page
                    .into_iter()
                    .map(|x| x.into())
                    .collect(),
            ),
            continuous_page_headers: vec![],
        }
    }
}

impl<F: PrimeField + SimpleField + PoseidonHash> AllocVar<CairoPublicInput, F>
    for PublicInputVerifier<FpVar<F>>
where
    FpVar<F>: PoseidonHash,
{
    fn new_variable<T: Borrow<CairoPublicInput>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        f().and_then(|public_input| {
            let ns = cs.into();
            let cs = ns.cs();
            let public_input = public_input.borrow();

            Ok(PublicInputVerifier {
                log_n_steps: FpVar::new_variable(
                    cs.clone(),
                    || Ok(F::from_constant(public_input.log_n_steps)),
                    mode,
                )?,
                range_check_min: FpVar::new_variable(
                    cs.clone(),
                    || Ok(F::from_constant(public_input.range_check_min)),
                    mode,
                )?,
                range_check_max: FpVar::new_variable(
                    cs.clone(),
                    || Ok(F::from_constant(public_input.range_check_max)),
                    mode,
                )?,
                layout: FpVar::new_variable(
                    cs.clone(),
                    || Ok(F::from_biguint(public_input.layout.clone())),
                    mode,
                )?,
                dynamic_params: public_input
                    .dynamic_params
                    .values()
                    .map(|x| {
                        FpVar::new_variable(cs.clone(), || Ok(F::from_biguint(x.clone())), mode)
                    })
                    .collect::<Result<Vec<_>, _>>()?,
                segments: public_input
                    .segments
                    .iter()
                    .map(|x| SegmentInfoVerifier::new_variable(cs.clone(), || Ok(x), mode))
                    .collect::<Result<Vec<_>, _>>()?,
                padding_addr: FpVar::new_variable(
                    cs.clone(),
                    || Ok(F::from_constant(public_input.padding_addr)),
                    mode,
                )?,
                padding_value: FpVar::new_variable(
                    cs.clone(),
                    || Ok(F::from_biguint(public_input.padding_value.clone())),
                    mode,
                )?,
                main_page: Page(
                    public_input
                        .main_page
                        .iter()
                        .map(|x| AddrValue::new_variable(cs.clone(), || Ok(x), mode))
                        .collect::<Result<Vec<_>, _>>()?,
                ),
                continuous_page_headers: vec![],
            })
        })
    }
}

impl<F: SimpleField + PoseidonHash> From<SegmentInfo> for SegmentInfoVerifier<F> {
    fn from(segment_info: SegmentInfo) -> Self {
        SegmentInfoVerifier {
            begin_addr: F::from_constant(segment_info.begin_addr),
            stop_ptr: F::from_constant(segment_info.stop_ptr),
        }
    }
}

impl<F: PrimeField + SimpleField + PoseidonHash> AllocVar<SegmentInfo, F>
    for SegmentInfoVerifier<FpVar<F>>
where
    FpVar<F>: PoseidonHash,
{
    fn new_variable<T: Borrow<SegmentInfo>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        f().and_then(|segment_info| {
            let ns = cs.into();
            let cs = ns.cs();
            let segment_info = segment_info.borrow();

            Ok(SegmentInfoVerifier {
                begin_addr: FpVar::new_variable(
                    cs.clone(),
                    || Ok(F::from_constant(segment_info.begin_addr)),
                    mode,
                )?,
                stop_ptr: FpVar::new_variable(
                    cs.clone(),
                    || Ok(F::from_constant(segment_info.stop_ptr)),
                    mode,
                )?,
            })
        })
    }
}

impl<F: SimpleField + PoseidonHash> From<PubilcMemoryCell> for AddrValue<F> {
    fn from(cell: PubilcMemoryCell) -> Self {
        AddrValue {
            address: F::from_constant(cell.address),
            value: F::from_biguint(cell.value),
        }
    }
}

impl<F: PrimeField + SimpleField + PoseidonHash> AllocVar<PubilcMemoryCell, F>
    for AddrValue<FpVar<F>>
where
    FpVar<F>: PoseidonHash,
{
    fn new_variable<T: Borrow<PubilcMemoryCell>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        f().and_then(|cell| {
            let ns = cs.into();
            let cs = ns.cs();
            let cell = cell.borrow();

            Ok(AddrValue {
                address: FpVar::new_variable(
                    cs.clone(),
                    || Ok(F::from_constant(cell.address)),
                    mode,
                )?,
                value: FpVar::new_variable(
                    cs.clone(),
                    || Ok(F::from_biguint(cell.value.clone())),
                    mode,
                )?,
            })
        })
    }
}

// =================================================================================================

impl<F: SimpleField + PoseidonHash> From<StarkUnsentCommitment>
    for StarkUnsentCommitmentVerifier<F>
{
    fn from(unsent_commitment: StarkUnsentCommitment) -> Self {
        StarkUnsentCommitmentVerifier {
            traces: unsent_commitment.traces.into(),
            composition: F::from_biguint(unsent_commitment.composition),
            oods_values: unsent_commitment
                .oods_values
                .into_iter()
                .map(|x| F::from_biguint(x))
                .collect(),
            fri: unsent_commitment.fri.into(),
            proof_of_work: unsent_commitment.proof_of_work.into(),
        }
    }
}

impl<F: PrimeField + SimpleField + PoseidonHash> AllocVar<StarkUnsentCommitment, F>
    for StarkUnsentCommitmentVerifier<FpVar<F>>
where
    FpVar<F>: PoseidonHash,
{
    fn new_variable<T: Borrow<StarkUnsentCommitment>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        f().and_then(|unsent_commitment| {
            let ns = cs.into();
            let cs = ns.cs();
            let unsent_commitment = unsent_commitment.borrow();

            Ok(StarkUnsentCommitmentVerifier {
                traces: TraceUnsentCommitmentVerifier::new_variable(
                    cs.clone(),
                    || Ok(unsent_commitment.traces.clone()),
                    mode,
                )?,
                composition: FpVar::new_variable(
                    cs.clone(),
                    || Ok(F::from_biguint(unsent_commitment.composition.clone())),
                    mode,
                )?,
                oods_values: unsent_commitment
                    .oods_values
                    .iter()
                    .map(|x| {
                        FpVar::new_variable(cs.clone(), || Ok(F::from_biguint(x.clone())), mode)
                    })
                    .collect::<Result<Vec<_>, _>>()?,
                fri: FriUnsentCommitmentVerifier::new_variable(
                    cs.clone(),
                    || Ok(unsent_commitment.fri.clone()),
                    mode,
                )?,
                proof_of_work: unsent_commitment.proof_of_work.clone().into(),
            })
        })
    }
}

impl<F: SimpleField + PoseidonHash> From<TracesUnsentCommitment>
    for TraceUnsentCommitmentVerifier<F>
{
    fn from(traces: TracesUnsentCommitment) -> Self {
        TraceUnsentCommitmentVerifier {
            original: F::from_biguint(traces.original),
            interaction: F::from_biguint(traces.interaction),
        }
    }
}

impl<F: PrimeField + SimpleField + PoseidonHash> AllocVar<TracesUnsentCommitment, F>
    for TraceUnsentCommitmentVerifier<FpVar<F>>
where
    FpVar<F>: PoseidonHash,
{
    fn new_variable<T: Borrow<TracesUnsentCommitment>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        f().and_then(|traces| {
            let ns = cs.into();
            let cs = ns.cs();
            let traces = traces.borrow();

            Ok(TraceUnsentCommitmentVerifier {
                original: FpVar::new_variable(
                    cs.clone(),
                    || Ok(F::from_biguint(traces.original.clone())),
                    mode,
                )?,
                interaction: FpVar::new_variable(
                    cs.clone(),
                    || Ok(F::from_biguint(traces.interaction.clone())),
                    mode,
                )?,
            })
        })
    }
}

impl<F: SimpleField + PoseidonHash> From<FriUnsentCommitment> for FriUnsentCommitmentVerifier<F> {
    fn from(fri: FriUnsentCommitment) -> Self {
        FriUnsentCommitmentVerifier {
            last_layer_coefficients: fri
                .last_layer_coefficients
                .into_iter()
                .map(|x| F::from_biguint(x))
                .collect(),
            inner_layers: fri
                .inner_layers
                .into_iter()
                .map(|x| F::from_biguint(x))
                .collect(),
        }
    }
}

impl<F: PrimeField + SimpleField + PoseidonHash> AllocVar<FriUnsentCommitment, F>
    for FriUnsentCommitmentVerifier<FpVar<F>>
where
    FpVar<F>: PoseidonHash,
{
    fn new_variable<T: Borrow<FriUnsentCommitment>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        f().and_then(|fri| {
            let ns = cs.into();
            let cs = ns.cs();
            let fri = fri.borrow();

            Ok(FriUnsentCommitmentVerifier {
                last_layer_coefficients: fri
                    .last_layer_coefficients
                    .iter()
                    .map(|x| {
                        FpVar::new_variable(cs.clone(), || Ok(F::from_biguint(x.clone())), mode)
                    })
                    .collect::<Result<Vec<_>, _>>()?,
                inner_layers: fri
                    .inner_layers
                    .iter()
                    .map(|x| {
                        FpVar::new_variable(cs.clone(), || Ok(F::from_biguint(x.clone())), mode)
                    })
                    .collect::<Result<Vec<_>, _>>()?,
            })
        })
    }
}

impl From<ProofOfWorkUnsentCommitment> for PowUnsentCommitmentVerifier {
    fn from(pow: ProofOfWorkUnsentCommitment) -> Self {
        PowUnsentCommitmentVerifier {
            nonce: pow.nonce.to_u64_digits()[0],
        }
    }
}

// =================================================================================================

impl<F: SimpleField + PoseidonHash> From<StarkWitness> for StarkWitnessVerifier<F> {
    fn from(witness: StarkWitness) -> Self {
        StarkWitnessVerifier {
            traces_decommitment: witness.traces_decommitment.into(),
            traces_witness: witness.traces_witness.into(),
            composition_decommitment: witness.composition_decommitment.into(),
            composition_witness: witness.composition_witness.into(),
            fri_witness: witness.fri_witness.into(),
        }
    }
}

impl<F: PrimeField + SimpleField + PoseidonHash> AllocVar<StarkWitness, F>
    for StarkWitnessVerifier<FpVar<F>>
where
    FpVar<F>: PoseidonHash,
{
    fn new_variable<T: Borrow<StarkWitness>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        f().and_then(|witness| {
            let ns = cs.into();
            let cs = ns.cs();
            let witness = witness.borrow();

            Ok(StarkWitnessVerifier {
                traces_decommitment: TraceDecommitmentVerifier::new_variable(
                    cs.clone(),
                    || Ok(witness.traces_decommitment.clone()),
                    mode,
                )?,
                traces_witness: TraceWitnessVerifier::new_variable(
                    cs.clone(),
                    || Ok(witness.traces_witness.clone()),
                    mode,
                )?,
                composition_decommitment: TableDecommitmentVerifier::new_variable(
                    cs.clone(),
                    || Ok(witness.composition_decommitment.clone()),
                    mode,
                )?,
                composition_witness: TableCommitmentWitnessVerifier::new_variable(
                    cs.clone(),
                    || Ok(witness.composition_witness.clone()),
                    mode,
                )?,
                fri_witness: FriWitnessVerifier::new_variable(
                    cs.clone(),
                    || Ok(witness.fri_witness.clone()),
                    mode,
                )?,
            })
        })
    }
}

impl<F: SimpleField + PoseidonHash> From<TracesDecommitment> for TraceDecommitmentVerifier<F> {
    fn from(traces: TracesDecommitment) -> Self {
        TraceDecommitmentVerifier {
            original: traces.original.into(),
            interaction: traces.interaction.into(),
        }
    }
}

impl<F: SimpleField + PoseidonHash> From<TableDecommitment> for TableDecommitmentVerifier<F> {
    fn from(table: TableDecommitment) -> Self {
        TableDecommitmentVerifier {
            values: table
                .values
                .into_iter()
                .map(|x| F::from_biguint(x))
                .collect(),
        }
    }
}

impl<F: PrimeField + SimpleField + PoseidonHash> AllocVar<TracesDecommitment, F>
    for TraceDecommitmentVerifier<FpVar<F>>
where
    FpVar<F>: PoseidonHash,
{
    fn new_variable<T: Borrow<TracesDecommitment>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        f().and_then(|traces| {
            let ns = cs.into();
            let cs = ns.cs();
            let traces = traces.borrow();

            Ok(TraceDecommitmentVerifier {
                original: TableDecommitmentVerifier::new_variable(
                    cs.clone(),
                    || Ok(traces.original.clone()),
                    mode,
                )?,
                interaction: TableDecommitmentVerifier::new_variable(
                    cs.clone(),
                    || Ok(traces.interaction.clone()),
                    mode,
                )?,
            })
        })
    }
}

impl<F: PrimeField + SimpleField + PoseidonHash> AllocVar<TableDecommitment, F>
    for TableDecommitmentVerifier<FpVar<F>>
where
    FpVar<F>: PoseidonHash,
{
    fn new_variable<T: Borrow<TableDecommitment>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        f().and_then(|table| {
            let ns = cs.into();
            let cs = ns.cs();
            let table = table.borrow();

            Ok(TableDecommitmentVerifier {
                values: table
                    .values
                    .iter()
                    .map(|x| {
                        FpVar::<F>::new_variable(
                            cs.clone(),
                            || Ok(F::from_biguint(x.clone())),
                            mode,
                        )
                    })
                    .collect::<Result<Vec<_>, _>>()?,
            })
        })
    }
}

impl<F: SimpleField + PoseidonHash> From<TracesWitness> for TraceWitnessVerifier<F> {
    fn from(traces: TracesWitness) -> Self {
        TraceWitnessVerifier {
            original: traces.original.into(),
            interaction: traces.interaction.into(),
        }
    }
}

impl<F: PrimeField + SimpleField + PoseidonHash> AllocVar<TracesWitness, F>
    for TraceWitnessVerifier<FpVar<F>>
where
    FpVar<F>: PoseidonHash,
{
    fn new_variable<T: Borrow<TracesWitness>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        f().and_then(|traces| {
            let ns = cs.into();
            let cs = ns.cs();
            let traces = traces.borrow();

            Ok(TraceWitnessVerifier {
                original: TableCommitmentWitnessVerifier::new_variable(
                    cs.clone(),
                    || Ok(traces.original.clone()),
                    mode,
                )?,
                interaction: TableCommitmentWitnessVerifier::new_variable(
                    cs.clone(),
                    || Ok(traces.interaction.clone()),
                    mode,
                )?,
            })
        })
    }
}

impl<F: SimpleField + PoseidonHash> From<TableCommitmentWitness>
    for TableCommitmentWitnessVerifier<F>
{
    fn from(table: TableCommitmentWitness) -> Self {
        TableCommitmentWitnessVerifier {
            vector: table.vector.into(),
        }
    }
}

impl<F: PrimeField + SimpleField + PoseidonHash> AllocVar<TableCommitmentWitness, F>
    for TableCommitmentWitnessVerifier<FpVar<F>>
where
    FpVar<F>: PoseidonHash,
{
    fn new_variable<T: Borrow<TableCommitmentWitness>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        f().and_then(|table| {
            let ns = cs.into();
            let cs = ns.cs();
            let table = table.borrow();

            Ok(TableCommitmentWitnessVerifier {
                vector: VectorCommitmentWitnessVerifier::new_variable::<VectorCommitmentWitness>(
                    cs.clone(),
                    || Ok(table.vector.clone()),
                    mode,
                )?,
            })
        })
    }
}

impl<F: SimpleField + PoseidonHash> From<VectorCommitmentWitness>
    for VectorCommitmentWitnessVerifier<F>
{
    fn from(vector: VectorCommitmentWitness) -> Self {
        VectorCommitmentWitnessVerifier {
            authentications: vector
                .authentications
                .into_iter()
                .map(|x| F::from_biguint(x))
                .collect(),
        }
    }
}

impl<F: PrimeField + SimpleField + PoseidonHash> AllocVar<VectorCommitmentWitness, F>
    for VectorCommitmentWitnessVerifier<FpVar<F>>
where
    FpVar<F>: PoseidonHash,
{
    fn new_variable<T: Borrow<VectorCommitmentWitness>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        f().and_then(|vector| {
            let ns = cs.into();
            let cs = ns.cs();
            let vector = vector.borrow();

            Ok(VectorCommitmentWitnessVerifier {
                authentications: vector
                    .authentications
                    .iter()
                    .map(|x| {
                        FpVar::<F>::new_variable(
                            cs.clone(),
                            || Ok(F::from_biguint(x.clone())),
                            mode,
                        )
                    })
                    .collect::<Result<Vec<_>, _>>()?,
            })
        })
    }
}

impl<F: SimpleField + PoseidonHash> From<FriWitness> for FriWitnessVerifier<F> {
    fn from(fri: FriWitness) -> Self {
        FriWitnessVerifier {
            layers: fri.layers.into_iter().map(|x| x.into()).collect(),
        }
    }
}

impl<F: SimpleField + PoseidonHash> From<FriLayerWitness> for LayerWitness<F> {
    fn from(layer: FriLayerWitness) -> Self {
        LayerWitness {
            leaves: layer
                .leaves
                .into_iter()
                .map(|x| F::from_biguint(x))
                .collect(),
            table_witness: layer.table_witness.into(),
        }
    }
}

impl<F: PrimeField + SimpleField + PoseidonHash> AllocVar<FriWitness, F>
    for FriWitnessVerifier<FpVar<F>>
where
    FpVar<F>: PoseidonHash,
{
    fn new_variable<T: Borrow<FriWitness>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        f().and_then(|fri| {
            let ns = cs.into();
            let cs = ns.cs();
            let fri = fri.borrow();

            Ok(FriWitnessVerifier {
                layers: fri
                    .layers
                    .iter()
                    .map(|layer| LayerWitness::new_variable(cs.clone(), || Ok(layer), mode))
                    .collect::<Result<Vec<_>, _>>()?,
            })
        })
    }
}

impl<F: PrimeField + SimpleField + PoseidonHash> AllocVar<FriLayerWitness, F>
    for LayerWitness<FpVar<F>>
where
    FpVar<F>: PoseidonHash,
{
    fn new_variable<T: Borrow<FriLayerWitness>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        f().and_then(|layer| {
            let ns = cs.into();
            let cs = ns.cs();
            let layer = layer.borrow();

            Ok(LayerWitness {
                leaves: layer
                    .leaves
                    .iter()
                    .map(|x| {
                        FpVar::<F>::new_variable(
                            cs.clone(),
                            || Ok(F::from_biguint(x.clone())),
                            mode,
                        )
                    })
                    .collect::<Result<Vec<_>, _>>()?,
                table_witness: TableCommitmentWitnessVerifier::new_variable::<
                    TableCommitmentWitnessFlat,
                >(
                    cs.clone(), || Ok(layer.table_witness.clone()), mode
                )?,
            })
        })
    }
}

impl<F: SimpleField + PoseidonHash> From<TableCommitmentWitnessFlat>
    for TableCommitmentWitnessVerifier<F>
{
    fn from(table: TableCommitmentWitnessFlat) -> Self {
        TableCommitmentWitnessVerifier {
            vector: table.vector.into(),
        }
    }
}

impl<F: PrimeField + SimpleField + PoseidonHash> AllocVar<TableCommitmentWitnessFlat, F>
    for TableCommitmentWitnessVerifier<FpVar<F>>
where
    FpVar<F>: PoseidonHash,
{
    fn new_variable<T: Borrow<TableCommitmentWitnessFlat>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        f().and_then(|flat| {
            let ns = cs.into();
            let cs = ns.cs();
            let flat = flat.borrow();

            Ok(TableCommitmentWitnessVerifier {
                vector: VectorCommitmentWitnessVerifier::new_variable::<VectorCommitmentWitnessFlat>(
                    cs.clone(),
                    || Ok(flat.vector.clone()),
                    mode,
                )?,
            })
        })
    }
}

impl<F: SimpleField + PoseidonHash> From<VectorCommitmentWitnessFlat>
    for VectorCommitmentWitnessVerifier<F>
{
    fn from(vector: VectorCommitmentWitnessFlat) -> Self {
        VectorCommitmentWitnessVerifier {
            authentications: vector
                .authentications
                .into_iter()
                .map(|x| F::from_biguint(x))
                .collect(),
        }
    }
}

impl<F: PrimeField + SimpleField + PoseidonHash> AllocVar<VectorCommitmentWitnessFlat, F>
    for VectorCommitmentWitnessVerifier<FpVar<F>>
where
    FpVar<F>: PoseidonHash,
{
    fn new_variable<T: Borrow<VectorCommitmentWitnessFlat>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        f().and_then(|flat| {
            let ns = cs.into();
            let cs = ns.cs();
            let flat = flat.borrow();

            Ok(VectorCommitmentWitnessVerifier {
                authentications: flat
                    .authentications
                    .iter()
                    .map(|x| {
                        FpVar::<F>::new_variable(
                            cs.clone(),
                            || Ok(F::from_biguint(x.clone())),
                            mode,
                        )
                    })
                    .collect::<Result<Vec<_>, _>>()?,
            })
        })
    }
}
