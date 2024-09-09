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
            n_verifier_friendly_commitment_layers: F::from_constant(config
                .n_verifier_friendly_commitment_layers)
        }
    }
}

impl From<ProofOfWorkConfig> for PowConfigVerifier {
    fn from(pow: ProofOfWorkConfig) -> Self {
        PowConfigVerifier { n_bits: pow.n_bits as u8 }
    }
}

impl<F: SimpleField + PoseidonHash> From<FriConfig> for FriConfigVerifier<F> {
    fn from(fri: FriConfig) -> Self {
        FriConfigVerifier {
            log_input_size: F::from_constant(fri.log_input_size),
            n_layers: F::from_constant(fri.n_layers),
            inner_layers: fri.inner_layers.into_iter().map(|x| x.into()).collect(),
            fri_step_sizes: fri.fri_step_sizes.into_iter().map(|x| F::from_constant(x)).collect(),
            log_last_layer_degree_bound: F::from_constant(fri.log_last_layer_degree_bound),
        }
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

impl<F: SimpleField + PoseidonHash> From<TableCommitmentConfig> for TableConfigVerifier<F> {
    fn from(config: TableCommitmentConfig) -> Self {
        TableConfigVerifier { n_columns: F::from_constant(config.n_columns), vector: config.vector.into() }
    }
}

impl<F: SimpleField + PoseidonHash> From<VectorCommitmentConfig> for VectorConfigVerifier<F> {
    fn from(vector: VectorCommitmentConfig) -> Self {
        VectorConfigVerifier {
            height: F::from_constant(vector.height),
            n_verifier_friendly_commitment_layers: F::from_constant(vector
                .n_verifier_friendly_commitment_layers)
        }
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
            dynamic_params: public_input.dynamic_params.values().map(|x| F::from_biguint(x.clone())).collect(),
            segments: public_input.segments.into_iter().map(|x| x.into()).collect(),
            padding_addr: F::from_constant(public_input.padding_addr),
            padding_value: F::from_biguint(public_input.padding_value),
            main_page: Page(public_input.main_page.into_iter().map(|x| x.into()).collect()),
            continuous_page_headers: vec![],
        }
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

impl<F: SimpleField + PoseidonHash> From<PubilcMemoryCell> for AddrValue<F> {
    fn from(cell: PubilcMemoryCell) -> Self {
        AddrValue { address: F::from_constant(cell.address), value: F::from_biguint(cell.value) }
    }
}

// =================================================================================================

impl<F: SimpleField + PoseidonHash> From<StarkUnsentCommitment> for StarkUnsentCommitmentVerifier<F> {
    fn from(unsent_commitment: StarkUnsentCommitment) -> Self {
        StarkUnsentCommitmentVerifier {
            traces: unsent_commitment.traces.into(),
            composition: F::from_biguint(unsent_commitment.composition),
            oods_values: unsent_commitment.oods_values.into_iter().map(|x| F::from_biguint(x)).collect(),
            fri: unsent_commitment.fri.into(),
            proof_of_work: unsent_commitment.proof_of_work.into(),
        }
    }
}

impl<F: SimpleField + PoseidonHash> From<TracesUnsentCommitment> for TraceUnsentCommitmentVerifier<F> {
    fn from(traces: TracesUnsentCommitment) -> Self {
        TraceUnsentCommitmentVerifier {
            original: F::from_biguint(traces.original),
            interaction: F::from_biguint(traces.interaction),
        }
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
            inner_layers: fri.inner_layers.into_iter().map(|x| F::from_biguint(x)).collect(),
        }
    }
}

impl From<ProofOfWorkUnsentCommitment> for PowUnsentCommitmentVerifier {
    fn from(pow: ProofOfWorkUnsentCommitment) -> Self {
        PowUnsentCommitmentVerifier { nonce: pow.nonce.to_u64_digits()[0] }
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
        TableDecommitmentVerifier { values: table.values.into_iter().map(|x| F::from_biguint(x)).collect() }
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

impl<F: SimpleField + PoseidonHash> From<TableCommitmentWitness> for TableCommitmentWitnessVerifier<F> {
    fn from(table: TableCommitmentWitness) -> Self {
        TableCommitmentWitnessVerifier { vector: table.vector.into() }
    }
}

impl<F: SimpleField + PoseidonHash> From<VectorCommitmentWitness> for VectorCommitmentWitnessVerifier<F> {
    fn from(vector: VectorCommitmentWitness) -> Self {
        VectorCommitmentWitnessVerifier {
            authentications: vector.authentications.into_iter().map(|x| F::from_biguint(x)).collect(),
        }
    }
}

impl<F: SimpleField + PoseidonHash> From<FriWitness> for FriWitnessVerifier<F> {
    fn from(fri: FriWitness) -> Self {
        FriWitnessVerifier { layers: fri.layers.into_iter().map(|x| x.into()).collect() }
    }
}

impl<F: SimpleField + PoseidonHash> From<FriLayerWitness> for LayerWitness<F> {
    fn from(layer: FriLayerWitness) -> Self {
        LayerWitness {
            leaves: layer.leaves.into_iter().map(|x| F::from_biguint(x)).collect(),
            table_witness: layer.table_witness.into(),
        }
    }
}

impl<F: SimpleField + PoseidonHash> From<TableCommitmentWitnessFlat> for TableCommitmentWitnessVerifier<F> {
    fn from(table: TableCommitmentWitnessFlat) -> Self {
        TableCommitmentWitnessVerifier { vector: table.vector.into() }
    }
}

impl<F: SimpleField + PoseidonHash> From<VectorCommitmentWitnessFlat> for VectorCommitmentWitnessVerifier<F> {
    fn from(vector: VectorCommitmentWitnessFlat) -> Self {
        VectorCommitmentWitnessVerifier {
            authentications: vector.authentications.into_iter().map(|x| F::from_biguint(x)).collect(),
        }
    }
}
