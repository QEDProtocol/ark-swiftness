use starknet_crypto::Felt;
use swiftness_commitment::{
    table::config::Config as TableCommitmentConfig,
    vector::config::Config as VectorCommitmentConfig,
};
use swiftness_field::SimpleField;
use swiftness_hash::poseidon::PoseidonHash;

use crate::config::StarkConfig;

pub fn get<F: SimpleField + PoseidonHash>() -> StarkConfig<F> {
    StarkConfig {
        traces: swiftness_air::fixtures::config::get(),
        composition: TableCommitmentConfig {
            n_columns: F::from_stark_felt(Felt::from_hex_unchecked("0x2")),
            vector: VectorCommitmentConfig {
                height: F::from_stark_felt(Felt::from_hex_unchecked("0x14")),
                n_verifier_friendly_commitment_layers: F::from_stark_felt(Felt::from_hex_unchecked("0x64")),
            },
        },
        fri: swiftness_fri::fixtures::config::get(),
        proof_of_work: swiftness_pow::fixtures::config::get(),
        log_trace_domain_size: F::from_stark_felt(Felt::from_hex_unchecked("0x12")),
        n_queries: F::from_stark_felt(Felt::from_hex_unchecked("0xa")),
        log_n_cosets: F::from_stark_felt(Felt::from_hex_unchecked("0x2")),
        n_verifier_friendly_commitment_layers: F::from_stark_felt(Felt::from_hex_unchecked("0x64")),
    }
}
