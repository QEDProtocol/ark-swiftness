use crate::config::Config;
use alloc::vec;
use starknet_crypto::Felt;
use swiftness_commitment::{table, vector};
use swiftness_field::SimpleField;
use swiftness_hash::poseidon::PoseidonHash;

pub fn get<F: SimpleField + PoseidonHash>() -> Config<F> {
    Config {
        log_input_size: F::from_stark_felt(Felt::from_hex_unchecked("0x14")),
        n_layers: F::from_stark_felt(Felt::from_hex_unchecked("0x5")),
        inner_layers: vec![
            table::config::Config {
                n_columns: F::from_stark_felt(Felt::from_hex_unchecked("0x10")),
                vector: vector::config::Config {
                    height: F::from_stark_felt(Felt::from_hex_unchecked("0x10")),
                    n_verifier_friendly_commitment_layers: F::from_stark_felt(Felt::from_hex_unchecked("0x64")),
                },
            },
            table::config::Config {
                n_columns: F::from_stark_felt(Felt::from_hex_unchecked("0x8")),
                vector: vector::config::Config {
                    height: F::from_stark_felt(Felt::from_hex_unchecked("0xd")),
                    n_verifier_friendly_commitment_layers: F::from_stark_felt(Felt::from_hex_unchecked("0x64")),
                },
            },
            table::config::Config {
                n_columns: F::from_stark_felt(Felt::from_hex_unchecked("0x4")),
                vector: vector::config::Config {
                    height: F::from_stark_felt(Felt::from_hex_unchecked("0xb")),
                    n_verifier_friendly_commitment_layers: F::from_stark_felt(Felt::from_hex_unchecked("0x64")),
                },
            },
            table::config::Config {
                n_columns: F::from_stark_felt(Felt::from_hex_unchecked("0x4")),
                vector: vector::config::Config {
                    height: F::from_stark_felt(Felt::from_hex_unchecked("0x9")),
                    n_verifier_friendly_commitment_layers: F::from_stark_felt(Felt::from_hex_unchecked("0x64")),
                },
            },
        ],
        fri_step_sizes: vec![
            F::from_stark_felt(Felt::from_hex_unchecked("0x0")),
            F::from_stark_felt(Felt::from_hex_unchecked("0x4")),
            F::from_stark_felt(Felt::from_hex_unchecked("0x3")),
            F::from_stark_felt(Felt::from_hex_unchecked("0x2")),
            F::from_stark_felt(Felt::from_hex_unchecked("0x2")),
        ],
        log_last_layer_degree_bound: F::from_stark_felt(Felt::from_hex_unchecked("0x7")),
    }
}
