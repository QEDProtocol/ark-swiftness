use crate::trace;
use starknet_crypto::Felt;
use swiftness_commitment::{table, vector};
use swiftness_field::SimpleField;
use swiftness_hash::poseidon::PoseidonHash;

pub fn get<F: SimpleField + PoseidonHash>() -> trace::config::Config<F> {
    trace::config::Config {
        original: table::config::Config {
            n_columns: F::from_stark_felt(Felt::from_hex_unchecked("0x7")),
            vector: vector::config::Config {
                height: F::from_stark_felt(Felt::from_hex_unchecked("0x14")),
                n_verifier_friendly_commitment_layers: F::from_stark_felt(
                    Felt::from_hex_unchecked("0x64"),
                ),
            },
        },
        interaction: table::config::Config {
            n_columns: F::from_stark_felt(Felt::from_hex_unchecked("0x3")),
            vector: vector::config::Config {
                height: F::from_stark_felt(Felt::from_hex_unchecked("0x14")),
                n_verifier_friendly_commitment_layers: F::from_stark_felt(
                    Felt::from_hex_unchecked("0x64"),
                ),
            },
        },
    }
}
