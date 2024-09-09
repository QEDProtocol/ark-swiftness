use super::{config, interaction_elements, unsent_commitment};
use crate::{layout::recursive::global_values::InteractionElements, trace::Commitment};
use starknet_crypto::Felt;
use swiftness_commitment::{table, vector};
use swiftness_field::SimpleField;
use swiftness_hash::poseidon::PoseidonHash;

pub fn get<F: SimpleField + PoseidonHash>() -> Commitment<InteractionElements<F>, F> {
    let unsent_commitment = unsent_commitment::get();
    let traces_config = config::get();

    Commitment {
        original: table::types::Commitment {
            config: traces_config.original,
            vector_commitment: vector::types::Commitment {
                config: vector::config::Config {
                    height: F::from_stark_felt(Felt::from_hex_unchecked("0x14")),
                    n_verifier_friendly_commitment_layers: F::from_stark_felt(Felt::from_hex_unchecked("0x64")),
                },
                commitment_hash: unsent_commitment.original,
            },
        },
        interaction_elements: interaction_elements::get(),
        interaction: table::types::Commitment {
            config: traces_config.interaction,
            vector_commitment: vector::types::Commitment {
                config: vector::config::Config {
                    height: F::from_stark_felt(Felt::from_hex_unchecked("0x14")),
                    n_verifier_friendly_commitment_layers: F::from_stark_felt(Felt::from_hex_unchecked("0x64")),
                },
                commitment_hash: unsent_commitment.interaction,
            },
        },
    }
}
