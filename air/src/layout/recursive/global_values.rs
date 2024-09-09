use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use swiftness_field::SimpleField;
use swiftness_hash::poseidon::PoseidonHash;
use swiftness_transcript::transcript::Transcript;

#[serde_as]
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct EcPoint<F: SimpleField + PoseidonHash> {
    #[cfg_attr(
        feature = "std",
        serde_as(as = "starknet_core::serde::unsigned_field_element::UfeHex")
    )]
    pub x: F,
    #[cfg_attr(
        feature = "std",
        serde_as(as = "starknet_core::serde::unsigned_field_element::UfeHex")
    )]
    pub y: F,
}

// Accumulation of member expressions for auto generated composition polynomial code.
#[serde_as]
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct GlobalValues<F: SimpleField + PoseidonHash> {
    // Public input.
    #[cfg_attr(
        feature = "std",
        serde_as(as = "starknet_core::serde::unsigned_field_element::UfeHex")
    )]
    pub trace_length: F,
    #[cfg_attr(
        feature = "std",
        serde_as(as = "starknet_core::serde::unsigned_field_element::UfeHex")
    )]
    pub initial_pc: F,
    #[cfg_attr(
        feature = "std",
        serde_as(as = "starknet_core::serde::unsigned_field_element::UfeHex")
    )]
    pub final_pc: F,
    #[cfg_attr(
        feature = "std",
        serde_as(as = "starknet_core::serde::unsigned_field_element::UfeHex")
    )]
    pub initial_ap: F,
    #[cfg_attr(
        feature = "std",
        serde_as(as = "starknet_core::serde::unsigned_field_element::UfeHex")
    )]
    pub final_ap: F,
    #[cfg_attr(
        feature = "std",
        serde_as(as = "starknet_core::serde::unsigned_field_element::UfeHex")
    )]
    pub initial_pedersen_addr: F,
    #[cfg_attr(
        feature = "std",
        serde_as(as = "starknet_core::serde::unsigned_field_element::UfeHex")
    )]
    pub initial_range_check_addr: F,
    #[cfg_attr(
        feature = "std",
        serde_as(as = "starknet_core::serde::unsigned_field_element::UfeHex")
    )]
    pub initial_bitwise_addr: F,
    #[cfg_attr(
        feature = "std",
        serde_as(as = "starknet_core::serde::unsigned_field_element::UfeHex")
    )]
    pub range_check_min: F,
    #[cfg_attr(
        feature = "std",
        serde_as(as = "starknet_core::serde::unsigned_field_element::UfeHex")
    )]
    pub range_check_max: F,
    // Constants.
    #[cfg_attr(
        feature = "std",
        serde_as(as = "starknet_core::serde::unsigned_field_element::UfeHex")
    )]
    pub offset_size: F,
    #[cfg_attr(
        feature = "std",
        serde_as(as = "starknet_core::serde::unsigned_field_element::UfeHex")
    )]
    pub half_offset_size: F,
    pub pedersen_shift_point: EcPoint<F>,
    // Periodic columns.
    #[cfg_attr(
        feature = "std",
        serde_as(as = "starknet_core::serde::unsigned_field_element::UfeHex")
    )]
    pub pedersen_points_x: F,
    #[cfg_attr(
        feature = "std",
        serde_as(as = "starknet_core::serde::unsigned_field_element::UfeHex")
    )]
    pub pedersen_points_y: F,
    // Interaction elements.
    #[cfg_attr(
        feature = "std",
        serde_as(as = "starknet_core::serde::unsigned_field_element::UfeHex")
    )]
    pub memory_multi_column_perm_perm_interaction_elm: F,
    #[cfg_attr(
        feature = "std",
        serde_as(as = "starknet_core::serde::unsigned_field_element::UfeHex")
    )]
    pub memory_multi_column_perm_hash_interaction_elm0: F,
    #[cfg_attr(
        feature = "std",
        serde_as(as = "starknet_core::serde::unsigned_field_element::UfeHex")
    )]
    pub range_check16_perm_interaction_elm: F,
    #[cfg_attr(
        feature = "std",
        serde_as(as = "starknet_core::serde::unsigned_field_element::UfeHex")
    )]
    pub diluted_check_permutation_interaction_elm: F,
    #[cfg_attr(
        feature = "std",
        serde_as(as = "starknet_core::serde::unsigned_field_element::UfeHex")
    )]
    pub diluted_check_interaction_z: F,
    #[cfg_attr(
        feature = "std",
        serde_as(as = "starknet_core::serde::unsigned_field_element::UfeHex")
    )]
    pub diluted_check_interaction_alpha: F,
    // Permutation products.
    #[cfg_attr(
        feature = "std",
        serde_as(as = "starknet_core::serde::unsigned_field_element::UfeHex")
    )]
    pub memory_multi_column_perm_perm_public_memory_prod: F,
    #[cfg_attr(
        feature = "std",
        serde_as(as = "starknet_core::serde::unsigned_field_element::UfeHex")
    )]
    pub range_check16_perm_public_memory_prod: F,
    #[cfg_attr(
        feature = "std",
        serde_as(as = "starknet_core::serde::unsigned_field_element::UfeHex")
    )]
    pub diluted_check_first_elm: F,
    #[cfg_attr(
        feature = "std",
        serde_as(as = "starknet_core::serde::unsigned_field_element::UfeHex")
    )]
    pub diluted_check_permutation_public_memory_prod: F,
    #[cfg_attr(
        feature = "std",
        serde_as(as = "starknet_core::serde::unsigned_field_element::UfeHex")
    )]
    pub diluted_check_final_cum_val: F,
}

// Elements that are sent from the prover after the commitment on the original trace.
// Used for components after the first interaction, e.g., memory and range check.
#[serde_as]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InteractionElements<F: SimpleField + PoseidonHash> {
    #[cfg_attr(
        feature = "std",
        serde_as(as = "starknet_core::serde::unsigned_field_element::UfeHex")
    )]
    pub memory_multi_column_perm_perm_interaction_elm: F,
    #[cfg_attr(
        feature = "std",
        serde_as(as = "starknet_core::serde::unsigned_field_element::UfeHex")
    )]
    pub memory_multi_column_perm_hash_interaction_elm0: F,
    #[cfg_attr(
        feature = "std",
        serde_as(as = "starknet_core::serde::unsigned_field_element::UfeHex")
    )]
    pub range_check16_perm_interaction_elm: F,
    #[cfg_attr(
        feature = "std",
        serde_as(as = "starknet_core::serde::unsigned_field_element::UfeHex")
    )]
    pub diluted_check_permutation_interaction_elm: F,
    #[cfg_attr(
        feature = "std",
        serde_as(as = "starknet_core::serde::unsigned_field_element::UfeHex")
    )]
    pub diluted_check_interaction_z: F,
    #[cfg_attr(
        feature = "std",
        serde_as(as = "starknet_core::serde::unsigned_field_element::UfeHex")
    )]
    pub diluted_check_interaction_alpha: F,
}

impl<F: SimpleField + PoseidonHash> InteractionElements<F> {
    pub fn new(transcript: &mut Transcript<F>) -> Self {
        Self {
            memory_multi_column_perm_perm_interaction_elm: transcript.random_felt_to_prover(),
            memory_multi_column_perm_hash_interaction_elm0: transcript.random_felt_to_prover(),
            range_check16_perm_interaction_elm: transcript.random_felt_to_prover(),
            diluted_check_permutation_interaction_elm: transcript.random_felt_to_prover(),
            diluted_check_interaction_z: transcript.random_felt_to_prover(),
            diluted_check_interaction_alpha: transcript.random_felt_to_prover(),
        }
    }
}
