use alloc::vec::Vec;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use swiftness_field::SimpleField;
use swiftness_hash::poseidon::PoseidonHash;

use crate::config;

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct StarkProof<F: SimpleField + PoseidonHash> {
    pub config: config::StarkConfig<F>,
    pub public_input: swiftness_air::public_memory::PublicInput<F>,
    pub unsent_commitment: StarkUnsentCommitment<F>,
    pub witness: StarkWitness<F>,
}

#[serde_as]
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct StarkUnsentCommitment<F: SimpleField + PoseidonHash> {
    pub traces: swiftness_air::trace::UnsentCommitment<F>,
    #[cfg_attr(
        feature = "std",
        serde_as(as = "starknet_core::serde::unsigned_field_element::UfeHex")
    )]
    pub composition: F,
    // n_oods_values elements. The i-th value is the evaluation of the i-th mask item polynomial at
    // the OODS point, where the mask item polynomial is the interpolation polynomial of the
    // corresponding column shifted by the corresponding row_offset.
    #[cfg_attr(
        feature = "std",
        serde_as(as = "Vec<starknet_core::serde::unsigned_field_element::UfeHex>")
    )]
    pub oods_values: Vec<F>,
    pub fri: swiftness_fri::types::UnsentCommitment<F>,
    pub proof_of_work: swiftness_pow::pow::UnsentCommitment,
}

#[serde_as]
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct StarkCommitment<InteractionElements, F: SimpleField + PoseidonHash> {
    pub traces: swiftness_air::trace::Commitment<InteractionElements, F>,
    pub composition: swiftness_commitment::table::types::Commitment<F>,
    #[cfg_attr(
        feature = "std",
        serde_as(as = "starknet_core::serde::unsigned_field_element::UfeHex")
    )]
    pub interaction_after_composition: F,
    #[cfg_attr(
        feature = "std",
        serde_as(as = "Vec<starknet_core::serde::unsigned_field_element::UfeHex>")
    )]
    pub oods_values: Vec<F>,
    #[cfg_attr(
        feature = "std",
        serde_as(as = "Vec<starknet_core::serde::unsigned_field_element::UfeHex>")
    )]
    pub interaction_after_oods: Vec<F>,
    pub fri: swiftness_fri::types::Commitment<F>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct StarkWitness<F: SimpleField + PoseidonHash> {
    pub traces_decommitment: swiftness_air::trace::Decommitment<F>,
    pub traces_witness: swiftness_air::trace::Witness<F>,
    pub composition_decommitment: swiftness_commitment::table::types::Decommitment<F>,
    pub composition_witness: swiftness_commitment::table::types::Witness<F>,
    pub fri_witness: swiftness_fri::types::Witness<F>,
}
