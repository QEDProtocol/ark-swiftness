use crate::config::Config;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use swiftness_field::SimpleField;
use swiftness_hash::poseidon::PoseidonHash;

// Commitment values for FRI. Used to generate a commitment by "reading" these values
// from the transcript.
#[serde_as]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UnsentCommitment<F: SimpleField + PoseidonHash> {
    // Array of size n_layers - 1 containing unsent table commitments for each inner layer.
    #[cfg_attr(
        feature = "std",
        serde_as(as = "Vec<starknet_core::serde::unsigned_field_element::UfeHex>")
    )]
    pub inner_layers: Vec<F>,
    // Array of size 2**log_last_layer_degree_bound containing coefficients for the last layer
    // polynomial.
    #[cfg_attr(
        feature = "std",
        serde_as(as = "Vec<starknet_core::serde::unsigned_field_element::UfeHex>")
    )]
    pub last_layer_coefficients: Vec<F>,
}

#[serde_as]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Commitment<F: SimpleField + PoseidonHash> {
    pub config: Config<F>,
    // Array of size n_layers - 1 containing table commitments for each inner layer.
    pub inner_layers: Vec<swiftness_commitment::table::types::Commitment<F>>,
    // Array of size n_layers, of one evaluation point for each layer.
    #[cfg_attr(
        feature = "std",
        serde_as(as = "Vec<starknet_core::serde::unsigned_field_element::UfeHex>")
    )]
    pub eval_points: Vec<F>,
    // Array of size 2**log_last_layer_degree_bound containing coefficients for the last layer
    // polynomial.
    #[cfg_attr(
        feature = "std",
        serde_as(as = "Vec<starknet_core::serde::unsigned_field_element::UfeHex>")
    )]
    pub last_layer_coefficients: Vec<F>,
}

#[serde_as]
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Decommitment<F: SimpleField + PoseidonHash> {
    // Array of size n_values, containing the values of the input layer at query indices.
    #[cfg_attr(
        feature = "std",
        serde_as(as = "Vec<starknet_core::serde::unsigned_field_element::UfeHex>")
    )]
    pub values: Vec<F>,
    // Array of size n_values, containing the field elements that correspond to the query indices
    // (See queries_to_points).
    #[cfg_attr(
        feature = "std",
        serde_as(as = "Vec<starknet_core::serde::unsigned_field_element::UfeHex>")
    )]
    pub points: Vec<F>,
}

// A witness for the decommitment of the FRI layers over queries.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Witness<F: SimpleField + PoseidonHash> {
    // An array of size n_layers - 1, containing a witness for each inner layer.
    pub layers: Vec<LayerWitness<F>>,
}

// A witness for a single FRI layer. This witness is required to verify the transition from an
// inner layer to the following layer.
#[serde_as]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LayerWitness<F: SimpleField + PoseidonHash> {
    // Values for the sibling leaves required for decommitment.
    #[cfg_attr(
        feature = "std",
        serde_as(as = "Vec<starknet_core::serde::unsigned_field_element::UfeHex>")
    )]
    pub leaves: Vec<F>,
    // Table commitment witnesses for decommiting all the leaves.
    pub table_witness: swiftness_commitment::table::types::Witness<F>,
}
