use super::config::Config;
use crate::vector;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use swiftness_field::SimpleField;
use swiftness_hash::poseidon::Permute;

// Commitment for a table (n_rows x n_columns) of field elements in montgomery form.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Commitment<F: SimpleField + Permute> {
    pub config: Config<F>,
    pub vector_commitment: vector::types::Commitment<F>,
}

// Responses for queries to the table commitment.
// Each query corresponds to a full row of the table.
#[serde_as]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Decommitment<F: SimpleField + Permute> {
    // n_columns * n_queries values to decommit.
    #[cfg_attr(
        feature = "std",
        serde_as(as = "starknet_core::serde::unsigned_field_element::UfeHex")
    )]
    pub values: Vec<F>,
}

// Witness for a decommitment over queries.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Witness<F: SimpleField + Permute> {
    pub vector: vector::types::Witness<F>,
}
