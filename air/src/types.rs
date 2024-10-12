use alloc::vec::Vec;
use core::ops::Deref;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use swiftness_field::SimpleField;
use swiftness_hash::poseidon::PoseidonHash;

#[serde_as]
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct SegmentInfo<F: SimpleField + PoseidonHash> {
    // Start address of the memory segment.
    #[cfg_attr(
        feature = "std",
        serde_as(as = "starknet_core::serde::unsigned_field_element::UfeHex")
    )]
    pub begin_addr: F,
    // Stop pointer of the segment - not necessarily the end of the segment.
    #[cfg_attr(
        feature = "std",
        serde_as(as = "starknet_core::serde::unsigned_field_element::UfeHex")
    )]
    pub stop_ptr: F,
}

#[serde_as]
#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub struct AddrValue<F: SimpleField + PoseidonHash> {
    #[cfg_attr(
        feature = "std",
        serde_as(as = "starknet_core::serde::unsigned_field_element::UfeHex")
    )]
    pub address: F,
    #[cfg_attr(
        feature = "std",
        serde_as(as = "starknet_core::serde::unsigned_field_element::UfeHex")
    )]
    pub value: F,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Page<F: SimpleField + PoseidonHash>(pub Vec<AddrValue<F>>);

impl<F: SimpleField + PoseidonHash> Deref for Page<F> {
    type Target = Vec<AddrValue<F>>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<F: SimpleField + PoseidonHash> Page<F> {
    // Returns the product of (z - (addr + alpha * val)) over a single page.
    pub fn get_product(&self, z: F, alpha: F) -> F {
        let mut res = F::one();
        let mut i = 0;
        loop {
            if i == self.len() {
                break res;
            }
            let current = &self[i];

            res *= z.clone() - (current.address.clone() + alpha.clone() * &current.value);
            i += 1;
        }
    }
}

// Information about a continuous page (a consecutive section of the public memory)..
// Each such page must be verified externally to the verifier:
//   hash = Hash(
//     memory[start_address], memory[start_address + 1], ..., memory[start_address + size - 1]).
//   prod = prod_i (z - ((start_address + i) + alpha * (memory[start_address + i]))).
// z, alpha are taken from the interaction values, and can be obtained directly from the
// StarkProof object.
//   z     = interaction_elements.memory_multi_column_perm_perm__interaction_elm
//   alpha = interaction_elements.memory_multi_column_perm_hash_interaction_elm0
#[serde_as]
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct ContinuousPageHeader<F: SimpleField + PoseidonHash> {
    // Start address.
    #[cfg_attr(
        feature = "std",
        serde_as(as = "starknet_core::serde::unsigned_field_element::UfeHex")
    )]
    pub start_address: F,
    // Size of the page.
    #[cfg_attr(
        feature = "std",
        serde_as(as = "starknet_core::serde::unsigned_field_element::UfeHex")
    )]
    pub size: F,
    // Hash of the page.
    #[cfg_attr(
        feature = "std",
        serde_as(as = "starknet_core::serde::unsigned_field_element::UfeHex")
    )]
    pub hash: F,
    // Cumulative product of the page.
    #[cfg_attr(
        feature = "std",
        serde_as(as = "starknet_core::serde::unsigned_field_element::UfeHex")
    )]
    pub prod: F,
}
