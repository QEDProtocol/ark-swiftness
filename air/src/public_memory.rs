use crate::types::{ContinuousPageHeader, Page, SegmentInfo};
use alloc::vec;
use alloc::vec::Vec;
use ark_ec::short_weierstrass::SWCurveConfig;
use ark_ff::{Field, PrimeField};
use ark_r1cs_std::{
    fields::{fp::FpVar, FieldOpsBounds, FieldVar},
    prelude::Boolean,
};
use log::debug;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use starknet_crypto::Felt;
use swiftness_field::SimpleField;
use swiftness_hash::{pedersen::PedersenHash, poseidon::PoseidonHash};

pub const MAX_LOG_N_STEPS: Felt = Felt::from_hex_unchecked("50");
pub const MAX_RANGE_CHECK: Felt = Felt::from_hex_unchecked("0xffff");
pub const MAX_ADDRESS: Felt = Felt::from_hex_unchecked("0xffffffffffffffff");
pub const INITIAL_PC: Felt = Felt::from_hex_unchecked("0x1");

#[serde_as]
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct PublicInput<F: SimpleField + PoseidonHash> {
    #[cfg_attr(
        feature = "std",
        serde_as(as = "starknet_core::serde::unsigned_field_element::UfeHex")
    )]
    pub log_n_steps: F,
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
    #[cfg_attr(
        feature = "std",
        serde_as(as = "starknet_core::serde::unsigned_field_element::UfeHex")
    )]
    pub layout: F,
    #[cfg_attr(
        feature = "std",
        serde_as(as = "Vec<starknet_core::serde::unsigned_field_element::UfeHex>")
    )]
    pub dynamic_params: Vec<F>,
    pub segments: Vec<SegmentInfo<F>>,
    #[cfg_attr(
        feature = "std",
        serde_as(as = "starknet_core::serde::unsigned_field_element::UfeHex")
    )]
    pub padding_addr: F,
    #[cfg_attr(
        feature = "std",
        serde_as(as = "starknet_core::serde::unsigned_field_element::UfeHex")
    )]
    pub padding_value: F,
    pub main_page: Page<F>,
    pub continuous_page_headers: Vec<ContinuousPageHeader<F>>,
}

impl<F: SimpleField + PoseidonHash> PublicInput<F> {
    // Returns the ratio between the product of all public memory cells and z^|public_memory|.
    // This is the value that needs to be at the memory__multi_column_perm__perm__public_memory_prod
    // member expression.
    pub fn get_public_memory_product_ratio(
        &self,
        z: F,
        alpha: F,
        public_memory_column_size: F,
    ) -> F {
        let (pages_product, total_length) =
            self.get_public_memory_product(z.clone(), alpha.clone());

        // Pad and divide
        let numerator = z.powers_felt(&public_memory_column_size);
        let padded = z - (self.padding_addr.clone() + alpha.clone() * &self.padding_value);

        // assert!(total_length <= public_memory_column_size);
        total_length.assert_lte(&public_memory_column_size);
        let denominator_pad = padded.powers_felt(&(public_memory_column_size - total_length));

        numerator
            .field_div(&pages_product)
            .field_div(&denominator_pad)
    }
    // Returns the product of all public memory cells.
    pub fn get_public_memory_product(&self, z: F, alpha: F) -> (F, F) {
        let main_page_prod = self.main_page.get_product(z, alpha);

        let (continuous_pages_prod, continuous_pages_total_length) =
            get_continuous_pages_product(&self.continuous_page_headers);

        let prod = main_page_prod * continuous_pages_prod;
        let total_length =
            F::from_constant(self.main_page.len() as u64) + &continuous_pages_total_length;

        (prod, total_length)
    }

    pub fn get_hash<P: SWCurveConfig>(&self) -> F
    where
        F: PedersenHash<P>,
        P::BaseField: PrimeField + SimpleField,
        <P::BaseField as Field>::BasePrimeField: SimpleField,
        FpVar<P::BaseField>:
            FieldVar<P::BaseField, <P::BaseField as Field>::BasePrimeField> + SimpleField,
        for<'a> &'a FpVar<P::BaseField>: FieldOpsBounds<'a, P::BaseField, FpVar<P::BaseField>>,
        <FpVar<P::BaseField> as SimpleField>::BooleanType:
            From<Boolean<<P::BaseField as Field>::BasePrimeField>>,
    {
        let mut main_page_hash = F::zero();
        debug!("self.main_page.len() = {}", self.main_page.len());
        let current = std::time::Instant::now();
        for memory in self.main_page.iter() {
            let memory = memory.clone();
            main_page_hash = PedersenHash::hash(main_page_hash, memory.address);
            main_page_hash = PedersenHash::hash(main_page_hash, memory.value);
        }
        debug!(
            "Main page hash computed in {} seconds",
            current.elapsed().as_secs_f32()
        );
        main_page_hash = PedersenHash::hash(
            main_page_hash,
            F::two() * F::from_constant(self.main_page.len() as u128),
        );

        let mut hash_data = vec![
            self.log_n_steps.clone(),
            self.range_check_min.clone(),
            self.range_check_max.clone(),
            self.layout.clone(),
        ];
        hash_data.extend(self.dynamic_params.iter().cloned());

        // Segments.
        hash_data.extend(
            self.segments
                .iter()
                .flat_map(|s| vec![s.begin_addr.clone(), s.stop_ptr.clone()]),
        );

        hash_data.push(self.padding_addr.clone());
        hash_data.push(self.padding_value.clone());
        hash_data.push(F::from_constant(
            (self.continuous_page_headers.len() + 1) as u64,
        ));

        // Main page.
        hash_data.push(F::from_constant(self.main_page.len() as u64));
        hash_data.push(main_page_hash);

        // Add the rest of the pages.
        hash_data.extend(
            self.continuous_page_headers
                .iter()
                .flat_map(|h| vec![h.start_address.clone(), h.size.clone(), h.hash.clone()]),
        );
        debug!("hash_data.len() = {}", hash_data.len());
        PoseidonHash::hash_many(&hash_data)
    }
}

fn get_continuous_pages_product<F: SimpleField + PoseidonHash>(
    page_headers: &[ContinuousPageHeader<F>],
) -> (F, F) {
    let mut res = F::one();
    let mut total_length = F::zero();

    for header in page_headers {
        res *= &header.prod;
        total_length += &header.size
    }

    (res, total_length)
}
