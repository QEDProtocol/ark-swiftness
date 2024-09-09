use starknet_crypto::Felt;
use swiftness_field::SimpleField;
use swiftness_hash::poseidon::PoseidonHash;

use crate::{fixtures::oods_values, types::StarkUnsentCommitment};

pub fn get<F: SimpleField + PoseidonHash>() -> StarkUnsentCommitment<F> {
    StarkUnsentCommitment {
        traces: swiftness_air::fixtures::unsent_commitment::get(),
        composition: F::from_stark_felt(Felt::from_hex_unchecked( "0x30b93bbd6b193eb57d9f818202b899b7e8e09b0c7d183537fe85f4e6b6f4373",)),
        oods_values: oods_values::get(),
        fri: swiftness_fri::fixtures::unsent_commitment::get(),
        proof_of_work: swiftness_pow::fixtures::unsent_commitment::get(),
    }
}
