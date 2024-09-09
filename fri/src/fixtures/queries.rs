use alloc::vec;
use alloc::vec::Vec;
use starknet_crypto::Felt;
use swiftness_field::SimpleField;
use swiftness_hash::poseidon::PoseidonHash;

pub fn get<F: SimpleField + PoseidonHash>() -> Vec<F> {
    vec![
        F::from_stark_felt(Felt::from_hex_unchecked("0x3982a")),
        F::from_stark_felt(Felt::from_hex_unchecked("0x52d42")),
        F::from_stark_felt(Felt::from_hex_unchecked("0x585a8")),
        F::from_stark_felt(Felt::from_hex_unchecked("0x7c3cc")),
        F::from_stark_felt(Felt::from_hex_unchecked("0x8af7f")),
        F::from_stark_felt(Felt::from_hex_unchecked("0x8e6f3")),
        F::from_stark_felt(Felt::from_hex_unchecked("0x97846")),
        F::from_stark_felt(Felt::from_hex_unchecked("0x9e330")),
        F::from_stark_felt(Felt::from_hex_unchecked("0xa9b57")),
        F::from_stark_felt(Felt::from_hex_unchecked("0xfa009")),
    ]
}
