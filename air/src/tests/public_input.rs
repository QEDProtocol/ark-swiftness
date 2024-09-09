use crate::fixtures::public_input::get;
use starknet_crypto::Felt;
use swiftness_field::{Fp, SimpleField};

#[test]
fn test_public_input_hash() {
    let public_input = get::<Fp>();
    assert_eq!(
        public_input.get_hash(),
        Fp::from_stark_felt(Felt::from_hex_unchecked(
            "0xaf91f2c71f4a594b1575d258ce82464475c82d8fb244142d0db450491c1b52"
        ))
    );
}
