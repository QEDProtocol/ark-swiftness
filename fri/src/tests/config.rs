use crate::fixtures::config;
use starknet_crypto::Felt;
use swiftness_field::{Fp, SimpleField};

#[test]
fn test_fri_config() {
    let fri_config = config::get::<Fp>();
    let log_n_cosets = Fp::from_stark_felt(Felt::from_hex_unchecked("0x2"));
    let n_verifier_friendly_commitment_layers =
        Fp::from_stark_felt(Felt::from_hex_unchecked("0x64"));
    let log_expected_input_degree = Fp::from_stark_felt(Felt::from_hex_unchecked("0x12"));

    assert_eq!(
        fri_config
            .validate(log_n_cosets, n_verifier_friendly_commitment_layers)
            .unwrap(),
        log_expected_input_degree
    );
}
