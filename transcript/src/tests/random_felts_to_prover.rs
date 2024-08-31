use alloc::vec;
use starknet_crypto::Felt;
use swiftness_field::{Fp, StarkArkConvert};

use crate::transcript::Transcript;

#[test]
fn test_random_felts_to_prover() {
    let mut transcript = Transcript::<Fp>::new_with_counter(
        StarkArkConvert::from_stark_felt(Felt::from_hex_unchecked(
            "0x55c2e30068db90407013a4cfcedee7895b328c6ba64b8bd5e4c71e470af5fde",
        )),
        StarkArkConvert::from_stark_felt(Felt::from_hex_unchecked("0x0")),
    );

    assert!(
        transcript.random_felts_to_prover(StarkArkConvert::from_stark_felt(
            Felt::from_hex_unchecked("0x3")
        )) == vec![
            StarkArkConvert::from_stark_felt(Felt::from_hex_unchecked(
                "0x120149e03e4939d3c2a4ca2fcaa6e9cfff0c64fbe115f54c439d76ff09c3dc7"
            )),
            StarkArkConvert::from_stark_felt(Felt::from_hex_unchecked(
                "0x3639344cc4b04d4c710b812e109e21f43f87c68d8648749cb25d30503037e4d"
            )),
            StarkArkConvert::from_stark_felt(Felt::from_hex_unchecked(
                "0xeca2849fb4c4c8e734eafe6d9cb7256c0f1bb43a5c4f2d27090cd8df21a699"
            )),
        ]
    );
    assert!(
        *transcript.digest()
            == StarkArkConvert::from_stark_felt(Felt::from_hex_unchecked(
                "0x55c2e30068db90407013a4cfcedee7895b328c6ba64b8bd5e4c71e470af5fde"
            )),
    );
    assert!(
        *transcript.counter() == StarkArkConvert::from_stark_felt(Felt::from_hex_unchecked("0x3"))
    );
}
