use crate::transcript::Transcript;
use starknet_crypto::Felt;
use swiftness_field::{Fp, StarkArkConvert};

#[test]
fn test_read_uint64_from_prover_0() {
    let mut transcript = Transcript::<Fp>::new_with_counter(
        StarkArkConvert::from_stark_felt(Felt::from_hex_unchecked(
            "0x69eb7eb40004d1d7375b1ff9ccff8f7aed629e669b4fc3e11db4e748fdfbb2f",
        )),
        StarkArkConvert::from_stark_felt(Felt::from_hex_unchecked("0x0")),
    );
    transcript.read_uint64_from_prover(0x1e7e0);
    assert!(
        *transcript.digest()
            == StarkArkConvert::from_stark_felt(Felt::from_hex_unchecked(
                "0xc5952bab5731090a953716ac821ee7374cc6c4bad31d21b7134f62d6e00593"
            ))
    );
    assert!(
        *transcript.counter() == StarkArkConvert::from_stark_felt(Felt::from_hex_unchecked("0x0"))
    );
}
