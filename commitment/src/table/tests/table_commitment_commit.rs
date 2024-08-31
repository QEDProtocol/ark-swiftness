use starknet_crypto::Felt;
use swiftness_field::{Fp, StarkArkConvert};
use swiftness_transcript::transcript::Transcript;

use crate::{
    table::{self, commit::table_commit},
    vector,
};

#[test]
fn test_table_commitment_commit() {
    let mut transcript = Transcript::new_with_counter(
        StarkArkConvert::from_stark_felt(Felt::from_hex_unchecked(
            "0x1b9182dce9dc1169fcd00c1f8c0b6acd6baad99ce578370ead5ca230b8fb8c6",
        )),
        StarkArkConvert::from_stark_felt(Felt::from_hex_unchecked("0x1")),
    );

    let unsent_commitment: Fp = StarkArkConvert::from_stark_felt(Felt::from_hex_unchecked(
        "0x1e9b0fa29ebe52b9c9a43a1d44e555ce42da3199370134d758735bfe9f40269",
    ));

    let config = table::config::Config {
        n_columns: StarkArkConvert::from_stark_felt(Felt::from_hex_unchecked("0x4")),
        vector: vector::config::Config {
            height: StarkArkConvert::from_stark_felt(Felt::from_hex_unchecked("0x9")),
            n_verifier_friendly_commitment_layers: StarkArkConvert::from_stark_felt(
                Felt::from_hex_unchecked("0x64"),
            ),
        },
    };

    assert!(
        table_commit(&mut transcript, unsent_commitment, config.clone())
            == table::types::Commitment {
                config: config.clone(),
                vector_commitment: vector::types::Commitment {
                    config: config.vector,
                    commitment_hash: unsent_commitment
                },
            }
    );

    assert!(
        *transcript.digest()
            == StarkArkConvert::from_stark_felt(Felt::from_hex_unchecked(
                "0x1abd607dab09dede570ed131d9df0a1997e33735b11933c45dc84353df84259"
            )),
    );
    assert!(
        *transcript.counter() == StarkArkConvert::from_stark_felt(Felt::from_hex_unchecked("0x0"))
    );
}
