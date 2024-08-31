use swiftness_field::SimpleField;
use swiftness_hash::poseidon::Permute;
use swiftness_transcript::transcript::Transcript;

use super::{config::Config, types::Commitment};

pub fn vector_commit<F: SimpleField + Permute>(
    transcript: &mut Transcript<F>,
    unsent_commitment: F,
    config: Config<F>,
) -> Commitment<F> {
    transcript.read_felt_from_prover(&unsent_commitment);
    Commitment {
        commitment_hash: unsent_commitment,
        config,
    }
}
