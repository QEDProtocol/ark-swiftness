use super::{config::Config, types::Commitment};
use crate::vector::commit::vector_commit;
use swiftness_field::SimpleField;
use swiftness_hash::poseidon::Permute;
use swiftness_transcript::transcript::Transcript;

pub fn table_commit<F: SimpleField + Permute>(
    transcript: &mut Transcript<F>,
    unsent_commitment: F,
    config: Config<F>,
) -> Commitment<F> {
    let vector_commitment = vector_commit(transcript, unsent_commitment, config.vector.clone());
    Commitment {
        config,
        vector_commitment,
    }
}
