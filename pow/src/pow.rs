use alloc::vec::Vec;

use serde::{Deserialize, Serialize};
use swiftness_field::SimpleField;
use swiftness_hash::blake2s::Blake2sHash;
use swiftness_hash::keccak::KeccakHash;
use swiftness_hash::poseidon::PoseidonHash;
use swiftness_transcript::transcript::Transcript;

use crate::config::Config;

const MAGIC: u64 = 0x0123456789abcded;

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct UnsentCommitment {
    pub nonce: u64,
}

impl UnsentCommitment {
    pub fn commit<F: SimpleField + Blake2sHash + KeccakHash + PoseidonHash>(
        &self,
        transcript: &mut Transcript<F>,
        config: &Config,
    ) -> Result<(), Error> {
        verify_pow::<F>(transcript.digest().to_le_bytes(), config.n_bits, self.nonce)?;
        transcript.read_uint64_from_prover(self.nonce);
        Ok(())
    }
}

pub fn verify_pow<F: SimpleField + Blake2sHash + KeccakHash + PoseidonHash>(
    digest: Vec<<F as SimpleField>::ByteType>,
    n_bits: u8,
    nonce: u64,
) -> Result<(), Error> {
    // Compute the initial hash.
    // Hash(0x0123456789abcded || digest   || n_bits )
    //      8 bytes            || 32 bytes || 1 byte
    // Total of 0x29 = 41 bytes.

    let mut init_data = Vec::with_capacity(41);
    init_data.extend_from_slice(
        MAGIC
            .to_be_bytes()
            .into_iter()
            .map(|b| F::construct_byte(b))
            .collect::<Vec<_>>()
            .as_slice(),
    );
    init_data.extend_from_slice(digest.as_slice());
    init_data.push(F::construct_byte(n_bits));

    let init_hash: Vec<<F as SimpleField>::ByteType>;
    cfg_if::cfg_if! {
        if #[cfg(feature = "keccak")] {
            init_hash = <F as KeccakHash>::hash(&init_data);
        } else if #[cfg(feature = "blake2s")] {
            init_hash = <F as Blake2sHash>::hash(&init_data);
        } else {
            compile_error!("Either 'keccak' or 'blake2s' feature must be enabled");
        }
    }

    // Reverse the endianness of the initial hash.
    // init_hash.reverse();

    // Compute Hash(init_hash || nonce)
    //              32 bytes  || 8 bytes
    // Total of 0x28 = 40 bytes.

    let mut hash_data = Vec::with_capacity(40);
    hash_data.extend_from_slice(&init_hash);
    hash_data.extend_from_slice(
        &nonce
            .to_be_bytes()
            .into_iter()
            .map(|b| F::construct_byte(b))
            .collect::<Vec<_>>()
            .as_slice(),
    );

    let final_hash: Vec<<F as SimpleField>::ByteType>;
    cfg_if::cfg_if! {
        if #[cfg(feature = "keccak")] {
            final_hash = <F as KeccakHash>::hash(&hash_data);
        } else if #[cfg(feature = "blake2s")] {
            final_hash = <F as Blake2sHash>::hash(&hash_data);
        } else {
            compile_error!("Either 'keccak' or 'blake2s' feature must be enabled");
        }
    }

    F::from_be_bytes(&final_hash.as_slice()[0..16])
        .assert_lt(&F::two().powers([(128 - n_bits) as u64]));

    Ok(())
}

#[cfg(feature = "std")]
use thiserror::Error;

#[cfg(feature = "std")]
#[derive(Error, Debug)]
pub enum Error {
    #[cfg_attr(feature = "std", error("proof of work verification fail"))]
    ProofOfWorkFail,
}

#[cfg(not(feature = "std"))]
use thiserror_no_std::Error;

#[cfg(not(feature = "std"))]
#[derive(Error, Debug)]
pub enum Error {
    #[error("proof of work verification fail")]
    ProofOfWorkFail,
}
