use super::types::{Commitment, Query, QueryWithDepth, Witness};
use alloc::vec::Vec;

use swiftness_field::SimpleField;
use swiftness_hash::{blake2s::Blake2sHash, keccak::KeccakHash, poseidon::PoseidonHash};

pub fn vector_commitment_decommit<F: SimpleField + PoseidonHash + KeccakHash + Blake2sHash>(
    commitment: Commitment<F>,
    queries: &[Query<F>],
    witness: Witness<F>,
) -> Result<(), Error<F>> {
    let shift = F::two().powers_felt(&commitment.config.height);
    // Shifts the query indices by shift=2**height, to convert index representation to heap-like.
    let shifted_queries: Vec<QueryWithDepth<F>> = queries
        .iter()
        .map(|q| QueryWithDepth {
            index: q.index.clone() + shift.clone(),
            value: q.value.clone(),
            depth: commitment.config.height.clone(),
        })
        .collect();

    let expected_commitment = compute_root_from_queries(
        shifted_queries,
        0,
        commitment.config.n_verifier_friendly_commitment_layers,
        &witness.authentications,
        0,
    )?;

    commitment
        .commitment_hash
        .assert_equal(&expected_commitment);
    Ok(())
}

pub fn compute_root_from_queries<F: SimpleField + PoseidonHash + KeccakHash + Blake2sHash>(
    mut queue: Vec<QueryWithDepth<F>>,
    mut start: usize,
    n_verifier_friendly_layers: F,
    authentications: &[F],
    mut auth_start: usize,
) -> Result<F, Error<F>> {
    if queue.is_empty() {
        return Err(Error::IndexInvalid);
    }

    while queue.len() > start {
        let current = queue.get(start).ok_or(Error::IndexInvalid)?;

        // Check if we've reached the root
        let is_root = current.index.is_equal(&F::one());
        let root_value = current.value.clone();

        // Compute non-root case
        let (parent, bit) = current.index.div2_rem();
        let current_is_left_child = bit.is_equal(&F::zero());
        let is_verifier_friendly = n_verifier_friendly_layers.greater_than(&current.depth);
        let merge = queue
            .get(start + 1)
            .map(|next| {
                <F as SimpleField>::and(
                    &current_is_left_child,
                    &(current.index.clone() + F::one()).is_equal(&next.index),
                )
            })
            .unwrap_or(<F as SimpleField>::construct_bool(false));

        let sibling_value = SimpleField::select(
            &merge,
            queue
                .get(start + 1)
                .map(|next| next.value.clone())
                .unwrap_or(current.value.clone()),
            authentications
                .get(auth_start)
                .cloned()
                .unwrap_or(current.value.clone()),
        );
        let non_root_value = SimpleField::select(
            &current_is_left_child,
            hash_friendly_unfriendly(
                current.value.clone(),
                sibling_value.clone(),
                is_verifier_friendly.clone(),
            ),
            hash_friendly_unfriendly(sibling_value, current.value.clone(), is_verifier_friendly),
        );

        let hash = SimpleField::select(&is_root, root_value, non_root_value);

        let next_query = QueryWithDepth {
            index: parent.clone(),
            value: hash.clone(),
            depth: current.depth.clone() - F::one(),
        };

        let next_start = SimpleField::select(
            &<F as SimpleField>::or(&merge, &is_root),
            F::from_constant((start + 2) as u64),
            F::from_constant((start + 1) as u64),
        );

        let next_auth_start = SimpleField::select(
            &<F as SimpleField>::or(&merge, &is_root),
            F::from_constant(auth_start as u64),
            F::from_constant((auth_start + 1) as u64),
        );

        // into_constant is safe here because we know it's constant
        start = next_start.into_constant();
        auth_start = next_auth_start.into_constant();
        queue.push(next_query);
    }

    Ok(queue
        .get(start - 1)
        .ok_or(Error::IndexInvalid)?
        .value
        .clone())
}

fn hash_friendly_unfriendly<F: SimpleField + PoseidonHash + KeccakHash + Blake2sHash>(
    x: F,
    y: F,
    is_verifier_friendly: F::BooleanType,
) -> F {
    F::select(
        &is_verifier_friendly,
        PoseidonHash::hash(x.clone(), y.clone()),
        {
            let mut hash_data = Vec::with_capacity(64);
            hash_data.extend(x.to_be_bytes());
            hash_data.extend(y.to_be_bytes());

            let final_hash: Vec<<F as SimpleField>::ByteType>;
            cfg_if::cfg_if! {
                if #[cfg(feature = "keccak")] {
                    final_hash = <F as PoseidonHash>::hash_out(&hash_data);
                } else if #[cfg(feature = "blake2s")] {
                    final_hash = <F as PoseidonHash>::hash_out(&hash_data);
                } else {
                    compile_error!("Either 'keccak' or 'blake2s' feature must be enabled");
                }
            }
            F::from_be_bytes(&final_hash.as_slice()[12..32])
        },
    )
}

#[cfg(feature = "std")]
use thiserror::Error;

#[cfg(feature = "std")]
#[derive(Error, Debug)]
pub enum Error<F: SimpleField> {
    #[error("mismatch value {value} expected {expected}")]
    MisMatch { value: F, expected: F },
    #[error("authentications length is invalid")]
    AuthenticationInvalid,
    #[error("root tree-node error")]
    RootInvalid,
    #[error("root tree-node error")]
    IndexInvalid,
}

#[cfg(not(feature = "std"))]
use thiserror_no_std::Error;

#[cfg(not(feature = "std"))]
#[derive(Error, Debug)]
pub enum Error<F: SimpleField> {
    #[error("mismatch value {value} expected {expected}")]
    MisMatch { value: F, expected: F },
    #[error("authentications length is invalid")]
    AuthenticationInvalid,
    #[error("root tree-node error")]
    RootInvalid,
    #[error("root tree-node error")]
    IndexInvalid,
}
