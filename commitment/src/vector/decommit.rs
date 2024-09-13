use super::types::{Commitment, Query, QueryWithDepth, Witness};
use alloc::vec::Vec;
// #[cfg(feature = "blake2s")]
// use blake2::Blake2s256;
// #[cfg(feature = "blake2s")]
// use blake2::Digest;
// #[cfg(feature = "keccak")]
// use sha3::Digest;
// #[cfg(feature = "keccak")]
// use sha3::Keccak256;
use swiftness_field::SimpleField;
use swiftness_hash::poseidon::PoseidonHash;

pub fn vector_commitment_decommit<F: SimpleField + PoseidonHash>(
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

pub fn compute_root_from_queries<F: SimpleField + PoseidonHash>(
    mut queue: Vec<QueryWithDepth<F>>,
    mut start: usize,
    _n_verifier_friendly_layers: F,
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

        // TODO: allow non-verifier friendly
        // let is_verifier_friendly = n_verifier_friendly_layers >= current.depth;
        let is_verifier_friendly = true;

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

        let hash = SimpleField::select(
            &is_root,
            root_value,
            SimpleField::select(
                &current_is_left_child,
                hash_friendly_unfriendly(
                    current.value.clone(),
                    sibling_value.clone(),
                    is_verifier_friendly,
                ),
                hash_friendly_unfriendly(
                    sibling_value,
                    current.value.clone(),
                    is_verifier_friendly,
                ),
            ),
        );

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

        // into_biguint is safe here because we know it's constant
        start = next_start.into_biguint().try_into().unwrap();
        auth_start = next_auth_start.into_biguint().try_into().unwrap();
        queue.push(next_query);
    }

    Ok(queue
        .get(start - 1)
        .ok_or(Error::IndexInvalid)?
        .value
        .clone())
}

fn hash_friendly_unfriendly<F: SimpleField + PoseidonHash>(
    x: F,
    y: F,
    is_verifier_friendly: bool,
) -> F {
    if is_verifier_friendly {
        PoseidonHash::hash(x, y)
    } else {
        todo!()
        // TODO: implement unfriendly hash
        // keccak hash
        // let mut hash_data = Vec::with_capacity(64);
        // hash_data.extend(&x.to_bytes_be());
        // hash_data.extend(&y.to_bytes_be());
        //
        // #[cfg(feature = "keccak")]
        // let mut hasher = Keccak256::new();
        // #[cfg(feature = "blake2s")]
        // let mut hasher = Blake2s256::new();
        //
        // hasher.update(&hash_data);
        // Felt::from_bytes_be_slice(&hasher.finalize().to_vec().as_slice()[12..32])
    }
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
