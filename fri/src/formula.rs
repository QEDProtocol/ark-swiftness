use alloc::vec::Vec;

// Constants representing primitive roots of unity for orders 2, 4, 8, and 16.
// These are calculated based on the formula 1 / 3^((PRIME - 1) / 16) where 3 is a generator.

// Function to fold 2 elements into one using one layer of FRI (Fast Reed-Solomon Interactive Oracle Proofs).
fn fri_formula2<F: SimpleField + PoseidonHash>(f_x: F, f_minus_x: F, eval_point: F, x_inv: F) -> F {
    f_x.clone() + f_minus_x.clone() + eval_point * x_inv * (f_x - f_minus_x)
}

// Function to fold 4 elements into one using 2 layers of FRI.
fn fri_formula4<F: SimpleField + PoseidonHash>(
    values: Vec<F>,
    eval_point: F,
    x_inv: F,
) -> Result<F, Error> {
    // Applying the first layer of folding.
    let g0 = fri_formula2(
        values.get(0).cloned().unwrap_or(F::zero()),
        values.get(1).cloned().unwrap_or(F::zero()),
        eval_point.clone(),
        x_inv.clone(),
    );
    let g1 = fri_formula2(
        values.get(2).cloned().unwrap_or(F::zero()),
        values.get(3).cloned().unwrap_or(F::zero()),
        eval_point.clone(),
        x_inv.clone()
            * F::from_stark_felt(Felt::from_hex_unchecked(
                "0x1dafdc6d65d66b5accedf99bcd607383ad971a9537cdf25d59e99d90becc81e",
            )),
    );

    // Last layer, combining the results of the first layer.
    Ok(fri_formula2(
        g0,
        g1,
        eval_point.clone() * eval_point,
        x_inv.clone() * x_inv,
    ))
}

// Function to fold 8 elements into one using 3 layers of FRI.
fn fri_formula8<F: SimpleField + PoseidonHash>(
    values: Vec<F>,
    eval_point: F,
    x_inv: F,
) -> Result<F, Error> {
    // Applying the first layer of folding.
    let g0 = fri_formula4(
        values
            .get(0..4)
            .map(|x| x.into_iter().cloned().collect::<Vec<_>>())
            .unwrap_or(core::iter::repeat_n(F::zero(), 4).collect::<Vec<_>>()),
        eval_point.clone(),
        x_inv.clone(),
    )?;
    let g1 = fri_formula4(
        values
            .get(4..8)
            .map(|x| x.into_iter().cloned().collect::<Vec<_>>())
            .unwrap_or(core::iter::repeat_n(F::zero(), 4).collect::<Vec<_>>()),
        eval_point.clone(),
        x_inv.clone()
            * F::from_stark_felt(Felt::from_hex_unchecked(
                "0x446ed3ce295dda2b5ea677394813e6eab8bfbc55397aacac8e6df6f4bc9ca34",
            )),
    )?;

    // Preparing variables for the last layer.
    let eval_point2 = eval_point.clone() * eval_point;
    let eval_point4 = eval_point2.clone() * eval_point2;
    let x_inv2 = x_inv.clone() * x_inv;
    let x_inv4 = x_inv2.clone() * x_inv2;

    // Last layer, combining the results of the second layer.
    Ok(fri_formula2(g0, g1, eval_point4, x_inv4))
}

// Function to fold 16 elements into one using 4 layers of FRI.
fn fri_formula16<F: SimpleField + PoseidonHash>(
    values: Vec<F>,
    eval_point: F,
    x_inv: F,
) -> Result<F, Error> {
    // Applying the first layer of folding.
    let g0 = fri_formula8(
        values
            .get(0..8)
            .map(|x| x.into_iter().cloned().collect::<Vec<_>>())
            .unwrap_or(core::iter::repeat_n(F::zero(), 4).collect::<Vec<_>>()),
        eval_point.clone(),
        x_inv.clone(),
    )?;
    let g1 = fri_formula8(
        values
            .get(8..16)
            .map(|x| x.into_iter().cloned().collect::<Vec<_>>())
            .unwrap_or(core::iter::repeat_n(F::zero(), 4).collect::<Vec<_>>()),
        eval_point.clone(),
        x_inv.clone()
            * F::from_stark_felt(Felt::from_hex_unchecked(
                "0x5c3ed0c6f6ac6dd647c9ba3e4721c1eb14011ea3d174c52d7981c5b8145aa75",
            )),
    )?;

    // Preparing variables for the last layer.
    let eval_point2 = eval_point.clone() * eval_point;
    let eval_point4 = eval_point2.clone() * eval_point2;
    let eval_point8 = eval_point4.clone() * eval_point4;
    let x_inv2 = x_inv.clone() * x_inv;
    let x_inv4 = x_inv2.clone() * x_inv2;
    let x_inv8 = x_inv4.clone() * x_inv4;

    // Last layer, combining the results of the second layer.
    Ok(fri_formula2(g0, g1, eval_point8, x_inv8))
}

// Folds 'coset_size' elements into one using log2(coset_size) layers of FRI.
// 'coset_size' can be 2, 4, 8, or 16.
pub fn fri_formula<F: SimpleField + PoseidonHash>(
    values: Vec<F>,
    eval_point: F,
    x_inv: F,
    coset_size: F,
) -> Result<F, Error> {
    let is_coset_2 = coset_size.is_equal(&F::from_constant(2u64));
    let is_coset_4 = coset_size.is_equal(&F::from_constant(4u64));
    let is_coset_8 = coset_size.is_equal(&F::from_constant(8u64));
    let is_coset_16 = coset_size.is_equal(&F::from_constant(16u64));
    F::assert_true(F::or(
        &F::or(&F::or(&is_coset_2, &is_coset_4), &is_coset_8),
        &is_coset_16,
    ));

    let result_2 = fri_formula2(
        values[0].clone(),
        values[1].clone(),
        eval_point.clone(),
        x_inv.clone(),
    );

    let result_4 = fri_formula4(values.clone(), eval_point.clone(), x_inv.clone())?;
    let result_8 = fri_formula8(values.clone(), eval_point.clone(), x_inv.clone())?;
    let result_16 = fri_formula16(values, eval_point, x_inv)?;

    Ok(F::select(
        &is_coset_2,
        result_2,
        F::select(
            &is_coset_4,
            result_4,
            F::select(&is_coset_8, result_8, result_16),
        ),
    ))
}

use starknet_crypto::Felt;
use swiftness_field::SimpleField;
use swiftness_hash::poseidon::PoseidonHash;
use thiserror_no_std::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Invalid values length: expected {expected}, got {got}")]
    InvalidValuesLength { expected: usize, got: usize },
}
