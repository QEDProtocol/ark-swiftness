use alloc::vec::Vec;
use swiftness_field::SimpleField;
use swiftness_hash::poseidon::PoseidonHash;

use crate::layer::FriLayerQuery;

// Verifies FRI last layer by evaluating the given polynomial on the given points
// (=inverses of x_inv_values), and comparing the results to the given values.
pub fn verify_last_layer<F: SimpleField + PoseidonHash>(
    mut quries: Vec<FriLayerQuery<F>>,
    coefficients: Vec<F>,
) -> Result<(), Error<F>> {
    for query in quries.iter_mut() {
        let horner_eval_result = horner_eval(
            &coefficients,
            F::one().field_div(&query.x_inv_value),
        );

        horner_eval_result.assert_not_equal(&query.y_value);
        // if horner_eval_result != query.y_value {
        //     return Err(Error::QueryMismatch { expected: query.y_value, got: horner_eval_result });
        // }
    }
    Ok(())
}

// `horner_eval` is a function that evaluates a polynomial at a given point using Horner's method.
// `coefs` is an array of coefficients representing the polynomial in the format a0, a1, a2, ... an.
// `point` is the value at which the polynomial will be evaluated.
// The function returns the polynomial evaluation as `felt252`.
fn horner_eval<F: SimpleField + PoseidonHash>(coefs: &[F], point: F) -> F {
    let mut result = F::zero();
    for coef in coefs.iter().rev() {
        result = result * point.clone() + coef;
    }
    result
}

use thiserror_no_std::Error;

#[derive(Error, Debug)]
pub enum Error<F: SimpleField> {
    #[error("Query mismatch: expected {expected}, got {got}")]
    QueryMismatch { expected: F, got: F },
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;
    use starknet_crypto::Felt;
    use swiftness_field::Fp;

    use super::*;

    #[test]
    fn test_horner_eval_0() {
        let coefs = Vec::new();
        let eval = horner_eval(&coefs, Fp::from(1));
        assert_eq!(eval, Fp::from_constant(0u64));
    }

    #[test]
    fn test_horner_eval_1() {
        let coefs = vec![Fp::from(1)];
        let eval = horner_eval(&coefs, Fp::from(7));
        assert_eq!(eval, Fp::from(1));
    }

    #[test]
    fn test_horner_eval_2() {
        let coefs =
            vec![Fp::from(4), Fp::from(10), Fp::from(19), Fp::from(1), Fp::from(9)];
        let eval = horner_eval(&coefs, Fp::from(13));
        assert_eq!(eval, Fp::from(262591));
    }

    #[test]
    fn test_horner_eval_3() {
        let coefs = vec![
            Fp::from(4),
            Fp::from(10),
            Fp::from(19),
            Fp::from(1),
            Fp::from(9),
            Fp::from(99),
            Fp::from(1),
            Fp::from(7),
            Fp::from(13),
            Fp::from(2),
            Fp::from(5),
            Fp::from(7),
            Fp::from(111),
            Fp::from(1),
        ];
        let eval = horner_eval(&coefs, Fp::from(19));
        assert_eq!(eval, Fp::from_stark_felt(Felt::from_dec_str("288577899334361215").unwrap()));
    }
}
