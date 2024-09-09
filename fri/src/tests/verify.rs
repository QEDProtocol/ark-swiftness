use swiftness_field::Fp;

use crate::{
    fixtures::{commitment, queries, witness},
    fri::fri_verify,
};

use super::*;

#[test]
fn test_fri_verify() {
    let queries = queries::get::<Fp>();
    let commitment = commitment::get::<Fp>();
    let decommitment = decommit::get::<Fp>();
    let withness = witness::get::<Fp>();

    fri_verify(&queries, commitment, decommitment, withness).unwrap();
}
