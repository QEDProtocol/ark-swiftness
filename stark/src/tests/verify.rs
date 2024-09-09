use crate::{
    fixtures::{commitment, domains, witness},
    verify::stark_verify,
};
use swiftness_air::layout::{recursive::Layout, LayoutTrait};
use swiftness_field::Fp;
use swiftness_fri::fixtures::queries;

#[test]
pub fn test_stark_verify() {
    let queries = queries::get::<Fp>();
    let commitment = commitment::get::<Fp>();
    let witness = witness::get::<Fp>();
    let stark_domains = domains::get::<Fp>();

    stark_verify::<Fp, Layout>(
        <Layout as LayoutTrait<Fp>>::NUM_COLUMNS_FIRST,
        <Layout as LayoutTrait<Fp>>::NUM_COLUMNS_SECOND,
        &queries,
        commitment,
        &witness,
        &stark_domains,
    )
    .unwrap()
}
