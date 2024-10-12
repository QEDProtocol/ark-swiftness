use ark_ec::short_weierstrass::Affine;
use ark_ec::short_weierstrass::Projective;
use ark_ec::short_weierstrass::SWCurveConfig;
use ark_ec::CurveConfig;
use ark_ec::CurveGroup;
use ark_ec::Group;
use ark_ff::Field;
use ark_ff::PrimeField;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::fields::FieldOpsBounds;
use ark_r1cs_std::fields::FieldVar;
use ark_r1cs_std::groups::curves::short_weierstrass::non_zero_affine::NonZeroAffineVar;
use ark_r1cs_std::groups::curves::short_weierstrass::AffineVar;
use ark_r1cs_std::groups::curves::short_weierstrass::ProjectiveVar;
use ark_r1cs_std::groups::CurveVar;
use ark_r1cs_std::prelude::Boolean;
use constants::P0;
use constants::P1;
use constants::P2;
use constants::P3;
use constants::P4;
use num_bigint::BigUint;
use ruint::aliases::U256;
use ruint::uint;
use swiftness_field::Fp;
use swiftness_field::Fr;
use swiftness_field::SimpleField;
use crate::pedersen::utils::{
    get_a_p0_proj_outer, get_a_p1_proj_outer, get_a_p2_proj_outer, get_b_p1_proj_outer,
    get_b_p2_proj_outer, CurveProjectiveProvider,
};
use swiftness_utils::binary::PedersenInstance;
use swiftness_utils::curve::calculate_slope_var;
use swiftness_utils::curve::StarkwareCurve;

pub mod constants;
pub mod periodic;
mod utils;

pub fn pedersen_hash(a: Fp, b: Fp) -> Fp {
    let a_p0 = P0;
    let a_p1 = P1;
    let a_p2 = P2;
    let _a_steps = gen_element_steps(a, a_p0, a_p1, a_p2);

    let b_p0 = (a_p0 + process_element(a, a_p1.into(), a_p2.into())).into();
    let b_p1 = P3;
    let b_p2 = P4;
    // check out initial value for the second input is correct
    // TODO: enable check
    // assert_eq!(a_steps.last().unwrap().point, b_p0);
    let b_steps = gen_element_steps(b, b_p0, b_p1, b_p2);

    b_steps.last().unwrap().point.x
}

/// Computes the Pedersen hash of a and b using StarkWare's parameters.
///
/// The hash is defined by:
///     shift_point + x_low * P_0 + x_high * P1 + y_low * P2  + y_high * P3
/// where x_low is the 248 low bits of x, x_high is the 4 high bits of x and
/// similarly for y. shift_point, P_0, P_1, P_2, P_3 are constant points
/// generated from the digits of pi.
// pub fn pedersen_hash(a: Fp, b: Fp) -> Fp {
//     let a = a.to_stark_felt();
//     let b = b.to_stark_felt();
//     let res = starknet_crypto::pedersen_hash(&a, &b);
//     StarkArkConvert::from_stark_felt(res)
// }

fn process_element(
    x: Fp,
    p1: Projective<StarkwareCurve>,
    p2: Projective<StarkwareCurve>,
) -> Projective<StarkwareCurve> {
    assert_eq!(252, Fp::MODULUS_BIT_SIZE);
    let x: BigUint = x.into_bigint().into();
    let shift = 252 - 4;
    let high_part = &x >> shift;
    let low_part = x - (&high_part << shift);
    let x_high = Fr::from(high_part);
    let x_low = Fr::from(low_part);
    p1 * x_low + p2 * x_high
}

fn process_element_var<
    P: SWCurveConfig,
    F: FieldVar<P::BaseField, <P::BaseField as Field>::BasePrimeField> + SimpleField,
>(
    x: F,
    p1: ProjectiveVar<P, F>,
    p2: ProjectiveVar<P, F>,
) -> ProjectiveVar<P, F>
where
    for<'a> &'a F: FieldOpsBounds<'a, P::BaseField, F>,
    <P as CurveConfig>::BaseField: SimpleField,
    F::BooleanType: From<Boolean<<<P as CurveConfig>::BaseField as ark_ff::Field>::BasePrimeField>>,
{
    // TODO: enable check
    // assert_eq!(252, F::MODULUS_BIT_SIZE);
    let shift = 252 - 4;
    let high_part = x.rsh(shift);
    let low_part = x - (&high_part.lsh(shift));
    let x_high = high_part;
    let x_low = low_part;
    p1.scalar_mul_le(x_low.to_bits_le().unwrap().iter())
        .unwrap()
        + p2.scalar_mul_le(x_high.to_bits_le().unwrap().iter())
            .unwrap()
}

#[derive(Clone, Copy, Debug)]
pub struct ElementPartialStep {
    pub point: Affine<StarkwareCurve>,
    pub suffix: Fp,
    pub slope: Fp,
}

#[derive(Clone, Debug)]
pub struct ElementPartialStepVar<
    P: SWCurveConfig,
    F: FieldVar<P::BaseField, <P::BaseField as Field>::BasePrimeField> + SimpleField,
> where
    for<'a> &'a F: FieldOpsBounds<'a, P::BaseField, F>,
    <P as CurveConfig>::BaseField: SimpleField,
    F::BooleanType: From<Boolean<<<P as CurveConfig>::BaseField as ark_ff::Field>::BasePrimeField>>,
{
    pub point: AffineVar<P, F>,
    pub suffix: F,
    pub slope: F,
}

#[derive(Clone, Debug)]
pub struct InstanceTrace {
    pub instance: PedersenInstance,
    pub output: Fp,
    pub a_steps: Vec<ElementPartialStep>,
    pub b_steps: Vec<ElementPartialStep>,
    pub a_bit251_and_bit196_and_bit192: bool,
    pub a_bit251_and_bit196: bool,
    pub b_bit251_and_bit196_and_bit192: bool,
    pub b_bit251_and_bit196: bool,
}

impl InstanceTrace {
    pub fn new(instance: PedersenInstance) -> Self {
        let PedersenInstance { a, b, .. } = instance;
        let a = Fp::from(BigUint::from(a));
        let b = Fp::from(BigUint::from(b));

        let a_p0 = P0;
        let a_p1 = P1;
        let a_p2 = P2;
        let a_steps = gen_element_steps(a, a_p0, a_p1, a_p2);

        let b_p0 = (a_p0 + process_element(a, a_p1.into(), a_p2.into())).into();
        let b_p1 = P3;
        let b_p2 = P4;
        // check out initial value for the second input is correct
        assert_eq!(a_steps.last().unwrap().point, b_p0);
        let b_steps = gen_element_steps(b, b_p0, b_p1, b_p2);

        // check the expected output matches
        let output = pedersen_hash(a, b);
        assert_eq!(output, b_steps.last().unwrap().point.x);

        let a_bit251 = instance.a.bit(251);
        let a_bit196 = instance.a.bit(196);
        let a_bit192 = instance.a.bit(192);
        let a_bit251_and_bit196_and_bit192 = a_bit251 && a_bit196 && a_bit192;
        let a_bit251_and_bit196 = a_bit251 && a_bit196;

        let b_bit251 = instance.b.bit(251);
        let b_bit196 = instance.b.bit(196);
        let b_bit192 = instance.b.bit(192);
        let b_bit251_and_bit196_and_bit192 = b_bit251 && b_bit196 && b_bit192;
        let b_bit251_and_bit196 = b_bit251 && b_bit196;

        Self {
            instance,
            output,
            a_steps,
            b_steps,
            a_bit251_and_bit196_and_bit192,
            a_bit251_and_bit196,
            b_bit251_and_bit196_and_bit192,
            b_bit251_and_bit196,
        }
    }
}

fn gen_element_steps(
    x: Fp,
    p0: Affine<StarkwareCurve>,
    p1: Affine<StarkwareCurve>,
    p2: Affine<StarkwareCurve>,
) -> Vec<ElementPartialStep> {
    // generate our constant points
    let mut constant_points = Vec::new();
    let mut p1_acc = Projective::from(p1);
    for _ in 0..252 - 4 {
        constant_points.push(p1_acc);
        p1_acc.double_in_place();
    }
    let mut p2_acc = Projective::from(p2);
    for _ in 0..4 {
        constant_points.push(p2_acc);
        p2_acc.double_in_place();
    }

    // generate partial sums
    let x_int = U256::from::<BigUint>(x.into());
    let mut partial_point = Projective::from(p0);
    let mut res = Vec::new();
    #[allow(clippy::needless_range_loop)]
    for i in 0..256 {
        let suffix = x_int >> i;
        let bit = suffix & uint!(1_U256);

        let slope: Fp = Fp::ZERO;
        let mut partial_point_next = partial_point;
        let partial_point_affine = partial_point.into_affine();
        if bit == uint!(1_U256) {
            let constant_point = constant_points[i];
            // slope = calculate_slope(constant_point.into(), partial_point_affine).unwrap();
            partial_point_next += constant_point;
        }

        res.push(ElementPartialStep {
            point: partial_point_affine,
            suffix: Fp::from(BigUint::from(suffix)),
            slope,
        });

        partial_point = partial_point_next;
    }

    res
}

fn gen_element_steps_var<
    P: SWCurveConfig,
    F: FieldVar<P::BaseField, <P::BaseField as Field>::BasePrimeField> + SimpleField,
>(
    x: F,
    p0: AffineVar<P, F>,
    p1: AffineVar<P, F>,
    p2: AffineVar<P, F>,
) ->
Vec<ElementPartialStepVar<P, F>>
where
    for<'a> &'a F: FieldOpsBounds<'a, P::BaseField, F>,
    <P as CurveConfig>::BaseField: SimpleField,
    F::BooleanType: From<Boolean<<<P as CurveConfig>::BaseField as ark_ff::Field>::BasePrimeField>>,
{
    // generate our constant points
    let mut constant_points = Vec::new();
    let mut p1_acc =
        NonZeroAffineVar::new(p1.x.clone(), p1.y.clone()).into_projective();


    for _ in 0..252 - 4 {
        constant_points.push(p1_acc.clone());
        p1_acc.double_in_place().unwrap();
    }
    let mut p2_acc = NonZeroAffineVar::new(p2.x.clone(), p2.y.clone()).into_projective();
    for _ in 0..4 {
        constant_points.push(p2_acc.clone());
        p2_acc.double_in_place().unwrap();
    }

    // generate partial sums
    let mut partial_point = NonZeroAffineVar::new(p0.x.clone(), p0.y.clone()).into_projective();
    let mut res = Vec::new();
    let x_bits = x.to_le_bits();
    #[allow(clippy::needless_range_loop)]
    for i in 0..256 {
        //let suffix = x.rsh(i);

        // Normally it's padded so this is not necessary
        //let bit = suffix.div2_rem().1;
        let bit = match x_bits.get(i) {
            Some(a) => a.clone(),
            None => F::construct_bool(false),
        };
        let bit: F = SimpleField::from_boolean(bit.clone());

        let mut slope = SimpleField::zero();
        let mut partial_point_next = partial_point.clone();
        let partial_point_affine = partial_point.clone().to_affine().unwrap();

        let constant_point = constant_points.get(i).unwrap_or(&partial_point);
        slope = SimpleField::select(
            &bit.is_equal(&SimpleField::one()),
            calculate_slope_var(
                constant_point.to_affine().unwrap(),
                partial_point_affine.clone(),
            )
            .unwrap(),
            slope,
        );
        let partial_point_add_constant_point = partial_point.clone() + constant_point;
        partial_point_next.x = SimpleField::select(
            &bit.is_equal(&SimpleField::one()),
            partial_point_add_constant_point.x,
            partial_point.x,
        );

        partial_point_next.y = SimpleField::select(
            &bit.is_equal(&SimpleField::one()),
            partial_point_add_constant_point.y,
            partial_point.y,
        );

        partial_point_next.z = SimpleField::select(
            &bit.is_equal(&SimpleField::one()),
            partial_point_add_constant_point.z,
            partial_point.z,
        );

        let suffix = <F as SimpleField>::zero();
        res.push(ElementPartialStepVar {
            point: partial_point_affine,
            suffix,
            slope,
        });

        partial_point = partial_point_next;
    }

    res
}

pub trait PedersenHash<P: SWCurveConfig>: SimpleField {
    fn hash(a: Self, b: Self) -> Self
    where
        P::BaseField: PrimeField + SimpleField,
        <P::BaseField as Field>::BasePrimeField: SimpleField,
        FpVar<P::BaseField>:
            FieldVar<P::BaseField, <P::BaseField as Field>::BasePrimeField> + SimpleField,
        for<'a> &'a FpVar<P::BaseField>: FieldOpsBounds<'a, P::BaseField, FpVar<P::BaseField>>,
        <FpVar<P::BaseField> as SimpleField>::BooleanType:
            From<Boolean<<P::BaseField as Field>::BasePrimeField>>;
}

impl<P> PedersenHash<P> for FpVar<P::BaseField>
where
    P: SWCurveConfig + CurveProjectiveProvider,
    P::BaseField: PrimeField + SimpleField,
    <P::BaseField as Field>::BasePrimeField: SimpleField,
{
    fn hash(a: Self, b: Self) -> Self
    where
        FpVar<P::BaseField>:
            FieldVar<P::BaseField, <P::BaseField as Field>::BasePrimeField> + SimpleField,
        for<'a> &'a FpVar<P::BaseField>: FieldOpsBounds<'a, P::BaseField, FpVar<P::BaseField>>,
        <FpVar<P::BaseField> as SimpleField>::BooleanType:
            From<Boolean<<P::BaseField as Field>::BasePrimeField>>,
    {
        let a_p0_proj = get_a_p0_proj_outer::<P>();
        let a_p0 = a_p0_proj.to_affine().unwrap();
        let a_p1_proj = get_a_p1_proj_outer::<P>();
        let a_p1 = a_p1_proj.to_affine().unwrap();
        let a_p2_proj = get_a_p2_proj_outer::<P>();
        let a_p2 = a_p2_proj.to_affine().unwrap();
        let _a_steps = gen_element_steps_var::<P, FpVar<P::BaseField>>(a.clone(), a_p0, a_p1, a_p2);

        let b_p0 = (a_p0_proj
            + process_element_var::<P, FpVar<P::BaseField>>(a.clone(), a_p1_proj, a_p2_proj))
        .to_affine()
        .unwrap();

        let b_p1_proj = get_b_p1_proj_outer::<P>();
        let b_p1 = b_p1_proj.to_affine().unwrap();
        let b_p2_proj = get_b_p2_proj_outer::<P>();
        let b_p2 = b_p2_proj.to_affine().unwrap();

        // check out initial value for the second input is correct
        // TODO: enable check
        // assert_eq!(a_steps.last().unwrap().point, b_p0);
        let b_steps = gen_element_steps_var::<P, FpVar<P::BaseField>>(b.clone(), b_p0, b_p1, b_p2);

        b_steps.last().unwrap().point.x.clone()
    }
}

impl<P: SWCurveConfig> PedersenHash<P> for Fp {
    fn hash(a: Self, b: Self) -> Self
    where
        P::BaseField: PrimeField + SimpleField,
        <P::BaseField as Field>::BasePrimeField: SimpleField,
        FpVar<P::BaseField>:
            FieldVar<P::BaseField, <P::BaseField as Field>::BasePrimeField> + SimpleField,
        for<'a> &'a FpVar<P::BaseField>: FieldOpsBounds<'a, P::BaseField, FpVar<P::BaseField>>,
        <FpVar<P::BaseField> as SimpleField>::BooleanType:
            From<Boolean<<P::BaseField as Field>::BasePrimeField>>,
    {
        pedersen_hash(a, b)
    }
}

#[cfg(test)]
mod tests {
    use crate::pedersen::pedersen_hash;
    use ark_ff::MontFp as Fp;
    use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar};
    use ark_relations::r1cs::ConstraintSystem;
    use swiftness_field::{Fp, SimpleField};
    use swiftness_utils::curve::StarkwareCurve;

    #[test]
    fn hash_example0_works() {
        // Example source:
        // https://github.com/starkware-libs/starkex-resources/blob/master/crypto/starkware/crypto/signature/signature_test_data.json#L87
        let a = Fp!("1740729136829561885683894917751815192814966525555656371386868611731128807883");
        let b = Fp!("919869093895560023824014392670608914007817594969197822578496829435657368346");

        let output = pedersen_hash(a, b);

        assert_eq!(
            Fp!("1382171651951541052082654537810074813456022260470662576358627909045455537762"),
            output
        )
    }

    #[test]
    fn hash_example1_works() {
        // Example source:
        // https://github.com/starkware-libs/starkex-resources/blob/master/crypto/starkware/crypto/signature/signature_test_data.json#L92
        let a = Fp!("2514830971251288745316508723959465399194546626755475650431255835704887319877");
        let b = Fp!("3405079826265633459083097571806844574925613129801245865843963067353416465931");

        let output = pedersen_hash(a, b);

        assert_eq!(
            Fp!("2962565761002374879415469392216379291665599807391815720833106117558254791559"),
            output
        )
    }

    #[test]
    fn test_pedersen_hash_fpvar() {
        let cs = ConstraintSystem::<Fp>::new_ref();

        // Create FpVar inputs
        let a = FpVar::new_witness(cs.clone(), || Ok(Fp::from(123u64))).unwrap();
        let b = FpVar::new_witness(cs.clone(), || Ok(Fp::from(456u64))).unwrap();

        // Compute the hash using FpVar
        let hash_var = super::PedersenHash::<StarkwareCurve>::hash(a.clone(), b.clone());

        // Compute the hash using regular Fp for comparison
        let expected_hash = pedersen_hash(Fp::from(123u64), Fp::from(456u64));

        // Assert that the computed hash matches the expected hash
        FpVar::assert_equal(&hash_var, &FpVar::Constant(expected_hash));

        // Check that the constraint system is satisfied
        assert!(cs.is_satisfied().unwrap());
    }
}
