use ark_ff::BigInt;
use ark_ff::Field;
use ark_ff::Fp256;
use ark_ff::MontBackend;
use ark_ff::MontConfig;
use ark_ff::PrimeField;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::alloc::AllocationMode;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::fields::FieldVar;
use ark_r1cs_std::prelude::Boolean;
use ark_r1cs_std::uint8::UInt8;
use ark_r1cs_std::ToBitsGadget;
use ark_r1cs_std::ToBytesGadget;
use ark_relations::ns;
use num_integer::Integer;
use ark_ff::{biginteger::BigInteger256 as B, BigInteger as _};


use std::ops::*;

#[derive(MontConfig)]
#[modulus = "3618502788666131213697322783095070105623107215331596699973092056135872020481"]
#[generator = "3"]
pub struct FpMontConfig;

pub type Fp = Fp256<MontBackend<FpMontConfig, 4>>;

#[derive(MontConfig)]
#[modulus = "3618502788666131213697322783095070105526743751716087489154079457884512865583"]
#[generator = "3"]
pub struct FrMontConfig;

pub type Fr = Fp256<MontBackend<FrMontConfig, 4>>;

pub trait StarkArkConvert {
    fn to_stark_felt(self) -> starknet_crypto::Felt;
    fn from_stark_felt(f: starknet_crypto::Felt) -> Self;
}

impl StarkArkConvert for Fp {
    fn to_stark_felt(self) -> starknet_crypto::Felt {
        starknet_crypto::Felt::from_raw({
            let mut val = self.0 .0;
            val.reverse();
            val
        })
    }

    fn from_stark_felt(f: starknet_crypto::Felt) -> Self {
        Fp::new_unchecked({
            let mut val = f.to_raw();
            val.reverse();
            BigInt(val)
        })
    }
}

pub trait SimpleField:
    Clone
    + Sized
    + Add<Self, Output = Self>
    + Sub<Self, Output = Self>
    + Mul<Self, Output = Self>
    + AddAssign<Self>
    + SubAssign<Self>
    + MulAssign<Self>
    + for<'a> Add<&'a Self, Output = Self>
    + for<'a> Sub<&'a Self, Output = Self>
    + for<'a> Mul<&'a Self, Output = Self>
    + for<'a> AddAssign<&'a Self>
    + for<'a> SubAssign<&'a Self>
    + for<'a> MulAssign<&'a Self>
{
    type BooleanType;
    type ByteType: Clone;

    fn zero() -> Self;
    fn one() -> Self;
    fn two() -> Self;
    fn three() -> Self;
    fn four() -> Self;
    fn negate(&self) -> Self;
    fn inv(&self) -> Option<Self>;
    fn powers<Exp: AsRef<[u64]>>(&self, n: Exp) -> Self;
    fn powers_felt(&self, n: &Self) -> Self;
    fn from_constant(value: impl Into<u128>) -> Self;
    fn into_constant(&self) -> u128;
    fn from_felt(value: Fp) -> Self;
    fn from_stark_felt(value: starknet_crypto::Felt) -> Self;
    fn assert_equal(&self, other: &Self);
    fn assert_not_equal(&self, other: &Self);
    fn div_rem(&self, other: &Self) -> (Self, Self);
    fn div2_rem(&self) -> (Self, Self);
    fn rsh(&self, n: usize) -> Self;
    fn lsh(&self, n: usize) -> Self;
    fn field_div(&self, other: &Self) -> Self;
    fn select(cond: &Self::BooleanType, true_value: Self, false_value: Self) -> Self;
    fn is_equal(&self, other: &Self) -> Self::BooleanType;
    fn is_not_equal(&self, other: &Self) -> Self::BooleanType;
    fn and(lhs: &Self::BooleanType, rhs: &Self::BooleanType) -> Self::BooleanType;
    fn or(lhs: &Self::BooleanType, rhs: &Self::BooleanType) -> Self::BooleanType;
    fn not(value: &Self::BooleanType) -> Self::BooleanType;
    fn gt(&self, other: &Self) -> Self::BooleanType;
    fn lt(&self, other: &Self) -> Self::BooleanType;
    fn lte(&self, other: &Self) -> Self::BooleanType;
    fn gte(&self, other: &Self) -> Self::BooleanType;
    fn assert_true(value: Self::BooleanType);
    fn assert_false(value: Self::BooleanType);
    fn assert_gt(&self, other: &Self);
    fn assert_lt(&self, other: &Self);
    fn assert_lte(&self, other: &Self);
    fn assert_gte(&self, other: &Self);
    fn to_le_bytes(&self) -> Vec<Self::ByteType>;
    fn to_be_bytes(&self) -> Vec<Self::ByteType>;
    fn from_be_bytes(bytes: &[Self::ByteType]) -> Self;
    fn to_le_bits(&self) -> Vec<Self::BooleanType>;
    fn to_be_bits(&self) -> Vec<Self::BooleanType>;
    fn construct_byte(value: u8) -> Self::ByteType;
}

impl<F: PrimeField + SimpleField> SimpleField for FpVar<F> {
    type BooleanType = Boolean<F>;
    type ByteType = UInt8<F>;

    fn zero() -> Self {
        FpVar::Constant(SimpleField::zero())
    }

    fn one() -> Self {
        FpVar::Constant(SimpleField::one())
    }

    fn two() -> Self {
        FpVar::Constant(SimpleField::two())
    }

    fn negate(&self) -> Self {
        FieldVar::<F, F>::negate(self).unwrap()
    }

    fn inv(&self) -> Option<Self> {
        FieldVar::<F, F>::inverse(self).ok()
    }

    fn from_constant(value: impl Into<u128>) -> Self {
        FpVar::Constant(F::from(value.into()))
    }

    fn into_constant(&self) -> u128 {
        match self {
            FpVar::Constant(value) => value.into_constant(),
            FpVar::Var(_) => unreachable!(),
        }
    }

    fn powers<Exp: AsRef<[u64]>>(&self, n: Exp) -> Self {
        FieldVar::<F, F>::pow_by_constant(self, n).unwrap()
    }

    fn from_felt(value: Fp) -> Self {
        FpVar::Constant(SimpleField::from_felt(value))
    }

    fn from_stark_felt(value: starknet_crypto::Felt) -> Self {
        FpVar::Constant(SimpleField::from_stark_felt(value))
    }

    fn assert_equal(&self, other: &Self) {
        assert!(ark_r1cs_std::eq::EqGadget::enforce_equal(self, other).is_ok());
    }

    fn assert_not_equal(&self, other: &Self) {
        assert!(ark_r1cs_std::eq::EqGadget::enforce_not_equal(self, other).is_ok());
    }

    fn powers_felt(&self, n: &Self) -> Self {
        ark_r1cs_std::bits::ToBitsGadget::to_bits_le(n)
            .and_then(|bits| FieldVar::pow_le(self, &bits))
            .unwrap()
    }

    fn div_rem(&self, other: &Self) -> (Self, Self) {
        if let (FpVar::Constant(dividend), FpVar::Constant(divisor)) = (self, other) {
            let (quotient, remainder) = dividend.div_rem(divisor);
            return (FpVar::Constant(quotient), FpVar::Constant(remainder));
        }

        let (cs, (quotient, remainder)) = match (self, other) {
            (FpVar::Var(dividend), FpVar::Var(divisor)) => (
                dividend.cs.clone(),
                dividend.value().unwrap().div_rem(&divisor.value().unwrap()),
            ),
            (FpVar::Var(dividend), FpVar::Constant(divisor)) => (
                dividend.cs.clone(),
                dividend.value().unwrap().div_rem(&divisor),
            ),
            (FpVar::Constant(dividend), FpVar::Var(divisor)) => (
                divisor.cs.clone(),
                dividend.div_rem(&divisor.value().unwrap()),
            ),
            _ => unreachable!(),
        };

        let (quotient, remainder) = (
            FpVar::new_variable(
                ns!(cs, "quotient"),
                || Ok(quotient),
                AllocationMode::Witness,
            )
            .unwrap(),
            FpVar::new_variable(
                ns!(cs, "remainder"),
                || Ok(remainder),
                AllocationMode::Witness,
            )
            .unwrap(),
        );

        quotient
            .clone()
            .mul(other)
            .add(&remainder)
            .enforce_equal(self)
            .unwrap();

        return (quotient, remainder);
    }

    fn div2_rem(&self) -> (Self, Self) {
        let bits = self.to_bits_le().unwrap();
        if bits.is_empty() {
            return (SimpleField::zero(), SimpleField::zero());
        }

        if bits.len() == 1 {
            return (
                SimpleField::zero(),
                Boolean::le_bits_to_fp_var(&bits).unwrap(),
            );
        }

        let (left, right) = bits.split_at(1);
        return (
            Boolean::le_bits_to_fp_var(&right).unwrap(),
            Boolean::le_bits_to_fp_var(&left).unwrap(),
        );
    }

    fn select(cond: &Self::BooleanType, a: Self, b: Self) -> Self {
        cond.select(&a, &b).unwrap()
    }

    fn is_equal(&self, other: &Self) -> Self::BooleanType {
        EqGadget::is_eq(self, other).unwrap()
    }

    fn and(lhs: &Self::BooleanType, rhs: &Self::BooleanType) -> Self::BooleanType {
        Boolean::and(lhs, rhs).unwrap()
    }

    fn or(lhs: &Self::BooleanType, rhs: &Self::BooleanType) -> Self::BooleanType {
        Boolean::or(lhs, rhs).unwrap()
    }

    fn not(value: &Self::BooleanType) -> Self::BooleanType {
        Boolean::not(value)
    }

    fn assert_gt(&self, other: &Self) {
        FpVar::<F>::enforce_cmp(self, other, core::cmp::Ordering::Greater, false).unwrap();
    }

    fn assert_lt(&self, other: &Self) {
        FpVar::<F>::enforce_cmp(self, other, core::cmp::Ordering::Less, false).unwrap();
    }

    fn assert_gte(&self, other: &Self) {
        FpVar::<F>::enforce_cmp(self, other, core::cmp::Ordering::Greater, true).unwrap();
    }

    fn assert_lte(&self, other: &Self) {
        FpVar::<F>::enforce_cmp(self, other, core::cmp::Ordering::Less, true).unwrap();
    }

    fn field_div(&self, other: &Self) -> Self {
        self.mul(&other.inv().unwrap())
    }

    fn rsh(&self, n: usize) -> Self {
        let bits = self.to_bits_le().unwrap();
        if bits.is_empty() || n >= bits.len() {
            return SimpleField::zero();
        }

        return Boolean::le_bits_to_fp_var(&bits[n..]).unwrap();
    }

    fn gt(&self, other: &Self) -> Self::BooleanType {
        FpVar::<F>::is_cmp_unchecked(self, other, core::cmp::Ordering::Greater, false).unwrap()
    }

    fn lt(&self, other: &Self) -> Self::BooleanType {
        FpVar::<F>::is_cmp_unchecked(self, other, core::cmp::Ordering::Less, false).unwrap()
    }

    fn lte(&self, other: &Self) -> Self::BooleanType {
        FpVar::<F>::is_cmp_unchecked(self, other, core::cmp::Ordering::Less, true).unwrap()
    }

    fn gte(&self, other: &Self) -> Self::BooleanType {
        FpVar::<F>::is_cmp_unchecked(self, other, core::cmp::Ordering::Greater, true).unwrap()
    }

    fn three() -> Self {
        FpVar::Constant(SimpleField::three())
    }

    fn four() -> Self {
        FpVar::Constant(SimpleField::four())
    }

    fn is_not_equal(&self, other: &Self) -> Self::BooleanType {
        EqGadget::is_neq(self, other).unwrap()
    }

    fn assert_true(value: Self::BooleanType) {
        value.enforce_equal(&Boolean::<F>::TRUE).unwrap()
    }

    fn assert_false(value: Self::BooleanType) {
        value.enforce_equal(&Boolean::<F>::FALSE).unwrap()
    }

    fn lsh(&self, n: usize) -> Self {
        let bits = self.to_bits_le().unwrap();
        if bits.is_empty() || n >= bits.len() {
            return SimpleField::zero();
        }

        return Boolean::le_bits_to_fp_var(
            &core::iter::repeat(Boolean::<F>::FALSE)
                .take(n)
                .chain(bits.iter().cloned())
                .collect::<Vec<_>>(),
        )
        .unwrap();
    }

    fn to_le_bytes(&self) -> Vec<Self::ByteType> {
        ToBytesGadget::to_bytes(self).unwrap()
    }

    fn to_be_bytes(&self) -> Vec<Self::ByteType> {
        ToBytesGadget::to_bytes(self)
            .unwrap()
            .into_iter()
            .rev()
            .collect()
    }

    fn to_le_bits(&self) -> Vec<Self::BooleanType> {
        ToBitsGadget::to_bits_le(self).unwrap()
    }

    fn to_be_bits(&self) -> Vec<Self::BooleanType> {
        ToBitsGadget::to_bits_be(self).unwrap()
    }

    fn construct_byte(value: u8) -> Self::ByteType {
        UInt8::<F>::constant(value)
    }

    fn from_be_bytes(bytes: &[Self::ByteType]) -> Self {
        Boolean::le_bits_to_fp_var(&
            bytes.into_iter().map(|b| b.to_bits_le().unwrap()).flatten().collect::<Vec<_>>()
        ).unwrap()
    }
}

impl SimpleField for ark_bls12_381::Fr {
    type BooleanType = bool;
    type ByteType = u8;

    fn zero() -> Self {
        ark_ff::Zero::zero()
    }

    fn one() -> Self {
        ark_ff::One::one()
    }

    fn two() -> Self {
        ark_bls12_381::Fr::from(2u64)
    }

    fn negate(&self) -> Self {
        Neg::neg(*self)
    }

    fn inv(&self) -> Option<Self> {
        Field::inverse(self)
    }

    fn from_constant(value: impl Into<u128>) -> Self {
        ark_bls12_381::Fr::from(value.into())
    }

    fn into_constant(&self) -> u128 {
        num_bigint::BigUint::from(self.clone())
            .try_into()
            .unwrap_or(u128::MAX)
    }

    fn powers<Exp: AsRef<[u64]>>(&self, n: Exp) -> Self {
        Field::pow(self, n)
    }

    fn from_felt(value: Fp) -> Self {
        ark_bls12_381::Fr::from(num_bigint::BigUint::from(value))
    }

    fn from_stark_felt(value: starknet_crypto::Felt) -> Self {
        Self::from_felt(SimpleField::from_stark_felt(value))
    }

    fn assert_equal(&self, other: &Self) {
        assert!(self == other);
    }

    fn assert_not_equal(&self, other: &Self) {
        assert!(self != other);
    }

    fn powers_felt(&self, n: &Self) -> Self {
        Field::pow(self, num_bigint::BigUint::from(n.clone()).to_u64_digits())
    }

    fn div_rem(&self, other: &Self) -> (Self, Self) {
        let (quotient, remainder) = num_bigint::BigUint::from(self.clone())
            .div_rem(&num_bigint::BigUint::from(other.clone()));
        return (
            Self::new(BigInt({
                let mut limbs = quotient.to_u64_digits();
                limbs.reverse();
                limbs.resize(4, 0);
                limbs.try_into().unwrap()
            })),
            Self::new(BigInt({
                let mut limbs = remainder.to_u64_digits();
                limbs.reverse();
                limbs.resize(4, 0);
                limbs.try_into().unwrap()
            })),
        );
    }

    fn div2_rem(&self) -> (Self, Self) {
        self.div_rem(&Self::two())
    }

    fn select(cond: &Self::BooleanType, true_value: Self, false_value: Self) -> Self {
        if *cond {
            true_value
        } else {
            false_value
        }
    }

    fn is_equal(&self, other: &Self) -> Self::BooleanType {
        self == other
    }

    fn and(lhs: &Self::BooleanType, rhs: &Self::BooleanType) -> Self::BooleanType {
        lhs & rhs
    }

    fn or(lhs: &Self::BooleanType, rhs: &Self::BooleanType) -> Self::BooleanType {
        lhs | rhs
    }

    fn not(value: &Self::BooleanType) -> Self::BooleanType {
        !value
    }

    fn assert_gt(&self, other: &Self) {
        assert!(self > other)
    }

    fn assert_lt(&self, other: &Self) {
        assert!(self < other)
    }

    fn assert_lte(&self, other: &Self) {
        assert!(self <= other)
    }

    fn assert_gte(&self, other: &Self) {
        assert!(self >= other)
    }

    fn field_div(&self, other: &Self) -> Self {
        self / other
    }

    fn rsh(&self, n: usize) -> Self {
        let res = num_bigint::BigUint::from(self.clone()).shr(n);
        return Self::new(BigInt({
            let mut limbs = res.to_u64_digits();
            limbs.reverse();
            limbs.resize(4, 0);
            limbs.try_into().unwrap()
        }));
    }

    fn gt(&self, other: &Self) -> Self::BooleanType {
        self > other
    }

    fn lt(&self, other: &Self) -> Self::BooleanType {
        self < other
    }

    fn lte(&self, other: &Self) -> Self::BooleanType {
        self <= other
    }

    fn gte(&self, other: &Self) -> Self::BooleanType {
        self >= other
    }

    fn three() -> Self {
        ark_bls12_381::Fr::from(3u64)
    }

    fn four() -> Self {
        ark_bls12_381::Fr::from(4u64)
    }

    fn is_not_equal(&self, other: &Self) -> Self::BooleanType {
        self != other
    }

    fn assert_true(value: Self::BooleanType) {
        assert!(value);
    }

    fn assert_false(value: Self::BooleanType) {
        assert!(!value);
    }

    fn lsh(&self, n: usize) -> Self {
        let res = num_bigint::BigUint::from(self.clone()).shl(n);
        return Self::new(BigInt({
            let mut limbs = res.to_u64_digits();
            limbs.reverse();
            limbs.resize(4, 0);
            limbs.try_into().unwrap()
        }));
    }

    fn to_le_bytes(&self) -> Vec<Self::ByteType> {
        B::to_bytes_le(&self.into_bigint())
    }

    fn to_be_bytes(&self) -> Vec<Self::ByteType> {
        B::to_bytes_be(&self.into_bigint())
    }

    fn to_le_bits(&self) -> Vec<Self::BooleanType> {
        B::to_bits_le(&self.into_bigint())
    }

    fn to_be_bits(&self) -> Vec<Self::BooleanType> {
        B::to_bits_be(&self.into_bigint())
    }

    fn construct_byte(value: u8) -> Self::ByteType {
        value
    }

    fn from_be_bytes(bytes: &[Self::ByteType]) -> Self {
        Self::from_be_bytes_mod_order(bytes)
    }
}

impl SimpleField for Fp {
    type BooleanType = bool;
    type ByteType = u8;

    fn zero() -> Self {
        ark_ff::Zero::zero()
    }

    fn one() -> Self {
        ark_ff::One::one()
    }

    fn two() -> Self {
        Fp::from(2u64)
    }

    fn negate(&self) -> Self {
        Neg::neg(*self)
    }

    fn inv(&self) -> Option<Self> {
        Field::inverse(self)
    }

    fn from_constant(value: impl Into<u128>) -> Self {
        Fp::from(value.into())
    }

    fn into_constant(&self) -> u128 {
        num_bigint::BigUint::from(self.clone())
            .try_into()
            .unwrap_or(u128::MAX)
    }

    fn powers<Exp: AsRef<[u64]>>(&self, n: Exp) -> Self {
        Field::pow(self, n)
    }

    fn from_felt(value: Fp) -> Self {
        value
    }

    fn from_stark_felt(value: starknet_crypto::Felt) -> Self {
        Fp::new_unchecked({
            let mut val = value.to_raw();
            val.reverse();
            BigInt(val)
        })
    }

    fn assert_equal(&self, other: &Self) {
        assert!(self == other);
    }

    fn assert_not_equal(&self, other: &Self) {
        assert!(self != other);
    }

    fn powers_felt(&self, n: &Self) -> Self {
        Field::pow(self, num_bigint::BigUint::from(n.clone()).to_u64_digits())
    }

    fn div_rem(&self, other: &Self) -> (Self, Self) {
        let (div, rem) = num_bigint::BigUint::from(self.clone())
            .div_rem(&num_bigint::BigUint::from(other.clone()));
        return (
            Fp::new(BigInt({
                let mut limbs = div.to_u64_digits();
                limbs.reverse();
                limbs.resize(4, 0);
                limbs.try_into().unwrap()
            })),
            Fp::new(BigInt({
                let mut limbs = rem.to_u64_digits();
                limbs.reverse();
                limbs.resize(4, 0);
                limbs.try_into().unwrap()
            })),
        );
    }

    fn div2_rem(&self) -> (Self, Self) {
        self.div_rem(&Self::two())
    }

    fn select(cond: &Self::BooleanType, true_value: Self, false_value: Self) -> Self {
        if *cond {
            true_value
        } else {
            false_value
        }
    }

    fn is_equal(&self, other: &Self) -> Self::BooleanType {
        self == other
    }

    fn and(lhs: &Self::BooleanType, rhs: &Self::BooleanType) -> Self::BooleanType {
        lhs & rhs
    }

    fn or(lhs: &Self::BooleanType, rhs: &Self::BooleanType) -> Self::BooleanType {
        lhs | rhs
    }

    fn not(value: &Self::BooleanType) -> Self::BooleanType {
        !value
    }

    fn assert_gt(&self, other: &Self) {
        assert!(self > other)
    }

    fn assert_lt(&self, other: &Self) {
        assert!(self < other)
    }

    fn assert_lte(&self, other: &Self) {
        assert!(self <= other)
    }

    fn assert_gte(&self, other: &Self) {
        assert!(self >= other)
    }

    fn field_div(&self, other: &Self) -> Self {
        self / other
    }

    fn rsh(&self, n: usize) -> Self {
        let res = num_bigint::BigUint::from(self.clone()).shr(n);
        return Self::new(BigInt({
            let mut limbs = res.to_u64_digits();
            limbs.reverse();
            limbs.resize(4, 0);
            limbs.try_into().unwrap()
        }));
    }

    fn gt(&self, other: &Self) -> Self::BooleanType {
        self > other
    }

    fn lt(&self, other: &Self) -> Self::BooleanType {
        self < other
    }

    fn lte(&self, other: &Self) -> Self::BooleanType {
        self <= other
    }

    fn gte(&self, other: &Self) -> Self::BooleanType {
        self >= other
    }

    fn three() -> Self {
        Fp::from(3u64)
    }

    fn four() -> Self {
        Fp::from(4u64)
    }

    fn is_not_equal(&self, other: &Self) -> Self::BooleanType {
        self != other
    }

    fn assert_true(value: Self::BooleanType) {
        assert!(value);
    }

    fn assert_false(value: Self::BooleanType) {
        assert!(!value);
    }

    fn lsh(&self, n: usize) -> Self {
        let res = num_bigint::BigUint::from(self.clone()).shl(n);
        return Self::new(BigInt({
            let mut limbs = res.to_u64_digits();
            limbs.reverse();
            limbs.resize(4, 0);
            limbs.try_into().unwrap()
        }));
    }

    fn to_le_bytes(&self) -> Vec<Self::ByteType> {
        B::to_bytes_le(&self.into_bigint())
    }

    fn to_be_bytes(&self) -> Vec<Self::ByteType> {
        B::to_bytes_be(&self.into_bigint())
    }

    fn to_le_bits(&self) -> Vec<Self::BooleanType> {
        B::to_bits_le(&self.into_bigint())
    }

    fn to_be_bits(&self) -> Vec<Self::BooleanType> {
        B::to_bits_be(&self.into_bigint())
    }

    fn construct_byte(value: u8) -> Self::ByteType {
        value
    }

    fn from_be_bytes(bytes: &[Self::ByteType]) -> Self {
        Self::from_be_bytes_mod_order(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Fr;
    use ark_ff::Field;
    use ark_groth16::Groth16;
    use ark_r1cs_std::fields::fp::FpVar;
    use ark_relations::{
        ns,
        r1cs::{ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, SynthesisError},
    };
    use ark_snark::{CircuitSpecificSetupSNARK, SNARK};
    use ark_std::rand::SeedableRng;
    use ark_std::UniformRand;

    #[test]
    fn test_field_operations() {
        let a = Fp::from(3u64);
        let b = Fp::from(5u64);
        assert_eq!(a + b, Fp::from(8u64));
        assert_eq!(a * b, Fp::from(15u64));
        assert_eq!(a.inv().unwrap() * a, Fp::from(1u64));
        let c = a.pow([2]);
        assert_eq!(c, Fp::from(9u64));
        let d = a.powers_felt(&Fp::from(2u64));
        assert_eq!(d, Fp::from(9u64));

        let (div, rem) = d.div_rem(&b);
        assert_eq!(div, Fp::from(1u64));
        assert_eq!(rem, Fp::from(4u64));
    }

    #[test]
    fn test_starkent_ark_field_conversion() {
        let a = Fp::from(3u64);

        let b = starknet_crypto::Felt::from(3u64);
        assert_eq!(a.to_stark_felt(), b);

        let c = StarkArkConvert::from_stark_felt(b);
        assert_eq!(a, c);
    }

    #[test]
    fn test_groth16() {
        use ark_bls12_381::{Bls12_381 as Curve, Fr as F};
        // use ark_bn254::{Bn254 as Curve, Fr as F};
        #[derive(Clone)]
        struct MyCircuit {
            a: Option<F>,
            b: Option<F>,
            sum: Option<F>,
            difference: Option<F>,
            product: Option<F>,
            powers: Option<F>,
        }

        impl ConstraintSynthesizer<F> for MyCircuit {
            fn generate_constraints(
                self,
                cs: ConstraintSystemRef<F>,
            ) -> Result<(), SynthesisError> {
                let a = FpVar::new_witness(ns!(cs, "a"), || {
                    self.a.ok_or(SynthesisError::AssignmentMissing)
                })?;
                let b = FpVar::new_witness(ns!(cs, "b"), || {
                    self.b.ok_or(SynthesisError::AssignmentMissing)
                })?;

                let sum = a.clone() + b.clone();
                let sum_input = FpVar::new_input(ns!(cs, "sum"), || {
                    self.sum.ok_or(SynthesisError::AssignmentMissing)
                })?;

                sum.enforce_equal(&sum_input)?;

                let difference = a.clone() - b.clone();
                let difference_input = FpVar::new_input(ns!(cs, "difference"), || {
                    self.difference.ok_or(SynthesisError::AssignmentMissing)
                })?;
                difference.enforce_equal(&difference_input)?;

                let product = a.clone() * b;
                let product_input = FpVar::new_input(ns!(cs, "product"), || {
                    self.product.ok_or(SynthesisError::AssignmentMissing)
                })?;
                product.enforce_equal(&product_input)?;

                let powers = a.powers_felt(&FpVar::two());
                let powers_input = FpVar::new_input(ns!(cs, "powers"), || {
                    self.powers.ok_or(SynthesisError::AssignmentMissing)
                })?;
                powers.enforce_equal(&powers_input)?;

                Ok(())
            }
        }

        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(9365255816191338696);

        let a = F::from(20);
        let b = F::from(10);

        let circuit = MyCircuit {
            a: Some(a),
            b: Some(b),
            sum: Some(a + b),
            difference: Some(a - b),
            product: Some(a * b),
            powers: Some(a.powers([2])),
        };

        let (pk, vk) = Groth16::<Curve>::setup(circuit.clone(), &mut rng).unwrap();
        let processed_vk = Groth16::<Curve>::process_vk(&vk).unwrap();

        let proof = Groth16::<Curve>::prove(&pk, circuit.clone(), &mut rng).unwrap();

        let public_inputs = vec![a + b, a - b, a * b, a.powers([2])];

        assert!(
            Groth16::<Curve>::verify_with_processed_vk(&processed_vk, &public_inputs, &proof)
                .unwrap()
        );
    }

    #[test]
    fn test_normal_div_rem() {
        use ark_bls12_381::{Bls12_381 as Curve, Fr};
        // use ark_bn254::{Bn254 as Curve, Fr as F};
        #[derive(Clone)]
        struct MyCircuit<F: SimpleField> {
            divisor: Option<F>,
            dividend: Option<F>,
        }

        impl<F: SimpleField + PrimeField> ConstraintSynthesizer<F> for MyCircuit<F> {
            fn generate_constraints(
                self,
                cs: ConstraintSystemRef<F>,
            ) -> Result<(), SynthesisError> {
                let divisor = FpVar::new_witness(ns!(cs, "divisor"), || {
                    self.divisor.ok_or(SynthesisError::AssignmentMissing)
                })?;

                let dividend = FpVar::new_witness(ns!(cs, "dividend"), || {
                    self.dividend.ok_or(SynthesisError::AssignmentMissing)
                })?;

                let quotient_input = FpVar::new_input(ns!(cs, "quotient"), || {
                    if let (FpVar::Var(ref dividend), FpVar::Var(ref divisor)) =
                        (&dividend, &divisor)
                    {
                        Ok(dividend
                            .value()
                            .unwrap()
                            .div_rem(&divisor.value().unwrap())
                            .0)
                    } else {
                        panic!("cannot compute quotient")
                    }
                })?;

                let remainder_input = FpVar::new_input(ns!(cs, "remainder"), || {
                    if let (FpVar::Var(dividend), FpVar::Var(divisor)) = (&dividend, &divisor) {
                        Ok(dividend
                            .value()
                            .unwrap()
                            .div_rem(&divisor.value().unwrap())
                            .1)
                    } else {
                        panic!("cannot compute remainder")
                    }
                })?;

                (remainder_input + quotient_input.mul(divisor)).enforce_equal(&dividend)?;

                Ok(())
            }
        }

        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(9365255816191338696);

        let divisor = Fr::from(10);
        let dividend = Fr::from(21);

        let circuit = MyCircuit {
            divisor: Some(divisor),
            dividend: Some(dividend),
        };

        let (pk, vk) = Groth16::<Curve>::setup(circuit.clone(), &mut rng).unwrap();
        let processed_vk = Groth16::<Curve>::process_vk(&vk).unwrap();

        let proof = Groth16::<Curve>::prove(&pk, circuit.clone(), &mut rng).unwrap();

        let public_inputs = vec![Fr::from(2), Fr::from(1)];

        assert!(
            Groth16::<Curve>::verify_with_processed_vk(&processed_vk, &public_inputs, &proof)
                .unwrap()
        );
    }

    #[test]
    fn test_div_rem() {
        use ark_bls12_381::{Bls12_381 as Curve, Fr};
        // use ark_bn254::{Bn254 as Curve, Fr as F};
        #[derive(Clone)]
        struct MyCircuit<F: SimpleField> {
            divisor: Option<F>,
            dividend: Option<F>,
            quotient: Option<F>,
            remainder: Option<F>,
        }

        impl<F: SimpleField + PrimeField> ConstraintSynthesizer<F> for MyCircuit<F> {
            fn generate_constraints(
                self,
                cs: ConstraintSystemRef<F>,
            ) -> Result<(), SynthesisError> {
                let divisor = FpVar::new_witness(ns!(cs, "divisor"), || {
                    self.divisor.ok_or(SynthesisError::AssignmentMissing)
                })?;

                let dividend = FpVar::new_witness(ns!(cs, "dividend"), || {
                    self.dividend.ok_or(SynthesisError::AssignmentMissing)
                })?;

                // TODO: make div_rem works

                let quotient_input = FpVar::new_input(ns!(cs, "quotient"), || {
                    self.quotient
                        .clone()
                        .ok_or(SynthesisError::AssignmentMissing)
                })?;

                let remainder_input = FpVar::new_input(ns!(cs, "remainder"), || {
                    self.remainder
                        .clone()
                        .ok_or(SynthesisError::AssignmentMissing)
                })?;

                (remainder_input + quotient_input.mul(divisor)).enforce_equal(&dividend)?;

                Ok(())
            }
        }

        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(9365255816191338696);

        let divisor = Fr::from(10);
        let dividend = Fr::from(21);

        let circuit = MyCircuit {
            divisor: Some(divisor),
            dividend: Some(dividend),
            quotient: Some(Fr::from(2)),
            remainder: Some(Fr::from(1)),
        };

        let (pk, vk) = Groth16::<Curve>::setup(circuit.clone(), &mut rng).unwrap();
        let processed_vk = Groth16::<Curve>::process_vk(&vk).unwrap();

        let proof = Groth16::<Curve>::prove(&pk, circuit.clone(), &mut rng).unwrap();

        let public_inputs = vec![Fr::from(2), Fr::from(1)];

        assert!(
            Groth16::<Curve>::verify_with_processed_vk(&processed_vk, &public_inputs, &proof)
                .unwrap()
        );
    }

    #[test]
    fn test_div2_rem() {
        use ark_bls12_381::{Bls12_381 as Curve, Fr};
        // use ark_bn254::{Bn254 as Curve, Fr as F};
        #[derive(Clone)]
        struct MyCircuit<F: SimpleField> {
            dividend: Option<F>,
            quotient: Option<F>,
            remainder: Option<F>,
        }

        impl<F: SimpleField + PrimeField> ConstraintSynthesizer<F> for MyCircuit<F> {
            fn generate_constraints(
                self,
                cs: ConstraintSystemRef<F>,
            ) -> Result<(), SynthesisError> {
                let dividend = FpVar::new_witness(ns!(cs, "dividend"), || {
                    self.dividend.ok_or(SynthesisError::AssignmentMissing)
                })?;

                let (quotient, remainder) = dividend.div2_rem();

                let quotient_input = FpVar::new_input(ns!(cs, "quotient"), || {
                    self.quotient
                        .clone()
                        .ok_or(SynthesisError::AssignmentMissing)
                })?;

                let remainder_input = FpVar::new_input(ns!(cs, "remainder"), || {
                    self.remainder
                        .clone()
                        .ok_or(SynthesisError::AssignmentMissing)
                })?;

                quotient.enforce_equal(&quotient_input)?;
                remainder.enforce_equal(&remainder_input)?;

                (remainder_input + quotient_input.mul(FpVar::two())).enforce_equal(&dividend)?;

                Ok(())
            }
        }

        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(9365255816191338696);

        let dividend = Fr::from(21);

        let circuit = MyCircuit {
            dividend: Some(dividend),
            quotient: Some(Fr::from(10)),
            remainder: Some(Fr::from(1)),
        };

        let (pk, vk) = Groth16::<Curve>::setup(circuit.clone(), &mut rng).unwrap();
        let processed_vk = Groth16::<Curve>::process_vk(&vk).unwrap();

        let proof = Groth16::<Curve>::prove(&pk, circuit.clone(), &mut rng).unwrap();

        let public_inputs = vec![Fr::from(10), Fr::from(1)];

        assert!(
            Groth16::<Curve>::verify_with_processed_vk(&processed_vk, &public_inputs, &proof)
                .unwrap()
        );
    }

    #[test]
    fn test_select_fp() {
        let mut rng = ark_std::test_rng();
        let a = Fr::rand(&mut rng);
        let b = Fr::rand(&mut rng);

        assert_eq!(Fr::select(&true, a, b), a);
        assert_eq!(Fr::select(&false, a, b), b);
    }

    #[test]
    fn test_select_fpvar() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let a = FpVar::new_witness(cs.clone(), || Ok(Fr::from(10u32))).unwrap();
        let b = FpVar::new_witness(cs.clone(), || Ok(Fr::from(20u32))).unwrap();
        let cond_true = Boolean::new_witness(cs.clone(), || Ok(true)).unwrap();
        let cond_false = Boolean::new_witness(cs.clone(), || Ok(false)).unwrap();

        FpVar::select(&cond_true, a.clone(), b.clone())
            .enforce_equal(&a)
            .unwrap();
        FpVar::select(&cond_false, a, b.clone())
            .enforce_equal(&b)
            .unwrap();

        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_div() {
        let a = Fp::from(3);
        let b = Fp::from(2);

        assert_eq!(a.field_div(&b), a / b);
    }

    #[test]
    fn test_shift() {
        let a = Fp::from(11);

        assert_eq!(a.rsh(2), Fp::from(2));
        assert_eq!(a.lsh(2), Fp::from(44));

        let cs = ConstraintSystem::<Fp>::new_ref();
        let a = FpVar::new_witness(cs.clone(), || Ok(Fp::from(11u32))).unwrap();
        let a_lsh = FpVar::new_witness(cs.clone(), || Ok(Fp::from(44u32))).unwrap();
        let a_rsh = FpVar::new_witness(cs.clone(), || Ok(Fp::from(2u32))).unwrap();

        a.lsh(2).enforce_equal(&a_lsh).unwrap();
        a.rsh(2).enforce_equal(&a_rsh).unwrap();

        assert!(cs.is_satisfied().unwrap());
    }
}
