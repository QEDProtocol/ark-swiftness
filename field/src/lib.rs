use ark_ff::BigInt;
use ark_ff::Field;
use ark_ff::Fp256;
use ark_ff::MontBackend;
use ark_ff::MontConfig;
use ark_ff::PrimeField;
use ark_ff::{biginteger::BigInteger256 as B, BigInteger as _};
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::fields::FieldVar;
use ark_r1cs_std::prelude::Boolean;
use ark_r1cs_std::uint8::UInt8;
use ark_r1cs_std::R1CSVar;
use ark_r1cs_std::ToBitsGadget;
use ark_r1cs_std::ToBytesGadget;
use num_integer::Integer;

use std::fmt::Debug;

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
    type Value: PrimeField + SimpleField;
    type BooleanType: Clone + Debug;
    type ByteType: Clone + Debug;

    fn zero() -> Self;
    fn one() -> Self;
    fn two() -> Self;
    fn three() -> Self;
    fn four() -> Self;
    fn get_value(&self) -> Self::Value;
    fn negate(&self) -> Self;
    fn inv(&self) -> Self;
    fn mul_by_constant(&self, n: impl Into<num_bigint::BigUint>) -> Self;
    fn powers<Exp: AsRef<[u64]>>(&self, n: Exp) -> Self;
    fn powers_felt(&self, n: &Self) -> Self;
    fn from_constant(value: impl Into<num_bigint::BigUint>) -> Self;
    fn from_boolean(value: Self::BooleanType) -> Self;
    fn into_boolean(&self) -> Self::BooleanType;
    fn from_biguint(value: num_bigint::BigUint) -> Self;
    fn into_biguint(&self) -> num_bigint::BigUint;
    fn into_constant<T: TryFrom<num_bigint::BigUint>>(&self) -> T
    where
        <T as TryFrom<num_bigint::BigUint>>::Error: Debug;
    fn from_felt(value: Fp) -> Self;
    fn from_stark_felt(value: starknet_crypto::Felt) -> Self;
    fn assert_equal(&self, other: &Self);
    fn assert_not_equal(&self, other: &Self);
    fn div_rem(&self, other: &Self) -> (Self, Self);
    fn div2_rem(&self) -> (Self, Self);
    fn rsh(&self, n: usize) -> Self;
    fn rshm(&self, n: usize) -> (Self, Self);
    fn lsh(&self, n: usize) -> Self;
    fn field_div(&self, other: &Self) -> Self;
    fn select(cond: &Self::BooleanType, true_value: Self, false_value: Self) -> Self;
    fn is_equal(&self, other: &Self) -> Self::BooleanType;
    fn is_not_equal(&self, other: &Self) -> Self::BooleanType;
    fn is_zero(&self) -> Self::BooleanType;
    fn is_one(&self) -> Self::BooleanType;
    fn and(lhs: &Self::BooleanType, rhs: &Self::BooleanType) -> Self::BooleanType;
    fn or(lhs: &Self::BooleanType, rhs: &Self::BooleanType) -> Self::BooleanType;
    fn xor(lhs: &Self::BooleanType, rhs: &Self::BooleanType) -> Self::BooleanType;
    fn not(value: &Self::BooleanType) -> Self::BooleanType;
    fn greater_than(&self, other: &Self) -> Self::BooleanType;
    fn less_than(&self, other: &Self) -> Self::BooleanType;
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
    fn from_le_bytes(bytes: &[Self::ByteType]) -> Self;
    fn to_le_bits(&self) -> Vec<Self::BooleanType>;
    fn to_be_bits(&self) -> Vec<Self::BooleanType>;
    fn from_le_bits(bits: &[Self::BooleanType]) -> Self;
    fn from_be_bits(bits: &[Self::BooleanType]) -> Self;
    fn reverse_bits(&self) -> Self;
    fn construct_byte(value: u8) -> Self::ByteType;
    fn construct_bool(value: bool) -> Self::BooleanType;

    fn sort(values: Vec<Self>) -> Vec<Self>;
    fn slice(values: &[Self], start: &Self, end: &Self) -> Vec<Self>;
    fn skip(values: &[Self], n: &Self) -> Vec<Self>;
    fn take(values: &[Self], n: &Self) -> Vec<Self>;
    fn range(start: &Self, end: &Self) -> Vec<Self>;
    fn at(values: &[Self], i: &Self) -> Self;
}

impl<F: PrimeField + SimpleField> SimpleField for FpVar<F> {
    type Value = F;
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

    fn is_zero(&self) -> Self::BooleanType {
        EqGadget::is_eq(self, &SimpleField::zero()).unwrap()
    }

    fn is_one(&self) -> Self::BooleanType {
        EqGadget::is_eq(self, &SimpleField::one()).unwrap()
    }

    fn inv(&self) -> Self {
        if self.is_constant() {
            FpVar::Constant(self.value().unwrap().inv().clone())
        } else {
            let is_zero = <Self as SimpleField>::is_zero(self);
            let inv = FpVar::new_witness(self.cs(), || Ok(self.value()?.inv())).unwrap();
            self.mul_equals(&inv, &Self::from_boolean(Self::not(&is_zero)))
                .unwrap();
            inv
        }
    }

    fn from_constant(value: impl Into<num_bigint::BigUint>) -> Self {
        FpVar::Constant(F::from_constant(value))
    }

    fn from_boolean(value: Self::BooleanType) -> Self {
        Self::from(value)
    }

    fn into_boolean(&self) -> Self::BooleanType {
        Self::assert_true(Self::or(
            &SimpleField::is_zero(self),
            &SimpleField::is_one(self),
        ));
        Boolean::select(
            &SimpleField::is_zero(self),
            &Boolean::<F>::FALSE,
            &Boolean::<F>::TRUE,
        )
        .unwrap()
    }

    fn from_biguint(value: num_bigint::BigUint) -> Self {
        FpVar::Constant(F::from_biguint(value))
    }

    fn into_biguint(&self) -> num_bigint::BigUint {
        self.value().unwrap().try_into().unwrap()
    }

    fn into_constant<T: TryFrom<num_bigint::BigUint>>(&self) -> T
    where
        <T as TryFrom<num_bigint::BigUint>>::Error: Debug,
    {
        self.into_biguint().try_into().unwrap()
    }

    fn powers<Exp: AsRef<[u64]>>(&self, n: Exp) -> Self {
        self.pow_by_constant(n).unwrap()
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

        let cs = self.cs().or(other.cs());

        let quotient = Self::new_witness(cs.clone(), || {
            Ok(self.value().unwrap().div_rem(&other.value().unwrap()).0)
        })
        .unwrap();

        let remainder = Self::new_witness(cs.clone(), || {
            Ok(self.value().unwrap().div_rem(&other.value().unwrap()).1)
        })
        .unwrap();

        (quotient.clone() * other + &remainder)
            .enforce_equal(self)
            .unwrap();

        (quotient, remainder)
    }

    fn div2_rem(&self) -> (Self, Self) {
        let bits = self.to_bits_le().unwrap();
        if bits.is_empty() {
            return (SimpleField::zero(), SimpleField::zero());
        }

        let (left, right) = bits.split_at(1);
        (
            Boolean::le_bits_to_fp_var(right).unwrap(),
            Boolean::le_bits_to_fp_var(left).unwrap(),
        )
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

    fn xor(lhs: &Self::BooleanType, rhs: &Self::BooleanType) -> Self::BooleanType {
        Boolean::xor(lhs, rhs).unwrap()
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
        self.mul(other.inv())
    }

    fn rsh(&self, n: usize) -> Self {
        let bits = self.to_bits_le().unwrap();
        if bits.is_empty() || n >= bits.len() {
            return SimpleField::zero();
        }

        Boolean::le_bits_to_fp_var(&bits[n..]).unwrap()
    }

    fn rshm(&self, n: usize) -> (Self, Self) {
        let bits = self.to_bits_le().unwrap();
        if bits.is_empty() || n >= bits.len() {
            return (SimpleField::zero(), self.clone());
        }

        (
            Boolean::le_bits_to_fp_var(&bits[n..]).unwrap(),
            Boolean::le_bits_to_fp_var(&bits[..n]).unwrap(),
        )
    }

    fn greater_than(&self, other: &Self) -> Self::BooleanType {
        FpVar::<F>::is_cmp_unchecked(self, other, core::cmp::Ordering::Greater, false).unwrap()
    }

    fn less_than(&self, other: &Self) -> Self::BooleanType {
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

    fn construct_bool(value: bool) -> Self::BooleanType {
        Boolean::<F>::constant(value)
    }

    fn from_be_bytes(bytes: &[Self::ByteType]) -> Self {
        Boolean::le_bits_to_fp_var(
            &bytes
                .iter()
                .rev()
                .flat_map(|b| b.to_bits_le().unwrap())
                .collect::<Vec<_>>(),
        )
        .unwrap()
    }

    fn from_le_bytes(bytes: &[Self::ByteType]) -> Self {
        Boolean::le_bits_to_fp_var(
            &bytes
                .iter()
                .flat_map(|b| b.to_bits_le().unwrap())
                .collect::<Vec<_>>(),
        )
        .unwrap()
    }

    fn from_le_bits(bits: &[Self::BooleanType]) -> Self {
        Boolean::le_bits_to_fp_var(&bits).unwrap()
    }

    fn from_be_bits(bits: &[Self::BooleanType]) -> Self {
        Boolean::le_bits_to_fp_var(
            bits.into_iter()
                .cloned()
                .rev()
                .collect::<Vec<_>>()
                .as_slice(),
        )
        .unwrap()
    }

    // Unsafe
    fn reverse_bits(&self) -> Self {
        if self.is_constant() {
            return FpVar::Constant(self.value().unwrap().reverse_bits());
        }

        let r = Self::new_witness(self.cs(), || Ok(self.value().unwrap().reverse_bits())).unwrap();

        // TODO: we should have been able to write this in circuits but arkworks' to_non_unique_bits looks buggy
        r
    }

    fn get_value(&self) -> Self::Value {
        self.value().unwrap().clone()
    }

    // Unsafe
    fn sort(values: Vec<Self>) -> Vec<Self> {
        if values.is_empty() {
            return vec![];
        }

        let cs = values.cs();

        // All should be constants
        if cs.is_none() {
            let mut new_values = values.value().unwrap();
            new_values.sort();
            return new_values.into_iter().map(|v| FpVar::Constant(v)).collect();
        }

        let new_values = Vec::<Self>::new_witness(cs, || {
            let mut values = values.value().unwrap();
            values.sort();
            Ok(values)
        })
        .unwrap();

        // TODO: check new_values come from the original vector
        new_values.iter().reduce(|prev, next| {
            SimpleField::assert_lte(prev, next);
            next
        });

        new_values
    }

    // Unsafe
    fn slice(values: &[Self], start: &Self, end: &Self) -> Vec<Self> {
        let cs = values.cs();

        // All should be constants
        if cs.is_none() {
            let start = start.get_value();
            let end = end.get_value();
            return values[start.into_constant()..end.into_constant()].to_vec();
        }

        let slice = Vec::<Self>::new_witness(cs, || {
            let start = start.get_value();
            let end = end.get_value();
            let values = values.value().unwrap();
            Ok(values[start.into_constant()..end.into_constant()].to_vec())
        })
        .unwrap();

        // TODO: check new slice comes from the original slice
        slice
    }

    fn skip(values: &[Self], n: &Self) -> Vec<Self> {
        let cs = values.cs();

        // All should be constants
        if cs.is_none() {
            let start = n.get_value();
            return values[start.into_constant()..].to_vec();
        }

        let slice = Vec::<Self>::new_witness(cs, || {
            let start = n.get_value();
            let values = values.value().unwrap();
            Ok(values[start.into_constant()..].to_vec())
        })
        .unwrap();

        // TODO: check new slice comes from the original slice
        slice
    }

    fn take(values: &[Self], n: &Self) -> Vec<Self> {
        let cs = values.cs();

        // All should be constants
        if cs.is_none() {
            let start = n.get_value();
            return values[..start.into_constant()].to_vec();
        }

        let slice = Vec::<Self>::new_witness(cs, || {
            let start = n.get_value();
            let values = values.value().unwrap();
            Ok(values[..start.into_constant()].to_vec())
        })
        .unwrap();

        // TODO: check new slice comes from the original slice
        slice
    }

    // Unsafe
    fn range(start: &Self, end: &Self) -> Vec<Self> {
        let cs = start.cs().or(end.cs());

        if cs.is_none() {
            return (start.value().unwrap().into_constant::<usize>()
                ..end.value().unwrap().into_constant::<usize>())
                .map(|v| Self::from_constant(v))
                .collect::<Vec<_>>();
        }

        let range = Vec::<Self>::new_witness(cs, || {
            Ok((start.value().unwrap().into_constant::<usize>()
                ..end.value().unwrap().into_constant::<usize>())
                .map(|v| F::from_constant(v))
                .collect::<Vec<_>>())
        })
        .unwrap();

        if let Some(first) = range.first() {
            first.assert_equal(start);
        }

        if let Some(last) = range.last() {
            last.assert_equal(&(end.clone() - &SimpleField::one()))
        }

        range.iter().reduce(|prev, next| {
            next.assert_equal(&(prev + &SimpleField::one()));
            next
        });

        return range;
    }

    // Unsafe
    fn at(values: &[Self], i: &Self) -> Self {
        let cs = values.cs();
        if i.is_constant() || cs.is_none() {
            return values[i.into_constant::<usize>()].clone();
        }

        let value = Self::new_witness(cs, || {
            Ok(<Self as R1CSVar<F>>::value(&values[i.into_constant::<usize>()]).unwrap())
        })
        .unwrap();

        // TODO: check value equals to element at i position
        value
    }

    fn mul_by_constant(&self, n: impl Into<num_bigint::BigUint>) -> Self {
        self.mul(&Self::from_constant(n))
    }
}

macro_rules! impl_simple_field_for {
    ($field:ty) => {
        impl SimpleField for $field {
            type Value = $field;
            type BooleanType = bool;
            type ByteType = u8;

            fn zero() -> Self {
                ark_ff::Zero::zero()
            }

            fn one() -> Self {
                ark_ff::One::one()
            }

            fn two() -> Self {
                <$field>::from(2u64)
            }

            fn is_zero(&self) -> Self::BooleanType {
                self == &SimpleField::zero()
            }

            fn is_one(&self) -> Self::BooleanType {
                self == &SimpleField::one()
            }

            fn negate(&self) -> Self {
                Neg::neg(*self)
            }

            fn inv(&self) -> Self {
                Field::inverse(self).unwrap_or(SimpleField::zero())
            }

            fn from_constant(value: impl Into<num_bigint::BigUint>) -> Self {
                <$field>::from(value.into())
            }

            fn from_boolean(value: Self::BooleanType) -> Self {
                Self::from(value)
            }

            fn into_boolean(&self) -> Self::BooleanType {
                assert!(self == &Self::zero() || self == &Self::one());
                self == &Self::one()
            }

            fn from_biguint(value: num_bigint::BigUint) -> Self {
                <$field>::from(value)
            }

            fn into_biguint(&self) -> num_bigint::BigUint {
                num_bigint::BigUint::from(self.clone())
            }

            fn into_constant<T: TryFrom<num_bigint::BigUint>>(&self) -> T
            where
                <T as TryFrom<num_bigint::BigUint>>::Error: Debug,
            {
                self.into_biguint().try_into().unwrap()
            }

            fn powers<Exp: AsRef<[u64]>>(&self, n: Exp) -> Self {
                Field::pow(self, n)
            }

            fn from_felt(value: Fp) -> Self {
                <$field>::from(num_bigint::BigUint::from(value))
            }

            fn from_stark_felt(value: starknet_crypto::Felt) -> Self {
                let mut val = value.to_raw();
                val.reverse();
                Self::new_unchecked(BigInt(val))
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
                        limbs.resize(4, 0);
                        limbs.try_into().unwrap()
                    })),
                    Self::new(BigInt({
                        let mut limbs = remainder.to_u64_digits();
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

            fn xor(lhs: &Self::BooleanType, rhs: &Self::BooleanType) -> Self::BooleanType {
                lhs ^ rhs
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
                self.mul(&other.inv())
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

            fn rshm(&self, n: usize) -> (Self, Self) {
                let (quotient, remainder) = num_bigint::BigUint::from(self.clone())
                    .div_rem(&num_bigint::BigUint::from(2u32).pow(n as u32));
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

            fn greater_than(&self, other: &Self) -> Self::BooleanType {
                self > other
            }

            fn less_than(&self, other: &Self) -> Self::BooleanType {
                self < other
            }

            fn lte(&self, other: &Self) -> Self::BooleanType {
                self <= other
            }

            fn gte(&self, other: &Self) -> Self::BooleanType {
                self >= other
            }

            fn three() -> Self {
                <$field>::from(3u64)
            }

            fn four() -> Self {
                <$field>::from(4u64)
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

            fn construct_bool(value: bool) -> Self::BooleanType {
                value
            }

            fn from_be_bytes(bytes: &[Self::ByteType]) -> Self {
                Self::from_be_bytes_mod_order(bytes)
            }

            fn from_le_bytes(bytes: &[Self::ByteType]) -> Self {
                Self::from_le_bytes_mod_order(bytes)
            }

            fn from_be_bits(bits: &[Self::BooleanType]) -> Self {
                Self::from_bigint(B::from_bits_be(bits)).unwrap()
            }

            fn from_le_bits(bits: &[Self::BooleanType]) -> Self {
                Self::from_bigint(B::from_bits_le(bits)).unwrap()
            }

            fn reverse_bits(&self) -> Self {
                Self::from_le_bits(
                    &self
                        .to_be_bits()
                        .into_iter()
                        .skip_while(|x| !x)
                        .collect::<Vec<_>>(),
                )
            }

            fn get_value(&self) -> Self::Value {
                self.clone()
            }

            fn sort(mut values: Vec<Self>) -> Vec<Self> {
                values.sort();
                values
            }

            fn slice(values: &[Self], start: &Self, end: &Self) -> Vec<Self> {
                values[start.into_constant()..end.into_constant()].to_vec()
            }

            fn skip(values: &[Self], n: &Self) -> Vec<Self> {
                values[n.into_constant()..].to_vec()
            }

            fn take(values: &[Self], n: &Self) -> Vec<Self> {
                values[..n.into_constant()].to_vec()
            }

            fn range(start: &Self, end: &Self) -> Vec<Self> {
                (start.get_value().into_constant::<usize>()
                    ..end.get_value().into_constant::<usize>())
                    .map(|v| Self::from(v as u64))
                    .collect()
            }

            fn at(values: &[Self], i: &Self) -> Self {
                values[i.into_constant::<usize>()].clone()
            }

            fn mul_by_constant(&self, n: impl Into<num_bigint::BigUint>) -> Self {
                self * &Self::from_constant(n)
            }
        }
    };
}

impl_simple_field_for!(Fr);
impl_simple_field_for!(Fp);
impl_simple_field_for!(ark_bls12_381::Fr);

#[cfg(test)]
mod tests {
    use std::str::FromStr;

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
    use starknet_crypto::Felt;

    #[test]
    fn test_field_operations() {
        let a = Fp::from(3u64);
        let b = Fp::from(5u64);
        assert_eq!(a + b, Fp::from(8u64));
        assert_eq!(a * b, Fp::from(15u64));
        assert_eq!(a.inv() * a, Fp::from(1u64));
        let c = a.pow([2]);
        assert_eq!(c, Fp::from(9u64));
        let d = a.powers_felt(&Fp::from(2u64));
        assert_eq!(d, Fp::from(9u64));

        let (div, rem) = d.div_rem(&b);
        assert_eq!(div, Fp::from(1u64));
        assert_eq!(rem, Fp::from(4u64));

        assert_eq!(Fp::from(1u64).inv(), Fp::from(1));
    }

    #[test]
    fn test_field_operations_fpvar() {
        let cs = ConstraintSystem::<Fp>::new_ref();
        let a = FpVar::new_witness(cs.clone(), || Ok(Fp::from(3u64))).unwrap();
        let a_const = FpVar::Constant(Fp::from(3u64));
        let b = FpVar::new_witness(cs.clone(), || Ok(Fp::from(5u64))).unwrap();

        let sum = a.clone() + b.clone();
        let product = a.clone() * b.clone();
        let inv_a = a.inv();
        let inv_a_constant = a_const.inv();
        let c = a.pow_by_constant([2]).unwrap();
        let d = a.powers_felt(&FpVar::constant(Fp::from(2u64)));

        sum.enforce_equal(&FpVar::constant(Fp::from(8u64))).unwrap();
        product
            .enforce_equal(&FpVar::constant(Fp::from(15u64)))
            .unwrap();
        (inv_a * a.clone())
            .enforce_equal(&FpVar::constant(Fp::from(1u64)))
            .unwrap();
        (inv_a_constant * a_const.clone())
            .enforce_equal(&FpVar::constant(Fp::from(1u64)))
            .unwrap();
        c.enforce_equal(&FpVar::constant(Fp::from(9u64))).unwrap();
        d.enforce_equal(&FpVar::constant(Fp::from(9u64))).unwrap();

        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_starkent_ark_field_conversion() {
        let a = Fp::from(
            num_bigint::BigUint::from_str("340282366920938463463374607431768211456").unwrap(),
        );

        let b = starknet_crypto::Felt::from_hex_unchecked("0x100000000000000000000000000000000");
        assert_eq!(a.to_stark_felt(), b);

        let c = StarkArkConvert::from_stark_felt(b);
        assert_eq!(a, c);
    }

    #[test]
    fn test_div_rem() {
        let divisor = Fr::from(10);
        let dividend = Fr::from(21);

        let (quotient, remainder) = dividend.div_rem(&divisor);
        assert_eq!(quotient, Fr::from(2));
        assert_eq!(remainder, Fr::from(1));

        let divisor = <Fp as SimpleField>::from_stark_felt(Felt::from_dec_str("340282366920938463463374607431768211456").unwrap());
        let dividend = <Fp as SimpleField>::from_stark_felt(Felt::from_dec_str("3385124832881611382833133824023403256452994652181471147230480383584863118128").unwrap());

        let (_, remainder) = dividend.div_rem(&divisor);
        assert_eq!(remainder, <Fp as SimpleField>::from_stark_felt(Felt::from_dec_str("217609915070804396630239679827883451184").unwrap()));
    }

    #[test]
    fn test_div_rem_fpvar() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let divisor = FpVar::new_witness(cs.clone(), || Ok(Fr::from(10))).unwrap();
        let dividend = FpVar::new_witness(cs.clone(), || Ok(Fr::from(21))).unwrap();

        let (quotient, remainder) = dividend.div_rem(&divisor);

        quotient
            .enforce_equal(&FpVar::constant(Fr::from(2)))
            .unwrap();
        remainder
            .enforce_equal(&FpVar::constant(Fr::from(1)))
            .unwrap();

        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_div2_rem() {
        let dividend = Fp::from(21);

        let (quotient, remainder) = dividend.div2_rem();

        assert_eq!(quotient, Fp::from(10));
        assert_eq!(remainder, Fp::from(1));
    }

    #[test]
    fn test_div2_rem_fpvar() {
        let cs = ConstraintSystem::<Fp>::new_ref();
        let dividend = FpVar::new_witness(cs.clone(), || Ok(Fp::from(21))).unwrap();

        let (quotient, remainder) = dividend.div2_rem();

        quotient
            .enforce_equal(&FpVar::constant(Fp::from(10)))
            .unwrap();
        remainder
            .enforce_equal(&FpVar::constant(Fp::from(1)))
            .unwrap();

        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_select() {
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
    fn test_field_div() {
        let a = Fp::from(3);
        let b = Fp::from(2);
        let zero = Fp::zero();

        assert_eq!(a.field_div(&b), a / b);
        assert_eq!(a.field_div(&zero), zero);
    }

    #[test]
    fn test_field_div_fpvar() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let a = FpVar::new_witness(cs.clone(), || Ok(Fr::from(3))).unwrap();
        let b = FpVar::new_witness(cs.clone(), || Ok(Fr::from(2))).unwrap();
        let zero = FpVar::new_witness(cs.clone(), || Ok(Fr::zero())).unwrap();

        a.field_div(&b)
            .enforce_equal(&FpVar::constant(Fr::from(3) / Fr::from(2)))
            .unwrap();
        a.field_div(&zero)
            .enforce_equal(&FpVar::Constant(Fr::zero()))
            .unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_shift() {
        let a = Fp::from(11);

        assert_eq!(a.rsh(2), Fp::from(2));
        assert_eq!(a.lsh(2), Fp::from(44));

        assert_eq!(a.rshm(2), (Fp::from(2), Fp::from(3)));
    }

    #[test]
    fn test_shift_fpvar() {
        let cs = ConstraintSystem::<Fp>::new_ref();
        let a = FpVar::new_witness(cs.clone(), || Ok(Fp::from(11))).unwrap();

        FpVar::assert_equal(&a.rsh(2), &FpVar::from_constant(2_u128));
        FpVar::assert_equal(&a.lsh(2), &FpVar::from_constant(44_u128));
        FpVar::assert_equal(&a.rshm(2).0, &FpVar::from_constant(2_u128));
        FpVar::assert_equal(&a.rshm(2).1, &FpVar::from_constant(3_u128));

        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_comparison_operations() {
        let a = Fp::from(5u64);
        let b = Fp::from(3u64);

        assert!(SimpleField::greater_than(&a, &b));
        assert!(SimpleField::less_than(&b, &a));
        assert!(a.gte(&b));
        assert!(b.lte(&a));
        assert!(!a.is_equal(&b));
        assert!(a.is_not_equal(&b));
    }

    #[test]
    fn test_comparison_operations_fpvar() {
        let cs = ConstraintSystem::<Fp>::new_ref();
        let a = FpVar::new_witness(cs.clone(), || Ok(Fp::from(5u64))).unwrap();
        let b = FpVar::new_witness(cs.clone(), || Ok(Fp::from(3u64))).unwrap();

        FpVar::assert_true(SimpleField::greater_than(&a, &b));
        FpVar::assert_true(SimpleField::less_than(&b, &a));
        FpVar::assert_true(a.gte(&b));
        FpVar::assert_true(b.lte(&a));
        FpVar::assert_false(a.is_equal(&b));
        FpVar::assert_true(a.is_not_equal(&b));

        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_boolean_operations() {
        let t = true;
        let f = false;

        assert!(Fp::and(&t, &t));
        assert!(!Fp::and(&t, &f));
        assert!(Fp::or(&t, &f));
        assert!(!Fp::or(&f, &f));
        assert!(!Fp::not(&t));
        assert!(Fp::not(&f));
        assert!(!Fp::xor(&f, &f));
        assert!(Fp::xor(&f, &t));
    }

    #[test]
    fn test_boolean_operations_fpvar() {
        let cs = ConstraintSystem::<Fp>::new_ref();
        let t = Boolean::new_witness(cs.clone(), || Ok(true)).unwrap();
        let f = Boolean::new_witness(cs.clone(), || Ok(false)).unwrap();

        FpVar::assert_true(FpVar::and(&t, &t));
        FpVar::assert_false(FpVar::and(&t, &f));
        FpVar::assert_true(FpVar::or(&t, &f));
        FpVar::assert_false(FpVar::or(&f, &f));
        FpVar::assert_false(FpVar::not(&t));
        FpVar::assert_true(FpVar::not(&f));
        FpVar::assert_false(FpVar::xor(&f, &f));
        FpVar::assert_true(FpVar::xor(&f, &t));

        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_byte_operations() {
        let a = Fp::from(0x1234u64);
        let bytes = a.to_le_bytes();
        assert_eq!(bytes.len(), 32);
        assert_eq!(bytes[0], 0x34);
        assert_eq!(bytes[1], 0x12);

        let reconstructed = Fp::from_le_bytes(&bytes);
        assert_eq!(reconstructed, a);

        let bytes = a.to_be_bytes();
        assert_eq!(bytes.len(), 32);
        assert_eq!(bytes[30], 0x12);
        assert_eq!(bytes[31], 0x34);

        let reconstructed = Fp::from_be_bytes(&bytes);
        assert_eq!(reconstructed, a);
    }

    #[test]
    fn test_byte_operations_fpvar() {
        let cs = ConstraintSystem::<Fp>::new_ref();
        let a = FpVar::new_witness(cs.clone(), || Ok(Fp::from(0x1234u64))).unwrap();
        let bytes = a.to_le_bytes();
        assert_eq!(bytes.len(), 32);
        bytes[0]
            .enforce_equal(&FpVar::construct_byte(0x34))
            .unwrap();
        bytes[1]
            .enforce_equal(&FpVar::construct_byte(0x12))
            .unwrap();

        let reconstructed = FpVar::from_le_bytes(&bytes);
        FpVar::assert_equal(&reconstructed, &a);

        let bytes = a.to_be_bytes();
        assert_eq!(bytes.len(), 32);
        bytes[30]
            .enforce_equal(&FpVar::construct_byte(0x12))
            .unwrap();
        bytes[31]
            .enforce_equal(&FpVar::construct_byte(0x34))
            .unwrap();

        let reconstructed = FpVar::from_be_bytes(&bytes);
        FpVar::assert_equal(&reconstructed, &a);

        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_bit_operations() {
        let a = Fp::from(0b1010u64);
        let bits = a.to_le_bits();
        assert_eq!(bits.len(), 256);
        assert!(!bits[0]);
        assert!(bits[1]);
        assert!(!bits[2]);
        assert!(bits[3]);

        let bits = a.to_be_bits();
        assert_eq!(bits.len(), 256);
        assert!(bits[252]);
        assert!(!bits[253]);
        assert!(bits[254]);
        assert!(!bits[255]);
    }

    #[test]
    fn test_bit_operations_fpvar() {
        let cs = ConstraintSystem::<Fp>::new_ref();
        let a = FpVar::new_witness(cs.clone(), || Ok(Fp::from(0b1010u64))).unwrap();
        let bits = a.to_le_bits();
        assert_eq!(bits.len(), 252);
        bits[0].enforce_equal(&Boolean::constant(false)).unwrap();
        bits[1].enforce_equal(&Boolean::constant(true)).unwrap();
        bits[2].enforce_equal(&Boolean::constant(false)).unwrap();
        bits[3].enforce_equal(&Boolean::constant(true)).unwrap();

        let bits = a.to_be_bits();
        assert_eq!(bits.len(), 252);
        bits[248].enforce_equal(&Boolean::constant(true)).unwrap();
        bits[249].enforce_equal(&Boolean::constant(false)).unwrap();
        bits[250].enforce_equal(&Boolean::constant(true)).unwrap();
        bits[251].enforce_equal(&Boolean::constant(false)).unwrap();

        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_from_constant_and_biguint_fp() {
        let value = 42u64;
        let biguint = num_bigint::BigUint::from(value);

        let from_constant = Fp::from_constant(value);
        let from_biguint = Fp::from_biguint(biguint.clone());

        assert_eq!(from_constant, from_biguint);
        assert_eq!(from_constant, Fp::from(value));
    }

    #[test]
    fn test_into_constant_and_biguint_fp() {
        let value = Fp::from(42u64);

        let into_biguint: num_bigint::BigUint = value.into_biguint();
        let into_constant: u64 = value.into_constant();

        assert_eq!(into_biguint, num_bigint::BigUint::from(42u64));
        assert_eq!(into_constant, 42u64);
    }

    #[test]
    fn test_from_constant_and_biguint_fpvar() {
        let cs = ConstraintSystem::<Fp>::new_ref();
        let value = 42u64;
        let biguint = num_bigint::BigUint::from(value);

        let from_constant = FpVar::from_constant(value);
        let from_biguint = FpVar::from_biguint(biguint.clone());

        from_constant
            .enforce_equal(&FpVar::constant(Fp::from(value)))
            .unwrap();
        from_biguint
            .enforce_equal(&FpVar::constant(Fp::from(value)))
            .unwrap();

        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_into_constant_and_biguint_fpvar() {
        let cs = ConstraintSystem::<Fp>::new_ref();
        let value = FpVar::new_witness(cs.clone(), || Ok(Fp::from(42u64))).unwrap();

        let into_biguint: num_bigint::BigUint = value.into_biguint();
        let into_constant: u64 = value.into_constant();

        assert_eq!(into_biguint, num_bigint::BigUint::from(42u64));
        assert_eq!(into_constant, 42u64);

        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_groth16_bls12381() {
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
    fn test_sort() {
        let mut values_fp = vec![Fp::from(3), Fp::from(1), Fp::from(4), Fp::from(2)];
        let sorted_fp = Fp::sort(values_fp.clone());
        values_fp.sort();
        assert_eq!(sorted_fp, values_fp);
    }

    #[test]
    fn test_sort_fpvar() {
        let cs = ConstraintSystem::<Fp>::new_ref();
        let values_fpvar: Vec<FpVar<Fp>> = vec![3, 1, 4, 2]
            .into_iter()
            .map(|v| FpVar::new_witness(cs.clone(), || Ok(Fp::from(v))).unwrap())
            .collect();
        let sorted_fpvar = FpVar::sort(values_fpvar.clone());

        // Check if the constraint system is satisfied
        assert!(cs.is_satisfied().unwrap());

        // Check if the sorted FpVar values match the sorted Fp values
        let sorted_fp_values: Vec<Fp> = sorted_fpvar.iter().map(|v| v.value().unwrap()).collect();
        let expected_sorted: Vec<Fp> = vec![1, 2, 3, 4].into_iter().map(Fp::from).collect();
        assert_eq!(sorted_fp_values, expected_sorted);
    }
    #[test]
    fn test_slice_fp() {
        let values_fp = vec![
            Fp::from(1),
            Fp::from(2),
            Fp::from(3),
            Fp::from(4),
            Fp::from(5),
        ];
        let start = Fp::from(1);
        let end = Fp::from(4);
        let sliced_fp = Fp::slice(&values_fp, &start, &end);
        let expected_slice = vec![Fp::from(2), Fp::from(3), Fp::from(4)];
        assert_eq!(sliced_fp, expected_slice);
    }

    #[test]
    fn test_slice_fpvar() {
        let cs = ConstraintSystem::<Fp>::new_ref();
        let values_fpvar: Vec<FpVar<Fp>> = vec![1, 2, 3, 4, 5]
            .into_iter()
            .map(|v| FpVar::new_witness(cs.clone(), || Ok(Fp::from(v))).unwrap())
            .collect();
        let start = FpVar::new_witness(cs.clone(), || Ok(Fp::from(1))).unwrap();
        let end = FpVar::new_witness(cs.clone(), || Ok(Fp::from(4))).unwrap();
        let sliced_fpvar = FpVar::slice(&values_fpvar, &start, &end);

        // Check if the constraint system is satisfied
        assert!(cs.is_satisfied().unwrap());

        // Check if the sliced FpVar values match the expected slice
        let sliced_fp_values: Vec<Fp> = sliced_fpvar.iter().map(|v| v.value().unwrap()).collect();
        let expected_slice: Vec<Fp> = vec![2, 3, 4].into_iter().map(Fp::from).collect();
        assert_eq!(sliced_fp_values, expected_slice);
    }

    #[test]
    fn test_range_fp() {
        let start = Fp::from(1);
        let end = Fp::from(5);
        let range = Fp::range(&start, &end);
        let expected_range: Vec<Fp> = vec![1, 2, 3, 4].into_iter().map(Fp::from).collect();
        assert_eq!(range, expected_range);
    }

    #[test]
    fn test_range_fpvar() {
        let cs = ConstraintSystem::<Fp>::new_ref();
        let start = FpVar::new_witness(cs.clone(), || Ok(Fp::from(1))).unwrap();
        let end = FpVar::new_witness(cs.clone(), || Ok(Fp::from(5))).unwrap();
        let range = FpVar::range(&start, &end);

        // Check if the constraint system is satisfied
        assert!(cs.is_satisfied().unwrap());

        // Check if the range FpVar values match the expected range
        let range_fp_values: Vec<Fp> = range.iter().map(|v| v.value().unwrap()).collect();
        let expected_range: Vec<Fp> = vec![1, 2, 3, 4].into_iter().map(Fp::from).collect();
        assert_eq!(range_fp_values, expected_range);
    }

    #[test]
    fn test_at_fp() {
        let values = vec![
            Fp::from(1),
            Fp::from(2),
            Fp::from(3),
            Fp::from(4),
            Fp::from(5),
        ];
        let index = Fp::from(2);
        let result = Fp::at(&values, &index);
        assert_eq!(result, Fp::from(3));
    }

    #[test]
    fn test_at_fpvar() {
        let cs = ConstraintSystem::<Fp>::new_ref();
        let values: Vec<FpVar<Fp>> = vec![1, 2, 3, 4, 5]
            .into_iter()
            .map(|v| FpVar::new_witness(cs.clone(), || Ok(Fp::from(v))).unwrap())
            .collect();
        let index = FpVar::new_witness(cs.clone(), || Ok(Fp::from(2))).unwrap();
        let result = FpVar::at(&values, &index);

        // Check if the constraint system is satisfied
        assert!(cs.is_satisfied().unwrap());

        // Check if the result matches the expected value
        assert_eq!(result.value().unwrap(), Fp::from(3));
    }

    #[test]
    fn test_mul_by_constant_fp() {
        let a = Fp::from(5u64);
        let result = a.mul_by_constant(3u64);
        assert_eq!(result, Fp::from(15u64));
    }

    #[test]
    fn test_mul_by_constant_fpvar() {
        let cs = ConstraintSystem::<Fp>::new_ref();
        let a = FpVar::new_witness(cs.clone(), || Ok(Fp::from(5u64))).unwrap();
        let result = a.mul_by_constant(3u64);

        // Check if the constraint system is satisfied
        assert!(cs.is_satisfied().unwrap());

        // Check if the result matches the expected value
        assert_eq!(result.value().unwrap(), Fp::from(15u64));
    }

    #[test]
    fn test_reverse_bits_fp() {
        let a = Fp::from(0b1010u64); // 10 in binary
        let reversed = a.reverse_bits();
        assert_eq!(reversed, Fp::from(0b0101u64));
    }

    #[test]
    fn test_reverse_bits_fpvar() {
        let cs = ConstraintSystem::<Fp>::new_ref();
        let a = FpVar::new_witness(cs.clone(), || Ok(Fp::from(0b1010u64))).unwrap(); // 10 in binary
        let reversed = a.reverse_bits();

        // Check if the constraint system is satisfied
        assert!(cs.is_satisfied().unwrap());

        // Check if the result matches the expected value
        assert_eq!(reversed.value().unwrap(), Fp::from(0b0101u64)); // 5 shifted left by 252 bits
    }

    #[test]
    fn test_skip_fp() {
        let values = vec![Fp::from(1), Fp::from(2), Fp::from(3), Fp::from(4), Fp::from(5)];
        let n = Fp::from(2);
        let result = Fp::skip(&values, &n);
        assert_eq!(result, vec![Fp::from(3), Fp::from(4), Fp::from(5)]);
    }

    #[test]
    fn test_skip_fpvar() {
        let cs = ConstraintSystem::<Fp>::new_ref();
        let values: Vec<FpVar<Fp>> = vec![1, 2, 3, 4, 5]
            .into_iter()
            .map(|v| FpVar::new_witness(cs.clone(), || Ok(Fp::from(v))).unwrap())
            .collect();
        let n = FpVar::new_witness(cs.clone(), || Ok(Fp::from(2))).unwrap();
        let result = FpVar::skip(&values, &n);

        // Check if the constraint system is satisfied
        assert!(cs.is_satisfied().unwrap());

        // Check if the result matches the expected values
        let result_values: Vec<Fp> = result.iter().map(|v| v.value().unwrap()).collect();
        assert_eq!(result_values, vec![Fp::from(3), Fp::from(4), Fp::from(5)]);
    }

    #[test]
    fn test_take_fp() {
        let values = vec![Fp::from(1), Fp::from(2), Fp::from(3), Fp::from(4), Fp::from(5)];
        let n = Fp::from(3);
        let result = Fp::take(&values, &n);
        assert_eq!(result, vec![Fp::from(1), Fp::from(2), Fp::from(3)]);
    }

    #[test]
    fn test_take_fpvar() {
        let cs = ConstraintSystem::<Fp>::new_ref();
        let values: Vec<FpVar<Fp>> = vec![1, 2, 3, 4, 5]
            .into_iter()
            .map(|v| FpVar::new_witness(cs.clone(), || Ok(Fp::from(v))).unwrap())
            .collect();
        let n = FpVar::new_witness(cs.clone(), || Ok(Fp::from(3))).unwrap();
        let result = FpVar::take(&values, &n);

        // Check if the constraint system is satisfied
        assert!(cs.is_satisfied().unwrap());

        // Check if the result matches the expected values
        let result_values: Vec<Fp> = result.iter().map(|v| v.value().unwrap()).collect();
        assert_eq!(result_values, vec![Fp::from(1), Fp::from(2), Fp::from(3)]);
    }
}
