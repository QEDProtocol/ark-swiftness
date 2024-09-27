use ark_ff::{BigInteger, PrimeField};
use ark_relations::{
    lc, ns,
    r1cs::{ConstraintSystemRef, Namespace, SynthesisError, Variable},
};
use num_bigint::BigUint;

use core::borrow::Borrow;

use ark_ff::Field;
type TargetField = crate::Fr;

use ark_r1cs_std::{
    fields::{fp::FpVar, FieldOpsBounds, FieldVar},
    prelude::*,
    Assignment, ToConstraintFieldGadget,
};

/// Represents a variable in the constraint system whose
/// value can be an arbitrary field element.
#[derive(Debug, Clone)]
pub struct SimpleAllocatedFp<F: PrimeField> {
    pub value: FpVar<F>,
    /// The allocated variable corresponding to `self` in `self.cs`.
    pub cs: ConstraintSystemRef<F>,
}

impl<F: PrimeField> SimpleAllocatedFp<F> {
    /// Constructs a new `SimpleAllocatedFp` from a (optional) value, a
    /// low-level Variable, and a `ConstraintSystemRef`.
    pub fn new(value: F, cs: ConstraintSystemRef<F>) -> Self {
        Self::new_with_mode(value, cs, AllocationMode::Witness)
    }

    pub fn new_with_mode(value: F, cs: ConstraintSystemRef<F>, mode: AllocationMode) -> Self {
        let base_value = FpVar::<F>::new_variable(ns!(cs, "baseF"), || Ok(value), mode).unwrap();
        Self {
            value: base_value,
            cs: cs.clone(),
            // marker: std::marker::PhantomData,
        }
    }

    pub fn variable(&self) -> Variable {
        let value_generator = || self.value();

        self.cs.new_witness_variable(value_generator).unwrap()
    }
}

/// Represent variables corresponding to a field element in `F`.
#[derive(Clone, Debug)]
pub enum SimpleFpVar<F: PrimeField> {
    /// Represents a constant in the constraint system, which means that
    /// it does not have a corresponding variable.
    Constant(F),
    /// Represents an allocated variable constant in the constraint system.
    Var(SimpleAllocatedFp<F>),
}

impl<F: PrimeField> R1CSVar<F> for SimpleFpVar<F> {
    type Value = F;

    fn cs(&self) -> ConstraintSystemRef<F> {
        match self {
            Self::Constant(_) => ConstraintSystemRef::None,
            Self::Var(a) => a.cs.clone(),
        }
    }

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        match self {
            Self::Constant(v) => Ok(*v),
            Self::Var(v) => v.value(),
        }
    }
}

impl<F: PrimeField> From<Boolean<F>> for SimpleFpVar<F> {
    fn from(other: Boolean<F>) -> Self {
        if let Boolean::Constant(b) = other {
            Self::Constant(F::from(b as u8))
        } else {
            // `other` is a variable
            let cs = other.cs();
            Self::Var(SimpleAllocatedFp::new(
                other.value().ok().map(|b| F::from(b as u8)).unwrap(),
                cs,
            ))
        }
    }
}

impl<F: PrimeField> From<SimpleAllocatedFp<F>> for SimpleFpVar<F> {
    fn from(other: SimpleAllocatedFp<F>) -> Self {
        Self::Var(other)
    }
}

impl<'a, F: PrimeField> FieldOpsBounds<'a, F, Self> for SimpleFpVar<F> {}
impl<'a, F: PrimeField> FieldOpsBounds<'a, F, SimpleFpVar<F>> for &'a SimpleFpVar<F> {}

impl<F: PrimeField> SimpleAllocatedFp<F> {
    /// Constructs `Self` from a `Boolean`: if `other` is false, this outputs
    /// `zero`, else it outputs `one`.
    pub fn from(other: Boolean<F>) -> Self {
        let cs = other.cs();
        Self::new(other.value().ok().map(|b| F::from(b as u8)).unwrap(), cs)
    }

    /// Returns the value assigned to `self` in the underlying constraint system
    /// (if a value was assigned).
    pub fn value(&self) -> Result<F, SynthesisError> {
        self.value.value()
    }

    fn modulus() -> F {
        let val: BigUint = TargetField::MODULUS.into();
        F::try_from(val).unwrap()
        // match F::from_str(
        //     "21888242871839275222246405745257275088548364400416034343698204186575808495617",
        // ) {
        //     Ok(val) => val,
        //     Err(_) => F::one(),
        // }
    }

    /// Outputs `self + other`.
    ///
    /// This does not create any constraints.

    pub fn add(&self, other: &Self) -> Self {
        let self_value = self.value.value().unwrap();
        let other_value = other.value.value().unwrap();

        let self_val: BigUint = self_value.into_bigint().into();
        let other_val: BigUint = other_value.into_bigint().into();
        let modulus: BigUint = Self::modulus().into();
        let result = self_val + other_val;
        let quotient = &result / &modulus;
        let reminder = &result % &modulus;

        let quotient = F::from_bigint(F::BigInt::try_from(quotient).unwrap()).unwrap();
        let reminder = F::from_bigint(F::BigInt::try_from(reminder).unwrap()).unwrap();

        // (quentient * MODUUS + reminder) % base_modulus = (self_val + other_val)
        // % base_modulus reminder = (self_val + other_val) % MODUUS
        let quotient_var = FpVar::<F>::new_witness(self.cs.clone(), || Ok(quotient)).unwrap();
        let reminder_var = FpVar::<F>::new_witness(self.cs.clone(), || Ok(reminder)).unwrap();

        let lhs = &self.value + &other.value;
        let rhs = quotient_var * Self::modulus() + reminder_var;

        lhs.enforce_equal(&rhs).unwrap();

        // todo: rangecheck quotient, reminder

        Self::new(reminder, self.cs.clone())
    }

    /// Outputs `self - other`.
    ///
    /// This does not create any constraints.
    pub fn sub(&self, other: &Self) -> Self {
        self.add(&other.negate())
    }

    /// Outputs `self * other`.
    ///
    /// This requires *one* constraint.
    pub fn mul(&self, other: &Self) -> Self {
        let self_value = self.value.value().unwrap();
        let other_value = other.value.value().unwrap();

        let self_val: BigUint = self_value.into_bigint().into();
        let other_val: BigUint = other_value.into_bigint().into();
        let modulus: BigUint = Self::modulus().into();
        let result = self_val * other_val;
        let quotient = &result / &modulus;
        let reminder = &result % &modulus;

        let quotient = F::from_bigint(F::BigInt::try_from(quotient).unwrap()).unwrap();
        let reminder = F::from_bigint(F::BigInt::try_from(reminder).unwrap()).unwrap();

        // (quentient * MODUUS + reminder) % base_modulus = (self_val + other_val)
        // % base_modulus reminder = (self_val + other_val) % MODUUS
        let quotient_var = FpVar::<F>::new_witness(self.cs.clone(), || Ok(quotient)).unwrap();
        let reminder_var = FpVar::<F>::new_witness(self.cs.clone(), || Ok(reminder)).unwrap();

        let lhs = &self.value * &other.value;
        let rhs = quotient_var * Self::modulus() + reminder_var;

        lhs.enforce_equal(&rhs).unwrap();

        // todo: rangecheck quotient, reminder

        Self::new(reminder, self.cs.clone())
    }

    /// Output `self + other`
    ///
    /// This does not create any constraints.
    pub fn add_constant(&self, other: F) -> Self {
        let other_val = Self::new(other, self.cs.clone());
        self.add(&other_val)
    }

    /// Output `self - other`
    ///
    /// This does not create any constraints.
    pub fn sub_constant(&self, other: F) -> Self {
        self.add_constant(-other)
    }

    /// Output `self * other`
    ///
    /// This does not create any constraints.
    pub fn mul_constant(&self, other: F) -> Self {
        let other_val = Self::new(other, self.cs.clone());
        self.mul(&other_val)
    }

    /// Output `self + self`
    ///
    /// This does not create any constraints.
    pub fn double(&self) -> Result<Self, SynthesisError> {
        Ok(self.add(self))
    }

    /// Output `-self`
    ///
    /// This does not create any constraints.
    pub fn negate(&self) -> Self {
        let mut result = self.clone();
        result.negate_in_place();
        result
    }

    /// Sets `self = -self`
    ///
    /// This does not create any constraints.
    pub fn negate_in_place(&mut self) -> &mut Self {
        self.value = FpVar::new_witness(self.cs.clone(), || {
            Ok(Self::modulus() - self.value().unwrap())
        })
        .unwrap();
        self
    }

    /// Outputs `self * self`
    ///
    /// This requires *one* constraint.
    pub fn square(&self) -> Result<Self, SynthesisError> {
        Ok(self.mul(self))
    }

    /// Outputs `result` such that `result * self = 1`.
    ///
    /// This requires *one* constraint.
    pub fn inverse(&self) -> Result<Self, SynthesisError> {
        let self_var = self.value.value()?;
        let self_var = self_var.into_bigint().into();
        let self_var = TargetField::try_from(self_var).unwrap();
        let self_var_inv = self_var.inverse().unwrap();
        let self_var_inv: BigUint = self_var_inv.into_bigint().into();
        let self_var_inv = F::try_from(self_var_inv).unwrap();

        let self_inv = Self::new_witness(self.cs.clone(), || Ok(self_var_inv))?;

        let one = self.mul(&self_inv);
        one.value.enforce_equal(&FpVar::<F>::one()).unwrap();

        Ok(self_inv)
    }

    /// This is a no-op for prime fields.
    pub fn frobenius_map(&self, _: usize) -> Result<Self, SynthesisError> {
        Ok(self.clone())
    }

    /// Enforces that `self * other = result`.
    ///
    /// This requires *one* constraint.
    pub fn mul_equals(&self, other: &Self, result: &Self) -> Result<(), SynthesisError> {
        let res = self.mul(other);
        res.value.enforce_equal(&result.value)
    }

    /// Enforces that `self * self = result`.
    ///
    /// This requires *one* constraint.
    pub fn square_equals(&self, result: &Self) -> Result<(), SynthesisError> {
        self.mul_equals(self, result)
    }

    /// Outputs the bit `self == other`.
    ///
    /// This requires three constraints.
    pub fn is_eq(&self, other: &Self) -> Result<Boolean<F>, SynthesisError> {
        Ok(self.is_neq(other)?.not())
    }

    /// Outputs the bit `self != other`.
    ///
    /// This requires three constraints.
    pub fn is_neq(&self, other: &Self) -> Result<Boolean<F>, SynthesisError> {
        let is_not_equal = Boolean::new_witness(self.cs.clone(), || {
            Ok(self.value.value() != other.value.value())
        })?;
        let _multiplier = if is_not_equal.value()? {
            self.sub(other).inverse().unwrap().value
        } else {
            FpVar::<F>::one()
        };

        // Completeness:
        // Case 1: self != other:
        // ----------------------
        //   constraint 1:
        //   (self - other) * multiplier = is_not_equal
        //   => (non_zero) * multiplier = 1 (satisfied, because multiplier = 1/(self -
        // other)
        //
        //   constraint 2:
        //   (self - other) * not(is_not_equal) = 0
        //   => (non_zero) * not(1) = 0
        //   => (non_zero) * 0 = 0
        //
        // Case 2: self == other:
        // ----------------------
        //   constraint 1:
        //   (self - other) * multiplier = is_not_equal
        //   => 0 * multiplier = 0 (satisfied, because multiplier = 1
        //
        //   constraint 2:
        //   (self - other) * not(is_not_equal) = 0
        //   => 0 * not(0) = 0
        //   => 0 * 1 = 0
        //
        // --------------------------------------------------------------------
        //
        // Soundness:
        // Case 1: self != other, but is_not_equal = 0.
        // --------------------------------------------
        //   constraint 1:
        //   (self - other) * multiplier = is_not_equal
        //   => non_zero * multiplier = 0 (only satisfiable if multiplier == 0)
        //
        //   constraint 2:
        //   (self - other) * not(is_not_equal) = 0
        //   => (non_zero) * 1 = 0 (impossible)
        //
        // Case 2: self == other, but is_not_equal = 1.
        // --------------------------------------------
        //   constraint 1:
        //   (self - other) * multiplier = is_not_equal
        //   0 * multiplier = 1 (unsatisfiable)
        // self.cs.enforce_constraint(
        //     lc!() + self.variable - other.variable,
        //     lc!() + multiplier,
        //     is_not_equal.lc(),
        // )?;
        // self.cs.enforce_constraint(
        //     lc!() + self.variable - other.variable,
        //     is_not_equal.not().lc(),
        //     lc!(),
        // )?;

        Ok(is_not_equal)
    }

    /// Enforces that self == other if `should_enforce.is_eq(&Boolean::TRUE)`.
    ///
    /// This requires one constraint.

    pub fn conditional_enforce_equal(
        &self,
        other: &Self,
        should_enforce: &Boolean<F>,
    ) -> Result<(), SynthesisError> {
        let should_enforce = Self::from(should_enforce.clone());
        let res = self.sub(other).mul(&should_enforce);
        FpVar::<F>::enforce_equal(&res.value, &FpVar::<F>::zero())
    }

    /// Enforces that self != other if `should_enforce.is_eq(&Boolean::TRUE)`.
    ///
    /// This requires one constraint.
    pub fn conditional_enforce_not_equal(
        &self,
        other: &Self,
        should_enforce: &Boolean<F>,
    ) -> Result<(), SynthesisError> {
        // The high level logic is as follows:
        // We want to check that self - other != 0. We do this by checking that
        // (self - other).inverse() exists. In more detail, we check the following:
        // If `should_enforce == true`, then we set `multiplier = (self -
        // other).inverse()`, and check that (self - other) * multiplier == 1.
        // (i.e., that the inverse exists)
        //
        // If `should_enforce == false`, then we set `multiplier == 0`, and check that
        // (self - other) * 0 == 0, which is always satisfied.
        let multiplier = {
            if should_enforce.value()? {
                self.sub(other).inverse().unwrap().value
            } else {
                FpVar::zero()
            }
        };

        let sub_res = self.sub(other).value;

        FpVar::<F>::enforce_equal(&(multiplier * sub_res), &FpVar::<F>::one())
    }
}

/// *************************************************************************
/// *************************************************************************

impl<F: PrimeField> ToBitsGadget<F> for SimpleAllocatedFp<F> {
    /// Outputs the unique bit-wise decomposition of `self` in *little-endian*
    /// form.
    ///
    /// This method enforces that the output is in the field, i.e.
    /// it invokes `Boolean::enforce_in_field_le` on the bit decomposition.
    fn to_bits_le(&self) -> Result<Vec<Boolean<F>>, SynthesisError> {
        let bits = self.to_non_unique_bits_le()?;
        Boolean::enforce_in_field_le(&bits)?;
        Ok(bits)
    }

    fn to_non_unique_bits_le(&self) -> Result<Vec<Boolean<F>>, SynthesisError> {
        let cs = self.cs.clone();
        use ark_ff::BitIteratorBE;

        let mut bits = if let Ok(value) = self.value() {
            let field_char = BitIteratorBE::new(F::characteristic());
            let bits: Vec<_> = BitIteratorBE::new(value.into_bigint())
                .zip(field_char)
                .skip_while(|(_, c)| !c)
                .map(|(b, _)| Some(b))
                .collect();
            assert_eq!(bits.len(), F::MODULUS_BIT_SIZE as usize);
            bits
        } else {
            vec![None; F::MODULUS_BIT_SIZE as usize]
        };

        // Convert to little-endian
        bits.reverse();

        let bits: Vec<_> = bits
            .into_iter()
            .map(|b| Boolean::new_witness(cs.clone(), || b.get()))
            .collect::<Result<_, _>>()?;

        // let mut lc = LinearCombination::zero();
        // let mut coeff = F::one();

        // for bit in bits.iter() {
        //     lc = &lc + bit.lc() * coeff;

        //     coeff.double_in_place();
        // }

        // lc = lc - &self.variable;

        // cs.enforce_constraint(lc!(), lc!(), lc)?;

        Ok(bits)
    }
}

impl<F: PrimeField> ToBytesGadget<F> for SimpleAllocatedFp<F> {
    /// Outputs the unique byte decomposition of `self` in *little-endian*
    /// form.
    ///
    /// This method enforces that the decomposition represents
    /// an integer that is less than `F::MODULUS`.
    fn to_bytes(&self) -> Result<Vec<UInt8<F>>, SynthesisError> {
        let num_bits = F::BigInt::NUM_LIMBS * 64;
        let mut bits = self.to_bits_le()?;
        let remainder = core::iter::repeat(Boolean::constant(false)).take(num_bits - bits.len());
        bits.extend(remainder);
        let bytes = bits
            .chunks(8)
            .map(|chunk| UInt8::from_bits_le(chunk))
            .collect();
        Ok(bytes)
    }

    fn to_non_unique_bytes(&self) -> Result<Vec<UInt8<F>>, SynthesisError> {
        let num_bits = F::BigInt::NUM_LIMBS * 64;
        let mut bits = self.to_non_unique_bits_le()?;
        let remainder = core::iter::repeat(Boolean::constant(false)).take(num_bits - bits.len());
        bits.extend(remainder);
        let bytes = bits
            .chunks(8)
            .map(|chunk| UInt8::from_bits_le(chunk))
            .collect();
        Ok(bytes)
    }
}

impl<F: PrimeField> ToConstraintFieldGadget<F> for SimpleAllocatedFp<F> {
    fn to_constraint_field(&self) -> Result<Vec<FpVar<F>>, SynthesisError> {
        let value = self.value()?;
        Ok(vec![FpVar::Constant(value)])
    }
}

impl<F: PrimeField> CondSelectGadget<F> for SimpleAllocatedFp<F> {
    #[inline]

    fn conditionally_select(
        cond: &Boolean<F>,
        true_val: &Self,
        false_val: &Self,
    ) -> Result<Self, SynthesisError> {
        match cond {
            Boolean::Constant(true) => Ok(true_val.clone()),
            Boolean::Constant(false) => Ok(false_val.clone()),
            _ => {
                let cs = cond.cs();
                let result = Self::new_witness(cs.clone(), || {
                    cond.value()
                        .and_then(|c| if c { true_val } else { false_val }.value())
                })?;
                // a = self; b = other; c = cond;
                //
                // r = c * a + (1  - c) * b
                // r = b + c * (a - b)
                // c * (a - b) = r - b

                cs.enforce_constraint(
                    cond.lc(),
                    lc!() + true_val.variable() - false_val.variable(),
                    lc!() + result.variable() - false_val.variable(),
                )?;

                Ok(result)
            }
        }
    }
}

/// Uses two bits to perform a lookup into a table
/// `b` is little-endian: `b[0]` is LSB.
impl<F: PrimeField> TwoBitLookupGadget<F> for SimpleAllocatedFp<F> {
    type TableConstant = F;

    fn two_bit_lookup(b: &[Boolean<F>], c: &[Self::TableConstant]) -> Result<Self, SynthesisError> {
        debug_assert_eq!(b.len(), 2);
        debug_assert_eq!(c.len(), 4);
        let result = Self::new_witness(b.cs(), || {
            let lsb = usize::from(b[0].value()?);
            let msb = usize::from(b[1].value()?);
            let index = lsb + (msb << 1);
            Ok(c[index])
        })?;
        let one = Variable::One;
        b.cs().enforce_constraint(
            lc!() + b[1].lc() * (c[3] - &c[2] - &c[1] + &c[0]) + (c[1] - &c[0], one),
            lc!() + b[0].lc(),
            lc!() + result.variable() - (c[0], one) + b[1].lc() * (c[0] - &c[2]),
        )?;

        Ok(result)
    }
}

impl<F: PrimeField> ThreeBitCondNegLookupGadget<F> for SimpleAllocatedFp<F> {
    type TableConstant = F;

    fn three_bit_cond_neg_lookup(
        b: &[Boolean<F>],
        b0b1: &Boolean<F>,
        c: &[Self::TableConstant],
    ) -> Result<Self, SynthesisError> {
        debug_assert_eq!(b.len(), 3);
        debug_assert_eq!(c.len(), 4);
        let result = Self::new_witness(b.cs(), || {
            let lsb = usize::from(b[0].value()?);
            let msb = usize::from(b[1].value()?);
            let index = lsb + (msb << 1);
            let intermediate = c[index];

            let is_negative = b[2].value()?;
            let y = if is_negative {
                -intermediate
            } else {
                intermediate
            };
            Ok(y)
        })?;

        let y_lc = b0b1.lc() * (c[3] - &c[2] - &c[1] + &c[0])
            + b[0].lc() * (c[1] - &c[0])
            + b[1].lc() * (c[2] - &c[0])
            + (c[0], Variable::One);
        // enforce y * (1 - 2 * b_2) == res
        b.cs().enforce_constraint(
            y_lc.clone(),
            b[2].lc() * F::from(2u64).neg() + (F::one(), Variable::One),
            lc!() + result.variable(),
        )?;

        Ok(result)
    }
}

impl<F: PrimeField> AllocVar<F, F> for SimpleAllocatedFp<F> {
    fn new_variable<T: Borrow<F>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        _mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        let val = f()?.borrow().clone();

        let value = FpVar::<F>::new_witness(cs.clone(), || Ok(val))?;

        Ok(Self {
            value,
            cs: cs.clone(),
            // marker: std::marker::PhantomData,
        })
    }
}

impl<F: PrimeField> FieldVar<F, F> for SimpleFpVar<F> {
    fn constant(f: F) -> Self {
        Self::Constant(f)
    }

    fn zero() -> Self {
        Self::Constant(F::zero())
    }

    fn one() -> Self {
        Self::Constant(F::one())
    }

    fn double(&self) -> Result<Self, SynthesisError> {
        match self {
            Self::Constant(c) => Ok(Self::Constant(c.double())),
            Self::Var(v) => Ok(Self::Var(v.double()?)),
        }
    }

    fn negate(&self) -> Result<Self, SynthesisError> {
        match self {
            Self::Constant(c) => Ok(Self::Constant(-*c)),
            Self::Var(v) => Ok(Self::Var(v.negate())),
        }
    }

    fn square(&self) -> Result<Self, SynthesisError> {
        match self {
            Self::Constant(c) => Ok(Self::Constant(c.square())),
            Self::Var(v) => Ok(Self::Var(v.square()?)),
        }
    }

    /// Enforce that `self * other == result`.

    fn mul_equals(&self, other: &Self, result: &Self) -> Result<(), SynthesisError> {
        use SimpleFpVar::*;
        match (self, other, result) {
            (Constant(_), Constant(_), Constant(_)) => Ok(()),
            (Constant(_), Constant(_), _) | (Constant(_), Var(_), _) | (Var(_), Constant(_), _) => {
                result.enforce_equal(&(self * other))
            } // this multiplication should be free
            (Var(v1), Var(v2), Var(v3)) => v1.mul_equals(v2, v3),
            (Var(v1), Var(v2), Constant(f)) => {
                let cs = v1.cs.clone();
                let v3 = SimpleAllocatedFp::new_constant(cs, f).unwrap();
                v1.mul_equals(v2, &v3)
            }
        }
    }

    /// Enforce that `self * self == result`.

    fn square_equals(&self, result: &Self) -> Result<(), SynthesisError> {
        use SimpleFpVar::*;
        match (self, result) {
            (Constant(_), Constant(_)) => Ok(()),
            (Constant(f), Var(r)) => {
                let cs = r.cs.clone();
                let v = SimpleAllocatedFp::new_witness(cs, || Ok(f))?;
                v.square_equals(&r)
            }
            (Var(v), Constant(f)) => {
                let cs = v.cs.clone();
                let r = SimpleAllocatedFp::new_witness(cs, || Ok(f))?;
                v.square_equals(&r)
            }
            (Var(v1), Var(v2)) => v1.square_equals(v2),
        }
    }

    fn inverse(&self) -> Result<Self, SynthesisError> {
        match self {
            SimpleFpVar::Var(v) => v.inverse().map(SimpleFpVar::Var),
            SimpleFpVar::Constant(f) => f.inverse().get().map(SimpleFpVar::Constant),
        }
    }

    fn frobenius_map(&self, power: usize) -> Result<Self, SynthesisError> {
        match self {
            SimpleFpVar::Var(v) => v.frobenius_map(power).map(SimpleFpVar::Var),
            SimpleFpVar::Constant(f) => {
                let mut f = *f;
                f.frobenius_map_in_place(power);
                Ok(SimpleFpVar::Constant(f))
            }
        }
    }

    fn frobenius_map_in_place(&mut self, power: usize) -> Result<&mut Self, SynthesisError> {
        *self = self.frobenius_map(power)?;
        Ok(self)
    }
}

#[macro_export]
macro_rules! impl_bounded_ops {
    (
        $type: ty,
        $native: ty,
        $trait: ident,
        $fn: ident,
        $assign_trait: ident,
        $assign_fn: ident,
        $impl: expr,
        $constant_impl: expr,
        ($($params:tt)+),
        $($bounds:tt)*
    ) => {
        impl<'a, $($params)+> core::ops::$trait<&'a $type> for &'a $type
        where
            $($bounds)*
        {
            type Output = $type;

            #[allow(unused_braces, clippy::redundant_closure_call)]
            fn $fn(self, other: Self) -> Self::Output {
                ($impl)(self, other)
            }
        }

        impl<'a, $($params)+> core::ops::$trait<$type> for &'a $type
        where
            $($bounds)*
        {
            type Output = $type;

            #[allow(unused_braces)]
            fn $fn(self, other: $type) -> Self::Output {
                core::ops::$trait::$fn(self, &other)
            }
        }

        impl<'a, $($params)+> core::ops::$trait<&'a $type> for $type
        where
            $($bounds)*
        {
            type Output = $type;

            #[allow(unused_braces)]
            fn $fn(self, other: &'a $type) -> Self::Output {
                core::ops::$trait::$fn(&self, other)
            }
        }

        impl<$($params)+> core::ops::$trait<$type> for $type
        where

            $($bounds)*
        {
            type Output = $type;

            #[allow(unused_braces)]
            fn $fn(self, other: $type) -> Self::Output {
                core::ops::$trait::$fn(&self, &other)
            }
        }

        impl<$($params)+> core::ops::$assign_trait<$type> for $type
        where

            $($bounds)*
        {
            #[allow(unused_braces)]
            fn $assign_fn(&mut self, other: $type) {
                let result = core::ops::$trait::$fn(&*self, &other);
                *self = result
            }
        }

        impl<'a, $($params)+> core::ops::$assign_trait<&'a $type> for $type
        where

            $($bounds)*
        {
            #[allow(unused_braces)]
            fn $assign_fn(&mut self, other: &'a $type) {
                let result = core::ops::$trait::$fn(&*self, other);
                *self = result
            }
        }

        impl<'a, $($params)+> core::ops::$trait<$native> for &'a $type
        where

            $($bounds)*
        {
            type Output = $type;

            #[allow(unused_braces, clippy::redundant_closure_call)]
            fn $fn(self, other: $native) -> Self::Output {
                ($constant_impl)(self, other)
            }
        }

        impl<$($params)+> core::ops::$trait<$native> for $type
        where

            $($bounds)*
        {
            type Output = $type;

            #[allow(unused_braces)]
            fn $fn(self, other: $native) -> Self::Output {
                core::ops::$trait::$fn(&self, other)
            }
        }

        impl<$($params)+> core::ops::$assign_trait<$native> for $type
        where

            $($bounds)*
        {

            #[allow(unused_braces)]
            fn $assign_fn(&mut self, other: $native) {
                let result = core::ops::$trait::$fn(&*self, other);
                *self = result
            }
        }
    }
}

impl_bounded_ops!(
    SimpleFpVar<F>,
    F,
    Add,
    add,
    AddAssign,
    add_assign,
    |this: &'a SimpleFpVar<F>, other: &'a SimpleFpVar<F>| {
        use SimpleFpVar::*;
        match (this, other) {
            (Constant(c1), Constant(c2)) => Constant(*c1 + c2),
            (Constant(c), Var(v)) | (Var(v), Constant(c)) => Var(v.add_constant(*c)),
            (Var(v1), Var(v2)) => Var(v1.add(v2)),
        }
    },
    |this: &'a SimpleFpVar<F>, other: F| { this + &SimpleFpVar::Constant(other) },
    ( F: PrimeField),
);

impl_bounded_ops!(
    SimpleFpVar<F>,
    F,
    Sub,
    sub,
    SubAssign,
    sub_assign,
    |this: &'a SimpleFpVar<F>, other: &'a SimpleFpVar<F>| {
        use SimpleFpVar::*;
        match (this, other) {
            (Constant(c1), Constant(c2)) => Constant(*c1 - c2),
            (Var(v), Constant(c)) => Var(v.sub_constant(*c)),
            (Constant(c), Var(v)) => Var(v.sub_constant(*c).negate()),
            (Var(v1), Var(v2)) => Var(v1.sub(v2)),
        }
    },
    |this: &'a SimpleFpVar<F>, other: F| {
        this - &SimpleFpVar::Constant(other)
    },
    ( F: PrimeField),
);

impl_bounded_ops!(
    SimpleFpVar<F>,
    F,
    Mul,
    mul,
    MulAssign,
    mul_assign,
    |this: &'a SimpleFpVar<F>, other: &'a SimpleFpVar<F>| {
        use SimpleFpVar::*;
        match (this, other) {
            (Constant(c1), Constant(c2)) => Constant(*c1 * c2),
            (Constant(c), Var(v)) | (Var(v), Constant(c)) => Var(v.mul_constant(*c)),
            (Var(v1), Var(v2)) => Var(v1.mul(v2)),
        }
    },
    |this: &'a SimpleFpVar<F>, other: F| {
        if other.is_zero() {
            SimpleFpVar::zero()
        } else {
            this * &SimpleFpVar::Constant(other)
        }
    },
    ( F: PrimeField),
);

/// *************************************************************************
/// *************************************************************************

impl<F: PrimeField> EqGadget<F> for SimpleFpVar<F> {
    fn is_eq(&self, other: &Self) -> Result<Boolean<F>, SynthesisError> {
        match (self, other) {
            (Self::Constant(c1), Self::Constant(c2)) => Ok(Boolean::Constant(c1 == c2)),
            (Self::Constant(c), Self::Var(v)) | (Self::Var(v), Self::Constant(c)) => {
                let cs = v.cs.clone();
                let c = SimpleAllocatedFp::new_constant(cs, c)?;
                c.is_eq(v)
            }
            (Self::Var(v1), Self::Var(v2)) => v1.is_eq(v2),
        }
    }

    fn conditional_enforce_equal(
        &self,
        other: &Self,
        should_enforce: &Boolean<F>,
    ) -> Result<(), SynthesisError> {
        match (self, other) {
            (Self::Constant(_), Self::Constant(_)) => Ok(()),
            (Self::Constant(c), Self::Var(v)) | (Self::Var(v), Self::Constant(c)) => {
                let cs = v.cs.clone();
                let c = SimpleAllocatedFp::new_constant(cs, c)?;
                c.conditional_enforce_equal(v, should_enforce)
            }
            (Self::Var(v1), Self::Var(v2)) => v1.conditional_enforce_equal(v2, should_enforce),
        }
    }

    fn conditional_enforce_not_equal(
        &self,
        other: &Self,
        should_enforce: &Boolean<F>,
    ) -> Result<(), SynthesisError> {
        match (self, other) {
            (Self::Constant(_), Self::Constant(_)) => Ok(()),
            (Self::Constant(c), Self::Var(v)) | (Self::Var(v), Self::Constant(c)) => {
                let cs = v.cs.clone();
                let c = SimpleAllocatedFp::new_constant(cs, c)?;
                c.conditional_enforce_not_equal(v, should_enforce)
            }
            (Self::Var(v1), Self::Var(v2)) => v1.conditional_enforce_not_equal(v2, should_enforce),
        }
    }
}

impl<F: PrimeField> ToBitsGadget<F> for SimpleFpVar<F> {
    fn to_bits_le(&self) -> Result<Vec<Boolean<F>>, SynthesisError> {
        match self {
            Self::Constant(_) => self.to_non_unique_bits_le(),
            Self::Var(v) => v.to_bits_le(),
        }
    }

    fn to_non_unique_bits_le(&self) -> Result<Vec<Boolean<F>>, SynthesisError> {
        use ark_ff::BitIteratorLE;
        match self {
            Self::Constant(c) => Ok(BitIteratorLE::new(&c.into_bigint())
                .take((F::MODULUS_BIT_SIZE) as usize)
                .map(Boolean::constant)
                .collect::<Vec<_>>()),
            Self::Var(v) => v.to_non_unique_bits_le(),
        }
    }
}

impl<F: PrimeField> ToBytesGadget<F> for SimpleFpVar<F> {
    /// Outputs the unique byte decomposition of `self` in *little-endian*
    /// form.

    fn to_bytes(&self) -> Result<Vec<UInt8<F>>, SynthesisError> {
        match self {
            Self::Constant(c) => Ok(UInt8::constant_vec(
                c.into_bigint().to_bytes_le().as_slice(),
            )),
            Self::Var(v) => v.to_bytes(),
        }
    }

    fn to_non_unique_bytes(&self) -> Result<Vec<UInt8<F>>, SynthesisError> {
        match self {
            Self::Constant(c) => Ok(UInt8::constant_vec(
                c.into_bigint().to_bytes_le().as_slice(),
            )),
            Self::Var(v) => v.to_non_unique_bytes(),
        }
    }
}

impl<F: PrimeField> ToConstraintFieldGadget<F> for SimpleFpVar<F> {
    fn to_constraint_field(&self) -> Result<Vec<FpVar<F>>, ark_relations::r1cs::SynthesisError> {
        let value = self.value()?;
        Ok(vec![FpVar::Constant(value)])
    }
}

impl<F: PrimeField> CondSelectGadget<F> for SimpleFpVar<F> {
    fn conditionally_select(
        cond: &Boolean<F>,
        true_value: &Self,
        false_value: &Self,
    ) -> Result<Self, SynthesisError> {
        match cond {
            Boolean::Constant(true) => Ok(true_value.clone()),
            Boolean::Constant(false) => Ok(false_value.clone()),
            _ => {
                match (true_value, false_value) {
                    (Self::Constant(t), Self::Constant(f)) => {
                        let is = SimpleAllocatedFp::from(cond.clone());
                        let not = SimpleAllocatedFp::from(cond.not());
                        // cond * t + (1 - cond) * f
                        Ok(is.mul_constant(*t).add(&not.mul_constant(*f)).into())
                    }
                    (..) => {
                        let cs = cond.cs();
                        let true_value = match true_value {
                            Self::Constant(f) => SimpleAllocatedFp::new_constant(cs.clone(), f)?,
                            Self::Var(v) => v.clone(),
                        };
                        let false_value = match false_value {
                            Self::Constant(f) => SimpleAllocatedFp::new_constant(cs, f)?,
                            Self::Var(v) => v.clone(),
                        };
                        cond.select(&true_value, &false_value).map(Self::Var)
                    }
                }
            }
        }
    }
}

/// Uses two bits to perform a lookup into a table
/// `b` is little-endian: `b[0]` is LSB.
impl<F: PrimeField> TwoBitLookupGadget<F> for SimpleFpVar<F> {
    type TableConstant = F;

    fn two_bit_lookup(b: &[Boolean<F>], c: &[Self::TableConstant]) -> Result<Self, SynthesisError> {
        debug_assert_eq!(b.len(), 2);
        debug_assert_eq!(c.len(), 4);
        if b.is_constant() {
            let lsb = usize::from(b[0].value()?);
            let msb = usize::from(b[1].value()?);
            let index = lsb + (msb << 1);
            Ok(Self::Constant(c[index]))
        } else {
            SimpleAllocatedFp::two_bit_lookup(b, c).map(Self::Var)
        }
    }
}

impl<F: PrimeField> ThreeBitCondNegLookupGadget<F> for SimpleFpVar<F> {
    type TableConstant = F;

    fn three_bit_cond_neg_lookup(
        b: &[Boolean<F>],
        b0b1: &Boolean<F>,
        c: &[Self::TableConstant],
    ) -> Result<Self, SynthesisError> {
        debug_assert_eq!(b.len(), 3);
        debug_assert_eq!(c.len(), 4);

        if b.cs().or(b0b1.cs()).is_none() {
            // We only have constants

            let lsb = usize::from(b[0].value()?);
            let msb = usize::from(b[1].value()?);
            let index = lsb + (msb << 1);
            let intermediate = c[index];

            let is_negative = b[2].value()?;
            let y = if is_negative {
                -intermediate
            } else {
                intermediate
            };
            Ok(Self::Constant(y))
        } else {
            SimpleAllocatedFp::three_bit_cond_neg_lookup(b, b0b1, c).map(Self::Var)
        }
    }
}

impl<F: PrimeField> AllocVar<F, F> for SimpleFpVar<F> {
    fn new_variable<T: Borrow<F>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        if mode == AllocationMode::Constant {
            Ok(Self::Constant(*f()?.borrow()))
        } else {
            SimpleAllocatedFp::new_variable(cs, f, mode).map(Self::Var)
        }
    }
}
