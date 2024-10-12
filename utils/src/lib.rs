#![feature(buf_read_has_data_left, int_roundings)]

pub mod mem_tools;

use ark_ff::FftField;
use ark_poly::univariate::DensePolynomial;
use ark_poly::EvaluationDomain;
use ark_poly::Evaluations;
use ark_poly::Radix2EvaluationDomain;
use std::ops::*;
use swiftness_field::SimpleField;

/// Generates a periodic table comprising of values in the matrix.
/// The columns of the periodic table are are represented by polynomials that
/// evaluate to the `i`th row when evaluated on the `i`th power of the `n`th
/// root of unity where n is the power-of-2 height of the table. For example a
/// matrix with 4 rows and 2 columns would be represented by two columns
/// `P_0(X)` and `P_1(X)`:
///
/// ```text
/// ┌───────────┬────────────────────┬────────────────────┐
/// │     X     │       P_0(X)       │       P_1(X)       │
/// ├───────────┼────────────────────┼────────────────────┤
/// │    ω^0    │     matrix_0_0     │     matrix_0_1     │
/// ├───────────┼────────────────────┼────────────────────┤
/// │    ω^1    │     matrix_1_0     │     matrix_1_1     │
/// ├───────────┼────────────────────┼────────────────────┤
/// │    ω^0    │     matrix_2_0     │     matrix_2_1     │
/// ├───────────┼────────────────────┼────────────────────┤
/// │    ω^1    │     matrix_3_0     │     matrix_3_1     │
/// └───────────┴────────────────────┴────────────────────┘
/// ```
///
/// Input and output matrix are to be represented in column-major.
// TODO: consider deleting
pub fn gen_periodic_table<F: FftField>(matrix: Vec<Vec<F>>) -> Vec<DensePolynomial<F>> {
    if matrix.is_empty() {
        return Vec::new();
    }

    let num_rows = matrix[0].len();
    assert!(num_rows.is_power_of_two());
    assert!(matrix.iter().all(|col| col.len() == num_rows));

    let domain = Radix2EvaluationDomain::new(num_rows).unwrap();
    matrix
        .into_iter()
        .map(|col| Evaluations::from_vec_and_domain(col, domain).interpolate())
        .collect()
}

#[derive(Clone, Copy, Default, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Mat3x3<T>(pub [[T; 3]; 3]);

impl<T> Mat3x3<T> {
    pub fn transpose(self) -> Self {
        let [[a, b, c], [d, e, f], [g, h, i]] = self.0;
        Mat3x3([[a, d, g], [b, e, h], [c, f, i]])
    }
}

impl<F: SimpleField> Mat3x3<F> {
    pub fn identity() -> Self {
        Self([
            [F::one(), F::zero(), F::zero()],
            [F::zero(), F::one(), F::zero()],
            [F::zero(), F::zero(), F::one()],
        ])
    }

    pub fn inverse(self) -> Option<Self> {
        let [[a, b, c], [d, e, f], [g, h, i]] = self.0;
        let a_prime = e.clone() * &i - f.clone() * &h;
        let b_prime = (b.clone() * &i - c.clone() * &h).negate();
        let c_prime = b.clone() * &f - c.clone() * &e;
        let d_prime = (d.clone() * &i - f.clone() * &g).negate();
        let e_prime = a.clone() * &i - c.clone() * &g;
        let f_prime = (a.clone() * &f - c.clone() * &d).negate();
        let g_prime = d.clone() * &h - e.clone() * &g;
        let h_prime = (a.clone() * &h - b.clone() * &g).negate();
        let i_prime = a.clone() * &e - b.clone() * &d;
        let determinant = a.clone() * &a_prime + b.clone() * &d_prime + c.clone() * &g_prime;
        let inv = Self([
            [a_prime, b_prime, c_prime],
            [d_prime, e_prime, f_prime],
            [g_prime, h_prime, i_prime],
        ]) * determinant.inv();
        Some(inv)
    }
}

impl<F: SimpleField> Mul<F> for Mat3x3<F> {
    type Output = Self;

    /// Multiplies the matrix by a scalar
    fn mul(self, rhs: F) -> Self {
        Self(self.0.map(|row| row.map(|cell| cell * rhs.clone())))
    }
}

impl<F: SimpleField> Mul<Self> for Mat3x3<F> {
    type Output = Self;

    /// Multiplies the matrix by another matrix
    fn mul(self, rhs: Self) -> Self {
        let [v0, v1, v2] = rhs.transpose().0;
        Mat3x3([self.clone() * v0, self.clone() * v1, self * v2]).transpose()
    }
}

impl<F: SimpleField> Mul<[F; 3]> for Mat3x3<F> {
    type Output = [F; 3];

    /// Multiplies the matrix by a vector
    fn mul(self, [x, y, z]: [F; 3]) -> [F; 3] {
        let [[a, b, c], [d, e, f], [g, h, i]] = self.0;
        [
            x.clone() * a + y.clone() * b + z.clone() * c,
            x.clone() * d + y.clone() * e + z.clone() * f,
            x * g + y * h + z * i,
        ]
    }
}

pub mod curve {
    use ark_ec::short_weierstrass::Affine;
    use ark_ec::short_weierstrass::SWCurveConfig;
    use ark_ec::CurveConfig;
    use ark_ff::Field;
    use ark_ff::MontFp as Fp;
    use ark_r1cs_std::fields::FieldOpsBounds;
    use ark_r1cs_std::fields::FieldVar;
    use ark_r1cs_std::groups::curves::short_weierstrass::AffineVar;
    use ark_r1cs_std::prelude::Boolean;
    use swiftness_field::Fp;
    use swiftness_field::Fr;
    use swiftness_field::SimpleField;

    /// calculates the slope between points `p1` and `p2`
    /// Returns None if one of the points is the point at infinity
    pub fn calculate_slope<P: SWCurveConfig>(
        p1: Affine<P>,
        p2: Affine<P>,
    ) -> Option<<P as CurveConfig>::BaseField>
    where
        <P as CurveConfig>::BaseField: SimpleField,
    {
        if p1.infinity || p2.infinity || (p1.x == p2.x && p1.y != p2.y) {
            return None;
        }

        let y1 = p1.y;
        let y2 = p2.y;
        let x1 = p1.x;
        let x2 = p2.x;

        Some(if x1 == x2 {
            // use tangent line
            assert_eq!(y1, y2);
            let xx = x1.square();
            (xx + xx + xx + P::COEFF_A) / (y1 + y1)
        } else {
            // use slope
            (y2 - y1) / (x2 - x1)
        })
    }

    pub fn calculate_slope_var<
        P: SWCurveConfig,
        F: FieldVar<P::BaseField, <P::BaseField as Field>::BasePrimeField> + SimpleField,
    >(
        p1: AffineVar<P, F>,
        p2: AffineVar<P, F>,
    ) -> Option<F>
    where
        for<'a> &'a F: FieldOpsBounds<'a, P::BaseField, F>,
        <P as CurveConfig>::BaseField: SimpleField,
        F::BooleanType:
            From<Boolean<<<P as CurveConfig>::BaseField as ark_ff::Field>::BasePrimeField>>,
    {
        // TODO: enable check
        // if p1.infinity || p2.infinity || (p1.x == p2.x && p1.y != p2.y) {
        //     return None;
        // }

        let y1 = p1.y;
        let y2 = p2.y;
        let x1 = p1.x;
        let x2 = p2.x;

        // TODO: enable check
        // SimpleField::assert_true(x1.is_neq(&x2).unwrap().or(&y1.is_eq(&y2).unwrap()));

        Some(SimpleField::select(
            &F::BooleanType::from(x1.is_eq(&x2).unwrap()),
            {
                // use tangent line
                let xx = x1.square().ok()?;
                (xx.clone() + &xx + &xx + P::COEFF_A).field_div(&(y1.clone() + &y1))
            },
            {
                // use slope
                (y2 - y1).field_div(&(x2 - x1))
            },
        ))
    }

    // StarkWare's Cairo curve params: https://docs.starkware.co/starkex/crypto/pedersen-hash-function.html
    pub struct StarkwareCurve;

    impl CurveConfig for StarkwareCurve {
        type BaseField = Fp;
        type ScalarField = Fr;

        const COFACTOR: &'static [u64] = &[1];
        const COFACTOR_INV: Self::ScalarField = Fr::ONE;
    }

    impl SWCurveConfig for StarkwareCurve {
        const COEFF_A: Self::BaseField = Fp::ONE;
        const COEFF_B: Self::BaseField =
            Fp!("3141592653589793238462643383279502884197169399375105820974944592307816406665");

        const GENERATOR: Affine<Self> = Affine::new_unchecked(
            Fp!("874739451078007766457464989774322083649278607533249481151382481072868806602"),
            Fp!("152666792071518830868575557812948353041420400780739481342941381225525861407"),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ec::{
        short_weierstrass::{Affine, Projective},
        AffineRepr, CurveGroup,
    };
    use ark_r1cs_std::alloc::AllocVar;
    use ark_r1cs_std::{
        fields::fp::FpVar, groups::curves::short_weierstrass::ProjectiveVar, prelude::*,
    };
    use ark_relations::r1cs::ConstraintSystem;
    use swiftness_field::{Fp, Fr};

    #[test]
    fn matrix_multiplication() {
        let a = Fp::from(37u8);
        let b = Fp::from(29u8);
        let c = Fp::from(13u8);
        let d = Fp::from(89u8);
        let e = Fp::from(67u8);
        let f = Fp::from(45u8);
        let g = Fp::from(5u8);
        let h = Fp::from(9u8);
        let i = Fp::from(2u8);
        let m = Mat3x3([[a, b, c], [d, e, f], [g, h, i]]);

        let mm = m * m;

        let [row0, row1, row2] = mm.0;
        assert_eq!(
            row0,
            [
                a * a + b * d + c * g,
                a * b + b * e + c * h,
                a * c + b * f + c * i,
            ]
        );
        assert_eq!(
            row1,
            [
                d * a + e * d + f * g,
                d * b + e * e + f * h,
                d * c + e * f + f * i,
            ]
        );
        assert_eq!(
            row2,
            [
                g * a + h * d + i * g,
                g * b + h * e + i * h,
                g * c + h * f + i * i,
            ]
        );
    }

    #[test]
    fn test_calculate_slope_var_1() {
        use curve::StarkwareCurve;

        let cs = ConstraintSystem::<Fp>::new_ref();
        let p1_affine = Affine::<StarkwareCurve>::generator();
        let p1_proj = Projective::from(p1_affine);
        let p2_proj = p1_proj.mul(Fr::from(3));
        let p2_affine = p2_proj.into_affine();

        let p1_proj_var =
            ProjectiveVar::<StarkwareCurve, FpVar<Fp>>::new_witness(cs.clone(), || Ok(p1_proj))
                .unwrap();
        let p1_affine_var = p1_proj_var.to_affine().unwrap();

        let p2_proj_var =
            ProjectiveVar::<StarkwareCurve, FpVar<Fp>>::new_witness(cs.clone(), || Ok(p2_proj))
                .unwrap();
        let p2_affine_var = p2_proj_var.to_affine().unwrap();

        p2_affine_var
            .x
            .enforce_equal(&FpVar::Constant(p2_affine.x))
            .unwrap();
        p2_affine_var
            .y
            .enforce_equal(&FpVar::Constant(p2_affine.y))
            .unwrap();

        let slope_var = curve::calculate_slope_var(p1_affine_var, p2_affine_var).unwrap();
        let slope = curve::calculate_slope(p1_affine, p2_affine).unwrap();

        assert_eq!(slope_var.value().unwrap(), slope);

        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_calculate_slope_var_2() {
        use ark_ff::MontFp as Fp;
        use curve::StarkwareCurve;

        let cs = ConstraintSystem::<Fp>::new_ref();
        let p1_affine = Affine::new(
            Fp!("163637187735534881657873805276162479037864365531085927085109320674493728224"),
            Fp!("2716166568522807705172708228845609579049129132263999535306570107375881002867"),
        );
        let p1_proj = Projective::from(p1_affine);
        let p2_proj = p1_proj.clone();
        let p2_affine = p2_proj.into_affine();

        let p1_proj_var =
            ProjectiveVar::<StarkwareCurve, FpVar<Fp>>::new_witness(cs.clone(), || Ok(p1_proj))
                .unwrap();
        let p1_affine_var = p1_proj_var.to_affine().unwrap();

        let p2_proj_var =
            ProjectiveVar::<StarkwareCurve, FpVar<Fp>>::new_witness(cs.clone(), || Ok(p2_proj))
                .unwrap();
        let p2_affine_var = p2_proj_var.to_affine().unwrap();

        p2_affine_var
            .x
            .enforce_equal(&FpVar::Constant(p2_affine.x))
            .unwrap();
        p2_affine_var
            .y
            .enforce_equal(&FpVar::Constant(p2_affine.y))
            .unwrap();

        let slope_var = curve::calculate_slope_var(p1_affine_var, p2_affine_var).unwrap();
        let slope = curve::calculate_slope(p1_affine, p2_affine).unwrap();

        assert_eq!(slope_var.value().unwrap(), slope);

        assert!(cs.is_satisfied().unwrap());
    }
}

pub mod binary {
    extern crate alloc;

    use alloc::vec::Vec;
    use ark_ff::Field;
    use ark_ff::PrimeField;
    use ark_serialize::CanonicalDeserialize;
    use ark_serialize::CanonicalSerialize;
    use ark_serialize::Valid;
    use num_bigint::BigUint;
    use ruint::aliases::U256;
    use ruint::uint;
    use serde::de;
    use serde::Deserialize;
    use serde::Deserializer;
    use serde::Serialize;
    use serde_json::value::Number;
    use std::error::Error;
    use std::fmt::Display;
    use std::io::BufRead;
    use std::io::BufReader;
    use std::io::Read;
    use std::marker::PhantomData;
    use std::ops::Deref;
    use std::path::PathBuf;

    #[derive(Debug, Clone, Copy)]
    pub struct InvalidFieldElementError {
        pub value: U256,
        pub modulus: U256,
    }

    impl Display for InvalidFieldElementError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(
                f,
                "Invalid value: {}, must be less than the field modulus {}",
                self.value, self.modulus
            )
        }
    }

    impl Error for InvalidFieldElementError {}

    // https://eprint.iacr.org/2021/1063.pdf figure 3
    /// Word offset of `off_DST`
    pub const OFF_DST_BIT_OFFSET: usize = 0;
    /// Word offset of `off_OP0`
    pub const OFF_OP0_BIT_OFFSET: usize = 16;
    /// Word offset of `off_OP1`
    pub const OFF_OP1_BIT_OFFSET: usize = 32;
    /// Word offset of instruction flags
    pub const FLAGS_BIT_OFFSET: usize = 48;

    /// Number of Cairo instruction flags
    pub const _NUM_FLAGS: usize = 16;

    // Mask for word offsets (16 bits each)
    pub const OFF_MASK: usize = 0xFFFF;

    pub const _OFFSET: usize = 2usize.pow(16);
    pub const HALF_OFFSET: usize = 2usize.pow(15);

    /// Holds register values
    #[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
    pub struct RegisterState {
        pub ap: usize,
        pub fp: usize,
        pub pc: usize,
    }

    /// SHARP layouts: <https://www.youtube.com/live/jPxD9h7BdzU?feature=share&t=2800>
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    pub enum Layout {
        Plain = 0,
        Small = 1,
        Dex = 2,
        Recursive = 3,
        Starknet = 4,
        RecursiveLargeOutput = 5,
        AllSolidity = 6,
        StarknetWithKeccak = 7,
    }

    impl Display for Layout {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(
                f,
                "{}",
                match self {
                    Self::Plain => "plain",
                    Self::Small => "small",
                    Self::Dex => "dex",
                    Self::Recursive => "recursive",
                    Self::Starknet => "starknet",
                    Self::RecursiveLargeOutput => "recursive_large_output",
                    Self::AllSolidity => "all_solidity",
                    Self::StarknetWithKeccak => "starknet_with_keccak",
                }
            )
        }
    }

    impl Layout {
        const SHARP_CODE_STARKNET: u128 = 8319381555716711796;
        const SHARP_CODE_RECURSIVE: u128 = 2110234636557836973669;

        // Returns the unique code used by SHARP associated to this layout
        pub const fn sharp_code(&self) -> u128 {
            match self {
                Self::Starknet => Self::SHARP_CODE_STARKNET,
                Self::Recursive => Self::SHARP_CODE_RECURSIVE,
                _ => unimplemented!(),
            }
        }

        pub const fn from_sharp_code(code: u128) -> Self {
            match code {
                Self::SHARP_CODE_STARKNET => Self::Starknet,
                Self::SHARP_CODE_RECURSIVE => Self::Recursive,
                _ => unimplemented!(),
            }
        }
    }

    impl CanonicalSerialize for Layout {
        fn serialize_with_mode<W: ark_serialize::Write>(
            &self,
            writer: W,
            compress: ark_serialize::Compress,
        ) -> Result<(), ark_serialize::SerializationError> {
            self.sharp_code()
                .to_be_bytes()
                .serialize_with_mode(writer, compress)
        }

        fn serialized_size(&self, _compress: ark_serialize::Compress) -> usize {
            core::mem::size_of::<u128>()
        }
    }

    impl Valid for Layout {
        fn check(&self) -> Result<(), ark_serialize::SerializationError> {
            Ok(())
        }
    }

    impl CanonicalDeserialize for Layout {
        fn deserialize_with_mode<R: ark_serialize::Read>(
            reader: R,
            compress: ark_serialize::Compress,
            validate: ark_serialize::Validate,
        ) -> Result<Self, ark_serialize::SerializationError> {
            Ok(Self::from_sharp_code(u128::from_be_bytes(
                <[u8; 16]>::deserialize_with_mode(reader, compress, validate)?,
            )))
        }
    }

    #[derive(Debug)]
    pub struct RegisterStates(Vec<RegisterState>);

    impl RegisterStates {
        /// Parses trace data in the format outputted by a `cairo-run`.
        pub fn from_reader(r: impl Read) -> Self {
            // TODO: errors
            let mut reader = BufReader::new(r);
            let mut register_states = Vec::new();
            while reader.has_data_left().unwrap() {
                let entry: RegisterState = bincode::deserialize_from(&mut reader).unwrap();
                register_states.push(entry);
            }
            RegisterStates(register_states)
        }
    }

    impl Deref for RegisterStates {
        type Target = Vec<RegisterState>;

        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }

    #[derive(Debug)]
    pub struct Memory<F>(Vec<Option<Word<F>>>);

    impl<F: Field> Memory<F> {
        /// Parses the partial memory data outputted by a `cairo-run`.
        pub fn from_reader(r: impl Read) -> Self
        where
            F: PrimeField,
        {
            // TODO: errors
            // TODO: each builtin has its own memory segment.
            // check it also contains other builtins
            // this file contains the contiguous memory segments:
            // - program
            // - execution
            // - builtin 0
            // - builtin 1
            // - ...
            let mut reader = BufReader::new(r);
            let mut partial_memory = Vec::new();
            let mut max_address = 0;
            let mut word_bytes = Vec::new();
            word_bytes.resize(field_bytes::<F>(), 0);
            while reader.has_data_left().unwrap() {
                // TODO: ensure always deserializes u64 and both are always little-endian
                let address = bincode::deserialize_from(&mut reader).unwrap();
                reader.read_exact(&mut word_bytes).unwrap();
                let word = U256::try_from_le_slice(&word_bytes).unwrap();
                partial_memory.push((address, Word::new(word)));
                max_address = std::cmp::max(max_address, address);
            }

            // TODO: DOC: None used for nondeterministic values?
            let mut memory = vec![None; max_address + 1];
            for (address, word) in partial_memory {
                // TODO: once arkworks v4 release remove num_bigint
                memory[address] = Some(word);
            }

            Memory(memory)
        }
    }

    impl<F: Field> Deref for Memory<F> {
        type Target = Vec<Option<Word<F>>>;

        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }

    #[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
    pub struct MemoryEntry<T> {
        pub address: u32,
        pub value: T,
    }

    impl<T: CanonicalSerialize> CanonicalSerialize for MemoryEntry<T> {
        fn serialize_with_mode<W: ark_serialize::Write>(
            &self,
            mut writer: W,
            compress: ark_serialize::Compress,
        ) -> Result<(), ark_serialize::SerializationError> {
            self.value.serialize_with_mode(&mut writer, compress)?;
            self.address.serialize_with_mode(writer, compress)
        }

        fn serialized_size(&self, compress: ark_serialize::Compress) -> usize {
            self.value.serialized_size(compress) + self.address.serialized_size(compress)
        }
    }

    impl MemoryEntry<U256> {
        /// Converts into an equivalent memory entry where the value is a field
        /// element. Returns none if the value is outside the range of the field.
        pub fn try_into_felt_entry<F: PrimeField>(self) -> Option<MemoryEntry<F>> {
            let value = BigUint::from(self.value);
            if value < F::MODULUS.into() {
                Some(MemoryEntry {
                    address: self.address,
                    value: value.into(),
                })
            } else {
                None
            }
        }
    }

    impl<T: Valid> Valid for MemoryEntry<T> {
        fn check(&self) -> Result<(), ark_serialize::SerializationError> {
            self.value.check()?;
            self.address.check()
        }
    }

    impl<T: CanonicalDeserialize> CanonicalDeserialize for MemoryEntry<T> {
        fn deserialize_with_mode<R: ark_serialize::Read>(
            mut reader: R,
            compress: ark_serialize::Compress,
            validate: ark_serialize::Validate,
        ) -> Result<Self, ark_serialize::SerializationError> {
            let value = T::deserialize_with_mode(&mut reader, compress, validate)?;
            let address = u32::deserialize_with_mode(reader, compress, validate)?;
            Ok(Self { value, address })
        }
    }

    #[derive(
        Serialize,
        Deserialize,
        Clone,
        Copy,
        Debug,
        PartialEq,
        Eq,
        CanonicalSerialize,
        CanonicalDeserialize,
    )]
    pub struct Segment {
        pub begin_addr: u32,
        pub stop_ptr: u32,
    }

    #[derive(Deserialize, Clone, Copy, Debug, CanonicalDeserialize, CanonicalSerialize)]
    pub struct MemorySegments {
        pub program: Segment,
        pub execution: Segment,
        pub output: Option<Segment>,
        pub pedersen: Option<Segment>,
        pub range_check: Option<Segment>,
        pub ecdsa: Option<Segment>,
        pub bitwise: Option<Segment>,
        pub ec_op: Option<Segment>,
        pub poseidon: Option<Segment>,
    }

    #[derive(Deserialize, Clone, Debug, CanonicalDeserialize, CanonicalSerialize)]
    #[serde(bound = "F: PrimeField")]
    pub struct AirPublicInput<F: Field> {
        pub rc_min: u16,
        pub rc_max: u16,
        pub n_steps: u64,
        pub layout: Layout,
        pub memory_segments: MemorySegments,
        #[serde(deserialize_with = "deserialize_hex_str_memory_entries")]
        pub public_memory: Vec<MemoryEntry<F>>,
    }

    impl<F: Field> AirPublicInput<F> {
        pub fn initial_pc(&self) -> u32 {
            self.memory_segments.program.begin_addr
        }

        pub fn final_pc(&self) -> u32 {
            self.memory_segments.program.stop_ptr
        }

        pub fn initial_ap(&self) -> u32 {
            self.memory_segments.execution.begin_addr
        }

        pub fn final_ap(&self) -> u32 {
            self.memory_segments.execution.stop_ptr
        }

        pub fn public_memory_padding(&self) -> MemoryEntry<F> {
            *self.public_memory.iter().find(|e| e.address == 1).unwrap()
        }
    }

    #[derive(Deserialize, Clone, Copy, Debug)]
    pub struct Signature {
        #[serde(deserialize_with = "deserialize_hex_str")]
        pub r: U256,
        #[serde(deserialize_with = "deserialize_hex_str")]
        pub w: U256,
    }

    #[derive(Deserialize, Clone, Copy, Debug)]
    pub struct EcdsaInstance {
        pub index: u32,
        #[serde(rename = "pubkey", deserialize_with = "deserialize_hex_str")]
        pub pubkey_x: U256,
        #[serde(rename = "msg", deserialize_with = "deserialize_hex_str")]
        pub message: U256,
        #[serde(rename = "signature_input")]
        pub signature: Signature,
    }

    impl EcdsaInstance {
        /// Get the memory address for this instance
        /// Output is of the form (pubkey_addr, msg_addr)
        pub fn mem_addr(&self, ecdsa_segment_addr: u32) -> (u32, u32) {
            let instance_offset = ecdsa_segment_addr + self.index * 2;
            (instance_offset, instance_offset + 1)
        }
    }

    #[derive(Deserialize, Clone, Copy, Debug)]
    pub struct PedersenInstance {
        pub index: u32,
        #[serde(rename = "x", deserialize_with = "deserialize_hex_str")]
        pub a: U256,
        #[serde(rename = "y", deserialize_with = "deserialize_hex_str")]
        pub b: U256,
    }

    impl PedersenInstance {
        pub fn new_empty(index: u32) -> Self {
            Self {
                index,
                a: U256::ZERO,
                b: U256::ZERO,
            }
        }

        /// Get the memory address for this instance
        /// Output is of the form (a_addr, b_addr, output_addr)
        pub fn mem_addr(&self, pedersen_segment_addr: u32) -> (u32, u32, u32) {
            let instance_offset = pedersen_segment_addr + self.index * 3;
            (instance_offset, instance_offset + 1, instance_offset + 2)
        }
    }

    #[derive(Deserialize, Clone, Copy, Debug)]
    pub struct RangeCheckInstance {
        pub index: u32,
        #[serde(deserialize_with = "deserialize_hex_str")]
        pub value: U256,
    }

    impl RangeCheckInstance {
        pub fn new_empty(index: u32) -> Self {
            Self {
                index,
                value: U256::ZERO,
            }
        }

        /// Get the memory address for this instance
        pub fn mem_addr(&self, range_check_segment_addr: u32) -> u32 {
            range_check_segment_addr + self.index
        }
    }

    #[derive(Deserialize, Clone, Copy, Debug)]
    pub struct BitwiseInstance {
        pub index: u32,
        #[serde(deserialize_with = "deserialize_hex_str")]
        pub x: U256,
        #[serde(deserialize_with = "deserialize_hex_str")]
        pub y: U256,
    }

    impl BitwiseInstance {
        pub fn new_empty(index: u32) -> Self {
            Self {
                index,
                x: U256::ZERO,
                y: U256::ZERO,
            }
        }

        /// Get the memory address for this instance
        /// Output is of the form (x_addr, y_addr, x&y_addr, x^y_addr, x|y_addr)
        // TODO: better to use struct. Could cause bug if user gets ordering wrong.
        pub fn mem_addr(&self, bitwise_segment_addr: u32) -> (u32, u32, u32, u32, u32) {
            let instance_offset = bitwise_segment_addr + self.index * 5;
            (
                instance_offset,
                instance_offset + 1,
                instance_offset + 2,
                instance_offset + 3,
                instance_offset + 4,
            )
        }
    }

    /// Elliptic Curve operation instance for `p + m * q` on an elliptic curve
    #[derive(Deserialize, Clone, Copy, Debug)]
    pub struct EcOpInstance {
        pub index: u32,
        #[serde(deserialize_with = "deserialize_hex_str")]
        pub p_x: U256,
        #[serde(deserialize_with = "deserialize_hex_str")]
        pub p_y: U256,
        #[serde(deserialize_with = "deserialize_hex_str")]
        pub q_x: U256,
        #[serde(deserialize_with = "deserialize_hex_str")]
        pub q_y: U256,
        #[serde(deserialize_with = "deserialize_hex_str")]
        pub m: U256,
    }

    impl EcOpInstance {
        /// Get the memory address for this instance
        /// Output is of the form (p_x_addr, p_y_addr, q_x_addr, q_y_addr, m_addr,
        /// r_x_addr, r_y_addr)
        pub fn mem_addr(&self, ec_op_segment_addr: u32) -> (u32, u32, u32, u32, u32, u32, u32) {
            let instance_offset = ec_op_segment_addr + self.index * 7;
            (
                instance_offset,
                instance_offset + 1,
                instance_offset + 2,
                instance_offset + 3,
                instance_offset + 4,
                instance_offset + 5,
                instance_offset + 6,
            )
        }
    }

    #[derive(Deserialize, Clone, Copy, Debug)]
    pub struct PoseidonInstance {
        pub index: u32,
        #[serde(rename = "input_s0", deserialize_with = "deserialize_hex_str")]
        pub input0: U256,
        #[serde(rename = "input_s1", deserialize_with = "deserialize_hex_str")]
        pub input1: U256,
        #[serde(rename = "input_s2", deserialize_with = "deserialize_hex_str")]
        pub input2: U256,
    }

    impl PoseidonInstance {
        pub fn new_empty(index: u32) -> Self {
            Self {
                index,
                input0: U256::ZERO,
                input1: U256::ZERO,
                input2: U256::ZERO,
            }
        }

        /// Get the memory address for this instance
        /// Output is of the form (input0_addr, input1_addr, input2_addr,
        /// output0_addr, output1_addr, output2_addr)
        pub fn mem_addr(&self, poseidon_segment_addr: u32) -> (u32, u32, u32, u32, u32, u32) {
            let instance_offset = poseidon_segment_addr + self.index * 6;
            (
                instance_offset,
                instance_offset + 1,
                instance_offset + 2,
                instance_offset + 3,
                instance_offset + 4,
                instance_offset + 5,
            )
        }
    }

    #[derive(Debug, Deserialize)]
    pub struct AirPrivateInput {
        pub trace_path: PathBuf,
        pub memory_path: PathBuf,
        pub pedersen: Vec<PedersenInstance>,
        pub range_check: Vec<RangeCheckInstance>,
        #[serde(default)]
        pub ecdsa: Vec<EcdsaInstance>,
        #[serde(default)]
        pub bitwise: Vec<BitwiseInstance>,
        #[serde(default)]
        pub ec_op: Vec<EcOpInstance>,
        #[serde(default)]
        pub poseidon: Vec<PoseidonInstance>,
    }

    #[derive(Clone, Deserialize, Debug)]
    #[serde(bound = "F: PrimeField")]
    pub struct CompiledProgram<F: Field> {
        #[serde(deserialize_with = "deserialize_vec_hex_str")]
        pub data: Vec<F>,
        pub prime: String,
    }

    impl<F: Field> CompiledProgram<F> {
        pub fn program_memory(&self) -> Vec<MemoryEntry<F>> {
            self.data
                .iter()
                .enumerate()
                .map(|(i, &value)| {
                    // address 0 is reserved for dummy accesses (it's null pointer)
                    MemoryEntry {
                        address: i as u32 + 1,
                        value,
                    }
                })
                .collect()
        }
    }

    /// Represents a Cairo word
    /// Value is a field element in the range `[0, Fp::MODULUS)`
    /// Stored as a U256 to make binary decompositions more efficient
    #[derive(Clone, Copy, Debug)]
    pub struct Word<F>(pub U256, PhantomData<F>);

    impl<F> Word<F> {
        /// Calculates $\tilde{f_i}$ - https://eprint.iacr.org/2021/1063.pdf
        pub fn get_flag_prefix(&self, flag: Flag) -> u16 {
            if flag == Flag::Zero {
                return 0;
            }

            let flag = flag as usize;
            let prefix = self.0 >> (FLAGS_BIT_OFFSET + flag);
            let mask = (uint!(1_U256) << (15 - flag)) - uint!(1_U256);
            (prefix & mask).try_into().unwrap()
        }

        pub fn get_op0_addr(&self, ap: usize, fp: usize) -> usize {
            // TODO: put the if statement first good for rust quiz
            self.get_off_op0() as usize + if self.get_flag(Flag::Op0Reg) { fp } else { ap }
                - HALF_OFFSET
        }

        pub fn get_dst_addr(&self, ap: usize, fp: usize) -> usize {
            self.get_off_dst() as usize + if self.get_flag(Flag::DstReg) { fp } else { ap }
                - HALF_OFFSET
        }

        pub fn get_flag(&self, flag: Flag) -> bool {
            self.0.bit(FLAGS_BIT_OFFSET + flag as usize)
        }

        pub fn get_off_dst(&self) -> u16 {
            let prefix = self.0 >> OFF_DST_BIT_OFFSET;
            let mask = U256::from(OFF_MASK);
            (prefix & mask).try_into().unwrap()
        }

        pub fn get_off_op0(&self) -> u16 {
            let prefix = self.0 >> OFF_OP0_BIT_OFFSET;
            let mask = U256::from(OFF_MASK);
            (prefix & mask).try_into().unwrap()
        }

        pub fn get_off_op1(&self) -> u16 {
            let prefix = self.0 >> OFF_OP1_BIT_OFFSET;
            let mask = U256::from(OFF_MASK);
            (prefix & mask).try_into().unwrap()
        }

        pub fn get_flag_group(&self, flag_group: FlagGroup) -> u8 {
            match flag_group {
                FlagGroup::DstReg => self.get_flag(Flag::DstReg) as u8,
                FlagGroup::Op0Reg => self.get_flag(Flag::Op0Reg) as u8,
                FlagGroup::Op1Src => {
                    self.get_flag(Flag::Op1Imm) as u8
                        + self.get_flag(Flag::Op1Fp) as u8 * 2
                        + self.get_flag(Flag::Op1Ap) as u8 * 4
                }
                FlagGroup::ResLogic => {
                    self.get_flag(Flag::ResAdd) as u8 + self.get_flag(Flag::ResMul) as u8 * 2
                }
                FlagGroup::PcUpdate => {
                    self.get_flag(Flag::PcJumpAbs) as u8
                        + self.get_flag(Flag::PcJumpRel) as u8 * 2
                        + self.get_flag(Flag::PcJnz) as u8 * 4
                }
                FlagGroup::ApUpdate => {
                    self.get_flag(Flag::ApAdd) as u8 + self.get_flag(Flag::ApAdd1) as u8 * 2
                }
                FlagGroup::Opcode => {
                    self.get_flag(Flag::OpcodeCall) as u8
                        + self.get_flag(Flag::OpcodeRet) as u8 * 2
                        + self.get_flag(Flag::OpcodeAssertEq) as u8 * 4
                }
            }
        }
    }

    impl<F: PrimeField> Word<F> {
        pub fn new(word: U256) -> Self {
            let modulus: BigUint = F::MODULUS.into();
            debug_assert!(BigUint::from(word) < modulus);
            Word(word, PhantomData)
        }

        pub fn get_op0(&self, ap: usize, fp: usize, mem: &Memory<F>) -> F {
            mem[self.get_op0_addr(ap, fp)].unwrap().into_felt()
        }

        pub fn get_dst(&self, ap: usize, fp: usize, mem: &Memory<F>) -> F {
            mem[self.get_dst_addr(ap, fp)].unwrap().into_felt()
        }

        pub fn get_op1_addr(&self, pc: usize, ap: usize, fp: usize, mem: &Memory<F>) -> usize {
            self.get_off_op1() as usize
                + match self.get_flag_group(FlagGroup::Op1Src) {
                    0 => usize::try_from(mem[self.get_op0_addr(ap, fp)].unwrap().0).unwrap(),
                    1 => pc,
                    2 => fp,
                    4 => ap,
                    _ => unreachable!(),
                }
                - HALF_OFFSET
        }

        pub fn get_op1(&self, pc: usize, ap: usize, fp: usize, mem: &Memory<F>) -> F {
            mem[self.get_op1_addr(pc, ap, fp, mem)].unwrap().into_felt()
        }

        pub fn get_res(&self, pc: usize, ap: usize, fp: usize, mem: &Memory<F>) -> F {
            let pc_update = self.get_flag_group(FlagGroup::PcUpdate);
            let res_logic = self.get_flag_group(FlagGroup::ResLogic);
            match pc_update {
                4 => {
                    let opcode = self.get_flag_group(FlagGroup::Opcode);
                    let ap_update = self.get_flag_group(FlagGroup::ApUpdate);
                    if res_logic == 0 && opcode == 0 && ap_update != 1 {
                        // From the Cairo whitepaper "We use the term Unused to
                        // describe a variable that will not be used later in the
                        // flow. As such, we don’t need to assign it a concrete
                        // value.". Note `res` is repurposed when calculating next_pc and
                        // stores the value of `dst^(-1)` (see air.rs for more details).
                        self.get_dst(ap, fp, mem).inverse().unwrap_or_else(F::zero)
                    } else {
                        unreachable!()
                    }
                }
                0..=2 => {
                    let op0: F = mem[self.get_op0_addr(ap, fp)].unwrap().into_felt();
                    let op1: F = mem[self.get_op1_addr(pc, ap, fp, mem)].unwrap().into_felt();
                    match res_logic {
                        0 => op1,
                        1 => op0 + op1,
                        2 => op0 * op1,
                        _ => unreachable!(),
                    }
                }
                _ => unreachable!(),
            }
        }

        pub fn get_tmp0(&self, ap: usize, fp: usize, mem: &Memory<F>) -> F {
            if self.get_flag(Flag::PcJnz) {
                self.get_dst(ap, fp, mem)
            } else {
                // TODO: change
                F::zero()
            }
        }

        pub fn get_tmp1(&self, pc: usize, ap: usize, fp: usize, mem: &Memory<F>) -> F {
            self.get_tmp0(ap, fp, mem) * self.get_res(pc, ap, fp, mem)
        }

        pub fn into_felt(self) -> F {
            BigUint::from(self.0).into()
        }
    }

    /// Cairo flag group
    /// https://eprint.iacr.org/2021/1063.pdf section 9.4
    #[derive(Clone, Copy)]
    pub enum FlagGroup {
        DstReg,
        Op0Reg,
        Op1Src,
        ResLogic,
        PcUpdate,
        ApUpdate,
        Opcode,
    }

    /// Cairo flag
    /// https://eprint.iacr.org/2021/1063.pdf section 9
    #[derive(Clone, Copy, PartialEq, Eq)]
    #[repr(u16)]
    pub enum Flag {
        // Group: [FlagGroup::DstReg]
        DstReg = 0,

        // Group: [FlagGroup::Op0]
        Op0Reg = 1,

        // Group: [FlagGroup::Op1Src]
        Op1Imm = 2,
        Op1Fp = 3,
        Op1Ap = 4,

        // Group: [FlagGroup::ResLogic]
        ResAdd = 5,
        ResMul = 6,

        // Group: [FlagGroup::PcUpdate]
        PcJumpAbs = 7,
        PcJumpRel = 8,
        PcJnz = 9,

        // Group: [FlagGroup::ApUpdate]
        ApAdd = 10,
        ApAdd1 = 11,

        // Group: [FlagGroup::Opcode]
        OpcodeCall = 12,
        OpcodeRet = 13,
        OpcodeAssertEq = 14,

        // 0 - padding to make flag cells a power-of-2
        Zero = 15,
    }

    fn try_felt_from_u256<F: PrimeField>(value: U256) -> Result<F, InvalidFieldElementError> {
        let modulus = U256::from::<BigUint>(F::MODULUS.into());
        if value < modulus {
            Ok(From::<BigUint>::from(value.into()))
        } else {
            Err(InvalidFieldElementError { value, modulus })
        }
    }

    /// Deserializes a hex string into a field element
    pub fn deserialize_hex_str_as_field_element<'de, D: Deserializer<'de>, F: PrimeField>(
        deserializer: D,
    ) -> Result<F, D::Error> {
        let num = deserialize_hex_str(deserializer)?;
        try_felt_from_u256(num).map_err(de::Error::custom)
    }

    /// Deserializes a hex string into a big integer
    pub fn deserialize_hex_str<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<U256, D::Error> {
        let hex_str = String::deserialize(deserializer)?;
        hex_str.parse::<U256>().map_err(de::Error::custom)
    }

    /// Deserializes a list of memory entries of the form
    /// `{value: "0x...", address: ...}`
    pub fn deserialize_hex_str_memory_entries<'de, D: Deserializer<'de>, F: PrimeField>(
        deserializer: D,
    ) -> Result<Vec<MemoryEntry<F>>, D::Error> {
        #[derive(Deserialize)]
        struct Entry<F: PrimeField> {
            #[serde(deserialize_with = "deserialize_hex_str_as_field_element")]
            pub value: F,
            pub address: u32,
        }
        let v = Vec::deserialize(deserializer)?;
        Ok(v.into_iter()
            .map(|Entry { address, value }| MemoryEntry { address, value })
            .collect())
    }

    /// Deserializes a list of hex strings into a list of big integers
    pub fn deserialize_vec_hex_str<'de, D: Deserializer<'de>, F: PrimeField>(
        deserializer: D,
    ) -> Result<Vec<F>, D::Error> {
        #[derive(Deserialize)]
        struct Wrapper<F: PrimeField>(
            #[serde(deserialize_with = "deserialize_hex_str_as_field_element")] F,
        );
        let v = Vec::deserialize(deserializer)?;
        Ok(v.into_iter().map(|Wrapper(a)| a).collect())
    }

    /// Deserializes a JSON big integer
    /// This deserializer uses serde_json's arbitrary precision features to convert
    /// large numbers to a string and then converts that string to a [U256]. Note
    /// that you can't just deserialize a [U256] because it deserializes a large
    /// number from smaller 32 bit number chunks. TODO: check
    pub fn deserialize_big_uint<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<U256, D::Error> {
        let num = Number::deserialize(deserializer)?.to_string();
        num.parse::<U256>().map_err(de::Error::custom)
    }

    /// Deserializes a JSON list of big integers
    /// See docs for [deserialize_big_uint] to understand why this is needed.
    // TODO: consider removing
    pub fn _deserialize_vec_big_uint<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<U256>, D::Error> {
        #[derive(Deserialize)]
        struct Wrapper(#[serde(deserialize_with = "deserialize_big_uint")] U256);
        let v = Vec::deserialize(deserializer)?;
        Ok(v.into_iter().map(|Wrapper(a)| a).collect())
    }

    /// Calculates the number of bytes per field element the
    /// same way as StarkWare's runner
    pub const fn field_bytes<F: PrimeField>() -> usize {
        F::MODULUS_BIT_SIZE.next_multiple_of(8) as usize / 8
    }
}
