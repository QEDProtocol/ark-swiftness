mod constants;
mod periodic;
mod utils;
use ark_bls12_381::{Bls12_381, Fr};
use ark_ff::UniformRand;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::nonnative::NonNativeFieldVar;
use ark_r1cs_std::uint64::UInt64;
use ark_r1cs_std::{R1CSVar, ToBitsGadget};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use ark_std::ops::{BitAnd, BitXor, Not};
use ark_std::rand::{thread_rng, Rng};
use constants::{ROTR, ROUND_CONSTANTS};

use crate::keccak::utils::{bitand, not, rotate_left};
use ark_ff::PrimeField;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::uint8::UInt8;
use sha3::Digest;
use sha3::Keccak256;
use swiftness_field::Fp;
use swiftness_field::SimpleField;

fn xor_2<F: PrimeField>(a: &UInt64<F>, b: &UInt64<F>) -> Result<UInt64<F>, SynthesisError> {
    a.xor(b)
}

fn xor_5<F: PrimeField>(
    a: &UInt64<F>,
    b: &UInt64<F>,
    c: &UInt64<F>,
    d: &UInt64<F>,
    e: &UInt64<F>,
) -> Result<UInt64<F>, SynthesisError> {
    // a ^ b ^ c ^ d ^ e
    //note: in aff-std 0.5, use .bitxor
    let ab = a.xor(b)?;
    let abc = ab.xor(c)?;
    let abcd = abc.xor(d)?;
    abcd.xor(e)
}

fn xor_not_and<F: PrimeField>(
    a: &UInt64<F>,
    b: &UInt64<F>,
    c: &UInt64<F>,
) -> Result<UInt64<F>, SynthesisError> {
    // let nb = b.not();
    let nb = not(b);

    // let nbc = nb.bitand(c);
    let nbc = bitand(&nb, c);
    a.xor(&nbc)
}

fn round_1600<F: PrimeField>(
    // cs: &ConstraintSystemRef<F>,
    a: Vec<UInt64<F>>,
    rc: u64,
) -> Result<Vec<UInt64<F>>, SynthesisError> {
    assert_eq!(a.len(), 25);

    // # θ step
    // C[x] = A[x,0] xor A[x,1] xor A[x,2] xor A[x,3] xor A[x,4],   for x in 0…4
    let mut c = Vec::new();
    for x in 0..5 {
        c.push(xor_5(
            &a[x + 0usize],
            &a[x + 5usize],
            &a[x + 10usize],
            &a[x + 15usize],
            &a[x + 20usize],
        )?);
    }

    // D[x] = C[x-1] xor rot(C[x+1],1),                             for x in 0…4
    let mut d = Vec::new();
    for x in 0..5 {
        d.push(xor_2(
            &c[(x + 4usize) % 5usize],
            // &c[(x + 1usize) % 5usize].rotate_left(1),
            &rotate_left(&c[(x + 1usize) % 5usize], 1),
        )?);
    }

    // A[x,y] = A[x,y] xor D[x],                           for (x,y) in (0…4,0…4)
    let mut a_new1 = Vec::new();
    for y in 0..5 {
        for x in 0..5 {
            a_new1.push(xor_2(&a[x + (y * 5usize)], &d[x])?);
        }
    }

    // # ρ and π steps
    // B[y,2*x+3*y] = rot(A[x,y], r[x,y]),                 for (x,y) in (0…4,0…4)
    let mut b = a_new1.clone();
    for y in 0..5 {
        for x in 0..5 {
            b[y + ((((2 * x) + (3 * y)) % 5) * 5usize)] =
                // a_new1[x + (y * 5usize)].rotate_left(ROTR[x + (y * 5usize)]);
                rotate_left(&a_new1[x + (y * 5usize)], ROTR[x + (y * 5usize)]);
        }
    }

    let mut a_new2 = Vec::new();

    // # χ step
    // A[x,y] = B[x,y] xor ((not B[x+1,y]) and B[x+2,y]),  for (x,y) in (0…4,0…4)
    for y in 0..5 {
        for x in 0..5 {
            a_new2.push(xor_not_and(
                &b[x + (y * 5usize)],
                &b[((x + 1usize) % 5usize) + (y * 5usize)],
                &b[((x + 2usize) % 5usize) + (y * 5usize)],
            )?);
        }
    }

    // // # ι step
    // // A[0,0] = A[0,0] xor RC
    let rc = UInt64::constant(rc);
    a_new2[0] = a_new2[0].clone().xor(&rc)?;

    Ok(a_new2)
}

fn keccak_f_1600<F: PrimeField>(
    // cs: &ConstraintSystemRef<F>,
    input: Vec<Boolean<F>>,
) -> Result<Vec<Boolean<F>>, SynthesisError> {
    assert_eq!(input.len(), 1600);

    let mut a = input
        .chunks(64)
        .map(|e| UInt64::from_bits_le(e))
        .collect::<Vec<_>>();

    for i in 0..24 {
        // a = round_1600(cs, a, ROUND_CONSTANTS[i])?;
        a = round_1600(a, ROUND_CONSTANTS[i])?;
    }

    let a_new = a.into_iter().flat_map(|e| e.to_bits_le()).collect();

    Ok(a_new)
}

pub fn keccak256<F: PrimeField>(
    // cs: &ConstraintSystemRef<F>,
    input: &[Boolean<F>],
) -> Result<Vec<Boolean<F>>, SynthesisError> {
    let block_size = 136 * 8; //136 bytes * 8 = 1088 bit
    let input_len = input.len();
    let num_blocks = input_len / block_size + 1;
    let padded_len = num_blocks * block_size;
    let mut padded = vec![Boolean::constant(false); padded_len];
    for i in 0..input.len() {
        padded[i] = input[i].clone();
    }

    // # Padding
    // d = 2^|Mbits| + sum for i=0..|Mbits|-1 of 2^i*Mbits[i]
    // P = Mbytes || d || 0x00 || … || 0x00
    // P = P xor (0x00 || … || 0x00 || 0x80)
    //0x0100 ... 0080
    padded[input_len] = Boolean::constant(true);
    padded[padded_len - 1] = Boolean::constant(true);

    // # Initialization
    // S[x,y] = 0,                               for (x,y) in (0…4,0…4)

    // # Absorbing phase
    // for each block Pi in P
    //   S[x,y] = S[x,y] xor Pi[x+5*y],          for (x,y) such that x+5*y < r/w
    //   S = Keccak-f[r+c](S)
    let mut m = vec![Boolean::constant(false); 1600];

    for i in 0..num_blocks {
        for j in 0..block_size {
            m[j] = m[j].clone().xor(&padded[i * block_size + j])?;
        }
        //m = keccak_f_1600(cs, m)?;
        m = keccak_f_1600(m)?;
    }

    // # Squeezing phase
    // Z = empty string
    let mut z = Vec::new();

    // while output is requested
    //   Z = Z || S[x,y],                        for (x,y) such that x+5*y < r/w
    //   S = Keccak-f[r+c](S)
    for i in 0..256 {
        z.push(m[i].clone());
    }

    return Ok(z);
}

pub trait KeccakHash: SimpleField {
    fn hash(data: &[<Self as SimpleField>::ByteType]) -> Vec<<Self as SimpleField>::ByteType>;
}

impl KeccakHash for Fp {
    fn hash(data: &[<Self as SimpleField>::ByteType]) -> Vec<<Self as SimpleField>::ByteType> {
        let mut hasher = Keccak256::new();
        hasher.update(data);
        hasher.finalize().to_vec()
    }
}

impl<F: PrimeField + SimpleField> KeccakHash for FpVar<F> {
    fn hash(data: &[<Self as SimpleField>::ByteType]) -> Vec<<Self as SimpleField>::ByteType> {
        // convert input to boolean
        let input = data
            .iter()
            .flat_map(|byte| byte.to_bits_le().unwrap())
            .collect::<Vec<_>>();

        let res = match keccak256(&input) {
            Ok(res) => res,
            Err(e) => {
                panic!("keccak256 hash err:{}", e);
            }
        };

        //convert output to bytes
        let output = res.chunks(8).map(UInt8::from_bits_le).collect::<Vec<_>>();
        output
    }
}

impl<F: PrimeField + SimpleField, ConstraintF: PrimeField + SimpleField> KeccakHash
    for NonNativeFieldVar<F, ConstraintF>
{
    fn hash(data: &[<Self as SimpleField>::ByteType]) -> Vec<<Self as SimpleField>::ByteType> {
        // convert input to boolean
        let input = data
            .iter()
            .flat_map(|byte| byte.to_bits_le().unwrap())
            .collect::<Vec<_>>();

        let res = match keccak256(&input) {
            Ok(res) => res,
            Err(e) => {
                panic!("keccak256 hash err:{}", e);
            }
        };

        //convert output to bytes
        let output = res.chunks(8).map(UInt8::from_bits_le).collect::<Vec<_>>();
        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::Field;
    use ark_ff::MontFp as Fp;
    use swiftness_field::Fp;
    use swiftness_field::StarkArkConvert;
    use KeccakHash;
    fn keccak_hash(data: &[u8]) -> Vec<u8> {
        let mut hasher = Keccak256::new();
        hasher.update(data);
        hasher.finalize().to_vec()
    }

    #[test]
    fn test_keccak_hash_fp() {
        let input_len = 1024;
        let mut rng = thread_rng();
        let input: Vec<u8> = (0..input_len).map(|_| rng.gen()).collect();
        let real_bytes: Vec<u8> = <Fp as KeccakHash>::hash(&input);
        let expected = keccak_hash(&input);
        assert_eq!(real_bytes, expected);
    }
    #[test]
    fn test_keccak_hash_fp_var() {
        let input_len = 1024;
        let mut rng = thread_rng();
        let input: Vec<u8> = (0..input_len).map(|_| rng.gen()).collect();
        //let input_fp = input.iter().map(|x| Fp::from(*x)).collect::<Vec<_>>();
        let cs = ConstraintSystem::<Fp>::new_ref();
        let input_fp = UInt8::new_input_vec(ark_relations::ns!(cs, "input"), &input).unwrap();
        let real_bytes: Vec<UInt8<Fp>> = <FpVar<Fp> as KeccakHash>::hash(&input_fp);
        let expected = keccak_hash(&input);
        assert_eq!(real_bytes.len(), expected.len());
        for i in 0..real_bytes.len() {
            assert_eq!(real_bytes[i].value().unwrap(), expected[i]);
        }
    }
}
