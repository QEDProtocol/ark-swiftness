use ark_crypto_primitives::prf::blake2s::constraints::evaluate_blake2s;
use ark_ff::PrimeField;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::ToBitsGadget;
use ark_r1cs_std::ToBytesGadget;
use blake2::Blake2s256;
use blake2::Digest;
use swiftness_field::Fp;
use swiftness_field::SimpleField;

pub trait Blake2sHash: SimpleField {
    fn hash(data: &[<Self as SimpleField>::ByteType]) -> Vec<<Self as SimpleField>::ByteType>;
}

impl Blake2sHash for Fp {
    fn hash(data: &[<Self as SimpleField>::ByteType]) -> Vec<<Self as SimpleField>::ByteType> {
        let mut hasher = Blake2s256::new();
        hasher.update(data);
        hasher.finalize().to_vec()
    }
}

impl<F: PrimeField + SimpleField> Blake2sHash for FpVar<F> {
    fn hash(data: &[<Self as SimpleField>::ByteType]) -> Vec<<Self as SimpleField>::ByteType> {
        let mut input_bits = vec![];
        for input_byte in data.iter() {
            input_bits.extend(ToBitsGadget::<F>::to_bits_le(input_byte).unwrap());
        }

        let r = evaluate_blake2s(&input_bits).unwrap();

        let mut res: Vec<<Self as SimpleField>::ByteType> = vec![];
        for chunk in r {
            for b in ToBytesGadget::to_bytes(&chunk).unwrap() {
                res.push(b)
            }
        }

        res
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_r1cs_std::{alloc::AllocVar, uint8::UInt8, R1CSVar};
    use ark_relations::r1cs::ConstraintSystem;
    use num_traits::ToPrimitive;

    #[test]
    fn test_blake2s_fp_and_fpvar_match() {
        let cs = ConstraintSystem::<Fp>::new_ref();

        let test_data: Vec<u8> = vec![1, 2, 3, 4, 5];

        let fp_hash = Fp::hash(&test_data);

        let fpvar_input: Vec<UInt8<Fp>> = test_data
            .iter()
            .map(|&byte| UInt8::new_witness(cs.clone(), || Ok(byte)).unwrap())
            .collect();

        let fpvar_hash = FpVar::<Fp>::hash(fpvar_input.as_slice());

        assert_eq!(fp_hash.len(), fpvar_hash.len());
        for (fp_byte, fpvar_byte) in fp_hash.iter().zip(fpvar_hash.iter()) {
            assert_eq!(fp_byte.to_u8(), fpvar_byte.value().unwrap().to_u8());
        }

        assert!(cs.is_satisfied().unwrap());
    }
}
