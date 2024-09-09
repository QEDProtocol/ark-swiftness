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
