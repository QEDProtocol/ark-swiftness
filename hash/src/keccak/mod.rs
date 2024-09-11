use ark_ff::PrimeField;
use ark_r1cs_std::fields::fp::FpVar;
use swiftness_field::Fp;
use swiftness_field::SimpleField;
use sha3::Keccak256;
use sha3::Digest;

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
        unimplemented!()
    }
}
