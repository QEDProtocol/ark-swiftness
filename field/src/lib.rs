use ark_ff::BigInt;
use ark_ff::Fp256;
use ark_ff::MontBackend;
use ark_ff::MontConfig;

#[derive(MontConfig)]
#[modulus = "3618502788666131213697322783095070105623107215331596699973092056135872020481"]
#[generator = "3"]
pub struct FpMontConfig;

pub type Fp = Fp256<MontBackend<FpMontConfig, 4>>;

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

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::Field;

    #[test]
    fn test_field_operations() {
        let a = Fp::from(3u64);
        let b = Fp::from(5u64);
        assert_eq!(a + b, Fp::from(8u64));
        assert_eq!(a * b, Fp::from(15u64));
        assert_eq!(a.inverse().unwrap() * a, Fp::from(1u64));
    }

    #[test]
    fn starkent_ark_field_conversion() {
        let a = Fp::from(3u64);

        let b = starknet_crypto::Felt::from(3u64);
        assert_eq!(a.to_stark_felt(), b);

        let c = StarkArkConvert::from_stark_felt(b);
        assert_eq!(a, c);
    }
}
