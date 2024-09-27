use ark_ff::PrimeField;
use ark_r1cs_std::uint64::UInt64;

//note: if aff-std version is 0.5, use rotate_left directly
pub fn rotate_left<F: PrimeField>(a: &UInt64<F>, by: usize) -> UInt64<F> {
    // limit `b` to 0..63
    let shift_by = by % 64; // `b % 64`
    let a_bits = a.to_bits_le();

    let mut rotated_bits = vec![a_bits[0].clone(); 64];
    for i in 0..64 {
        let new_index = (i + shift_by) % 64;
        rotated_bits[new_index] = a_bits[i].clone();
    }

    UInt64::from_bits_le(&rotated_bits)
}

//note: if aff-std version is 0.5, use not directly
pub fn not<F: PrimeField>(a: &UInt64<F>) -> UInt64<F> {
    let a_bits = a.to_bits_le();
    let not_bits = a_bits.iter().map(|b| b.not()).collect::<Vec<_>>();
    UInt64::from_bits_le(&not_bits)
}

//note: if aff-std version is 0.5, use bitand directly
pub fn bitand<F: PrimeField>(a: &UInt64<F>, b: &UInt64<F>) -> UInt64<F> {
    let a_bits = a.to_bits_le();
    let b_bits = b.to_bits_le();
    let and_bits = a_bits
        .iter()
        .zip(b_bits.iter())
        .map(|(a, b)| a.and(b).unwrap())
        .collect::<Vec<_>>();
    UInt64::from_bits_le(&and_bits)
}

fn from_bits_to_u8(bools: &[bool]) -> u8 {
    assert_eq!(bools.len(), 8);
    let mut result: u8 = 0;
    let mut shift = 0;
    for &bit in bools {
        if bit {
            result |= 1 << shift;
        }
        shift += 1;
        if shift == 8 {
            break;
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::PrimeField;
    use ark_r1cs_std::alloc::AllocVar;
    use ark_r1cs_std::uint64::UInt64;
    use ark_r1cs_std::R1CSVar;
    use ark_relations::r1cs::*;
    use swiftness_field::Fr;

    #[test]
    fn test_uint64_rotate_left() {
        let input = 0xa10000b1a20000b2u64;
        let expected = 0xb1a20000b2a1;
        let cs = ConstraintSystem::<Fr>::new_ref();

        let input: UInt64<Fr> =
            UInt64::new_witness(ark_relations::ns!(cs, "new witness"), || Ok(input)).unwrap();
        let expected: UInt64<Fr> =
            UInt64::new_input(ark_relations::ns!(cs, "new input"), || Ok(expected)).unwrap();
        assert_eq!(
            rotate_left(&input, 8).value().unwrap(),
            expected.value().unwrap()
        );
    }
    #[test]
    fn test_uint64_not() {
        let input = 0x100000b3u64;
        let expected = !input;
        let cs = ConstraintSystem::<Fr>::new_ref();

        let input: UInt64<Fr> =
            UInt64::new_witness(ark_relations::ns!(cs, "new witness"), || Ok(input)).unwrap();
        let expected: UInt64<Fr> =
            UInt64::new_input(ark_relations::ns!(cs, "new input"), || Ok(expected)).unwrap();
        assert_eq!(not(&input).value().unwrap(), expected.value().unwrap());
    }
    #[test]
    fn test_uint64_bitand() {
        let input1 = 0x110000b3u64;
        let input2 = 0x100010b3u64;
        let expected = input1 & input2;
        let cs = ConstraintSystem::<Fr>::new_ref();

        let input1: UInt64<Fr> =
            UInt64::new_witness(ark_relations::ns!(cs, "new witness"), || Ok(input1)).unwrap();
        let input2: UInt64<Fr> =
            UInt64::new_witness(ark_relations::ns!(cs, "new witness"), || Ok(input2)).unwrap();
        let expected: UInt64<Fr> =
            UInt64::new_input(ark_relations::ns!(cs, "new input"), || Ok(expected)).unwrap();
        assert_eq!(
            bitand(&input1, &input2).value().unwrap(),
            expected.value().unwrap()
        );
    }
}
