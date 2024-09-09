use alloc::vec::Vec;
use starknet_crypto::Felt;
use swiftness_air::domains::StarkDomains;
use swiftness_field::SimpleField;
use swiftness_hash::poseidon::PoseidonHash;
use swiftness_transcript::transcript::Transcript;

const FIELD_GENERATOR: Felt = Felt::from_hex_unchecked("0x3");

pub fn generate_queries<F: SimpleField + PoseidonHash>(
    transcript: &mut Transcript<F>,
    n_samples: F,
    query_upper_bound: F,
) -> Vec<F> {
    let n: u128 = n_samples.into_constant().try_into().unwrap();
    let mut samples: Vec<F> = (0..n)
        .map(|_| {
            let res = transcript.random_felt_to_prover();
            let (_, low) = res.div_rem(&
                F::from_stark_felt(Felt::from_hex_unchecked("0x100000000000000000000000000000000")),
            );
            let (_, sample) = low.div_rem(&query_upper_bound);
            sample
        })
        .collect();

    // TODO: should sort
    // samples.sort();
    samples
}

pub fn queries_to_points<F: SimpleField + PoseidonHash>(queries: &[F], stark_domains: &StarkDomains<F>) -> Vec<F> {
    let mut points = Vec::<F>::new();

    // Evaluation domains of size greater than 2**64 are not supported
    // assert!((stark_domains.log_eval_domain_size) <= Felt::from(64));
    stark_domains.log_eval_domain_size.assert_lte(&F::from_constant(64_u128));

    // A 'log_eval_domain_size' bits index can be bit reversed using bit_reverse_u64 if it is
    // multiplied by 2**(64 - log_eval_domain_size) first.
    let shift = F::two().powers_felt(&(F::from_constant(64_u128) - stark_domains.log_eval_domain_size.clone()));

    for query in queries {
        let index: u64 = (query.clone() * &shift).into_constant().try_into().unwrap();
        points.push(F::from_stark_felt(FIELD_GENERATOR) * stark_domains.eval_generator.powers([index.reverse_bits()]))
    }
    points
}
