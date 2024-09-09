use alloc::vec;
use alloc::vec::Vec;
use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar};
use ark_relations::r1cs::{Namespace, SynthesisError};
use swiftness_field::{Fp, SimpleField};
use swiftness_hash::poseidon::PoseidonHash;

impl AllocVar<Transcript<Fp>, Fp> for Transcript<FpVar<Fp>> {
    fn new_variable<T: core::borrow::Borrow<Transcript<Fp>>>(
        cs: impl Into<Namespace<Fp>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: ark_r1cs_std::prelude::AllocationMode,
    ) -> Result<Self, SynthesisError> {
        f().and_then(|transcript| {
            let transcript = transcript.borrow();
            let cs = cs.into();

            Ok(Self {
                digest: FpVar::new_variable(cs.clone(), || Ok(&transcript.digest), mode)?,
                counter: FpVar::new_variable(cs, || Ok(&transcript.counter), mode)?,
            })
        })
    }
}

#[derive(Clone, Debug)]
pub struct Transcript<F: SimpleField + PoseidonHash> {
    digest: F,
    counter: F,
}

impl<F: SimpleField + PoseidonHash> Transcript<F> {
    pub fn new(digest: F) -> Self {
        Self {
            digest,
            counter: F::from_constant(0u64),
        }
    }

    pub fn new_with_counter(digest: F, counter: F) -> Self {
        Self { digest, counter }
    }

    pub fn digest(&self) -> &F {
        &self.digest
    }

    pub fn counter(&self) -> &F {
        &self.counter
    }

    pub fn random_felt_to_prover(&mut self) -> F {
        let hash = PoseidonHash::hash(self.digest.clone(), self.counter.clone());
        self.counter += F::one();
        hash
    }

    pub fn random_felts_to_prover(&mut self, mut len: F) -> Vec<F>
    where
        F: PartialOrd,
    {
        let mut res = Vec::new();
        while len > F::zero() {
            res.push(self.random_felt_to_prover());
            len -= F::one()
        }
        res
    }

    pub fn read_felt_from_prover(&mut self, val: &F) {
        let hash = PoseidonHash::hash_many([&(self.digest.clone() + F::one()), val]);
        self.digest = hash;
        self.counter = F::zero();
    }

    pub fn read_felt_vector_from_prover(&mut self, val: &[F]) {
        let digest = self.digest.clone();
        let hash = PoseidonHash::hash_many(vec![&(digest + F::one())].into_iter().chain(val));
        self.digest = hash;
        self.counter = F::zero();
    }

    pub fn read_uint64_from_prover(&mut self, val: u64) {
        self.read_felt_from_prover(&F::from_constant(val))
    }
}
