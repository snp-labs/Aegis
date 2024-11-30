// use crate::cbdc::poseidon_params::get_poseidon_params;
use crate::cbdc::MockingCircuit;
use crate::gadget::hashes::poseidon::poseidon_params::get_poseidon_params;
use ark_crypto_primitives::{
    crh::{
        poseidon::{
            constraints::{CRHGadget, CRHParametersVar},
            CRH,
        },
        CRHScheme, CRHSchemeGadget,
    },
    sponge::{poseidon::PoseidonConfig, Absorb},
};
use ark_ec::CurveGroup;
use ark_ff::{BigInteger, Field, PrimeField};
use ark_r1cs_std::{fields::fp::FpVar, prelude::*};
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, SynthesisError,
};
use rand::thread_rng;
use std::{marker::PhantomData, os::unix::thread};

use crate::cbdc::MockingHashCircuit;

pub type ConstraintF<C> = <<C as CurveGroup>::BaseField as Field>::BasePrimeField;

#[derive(Clone, Debug)]
pub struct PoseidonCircuit<C: CurveGroup, GG: CurveVar<C, ConstraintF<C>>>
where
    C: CurveGroup,
    GG: CurveVar<C, C::BaseField>,
    <C as CurveGroup>::BaseField: PrimeField + Absorb,
    for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
{
    pub hash_params: PoseidonConfig<C::BaseField>,
    pub digest: Option<C::BaseField>,
    pub message: Option<C::BaseField>,
    _curve: PhantomData<GG>,
}

impl<C, GG> PoseidonCircuit<C, GG>
where
    C: CurveGroup,
    GG: CurveVar<C, C::BaseField>,
    <C as CurveGroup>::BaseField: PrimeField + Absorb,
    for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
{
    pub fn new(
        hash_params: PoseidonConfig<C::BaseField>,
        digest: C::BaseField,
        message: C::BaseField,
    ) -> Self {
        Self {
            hash_params,
            digest: Some(digest),
            message: Some(message),
            _curve: PhantomData,
        }
    }
}

impl<C, GG> ConstraintSynthesizer<C::BaseField> for PoseidonCircuit<C, GG>
where
    C: CurveGroup,
    GG: CurveVar<C, C::BaseField>,
    <C as CurveGroup>::BaseField: PrimeField + Absorb,
    for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
{
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<C::BaseField>,
    ) -> ark_relations::r1cs::Result<()> {
        let hash_params =
            CRHParametersVar::<C::BaseField>::new_constant(cs.clone(), self.hash_params)?;
        let digest_var = FpVar::<C::BaseField>::new_input(cs.clone(), || {
            self.digest.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let message_var = FpVar::<C::BaseField>::new_witness(cs.clone(), || {
            self.message.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let digest_expected = CRHGadget::<C::BaseField>::evaluate(&hash_params, &[message_var])?;
        digest_var.enforce_equal(&digest_expected)?;
        Ok(())
    }
}

#[allow(non_snake_case)]
impl<C, GG> MockingHashCircuit<C, GG> for PoseidonCircuit<C, GG>
where
    C: CurveGroup,
    GG: CurveVar<C, C::BaseField>,
    <C as CurveGroup>::BaseField: PrimeField + Absorb,
    for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
{
    type F = C::BaseField;
    type HashParam = PoseidonConfig<Self::F>;
    type H = CRH<Self::F>;
    type Output = PoseidonCircuit<C, GG>;

    fn generate_circuit() -> Result<Self::Output, crate::Error> {
        use ark_ec::AffineRepr;
        use ark_std::UniformRand;
        use ark_std::Zero;
        let mut rng = thread_rng();
        let hash_params: PoseidonConfig<<<C as CurveGroup>::Affine as AffineRepr>::BaseField> =
            get_poseidon_params();
        let message = Self::F::rand(&mut rng);
        // let message = Self::F::from(256u64);
        let digest = Self::H::evaluate(&hash_params, vec![message]).unwrap();
        let digest_bigint = digest.into_bigint();
        let digest_bytes = digest_bigint.to_bytes_le();

        println!("message: {:?}", message.to_string());
        println!("digest: {:?}", digest.to_string());
        println!("digest bit length {:?}", digest_bigint.num_bits());
        

        Ok(PoseidonCircuit::new(hash_params, digest, message))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::cbdc::MockingCircuit;
    use ark_bn254::Bn254;
    use ark_crypto_primitives::snark::SNARK;
    use ark_ec::{AffineRepr, CurveGroup};
    use ark_ff::Field;
    use ark_groth16::Groth16;
    use ark_relations::r1cs::ConstraintSystem;
    use ark_std::Zero;
    use ark_std::UniformRand;

    type C = ark_ed_on_bn254::EdwardsProjective;
    type GG = ark_ed_on_bn254::constraints::EdwardsVar;
    type F = ark_bn254::Fr;

    fn make_mocking_circuit() -> PoseidonCircuit<C, GG> {
        let test_circuit =
            <PoseidonCircuit<C, GG> as MockingHashCircuit<C, GG>>::generate_circuit().unwrap();
        test_circuit
    }

    fn make_ark_matrix() -> Vec<Vec<String>> {
        let mut rng = thread_rng();
        let mut ark = vec![vec![String::new(); 3]; 8 + 57];
        for i in 0..8 + 57 {
            for j in 0..3 {
                let field_element = F::rand(&mut rng);
                ark[i][j] = field_element.to_string();
            }
        }
        ark
    }

    // #[test]
    // fn test_ark_matrix() {
    //     let ark = make_ark_matrix();
    //     println!("{:?}", ark);
    // }

    #[test]
    fn test_poseidon_constraints() {
        use ark_relations::r1cs::ConstraintSynthesizer;
        let test_circuit = make_mocking_circuit();
        let cs = ConstraintSystem::<F>::new_ref();

        test_circuit
            .clone()
            .generate_constraints(cs.clone())
            .unwrap();
        println!("Number of constraints: {}", cs.num_constraints());
        assert!(cs.is_satisfied().unwrap());
    }
}
