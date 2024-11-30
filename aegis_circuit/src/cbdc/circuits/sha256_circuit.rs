use ark_crypto_primitives::crh::{
    sha256::constraints::{DigestVar, Sha256Gadget, UnitVar},
    CRHScheme, CRHSchemeGadget,
};
use sha3::{Sha3_256, Digest, Sha3_256Core};
use ark_crypto_primitives::sponge::Absorb;
use ark_ec::CurveGroup;
use ark_ff::{BigInteger, Field, PrimeField};
use ark_r1cs_std::{fields::fp::FpVar, prelude::*};
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, SynthesisError,
};
use rand::thread_rng;
use sha2::Sha256;
use std::{marker::PhantomData, os::unix::thread};
use ark_ff::BigInt;

use crate::cbdc::MockingSha256Circuit;

pub type ConstraintF<C> = <<C as CurveGroup>::BaseField as Field>::BasePrimeField;

#[derive(Clone, Debug)]
pub struct Sha256Circuit<C: CurveGroup, GG: CurveVar<C, ConstraintF<C>>>
where
    C: CurveGroup,
    GG: CurveVar<C, C::BaseField>,
    <C as CurveGroup>::BaseField: PrimeField + Absorb,
    for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
{
    pub digest: Option<Vec<u8>>,
    pub message: Option<C::BaseField>,
    _curve: PhantomData<GG>,
}

impl<C, GG> Sha256Circuit<C, GG>
where
    C: CurveGroup,
    GG: CurveVar<C, C::BaseField>,
    <C as CurveGroup>::BaseField: PrimeField + Absorb,
    for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
{
    pub fn new(digest: Vec<u8>, message: C::BaseField) -> Self {
        Self {
            digest: Some(digest),
            message: Some(message),
            _curve: PhantomData,
        }
    }
}

impl<C, GG> ConstraintSynthesizer<C::BaseField> for Sha256Circuit<C, GG>
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
        let digest_var = DigestVar::<C::BaseField>::new_input(cs.clone(), || {
            self.digest.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let message_var = FpVar::<C::BaseField>::new_input(cs.clone(), || {
            self.message.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let digest_expected =
            Sha256Gadget::<C::BaseField>::evaluate(&UnitVar::default(), &message_var.to_bytes()?)?;

        digest_var.enforce_equal(&digest_expected)?;
        Ok(())
    }
}

#[allow(non_snake_case)]
impl<C, GG> MockingSha256Circuit<C, GG> for Sha256Circuit<C, GG>
where
    C: CurveGroup,
    GG: CurveVar<C, C::BaseField>,
    <C as CurveGroup>::BaseField: PrimeField + Absorb,
    for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
{
    type F = C::BaseField;
    type H = Sha256;
    type Output = Sha256Circuit<C, GG>;

    fn generate_circuit() -> Result<Self::Output, crate::Error> {
        use ark_std::UniformRand;
        let mut rng = thread_rng();
        let mut hasher = Sha3_256::new();
        // let message = Self::F::rand(&mut rng);
        let message = Self::F::from(5u64);

        let message_bytes = message.into_bigint().to_bytes_le();

        println!("message: {:?}", message.to_string());
        println!("message_bytes: {:?}", message_bytes);

        let digest: Vec<u8> = Self::H::evaluate(&(), message_bytes.clone()).unwrap();
        let digest_field = Self::F::from_le_bytes_mod_order(&digest);
        let digest_bigint = digest_field.into_bigint();
        let digest_hex = hex::encode(digest_bigint.to_bytes_le());

        hasher.update(b"5");
        let digest_sha3_256 = hasher.finalize();
        let digest_sha3_256_hex = hex::encode(digest_sha3_256);

        

        println!("message: {:?}", message.to_string());
        println!("digest: {:?}", digest_hex); 
        println!("digest_sha3_256(5): {:?}", digest_sha3_256_hex);

        Ok(Sha256Circuit::new(digest, message))
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

    type C = ark_ed_on_bn254::EdwardsProjective;
    type GG = ark_ed_on_bn254::constraints::EdwardsVar;
    type F = ark_bn254::Fr;

    fn make_mocking_circuit() -> Sha256Circuit<C, GG> {
        let test_circuit =
            <Sha256Circuit<C, GG> as MockingSha256Circuit<C, GG>>::generate_circuit().unwrap();
        test_circuit
    }

    #[test]
    fn test_sha256_constraints() {
        use ark_relations::r1cs::ConstraintSynthesizer;
        let test_circuit = make_mocking_circuit();
        let cs = ConstraintSystem::<F>::new_ref();

        test_circuit
            .clone()
            .generate_constraints(cs.clone())
            .unwrap();
        println!("[Sha256] Number of constraints: {}", cs.num_constraints());
        if !cs.is_satisfied().unwrap() {
            println!(
                "Unsatisfied constraints: {:?}",
                cs.which_is_unsatisfied().unwrap()
            );
        }

        assert!(cs.is_satisfied().unwrap());
    }
}
