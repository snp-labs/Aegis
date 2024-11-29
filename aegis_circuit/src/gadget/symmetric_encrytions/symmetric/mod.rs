use crate::Error;
use ark_crypto_primitives::sponge::Absorb;
use ark_ff::{Field, PrimeField};
use std::marker::PhantomData;

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use super::SymmetricEncryption;
use ark_crypto_primitives::crh::{
    poseidon::CRH,
    CRHScheme
};
use ark_crypto_primitives::sponge::poseidon::PoseidonConfig;

pub mod constraints;

#[derive(Clone, Default, Debug, PartialEq, CanonicalDeserialize, CanonicalSerialize)]
pub struct Randomness<F: Field> {
    pub r: F,
}

#[derive(Clone, Default, Debug, PartialEq)]
pub struct SymmetricKey<F: Field> {
    pub k: F,
}

#[derive(Clone, Default, Debug, PartialEq, CanonicalDeserialize, CanonicalSerialize)]
pub struct Ciphertext<F: Field> {
    pub r: F,
    pub c: F,
}

#[derive(Clone, Default, Debug, PartialEq, CanonicalDeserialize, CanonicalSerialize)]
pub struct Plaintext<F: Field> {
    pub m: F,
}

pub struct SymmetricEncryptionScheme<F: Field> {
    _field: PhantomData<F>,
}

impl<F> SymmetricEncryption for SymmetricEncryptionScheme<F>
where
    F: PrimeField + Absorb,
{
    type Parameters = PoseidonConfig<F>;

    type Randomness = Randomness<F>;
    type SymmetricKey = SymmetricKey<F>;
    type Ciphertext = Ciphertext<F>;
    type Plaintext = Plaintext<F>;

    fn keygen(_params: Self::Parameters) -> Result<Self::SymmetricKey, Error> {
        unimplemented!()
    }

    fn encrypt(
        hash_params: Self::Parameters,
        r: Self::Randomness,
        k: Self::SymmetricKey,
        m: Self::Plaintext,
    ) -> Result<Self::Ciphertext, Error> {
        let hash_params = hash_params.clone();
        let r = r.r.clone();
        let k = k.k.clone();
        let m = m.m.clone();

        let h = CRH::evaluate(&hash_params, vec![k, r]).unwrap();
        let c = h + m;

        Ok(Ciphertext { r, c })
    }

    fn decrypt(
        hash_params: Self::Parameters,
        k: Self::SymmetricKey,
        ct: Self::Ciphertext,
    ) -> Result<Self::Plaintext, Error> {
        let hash_params = hash_params.clone();
        let Ciphertext { r, c } = ct.clone();
        let k = k.k.clone();

        let h = CRH::evaluate(&hash_params, vec![k, r]).unwrap();
        let m = c - h;

        Ok(Plaintext { m })
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use ark_bn254::Fr;
    use ark_ff::Fp;

    use crate::gadget::hashes::poseidon::poseidon_params::get_poseidon_params;
    use crate::gadget::symmetric_encrytions::SymmetricEncryption;
    use super::{Plaintext, Randomness, SymmetricEncryptionScheme, SymmetricKey};

    #[test]
    fn test_semmetic_encryption() {
        let hash_params = get_poseidon_params();
        let r: Fr = Fp::from_str("3").unwrap();
        let k: Fr = Fp::from_str("3").unwrap();
        let m: Fr = Fp::from_str("5").unwrap();

        let random = Randomness { r };
        let key = SymmetricKey { k };
        let msg = Plaintext { m };

        let ct = SymmetricEncryptionScheme::<Fr>::encrypt(
            hash_params.clone(),
            random.clone(),
            key.clone(),
            msg.clone(),
        )
        .unwrap();

        println!("ct: {:?}", ct.c);

        let m_dec = SymmetricEncryptionScheme::<Fr>::decrypt(hash_params, key, ct).unwrap();
        println!("m: {:?}", m_dec.m);
    }
}
