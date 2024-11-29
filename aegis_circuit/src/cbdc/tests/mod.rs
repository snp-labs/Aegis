pub mod register_test;
pub mod send_test;
pub mod receive_test;
pub mod exchange_test;

pub mod import {
    pub use std::fs;

    pub use ark_bn254::Bn254;
    pub use ark_crypto_primitives::snark::{CircuitSpecificSetupSNARK, SNARK};
    pub use ark_ec::AffineRepr;
    pub use ark_ff::PrimeField;
    pub use ark_groth16::Groth16;
    pub use ark_serialize::CanonicalSerialize;
    pub use ark_std::{
        end_timer, start_timer, test_rng,
        rand::{RngCore, SeedableRng},
    };

    pub use crate::cbdc::MockingCircuit;
    pub use crate::gadget::*;

    pub type C = ark_ed_on_bn254::EdwardsProjective;
    pub type GG = ark_ed_on_bn254::constraints::EdwardsVar;
    pub type F = ark_bn254::Fr;
}
