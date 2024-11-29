mod send_tests {
    use std::fs;

    use ark_bn254::Bn254;
    use ark_crypto_primitives::snark::CircuitSpecificSetupSNARK;
    use ark_crypto_primitives::snark::SNARK;
    use ark_ec::AffineRepr;

    use ark_ff::PrimeField;
    use ark_groth16::Groth16;

    use ark_serialize::CanonicalSerialize;
    use ark_std::end_timer;
    use ark_std::rand::RngCore;
    use ark_std::rand::SeedableRng;
    use ark_std::start_timer;
    use ark_std::test_rng;

    use crate::cbdc::circuits::send_circuit::SendCircuit;
    use crate::cbdc::MockingCircuit;

    use crate::gadget::*;

    
    type C = ark_ed_on_bn254::EdwardsProjective;
    type GG = ark_ed_on_bn254::constraints::EdwardsVar;

    type F = ark_bn254::Fr;

    #[test]
    fn test_constraints() {
        use ark_relations::r1cs::ConstraintSynthesizer;

        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());


        let test_input =
            <SendCircuit<C, GG> as MockingCircuit<C, GG>>::generate_circuit(32)
                .unwrap();

        let cs = ark_relations::r1cs::ConstraintSystem::new_ref();

        test_input.clone().generate_constraints(cs.clone()).unwrap();
        assert!(cs.is_satisfied().unwrap());
        println!("Number of constraints: {}", cs.num_constraints());
    }
}