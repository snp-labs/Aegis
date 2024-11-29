mod send_tests {
    use crate::cbdc::tests::import::*;
    use crate::cbdc::circuits::register_circuit::RegisterCircuit;
    #[test]
    fn test_constraints() {
        use ark_relations::r1cs::ConstraintSynthesizer;

        let test_input =
            <RegisterCircuit<C, GG> as MockingCircuit<C, GG>>::generate_circuit(32)
                .unwrap();

        let cs = ark_relations::r1cs::ConstraintSystem::new_ref();

        test_input.clone().generate_constraints(cs.clone()).unwrap();
        assert!(cs.is_satisfied().unwrap());
        println!("[Register] Number of constraints: {}", cs.num_constraints());
    }
}