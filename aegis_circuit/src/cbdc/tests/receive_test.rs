mod send_tests {
    use crate::cbdc::circuits::receive_circuit::ReceiveCircuit;
    use crate::cbdc::tests::import::*;
    #[test]
    fn test_constraints() {
        use ark_relations::r1cs::ConstraintSynthesizer;

        let test_input =
            <ReceiveCircuit<C, GG> as MockingCircuit<C, GG>>::generate_circuit(32)
                .unwrap();

        let cs = ark_relations::r1cs::ConstraintSystem::new_ref();

        test_input.clone().generate_constraints(cs.clone()).unwrap();
        assert!(cs.is_satisfied().unwrap());
        println!("[Receive] Number of constraints: {}", cs.num_constraints());
    }
}