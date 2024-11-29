mod send_tests {
    use crate::cbdc::tests::import::*;
    use crate::cbdc::circuits::exchange_circuit::ExchangeCircuit;
    #[test]
    fn test_constraints() {
        use ark_relations::r1cs::ConstraintSynthesizer;

        let test_input =
            <ExchangeCircuit<C, GG> as MockingCircuit<C, GG>>::generate_circuit(32)
                .unwrap();

        let cs = ark_relations::r1cs::ConstraintSystem::new_ref();

        test_input.clone().generate_constraints(cs.clone()).unwrap();
        assert!(cs.is_satisfied().unwrap());
        println!("[Exchange] Number of constraints: {}", cs.num_constraints());
    }
}