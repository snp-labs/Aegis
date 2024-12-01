mod receive_tests {
    use crate::cbdc::circuits::receive_circuit::ReceiveCircuit;
    use crate::cbdc::tests::import::*;
    use std::{fs::File, io::Write};
    use lazy_static::lazy_static;

    lazy_static! {
        pub static ref PK_FILE: String = "receive.pk.dat".to_string();
        pub static ref VK_FILE: String = "receive.vk.dat".to_string();
        pub static ref PK_UNCOMP_FILE: String = "receive.pk.uncompressed.dat".to_string();
        pub static ref VK_UNCOMP_FILE: String = "receive.vk.uncompressed.dat".to_string();
        pub static ref PRF_FILE: String = "receive.proof.dat".to_string();
    }

    const TREE_HEIGHT: u64 = 33;
    
    #[test]
    fn test_constraints() {
        use ark_relations::r1cs::ConstraintSynthesizer;

        let test_input =
            <ReceiveCircuit<C, GG> as MockingCircuit<C, GG>>::generate_circuit(33)
                .unwrap();

        let cs = ark_relations::r1cs::ConstraintSystem::new_ref();

        test_input.clone().generate_constraints(cs.clone()).unwrap();
        assert!(cs.is_satisfied().unwrap());
        println!("[Receive] Number of constraints: {}", cs.num_constraints());
    }

    #[test]
    fn test_make_pk_vk_size() {
        let path = "./src/keys/receive/";
        let pk_file = format!("{}{}", path, PK_FILE.as_str());
        let vk_file = format!("{}{}", path, VK_FILE.as_str());
        let pk_file_uncompressed = format!("{}{}", path, PK_UNCOMP_FILE.as_str());
        let vk_file_uncompressed = format!("{}{}", path, VK_UNCOMP_FILE.as_str());

        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
        println!("Generate Receive circuit test input!");

        let test_input =
            <ReceiveCircuit<C, GG> as MockingCircuit<C, GG>>::generate_circuit(TREE_HEIGHT)
                .unwrap();

        println!("Generate CRS!");
        let (pk, vk) = {
            let c = test_input.clone();

            Groth16::<Bn254>::setup(c, &mut rng).unwrap()
        };

        let mut pk_bytes = Vec::new();
        pk.serialize_compressed(&mut pk_bytes).unwrap();

        let mut pk_byptes_uncompressed = Vec::new();
        pk.serialize_uncompressed(&mut pk_byptes_uncompressed)
            .unwrap();

        let mut vk_bytes = Vec::new();
        vk.serialize_compressed(&mut vk_bytes).unwrap();

        let mut vk_byptes_uncompressed = Vec::new();
        vk.serialize_uncompressed(&mut vk_byptes_uncompressed)
            .unwrap();

        // Write data in .dat
        fs::write(pk_file.as_str(), pk_bytes).unwrap();
        fs::write(vk_file.as_str(), vk_bytes).unwrap();
        fs::write(pk_file_uncompressed, pk_byptes_uncompressed).unwrap();
        fs::write(vk_file_uncompressed, vk_byptes_uncompressed).unwrap();
    }


    #[test]
    fn test_pk_vk_size() {
        let path = "./src/keys/receive/";
        let pk_file = format!("{}{}", path, PK_FILE.as_str());
        let vk_file = format!("{}{}", path, VK_FILE.as_str());
        let pk_file_uncompressed = format!("{}{}", path, PK_UNCOMP_FILE.as_str());
        let vk_file_uncompressed = format!("{}{}", path, VK_UNCOMP_FILE.as_str());

        let pk_bytes = fs::read(pk_file.as_str()).unwrap();
        let vk_bytes = fs::read(vk_file.as_str()).unwrap();
        let pk_bytes_uncompressed = fs::read(pk_file_uncompressed).unwrap();
        let vk_bytes_uncompressed = fs::read(vk_file_uncompressed).unwrap();

        println!("pk size: {}", pk_bytes.len());
        println!("vk size: {}", vk_bytes.len());
        println!("pk uncompressed size: {}", pk_bytes_uncompressed.len());
        println!("vk uncompressed size: {}", vk_bytes_uncompressed.len());
    }

    #[test]
    fn test_setup_and_proving_time() {
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
        let path = "../aegis_contract/result/";
        println!("Generate Receive circuit test input!");

        let test_input =
            <ReceiveCircuit<C, GG> as MockingCircuit<C, GG>>::generate_circuit(TREE_HEIGHT)
                .unwrap();

        println!("Generate CRS!");
        let (pk, vk) = {
            let c = test_input.clone();

            Groth16::<Bn254>::setup(c, &mut rng).unwrap()
        };

        let vk_for_smart_contract = MyVerifyingKey(vk.clone());
        save_json_to_file(&vk_for_smart_contract.to_string(), &format!("{}{}", path, "receive/receive.vk.json"));
        
        println!("Prepared verifying key!");
        let pvk = Groth16::<Bn254>::process_vk(&vk).unwrap();

        let mut image: Vec<_> = vec![
            *test_input.instance.apk.clone().unwrap().x().unwrap(),
            *test_input.instance.apk.clone().unwrap().y().unwrap(),
        ];
        image.append(&mut vec![
            test_input.instance.sn_v.clone().unwrap(),
            test_input.instance.sn_cur.clone().unwrap(),
            test_input.instance.cm_new.clone().unwrap(),
            test_input.instance.rt.clone().unwrap(),
            *test_input.instance.G_r.clone().unwrap().x().unwrap(),
            *test_input.instance.G_r.clone().unwrap().y().unwrap(),
            *test_input.instance.K_u.clone().unwrap().x().unwrap(),
            *test_input.instance.K_u.clone().unwrap().y().unwrap(),
            *test_input.instance.K_a.clone().unwrap().x().unwrap(),
            *test_input.instance.K_a.clone().unwrap().y().unwrap(),
        ]);
        image.append(&mut test_input.instance.CT.clone().unwrap());

        let mut data = vec![];
        for i in image.iter() {
            data.push(i.to_string());
        }

        let json_data =
            serde_json::to_string(&data).expect("벡터를 JSON으로 변환하는 데 실패했습니다.");

        // 파일에 저장
        let mut file = File::create(&format!("{}{}", path, "receive/receive.vk.json"))
            .expect("파일 생성에 실패했습니다.");
        file.write_all(json_data.as_bytes())
            .expect("파일에 JSON 데이터를 쓰는 데 실패했습니다.");

        let c = test_input.clone();

        println!("Generate proof!");
        let proof = Groth16::<Bn254>::prove(&pk, c.clone(), &mut rng).unwrap();

        let proof_for_smart_contract = MyProof(proof.clone());
        save_json_to_file(&proof_for_smart_contract.to_string(), &format!("{}{}", path, "receive/receive.proof.json"));
        
        let verifier_timer = start_timer!(|| "Groth16:Verifier");
        assert!(Groth16::<Bn254>::verify_with_processed_vk(&pvk, &image, &proof).unwrap());
        end_timer!(verifier_timer);
    }
}