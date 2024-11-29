use crate::cbdc::circuits::import::*;
pub type ConstraintF<C> = <<C as CurveGroup>::BaseField as Field>::BasePrimeField;

#[allow(non_snake_case)]
#[derive(Clone)]
pub struct ReceiveInstance<C: CurveGroup, GG: CurveVar<C, ConstraintF<C>>>
where 
    <C as CurveGroup>::BaseField: PrimeField + Absorb,
{
    pub apk: Option<elgamal::PublicKey<C>>,
    pub sn_v: Option<C::BaseField>,
    pub sn_cur: Option<C::BaseField>,
    pub cm_new: Option<C::BaseField>,
    pub rt: Option<C::BaseField>,
    pub G_r: Option<C::Affine>, // CT
    pub K_u: Option<C::Affine>, // CT
    pub K_a: Option<C::Affine>, // CT
    _curve_var: PhantomData<GG>,
}


#[allow(non_snake_case)]
#[derive(Clone)]
pub struct ReceiveWitness<C: CurveGroup, GG: CurveVar<C, ConstraintF<C>>>
where 
    <C as CurveGroup>::BaseField: PrimeField + Absorb,
{
    pub pk_rcv: Option<elgamal::PublicKey<C>>,
    pub sk_rcv: Option<C::BaseField>,
    pub addr_snd: Option<C::BaseField>,
    pub addr_rcv: Option<C::BaseField>,
    pub v: Option<C::BaseField>,
    pub v_cur: Option<C::BaseField>,
    pub opening_v: Option<C::BaseField>,
    pub opening_cur: Option<C::BaseField>,
    pub opening_new: Option<C::BaseField>,
    pub sn_new: Option<C::BaseField>,
    pub cm_v: Option<C::BaseField>,
    pub cm_cur: Option<C::BaseField>,
    pub leaf_pos: Option<u32>,
    pub path: Option<merkle_tree::Path<MerkleTreeParams<C::BaseField>>>, // tree_proof
    pub CT: Option<Vec<C::BaseField>>,
    pub r: Option<elgamal::Randomness<C>>, // CT
    pub k: Option<elgamal::Plaintext<C>>,  // CT
    pub k_point_x: Option<symmetric::SymmetricKey<C::BaseField>>, // CT
    _curve_var: PhantomData<GG>,
}

#[allow(non_snake_case)]
#[derive(Clone)]
pub struct ReceiveCircuit<C: CurveGroup, GG: CurveVar<C, ConstraintF<C>>>
where
    <C as CurveGroup>::BaseField: PrimeField + Absorb,
{
    // constant
    pub hash_params: PoseidonConfig<C::BaseField>,
    pub G: elgamal::Parameters<C>,
    
    pub instance: ReceiveInstance<C, GG>,
    pub witness: ReceiveWitness<C, GG>,
    _curve_var: PhantomData<GG>,
}

#[allow(non_snake_case)]
impl<C, GG> ConstraintSynthesizer<C::BaseField> for ReceiveCircuit<C, GG>
where 
    C: CurveGroup,
    GG: CurveVar<C, C::BaseField>,
    <C as CurveGroup>::BaseField: PrimeField + Absorb,
    for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
{
    fn generate_constraints(self, cs: ConstraintSystemRef<C::BaseField>) -> ark_relations::r1cs::Result<()> {
        //////////////////// constants //////////////////////////
        let hash_params =
            CRHParametersVar::<C::BaseField>::new_constant(cs.clone(), self.hash_params)?;
        let G = ParametersVar::new_constant(
            ark_relations::ns!(cs, "generator"),
            self.G,
        )?;


        //////////////////// instance //////////////////////////
        let apk =
            PublicKeyVar::new_input(ark_relations::ns!(cs, "apk"), || {
                self.instance.apk.ok_or(SynthesisError::AssignmentMissing)
            })?;

        let sn_v = FpVar::new_input(ark_relations::ns!(cs, "sn_v"), || {
            self.instance.sn_v.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let sn_cur = FpVar::new_input(ark_relations::ns!(cs, "sn_cur"), || {
            self.instance.sn_cur.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let cm_new = FpVar::new_input(ark_relations::ns!(cs, "cm_new"), || {
            Ok(self.instance.cm_new.unwrap())
        })
        .unwrap();

        let rt = FpVar::new_input(cs.clone(), || {
            self.instance.rt.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let K_u = OutputVar::new_input(ark_relations::ns!(cs, "K_u"), || {
            Ok((self.instance.G_r.unwrap(), self.instance.K_u.unwrap()))
        })
        .unwrap();

        let K_a = GG::new_input(ark_relations::ns!(cs, "K_a"), || {
            self.instance.K_a.ok_or(SynthesisError::AssignmentMissing)
        })?;


        //////////////////// witness //////////////////////////
        let pk_rcv = PublicKeyVar::new_witness(
            ark_relations::ns!(cs, "pk_rcv"),
            || self.witness.pk_rcv.ok_or(SynthesisError::AssignmentMissing),
        )?;

        let sk_rcv = FpVar::new_witness(ark_relations::ns!(cs, "sk_rcv"), || {
            self.witness.sk_rcv.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let addr_snd = FpVar::new_witness(ark_relations::ns!(cs, "addr_snd"), || {
            self.witness.addr_snd.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let addr_rcv = FpVar::new_witness(ark_relations::ns!(cs, "addr_rcv"), || {
            self.witness.addr_rcv.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let v = FpVar::new_witness(cs.clone(), || {
            self.witness.v.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let v_cur = FpVar::new_witness(cs.clone(), || {
            self.witness.v_cur.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let opening_v = FpVar::new_witness(ark_relations::ns!(cs, "opening_v"), || {
            self.witness.opening_v.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let opening_cur = FpVar::new_witness(ark_relations::ns!(cs, "opening_cur"), || {
            self.witness.opening_cur.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let opening_new = FpVar::new_witness(ark_relations::ns!(cs, "opening_new"), || {
            self.witness.opening_new.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let sn_new = FpVar::new_witness(ark_relations::ns!(cs, "sn_new"), || {
            self.witness.sn_new.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let cm_v =
            FpVar::new_witness(ark_relations::ns!(cs, "cm_v"), || Ok(self.witness.cm_v.unwrap())).unwrap();

        let cm_cur = FpVar::new_witness(ark_relations::ns!(cs, "cm_cur"), || {
            Ok(self.witness.cm_cur.unwrap())
        })
        .unwrap();

        let mut path = merkle_tree::constraints::PathVar::<
            MerkleTreeParams<C::BaseField>,
            C::BaseField,
            MerkleTreeParamsVar<C::BaseField>,
        >::new_witness(ark_relations::ns!(cs, "path"), || {
            self.witness.path.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let leaf_pos = UInt32::new_witness(ark_relations::ns!(cs, "leaf_pos"), || {
            self.witness.leaf_pos.ok_or(SynthesisError::AssignmentMissing)
        })?
        .to_bits_le();

        let r =
            RandomnessVar::new_witness(ark_relations::ns!(cs, "r"), || {
                self.witness.r.ok_or(SynthesisError::AssignmentMissing)
            })?;

        let k: PlaintextVar<C, GG> =
            PlaintextVar::new_witness(ark_relations::ns!(cs, "k"), || {
                self.witness.k.ok_or(SynthesisError::AssignmentMissing)
            })?;

        let k_point_x = SymmetricKeyVar::new_witness(
            ark_relations::ns!(cs, "k_point_x"),
            || self.witness.k_point_x.ok_or(SynthesisError::AssignmentMissing),
        )?;

        
        //////////////////// constraints //////////////////////////
        // 1번 확인
        let binding = pk_rcv.clone().pk.to_bits_le()?;
        let pk_enc_recv_point_x = Boolean::le_bits_to_fp_var(&binding[..binding.len() / 2])?;
        let pk_enc_recv_point_y = Boolean::le_bits_to_fp_var(&binding[binding.len() / 2..])?;

        let hash_input = [
            addr_snd.clone(),
            v.clone(),
            opening_v.clone(),
            pk_enc_recv_point_x.clone(),
            pk_enc_recv_point_y.clone(),
            sn_cur.clone(),
        ]
        .to_vec();
        let result_cm_v = CRHGadget::<C::BaseField>::evaluate(&hash_params, &hash_input).unwrap();
        cm_v.enforce_equal(&result_cm_v).unwrap();

        // 2번 확인
        let hash_input_sn_v = [opening_v.clone(), sk_rcv.clone()].to_vec();
        let result_sn_v = CRHGadget::<C::BaseField>::evaluate(&hash_params, &hash_input_sn_v).unwrap();
        sn_v.enforce_equal(&result_sn_v)?;

        // 3,4번 확인
        let leaf: Vec<_> = vec![cm_v.clone(), cm_cur.clone()];
        path.set_leaf_position(leaf_pos.clone());

        let path_check = path
            .verify_membership(&hash_params.clone(), &hash_params.clone(), &rt, &leaf)
            .unwrap();

        path_check.enforce_equal(&Boolean::Constant(true))?;

        // 5번 확인
        let max_bytes: [u8; 8] = (std::u64::MAX - 1).to_le_bytes();
        let result_sum = v.clone() + v_cur.clone();
        let constant_max = <C::BaseField as PrimeField>::from_le_bytes_mod_order(&max_bytes);
        Boolean::enforce_smaller_or_equal_than_le(
            result_sum.to_non_unique_bits_le().unwrap().as_slice(),
            constant_max.into_bigint(),
        )?;

        // 6번 확인
        let hash_input_sn_cur = [opening_cur.clone(), sk_rcv.clone()].to_vec();
        let result_sn_cur = CRHGadget::<C::BaseField>::evaluate(&hash_params, &hash_input_sn_cur).unwrap();
        sn_cur.enforce_equal(&result_sn_cur)?;

        // 7번 확인
        let hash_input_sn_new = [sn_cur.clone(), sk_rcv.clone()].to_vec();
        let result_sn_new = CRHGadget::<C::BaseField>::evaluate(&hash_params, &hash_input_sn_new).unwrap();
        sn_new.enforce_equal(&result_sn_new)?;

        // 8번 확인
        let hash_input_opening_new = [opening_cur.clone(), sk_rcv.clone()].to_vec();
        let result_opening_new =
            CRHGadget::<C::BaseField>::evaluate(&hash_params, &hash_input_opening_new).unwrap();
        opening_new.enforce_equal(&result_opening_new)?;

        // 9번 확인
        let binding = pk_rcv.clone().pk.to_bits_le()?;
        let pk_enc_recv_point_x = Boolean::le_bits_to_fp_var(&binding[..binding.len() / 2])?;
        let pk_enc_recv_point_y = Boolean::le_bits_to_fp_var(&binding[binding.len() / 2..])?;

        let hash_input = [
            addr_rcv.clone(),
            v.clone() + v_cur.clone(),
            opening_new.clone(),
            pk_enc_recv_point_x.clone(),
            pk_enc_recv_point_y.clone(),
            sn_new.clone(),
        ]
        .to_vec();
        let result_cm_new = CRHGadget::<C::BaseField>::evaluate(&hash_params, &hash_input).unwrap();
        cm_new.enforce_equal(&result_cm_new).unwrap();

        // 10번 확인
        let K_a = OutputVar {
            c1: K_u.clone().c1,
            c2: K_a,
            _curve: PhantomData,
        };

        let result_K_u =
            ElGamalEncGadget::<C, GG>::encrypt(&G.clone(), &k.clone(), &r, &pk_rcv).unwrap();
        let result_K_a =
            ElGamalEncGadget::<C, GG>::encrypt(&G.clone(), &k.clone(), &r, &apk).unwrap();
        K_u.enforce_equal(&result_K_u)?;
        K_a.enforce_equal(&result_K_a)?;

        // CT
        let CT: Vec<FpVar<C::BaseField>> = Vec::new_input(ark_relations::ns!(cs, "CT"), || {
            self.witness.CT.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let CT = vec![
            symmetric::constraints::CiphertextVar {
                c: CT[0].clone(),
                r: FpVar::zero(),
            },
            symmetric::constraints::CiphertextVar {
                c: CT[1].clone(),
                r: FpVar::one(),
            },
            symmetric::constraints::CiphertextVar {
                c: CT[2].clone(),
                r: FpVar::one() + FpVar::one(),
            },
            symmetric::constraints::CiphertextVar {
                c: CT[3].clone(),
                r: FpVar::one() + FpVar::one() + FpVar::one(),
            },
            symmetric::constraints::CiphertextVar {
                c: CT[4].clone(),
                r: FpVar::one() + FpVar::one() + FpVar::one() + FpVar::one(),
            },
            symmetric::constraints::CiphertextVar {
                c: CT[5].clone(),
                r: FpVar::one() + FpVar::one() + FpVar::one() + FpVar::one() + FpVar::one(),
            },
        ];

        let plain: Vec<FpVar<C::BaseField>> = vec![
            addr_snd.clone(),
            v.clone(),
            opening_v.clone(),
            sn_cur.clone(),
            pk_enc_recv_point_x.clone(),
            pk_enc_recv_point_y.clone(),
        ];
        for (i, m) in plain.iter().enumerate() {
            let randomness = symmetric::constraints::RandomnessVar::new_constant(
                ark_relations::ns!(cs, "randomness"),
                symmetric::Randomness {
                    r: C::BaseField::from_bigint((i as u64).into()).unwrap(),
                },
            )?;

            let c = SymmetricEncryptionSchemeGadget::<C::BaseField>::encrypt(
                hash_params.clone(),
                randomness,
                k_point_x.clone(),
                symmetric::constraints::PlaintextVar { m: m.clone() },
            )
            .unwrap();

            c.enforce_equal(&CT[i])?;
        }
        Ok(())
    }
}

#[allow(non_snake_case)]
impl<C, GG> MockingCircuit<C, GG> for ReceiveCircuit<C, GG>
where
    C: CurveGroup,
    GG: CurveVar<C, C::BaseField>,
    <C as CurveGroup>::BaseField: PrimeField + Absorb,
    for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
{
    type F = C::BaseField;
    type HashParam = PoseidonConfig<Self::F>;
    type H = CRH<Self::F>;
    type Output = ReceiveCircuit<C, GG>;
    
    fn generate_circuit(tree_height: u64) -> Result<Self::Output, crate::Error> {
        use ark_crypto_primitives::{
            crh::CRHScheme,
            encryption::{elgamal::ElGamal, AsymmetricEncryptionScheme},
        };
        
        use crate::gadget::{
            symmetric_encrytions::SymmetricEncryption,
            merkle_tree::mocking::MockingMerkleTree,
        };

        use ark_ec::AffineRepr;
        use ark_std::{
            One, UniformRand,
            rand::{RngCore, SeedableRng},
            test_rng,
        };

        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
        let generator = C::generator().into_affine();
        let hash_params = get_poseidon_params();
        let elgamal_param: elgamal::Parameters<C> = elgamal::Parameters {
            generator: generator.clone(),
        };

        let (apk, _) = ElGamal::keygen(&elgamal_param, &mut rng).unwrap();
        // receiver pk, sk
        let (pk_snd, _) = ElGamal::keygen(&elgamal_param, &mut rng).unwrap();
        let (pk_rcv, sk_rcv) = ElGamal::keygen(&elgamal_param, &mut rng).unwrap();

        let (pk_enc_send_point_x, pk_enc_send_point_y) = pk_snd.xy().unwrap();
        let (pk_enc_recv_point_x, pk_enc_recv_point_y) = pk_rcv.xy().unwrap();

        let mut bytes = vec![];
        sk_rcv.serialize_uncompressed(&mut bytes).unwrap();
        let sk_rcv = Self::F::from_le_bytes_mod_order(&bytes);

        let r = C::ScalarField::rand(&mut rng);
        let random = elgamal::Randomness { 0: r };
        let k = C::rand(&mut rng).into_affine();

        // value of amount
        let v: Self::F = Self::F::one();
        let v_cur: Self::F = Self::F::one();

        // generate random key and opening
        let opening_v = Self::F::rand(&mut rng);
        let opening_cur = Self::F::rand(&mut rng);
        let opening_new =
            Self::H::evaluate(&hash_params.clone(), [opening_cur.clone(), sk_rcv.clone()].to_vec()).unwrap();

        // sn -> PRF using mimc
        let sn_v =
            Self::H::evaluate(&hash_params.clone(), [opening_v.clone(), sk_rcv.clone()].to_vec()).unwrap();
        let sn_cur =
            Self::H::evaluate(&hash_params.clone(), [opening_cur.clone(), sk_rcv.clone()].to_vec()).unwrap();
        let sn_new =
            Self::H::evaluate(&hash_params.clone(), [sn_cur.clone(), sk_rcv.clone()].to_vec()).unwrap();

        // addr_snd, addr_rcv
        let k_b = Self::H::evaluate(&hash_params.clone(), [sk_rcv.clone()].to_vec()).unwrap();
        let k_b_ = Self::H::evaluate(&hash_params.clone(), [Self::F::rand(&mut rng)].to_vec()).unwrap();
        let addr_snd = Self::H::evaluate(
            &hash_params.clone(),
            [
                k_b.clone(),
                pk_enc_send_point_x.clone(),
                pk_enc_send_point_y.clone(),
            ]
            .to_vec(),
        )
        .unwrap();

        let addr_rcv = Self::H::evaluate(
            &hash_params.clone(),
            [
                k_b_.clone(),
                pk_enc_recv_point_x.clone(),
                pk_enc_recv_point_y.clone(),
            ]
            .to_vec(),
        )
        .unwrap();

        // cm_v
        let cm_v = Self::H::evaluate(
            &hash_params.clone(),
            [
                addr_snd.clone(),
                v.clone(),
                opening_v.clone(),
                pk_enc_recv_point_x.clone(),
                pk_enc_recv_point_y.clone(),
                sn_cur.clone(),
            ]
            .to_vec(),
        )
        .unwrap();

        // cm_new
        let cm_new = Self::H::evaluate(
            &hash_params.clone(),
            [
                addr_rcv.clone(),
                v.clone() + v_cur.clone(),
                opening_new.clone(),
                pk_enc_recv_point_x.clone(),
                pk_enc_recv_point_y.clone(),
                sn_new.clone(),
            ]
            .to_vec(),
        )
        .unwrap();

        // cm_cur
        let cm_cur = Self::H::evaluate(
            &hash_params.clone(),
            [
                addr_rcv.clone(),
                v_cur.clone(),
                opening_cur.clone(),
                pk_enc_recv_point_x.clone(),
                pk_enc_recv_point_y.clone(),
                sn_cur.clone(),
            ]
            .to_vec(),
        )
        .unwrap();

        // CT
        let (_, K_u) = ElGamal::encrypt(&elgamal_param, &pk_rcv, &k, &random).unwrap(); // pk_rcv -> k_u
        let (G_r, K_a) = ElGamal::encrypt(&elgamal_param, &apk, &k, &random).unwrap();

        let k_point_x = k.x().unwrap();
        let k_point_x = symmetric::SymmetricKey { k: *k_point_x };

        let mut CT: Vec<_> = Vec::new();

        let plain = vec![
            addr_snd.clone(),
            v.clone(),
            opening_v.clone(),
            sn_cur.clone(),
            pk_enc_recv_point_x.clone(),
            pk_enc_recv_point_y.clone(),
        ];

        plain.iter().enumerate().for_each(|(i, m)| {
            let random = symmetric::Randomness {
                r: Self::F::from_bigint((i as u64).into()).unwrap(),
            };
            let c = symmetric::SymmetricEncryptionScheme::encrypt(
                hash_params.clone(),
                random,
                k_point_x.clone(),
                symmetric::Plaintext { m: m.clone() },
            )
            .unwrap();

            CT.push(c.c);
        });

        // merkle tree for cm_v
        println!("generate mocking tree");
        let leaf_crh_params = hash_params.clone();
        let two_to_one_params = leaf_crh_params.clone();

        let path: merkle_tree::Path<MerkleTreeParams<Self::F>> =
            merkle_tree::mocking::get_mocking_merkle_tree(tree_height);
        let i: u32 = 0;

        let rt = path
            .get_test_root(
                &leaf_crh_params,
                &two_to_one_params,
                [cm_v.clone(), cm_cur.clone()],
            )
            .unwrap();

        assert!(path
            .verify(
                &leaf_crh_params,
                &two_to_one_params,
                &rt,
                [cm_v.clone(), cm_cur.clone()]
            )
            .unwrap());

        println!("root: {:?}", rt.to_string());
        println!("cm_v: {:?}", cm_v.to_string());
        println!("cm_new: {:?}", cm_cur.to_string());
        println!("sn_cur: {:?}", sn_cur.to_string());
        println!("sn_v: {:?}", sn_v.to_string());

        // let mut data = vec![
        //     apk.clone(),
        //     sn_v.clone(),
        //     sn_cur.clone(),
        //     cm_new.clone(),
        //     rt.clone(),
        //     G_r.clone(),
        //     K_u.clone(),
        //     K_a.clone(),
        // ];

        let data = vec![
            apk.clone().x().unwrap().clone().to_string(),
            apk.clone().y().unwrap().clone().to_string(),
            sn_v.clone().to_string(),
            sn_cur.clone().to_string(),
            cm_new.clone().to_string(),
            rt.clone().to_string(),
            G_r.clone().x().unwrap().clone().to_string(),
            G_r.clone().y().unwrap().clone().to_string(),
            K_u.clone().x().unwrap().clone().to_string(),
            K_u.clone().y().unwrap().clone().to_string(),
            K_a.clone().x().unwrap().clone().to_string(),
            K_a.clone().y().unwrap().clone().to_string(),
        ];

        // 파일에 저장
        let json_data =
            serde_json::to_string(&data).expect("벡터를 JSON으로 변환하는 데 실패했습니다.");

        let mut file =
            File::create("../aegis_contract/result/receive.input.json").expect("파일 생성에 실패했습니다.");
            
        file.write_all(json_data.as_bytes())
            .expect("파일에 JSON 데이터를 쓰는 데 실패했습니다.");

        let instance = ReceiveInstance {
            apk: Some(apk),
            sn_v: Some(sn_v),
            sn_cur: Some(sn_cur),
            cm_new: Some(cm_new),
            rt: Some(rt),
            G_r: Some(G_r),
            K_u: Some(K_u),
            K_a: Some(K_a),
            _curve_var: PhantomData,
        };

        let witness = ReceiveWitness {
            pk_rcv: Some(pk_rcv), 
            sk_rcv: Some(sk_rcv),
            addr_snd: Some(addr_snd),
            addr_rcv: Some(addr_rcv),
            v: Some(v),
            v_cur: Some(v_cur),
            opening_v: Some(opening_v),
            opening_cur: Some(opening_cur),
            opening_new: Some(opening_new),
            sn_new: Some(sn_new),
            cm_v: Some(cm_v),
            cm_cur: Some(cm_cur),
            leaf_pos: Some(i),
            path: Some(path),
            CT: Some(CT),
            r: Some(random),                      // CT
            k: Some(k),                           // CT
            k_point_x: Some(k_point_x),           // CT
            _curve_var: PhantomData, // phantom
        };

        Ok(ReceiveCircuit {
            hash_params,
            G: elgamal_param,
            instance,
            witness,
            _curve_var: PhantomData,
        })
    }
}
