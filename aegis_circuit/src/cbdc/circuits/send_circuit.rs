use crate::cbdc::circuits::import::*;

pub type ConstraintF<C> = <<C as CurveGroup>::BaseField as Field>::BasePrimeField;

#[allow(non_snake_case)]
#[derive(Clone)]
pub struct SendInstance<C: CurveGroup, GG: CurveVar<C, ConstraintF<C>>>
where 
    <C as CurveGroup>::BaseField: PrimeField + Absorb,
{
    pub sn_cur: Option<C::BaseField>,
    pub cm_new: Option<C::BaseField>,
    pub cm_v: Option<C::BaseField>,
    pub rt: Option<C::BaseField>,
    pub tag: Option<C::BaseField>,
    pub auth: Option<C::BaseField>,
    pub apk: Option<elgamal::PublicKey<C>>,
    pub ct_bar: Option<Vec<C::BaseField>>,
    pub g_r: Option<C::Affine>,
    pub k_a: Option<C::Affine>,
    _curve_var: PhantomData<GG>,
}


#[allow(non_snake_case)]
#[derive(Clone)]
pub struct SendWitness<C: CurveGroup, GG: CurveVar<C, ConstraintF<C>>>
where 
    <C as CurveGroup>::BaseField: PrimeField + Absorb,
{
    pub sk_snd: Option<C::BaseField>,
    pub pk_snd: Option<elgamal::PublicKey<C>>,
    pub addr_snd: Option<C::BaseField>,
    pub pk_rcv: Option<elgamal::PublicKey<C>>,
    pub v_cur: Option<C::BaseField>,
    pub v: Option<C::BaseField>,
    pub o_cur: Option<C::BaseField>,
    pub o_v: Option<C::BaseField>,
    pub o_new: Option<C::BaseField>,
    pub sn_new: Option<C::BaseField>,
    pub cm_cur: Option<C::BaseField>,
    pub leaf_pos: Option<u32>,
    pub tree_proof: Option<merkle_tree::Path<MerkleTreeParams<C::BaseField>>>,
    pub k: Option<elgamal::Plaintext<C>>,
    pub r: Option<elgamal::Randomness<C>>,
    pub k_point_x: Option<symmetric::SymmetricKey<C::BaseField>>,
    _curve_var: PhantomData<GG>,
}


#[allow(non_snake_case)]
#[derive(Clone)]
pub struct SendCircuit<C: CurveGroup, GG: CurveVar<C, ConstraintF<C>>>
where
    <C as CurveGroup>::BaseField: PrimeField + Absorb,
{
    // constant
    pub hash_params: PoseidonConfig<C::BaseField>,
    pub G: elgamal::Parameters<C>,
    
    pub instance: SendInstance<C, GG>,
    pub witness: SendWitness<C, GG>,
    _curve_var: PhantomData<GG>,
}


#[allow(non_snake_case)]
impl<C, GG> ConstraintSynthesizer<C::BaseField> for SendCircuit<C, GG>
where
    C: CurveGroup,
    GG: CurveVar<C, C::BaseField>,
    <C as CurveGroup>::BaseField: PrimeField + Absorb,
    for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
{
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<C::BaseField>,
    ) -> Result<(), SynthesisError> {
        //////////////////// constants //////////////////////////
        let hash_params =
            CRHParametersVar::<C::BaseField>::new_constant(cs.clone(), self.hash_params)?;
        let G = elgamal::constraints::ParametersVar::new_constant(
            ark_relations::ns!(cs, "generator"),
            self.G,
        )?;


        //////////////////// instance //////////////////////////
        let sn_cur = FpVar::new_input(ark_relations::ns!(cs, "sn_cur"), || {
            self.instance.sn_cur.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let cm_new = FpVar::new_input(ark_relations::ns!(cs, "cm_new"), || {
            self.instance.cm_new.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let cm_v = FpVar::new_input(ark_relations::ns!(cs, "cm_v"), || {
            self.instance.cm_v.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let rt = FpVar::new_input(cs.clone(), || {
            self.instance.rt.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let tag = FpVar::new_input(ark_relations::ns!(cs, "tag"), || {
            self.instance.tag.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let auth = FpVar::new_input(ark_relations::ns!(cs, "auth"), || {
            self.instance.auth.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let apk =
            elgamal::constraints::PublicKeyVar::new_input(ark_relations::ns!(cs, "apk"), || {
                self.instance.apk.ok_or(SynthesisError::AssignmentMissing)
            })?;
        let ct_bar =
            Vec::<FpVar<C::BaseField>>::new_input(ark_relations::ns!(cs, "ct_bar"), || {
                self.instance.ct_bar.ok_or(SynthesisError::AssignmentMissing)
            })?;
        let ct_bar = vec![
            CiphertextVar {
                c: ct_bar[0].clone(),
                r: FpVar::zero(),
            },
            CiphertextVar {
                c: ct_bar[1].clone(),
                r: FpVar::one(),
            },
            CiphertextVar {
                c: ct_bar[2].clone(),
                r: FpVar::one() + FpVar::one(),
            },
            CiphertextVar {
                c: ct_bar[3].clone(),
                r: FpVar::one() + FpVar::one() + FpVar::one(),
            },
            CiphertextVar {
                c: ct_bar[4].clone(),
                r: FpVar::one() + FpVar::one() + FpVar::one() + FpVar::one(),
            },
            CiphertextVar {
                c: ct_bar[5].clone(),
                r: FpVar::one() + FpVar::one() + FpVar::one() + FpVar::one() + FpVar::one(),
            },
        ];
        let g_r = GG::new_input(ark_relations::ns!(cs, "G_r"), || {
            self.instance.g_r.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let k_a = GG::new_input(ark_relations::ns!(cs, "K_a"), || {
            self.instance.k_a.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let k_a = elgamal::constraints::OutputVar {
            c1: g_r,
            c2: k_a,
            _curve: PhantomData,
        };


        //////////////////// witness //////////////////////////
        let sk_snd = FpVar::new_witness(ark_relations::ns!(cs, "sk_snd"), || {
            self.witness.sk_snd.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let pk_snd = elgamal::constraints::PublicKeyVar::new_witness(
            ark_relations::ns!(cs, "pk_snd"),
            || self.witness.pk_snd.ok_or(SynthesisError::AssignmentMissing),
        )?;
        let addr_snd = FpVar::new_witness(ark_relations::ns!(cs, "addr_snd"), || {
            self.witness.addr_snd.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let pk_rcv = elgamal::constraints::PublicKeyVar::new_witness(
            ark_relations::ns!(cs, "pk_rcv"),
            || self.witness.pk_rcv.ok_or(SynthesisError::AssignmentMissing),
        )?;
        let v_cur = FpVar::new_witness(ark_relations::ns!(cs, "v_cur"), || {
            self.witness.v_cur.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let v = FpVar::new_witness(ark_relations::ns!(cs, "v"), || {
            self.witness.v.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let o_cur = FpVar::new_witness(ark_relations::ns!(cs, "o_cur"), || {
            self.witness.o_cur.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let o_v = FpVar::new_witness(ark_relations::ns!(cs, "o_v"), || {
            self.witness.o_v.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let o_new = FpVar::new_witness(ark_relations::ns!(cs, "o_new"), || {
            self.witness.o_new.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let sn_new = FpVar::new_witness(ark_relations::ns!(cs, "sn_new"), || {
            self.witness.sn_new.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let cm_cur = FpVar::new_witness(ark_relations::ns!(cs, "cm_cur"), || {
            Ok(self.witness.cm_cur.unwrap())
        })
        .unwrap();

        let mut cw = merkle_tree::constraints::PathVar::<
            MerkleTreeParams<C::BaseField>,
            C::BaseField,
            MerkleTreeParamsVar<C::BaseField>,
        >::new_witness(ark_relations::ns!(cs, "cw"), || {
            self.witness.tree_proof.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let leaf_pos = UInt32::new_witness(ark_relations::ns!(cs, "leaf_pos"), || {
            self.witness.leaf_pos.ok_or(SynthesisError::AssignmentMissing)
        })?
        .to_bits_le();
        let r =
            elgamal::constraints::RandomnessVar::new_witness(ark_relations::ns!(cs, "r"), || {
                self.witness.r.ok_or(SynthesisError::AssignmentMissing)
            })?;
        let k: elgamal::constraints::PlaintextVar<C, GG> =
            elgamal::constraints::PlaintextVar::new_witness(ark_relations::ns!(cs, "k"), || {
                self.witness.k.ok_or(SynthesisError::AssignmentMissing)
            })?;
        let k_point_x = symmetric::constraints::SymmetricKeyVar::new_witness(
            ark_relations::ns!(cs, "k_point_x"),
            || self.witness.k_point_x.ok_or(SynthesisError::AssignmentMissing),
        )?;


        //////////////////// constraints //////////////////////////
        // 1. pk_snd = G^{sk_snd}
        let sk_snd_le_bits = sk_snd.to_bits_le().unwrap();
        let pk_snd_computed = G.generator.scalar_mul_le(sk_snd_le_bits.iter()).unwrap();
        pk_snd.pk.enforce_equal(&pk_snd_computed)?;

        // 2.addr_snd = H(pk_snd)
        let binding = pk_snd.clone().pk.to_bits_le()?;
        let pk_snd_point_x = Boolean::le_bits_to_fp_var(&binding[..binding.len() / 2])?;
        let pk_snd_point_y = Boolean::le_bits_to_fp_var(&binding[binding.len() / 2..])?;

        let hash_intput = vec![pk_snd_point_x, pk_snd_point_y];
        let addr_snd_computed =
            CRHGadget::<C::BaseField>::evaluate(&hash_params, &hash_intput).unwrap();
        addr_snd_computed.enforce_equal(&addr_snd)?;

        // 3. sn_cur = H(sk_snd, o_cur)
        let hash_input = [sk_snd.clone(), o_cur.clone()];
        let sn_cur_computed =
            CRHGadget::<C::BaseField>::evaluate(&hash_params, &hash_input).unwrap();
        sn_cur_computed.enforce_equal(&sn_cur)?;

        // 4. sn_new = H(sk_snd, o_new)
        let hash_input = [sk_snd.clone(), o_new.clone()];
        let sn_new_computed =
            CRHGadget::<C::BaseField>::evaluate(&hash_params, &hash_input).unwrap();
        sn_new_computed.enforce_equal(&sn_new)?;
        
        // 5. MT.Verify(cm_cur, path, rt)
        let leaf_g: Vec<_> = vec![cm_cur.clone()];

        cw.set_leaf_position(leaf_pos.clone());

        let path_check = cw
            .verify_membership(&hash_params.clone(), &hash_params.clone(), &rt, &leaf_g)
            .unwrap();
        path_check.enforce_equal(&Boolean::Constant(true))?;

        // 6. cm_cur = H(addr_snd, v_cur, sn_cur, o_cur)
        let hash_input = vec![
            addr_snd.clone(),
            v_cur.clone(),
            sn_cur.clone(),
            o_cur.clone(),
        ];
        let cm_cur_computed =
            CRHGadget::<C::BaseField>::evaluate(&hash_params, &hash_input).unwrap();
        cm_cur.enforce_equal(&cm_cur_computed)?;
        
        // 7. cm_new = H(addr_snd, v_cur - v, sn_new, o_new)
        let hash_input = vec![
            addr_snd.clone(),
            v_cur.clone() - v.clone(),
            sn_new.clone(),
            o_new.clone(),
        ];
        let cm_new_computed =
            CRHGadget::<C::BaseField>::evaluate(&hash_params, &hash_input).unwrap();
        cm_new.enforce_equal(&cm_new_computed)?;

        // 8. v_cur >= v >= 0
        let v_cur_minus_v = v_cur.clone() - v.clone();
        v_cur_minus_v.enforce_smaller_or_equal_than_mod_minus_one_div_two()?;
        v.enforce_smaller_or_equal_than_mod_minus_one_div_two()?;

        // 9. cm_v = H(addr_snd, v, pk_rcv, sn_new, o_v)
        let binding = pk_rcv.clone().pk.to_bits_le()?;
        let pk_rcv_point_x = Boolean::le_bits_to_fp_var(&binding[..binding.len() / 2])?;
        let pk_rcv_point_y = Boolean::le_bits_to_fp_var(&binding[binding.len() / 2..])?;

        let hash_input = vec![
            addr_snd.clone(),
            v.clone(),
            pk_rcv_point_x.clone(),
            pk_rcv_point_y.clone(),
            sn_cur.clone(),
            o_v.clone(),
        ];
        let cm_v_computed = CRHGadget::<C::BaseField>::evaluate(&hash_params, &hash_input).unwrap();
        cm_v.enforce_equal(&cm_v_computed)?;

        // 10. auth = H(sk_snd, tag)
        let hash_input = vec![sk_snd.clone(), tag.clone()];
        let auth_computed = CRHGadget::<C::BaseField>::evaluate(&hash_params, &hash_input).unwrap();
        auth_computed.enforce_equal(&auth)?;

        // 11. ct_bar = PEnc(apk, (addr_snd, v, o_v, sn_cur, pk_rcv))
        let k_a_computed =
            ElGamalEncGadget::<C, GG>::encrypt(&G.clone(), &k.clone(), &r, &apk).unwrap();
        k_a.enforce_equal(&k_a_computed)?;


        // check k == g(k_point_x, _k_point_y)
        let check_g_k_point_x = k.plaintext.to_bits_le()?;
        let check_g_k_point_x =
            Boolean::le_bits_to_fp_var(&check_g_k_point_x[..check_g_k_point_x.len() / 2])?;
        check_g_k_point_x.enforce_equal(&k_point_x.k)?;

        // check ct_bar
        let binding = pk_rcv.clone().pk.to_bits_le()?;
        let pk_rcv_point_x = Boolean::le_bits_to_fp_var(&binding[..binding.len() / 2])?;
        let pk_rcv_point_y = Boolean::le_bits_to_fp_var(&binding[binding.len() / 2..])?;

        let plain: Vec<FpVar<C::BaseField>> = vec![
            addr_snd.clone(),
            v.clone(),
            o_v.clone(),
            sn_cur.clone(),
            pk_rcv_point_x.clone(),
            pk_rcv_point_y.clone(),
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

            c.enforce_equal(&ct_bar[i])?;
        }

        Ok(())
    }
}

#[allow(non_snake_case)]
impl<C, GG> MockingCircuit<C, GG> for SendCircuit<C, GG>
where
    C: CurveGroup,
    GG: CurveVar<C, C::BaseField>,
    <C as CurveGroup>::BaseField: PrimeField + Absorb,
    for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
{
    type F = C::BaseField;
    type HashParam = PoseidonConfig<Self::F>;
    type H = CRH<Self::F>;
    type Output = SendCircuit<C, GG>;

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
        use ark_std::One;
        use ark_std::UniformRand;

        let mut rng = thread_rng();
        let generator = C::generator().into_affine();
        let hash_params = get_poseidon_params();
        let elgamal_param: elgamal::Parameters<C> = elgamal::Parameters {
            generator: generator.clone(),
        };

        let (pk_snd, sk_snd) = ElGamal::keygen(&elgamal_param, &mut rng).unwrap();
        let (apk, _) = ElGamal::keygen(&elgamal_param, &mut rng).unwrap();
        let (pk_rcv, _) = ElGamal::keygen(&elgamal_param, &mut rng).unwrap();

        let r = C::ScalarField::rand(&mut rng);
        let k = C::rand(&mut rng).into_affine();

        let o_cur = Self::F::rand(&mut rng);
        let o_new = Self::F::rand(&mut rng);
        let o_v = Self::F::rand(&mut rng);
        let v_cur: Self::F = Self::F::one() + Self::F::one() + Self::F::one() + Self::F::one();
        let v: Self::F = Self::F::one();

        // addr_snd
        let (pk_snd_point_x, pk_snd_point_y) = pk_snd.xy().unwrap();
        let addr_snd = Self::H::evaluate(
            &hash_params.clone(),
            vec![pk_snd_point_x.clone(), pk_snd_point_y.clone()],
        )
        .unwrap();

        // sn_cur
        let mut bytes = vec![];
        sk_snd.serialize_uncompressed(&mut bytes).unwrap();
        let sk_snd_basefield = Self::F::from_le_bytes_mod_order(&bytes);
        let sn_cur =
            Self::H::evaluate(&hash_params.clone(), vec![sk_snd_basefield.clone(), o_cur.clone()]).unwrap();

        // sn_new
        let sn_new =
            Self::H::evaluate(&hash_params.clone(), vec![sk_snd_basefield.clone(), o_new.clone()]).unwrap();

        // cm_cur
        let cm_cur = Self::H::evaluate(
            &hash_params.clone(),
            vec![
                addr_snd.clone(),
                v_cur.clone(),
                sn_cur.clone(),
                o_cur.clone(),
            ],
        )
        .unwrap();

        fn basefield_to_biguint<F: PrimeField>(f: F) -> BigUint {
            let mut bytes = vec![];
            f.serialize_uncompressed(&mut bytes).unwrap();
            BigUint::from_bytes_le(&bytes)
        }

        println!("cm_cur: {:?}", basefield_to_biguint(cm_cur));

        // cm_new
        let cm_new = Self::H::evaluate(
            &hash_params.clone(),
            vec![
                addr_snd.clone(),
                v_cur.clone() - v.clone(),
                sn_new.clone(),
                o_new.clone(),
            ],
        )
        .unwrap();

        // cm_v
        let (pk_rcv_point_x, pk_rcv_point_y) = pk_rcv.xy().unwrap();
        let cm_v = Self::H::evaluate(
            &hash_params.clone(),
            vec![
                addr_snd.clone(),
                v.clone(),
                pk_rcv_point_x.clone(),
                pk_rcv_point_y.clone(),
                sn_cur.clone(),
                o_v.clone(),
            ],
        )
        .unwrap();

        // merkle tree
        let leaf_crh_params = hash_params.clone();
        let two_to_one_params = leaf_crh_params.clone();

        let proof: merkle_tree::Path<MerkleTreeParams<Self::F>> =
            merkle_tree::mocking::get_mocking_merkle_tree(tree_height);
        let leaf: Self::F = cm_cur.clone();

        let rt = proof
            .get_test_root(&leaf_crh_params, &two_to_one_params, [leaf])
            .unwrap();
        println!("rt: {:?}", basefield_to_biguint(rt));
        let i: u32 = 0;
        assert!(proof
            .verify(&leaf_crh_params, &two_to_one_params, &rt, [leaf])
            .unwrap());

        // encryption symmetric key
        let random = elgamal::Randomness { 0: r };
        let (_, _) = ElGamal::encrypt(&elgamal_param, &pk_snd, &k, &random).unwrap();
        let (G_r_auth, K_a_auth) = ElGamal::encrypt(&elgamal_param, &apk, &k, &random).unwrap();

        let k_point_x = k.x().unwrap();
        let k_point_x = symmetric::SymmetricKey { k: *k_point_x };

        // ct_bar
        let mut ct_bar: Vec<_> = Vec::new();
        let plain = vec![
            addr_snd.clone(),
            v.clone(),
            o_v.clone(),
            sn_cur.clone(),
            pk_rcv_point_x.clone(),
            pk_rcv_point_y.clone(),
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

            ct_bar.push(c.c);
        });

        // ct
        let mut ct = vec![];
        let plain = vec![addr_snd.clone(), v.clone(), o_v.clone(), sn_cur.clone()];
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

            ct.push(c.c);
        });

        // tag
        let tag = Self::H::evaluate(&hash_params.clone(), ct.clone()).unwrap();
        println!("tag: {:?}", (tag.to_string()));

        // auth
        let auth =
            Self::H::evaluate(&hash_params.clone(), vec![sk_snd_basefield.clone(), tag.clone()]).unwrap();
        let mut data = vec![
            sn_cur.clone().to_string(),
            cm_new.clone().to_string(),
            cm_v.clone().to_string(),
            rt.clone().to_string(),
            auth.clone().to_string(),
            apk.clone().x().unwrap().clone().to_string(),
            apk.clone().y().unwrap().clone().to_string(),
        ];
        data.extend(ct_bar.clone().iter().map(|c| c.to_string())); // 7
        data.extend(vec![
            G_r_auth.clone().x().unwrap().clone().to_string(),
            G_r_auth.clone().y().unwrap().clone().to_string(),
            K_a_auth.clone().x().unwrap().clone().to_string(),
            K_a_auth.clone().y().unwrap().clone().to_string(),
        ]);
        data.extend(ct.clone().iter().map(|c| c.to_string())); // 11
        let json_data =
            serde_json::to_string(&data).expect("벡터를 JSON으로 변환하는 데 실패했습니다.");

        // 파일에 저장
        let mut file =
            File::create("../aegis_contract/result/send.input.json").expect("파일 생성에 실패했습니다.");
            
        file.write_all(json_data.as_bytes())
            .expect("파일에 JSON 데이터를 쓰는 데 실패했습니다.");

        let instance = SendInstance {
            sn_cur: Some(sn_cur),
            cm_new: Some(cm_new),
            cm_v: Some(cm_v),
            rt: Some(rt),
            ct_bar: Some(ct_bar),
            apk: Some(apk),
            tag: Some(tag),
            auth: Some(auth),
            g_r: Some(G_r_auth),
            k_a: Some(K_a_auth),
            _curve_var: PhantomData,
        };

        let witness = SendWitness {
            sk_snd: Some(sk_snd_basefield),
            pk_snd: Some(pk_snd),
            addr_snd: Some(addr_snd),
            pk_rcv: Some(pk_rcv),
            v_cur: Some(v_cur),
            v: Some(v),
            o_cur: Some(o_cur),
            o_v: Some(o_v),
            o_new: Some(o_new),
            sn_new: Some(sn_new),
            cm_cur: Some(cm_cur),
            leaf_pos: Some(i),
            tree_proof: Some(proof),
            k: Some(k),
            r: Some(random),
            k_point_x: Some(k_point_x),
            _curve_var: PhantomData,
        };
        
        Ok(SendCircuit {
            hash_params,
            G: elgamal_param,
            instance,
            witness,
            _curve_var: PhantomData,
        })
    }
}
