use crate::cbdc::circuits::import::*;
use ark_std::Zero;
pub type ConstraintF<C> = <<C as CurveGroup>::BaseField as Field>::BasePrimeField;

#[allow(non_snake_case)]
#[derive(Clone)]
pub struct RegisterInstance<C: CurveGroup> {
    pub cm: Option<C::BaseField>,
    pub ct_bar: Option<Vec<C::BaseField>>,
    pub apk: Option<elgamal::PublicKey<C>>,
    pub g_r: Option<C::Affine>,
    pub k_a: Option<C::Affine>,
}

#[derive(Clone)]
pub struct RegisterWitness<C: CurveGroup>
where
    C::BaseField: PrimeField,
{
    pub sk: Option<C::BaseField>,
    pub pk: Option<elgamal::PublicKey<C>>,
    pub addr: Option<C::BaseField>,
    pub v: Option<C::BaseField>,
    pub sn: Option<C::BaseField>,
    pub o: Option<C::BaseField>,
    pub k: Option<elgamal::Plaintext<C>>,
    pub r: Option<elgamal::Randomness<C>>,
    pub k_x: Option<symmetric::SymmetricKey<C::BaseField>>,
}

#[allow(non_snake_case)]
#[derive(Clone)]
pub struct RegisterCircuit<C: CurveGroup, GG: CurveVar<C, ConstraintF<C>>>
where
    <C as CurveGroup>::BaseField: PrimeField + Absorb,
{
    // constant
    pub hash_params: PoseidonConfig<C::BaseField>,
    pub G: elgamal::Parameters<C>,

    pub instance: RegisterInstance<C>,
    pub witness: RegisterWitness<C>,
    _curve_var: PhantomData<GG>,
}

#[allow(non_snake_case)]
impl<C, GG> ConstraintSynthesizer<C::BaseField> for RegisterCircuit<C, GG>
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
        //////////////////// constants //////////////////////////
        let hash_params =
            CRHParametersVar::<C::BaseField>::new_constant(cs.clone(), self.hash_params)?;
        let G = elgamal::constraints::ParametersVar::new_constant(
            ark_relations::ns!(cs, "generator"),
            self.G,
        )?;
        let zero = FpVar::<C::BaseField>::Constant(C::BaseField::zero());

        
        //////////////////// instance //////////////////////////
        let cm = FpVar::<C::BaseField>::new_input(cs.clone(), || {
            self.instance.cm.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let ct_bar = Vec::<FpVar<C::BaseField>>::new_input(cs.clone(), || {
            self.instance
                .ct_bar
                .ok_or(SynthesisError::AssignmentMissing)
        })?;
        let ct_bar = vec![
            symmetric::constraints::CiphertextVar {
                c: ct_bar[0].clone(),
                r: FpVar::zero(),
            },
            symmetric::constraints::CiphertextVar {
                c: ct_bar[1].clone(),
                r: FpVar::one(),
            },
            symmetric::constraints::CiphertextVar {
                c: ct_bar[2].clone(),
                r: FpVar::one() + FpVar::one(),
            },
            symmetric::constraints::CiphertextVar {
                c: ct_bar[3].clone(),
                r: FpVar::one() + FpVar::one() + FpVar::one(),
            },
            symmetric::constraints::CiphertextVar {
                c: ct_bar[4].clone(),
                r: FpVar::one() + FpVar::one() + FpVar::one() + FpVar::one(),
            },
            symmetric::constraints::CiphertextVar {
                c: ct_bar[5].clone(),
                r: FpVar::one() + FpVar::one() + FpVar::one() + FpVar::one() + FpVar::one(),
            },
            symmetric::constraints::CiphertextVar {
                c: ct_bar[6].clone(),
                r: FpVar::one()
                    + FpVar::one()
                    + FpVar::one()
                    + FpVar::one()
                    + FpVar::one()
                    + FpVar::one(),
            },
        ];
        let apk = PublicKeyVar::new_input(cs.clone(), || {
            self.instance.apk.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let g_r = GG::new_input(cs.clone(), || {
            self.instance.g_r.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let k_a = GG::new_input(cs.clone(), || {
            self.instance.k_a.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let k_a = OutputVar {
            c1: g_r,
            c2: k_a,
            _curve: PhantomData,
        };


        //////////////////// witness //////////////////////////
        let sk = FpVar::<C::BaseField>::new_witness(cs.clone(), || {
            self.witness.sk.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let pk = PublicKeyVar::new_witness(cs.clone(), || {
            self.witness.pk.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let addr = FpVar::<C::BaseField>::new_witness(cs.clone(), || {
            self.witness.addr.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let v = FpVar::<C::BaseField>::new_witness(cs.clone(), || {
            self.witness.v.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let sn = FpVar::<C::BaseField>::new_witness(cs.clone(), || {
            self.witness.sn.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let o = FpVar::<C::BaseField>::new_witness(cs.clone(), || {
            self.witness.o.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let r = RandomnessVar::new_witness(cs.clone(), || {
            self.witness.r.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let k = PlaintextVar::new_witness(cs.clone(), || {
            self.witness.k.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let k_x = SymmetricKeyVar::new_witness(cs.clone(), || {
            self.witness.k_x.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let check_g_k_x = k.plaintext.to_bits_le()?;
        let check_g_k_x = Boolean::le_bits_to_fp_var(&check_g_k_x[..check_g_k_x.len() / 2])?;
        check_g_k_x.enforce_equal(&k_x.k)?;


        //////////////////// constraints //////////////////////////
        // 1. (pk, sk) is well-formed => pk = g^sk
        let sk_bits = sk.to_non_unique_bits_le()?;
        let pk_computed = G.generator.scalar_mul_le(sk_bits.iter())?;
        pk.pk.enforce_equal(&pk_computed)?;

        // 2. addr = CRH(pk)
        let pk_bits = pk.clone().pk.to_bits_le()?;
        let pk_x = Boolean::le_bits_to_fp_var(&pk_bits[..pk_bits.len() / 2])?;
        let pk_y = Boolean::le_bits_to_fp_var(&pk_bits[pk_bits.len() / 2..])?;

        let hash_input = vec![pk_x.clone(), pk_y.clone()];
        let addr_computed = CRHGadget::<C::BaseField>::evaluate(&hash_params, &hash_input).unwrap();
        addr_computed.enforce_equal(&addr)?;

        // 3. v = 0
        v.enforce_equal(&zero)?;

        // 4. sn = PRF(sk, o)
        let hash_input = [sk.clone(), o.clone()];
        let sn_computed = CRHGadget::<C::BaseField>::evaluate(&hash_params, &hash_input).unwrap();
        sn_computed.enforce_equal(&sn)?;

        // 5. cm = COM(addr, v, sn, o) = CRH(addr, v, sn, o)
        let hash_input = vec![addr.clone(), v.clone(), sn.clone(), o.clone()];
        let cm_computed = CRHGadget::<C::BaseField>::evaluate(&hash_params, &hash_input).unwrap();
        cm_computed.enforce_equal(&cm)?;

        // 6. ct_bar = Elgamal.Enc_apk(pk, cm, addr, v, sn, o)
        let k_a_computed = ElGamalEncGadget::<C, GG>::encrypt(&G, &k, &r, &apk).unwrap();
        k_a.enforce_equal(&k_a_computed)?;

        let plain = vec![pk_x, pk_y, cm, addr, v, sn, o];

        for (i, m) in plain.iter().enumerate() {
            let randomness = symmetric::constraints::RandomnessVar::new_constant(
                cs.clone(),
                Randomness {
                    r: C::BaseField::from_bigint((i as u64).into()).unwrap(),
                },
            )?;

            let c = SymmetricEncryptionSchemeGadget::<C::BaseField>::encrypt(
                hash_params.clone(),
                randomness,
                k_x.clone(),
                symmetric::constraints::PlaintextVar { m: m.clone() },
            )
            .unwrap();

            c.enforce_equal(&ct_bar[i])?;
        }

        Ok(())
    }
}

#[allow(non_snake_case)]
impl<C, GG> MockingCircuit<C, GG> for RegisterCircuit<C, GG>
where
    C: CurveGroup,
    GG: CurveVar<C, C::BaseField>,
    <C as CurveGroup>::BaseField: PrimeField + Absorb,
    for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
{
    type F = C::BaseField;
    type HashParam = PoseidonConfig<Self::F>;
    type H = CRH<Self::F>;
    type Output = RegisterCircuit<C, GG>;
    
    fn generate_circuit(tree_height: u64) -> Result<Self::Output, crate::Error> {
        use ark_crypto_primitives::{
            crh::CRHScheme,
            encryption::{elgamal::ElGamal, AsymmetricEncryptionScheme},
        };
        
        use crate::gadget::symmetric_encrytions::SymmetricEncryption;

        use ark_ec::AffineRepr;
        use ark_std::{
            UniformRand,
            rand::{RngCore, SeedableRng},
            test_rng,
        };

        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
        let generator = C::rand(&mut rng).into();
        let hash_params = get_poseidon_params();
        let elgamal_param: elgamal::Parameters<C> = elgamal::Parameters {
            generator: generator.clone(),
        };

        let _ = tree_height;
        let (pk, sk): (elgamal::PublicKey<C>, elgamal::SecretKey<C>) =
            ElGamal::keygen(&elgamal_param, &mut rng).unwrap();
        let (apk, _) = ElGamal::keygen(&elgamal_param, &mut rng).unwrap();

        // randomness for encryption
        let r = C::ScalarField::rand(&mut rng);
        let k = C::rand(&mut rng).into_affine();

        let (pk_x, pk_y) = pk.xy().unwrap();
        let addr = Self::H::evaluate(&hash_params, vec![pk_x.clone(), pk_y.clone()]).unwrap();

        let v = Self::F::zero();

        let o = Self::F::rand(&mut rng);

        let mut bytes = vec![];
        sk.serialize_uncompressed(&mut bytes)?;
        let sk_base = Self::F::from_le_bytes_mod_order(&bytes);
        let hash_input = vec![sk_base.clone(), o.clone()];
        let sn = Self::H::evaluate(&hash_params.clone(), hash_input).unwrap();

        let cm =
            Self::H::evaluate(&hash_params, vec![addr.clone(), v.clone(), sn.clone(), o.clone()]).unwrap();

        fn basefield_to_biguint<F: PrimeField>(f: F) -> BigUint {
            let mut bytes = vec![];
            f.serialize_uncompressed(&mut bytes).unwrap();
            BigUint::from_bytes_le(&bytes)
        }

        println!("cm_cur: {:?}", basefield_to_biguint(cm));

        // encryption symmetric key
        let randomness = elgamal::Randomness { 0: r };
        let (_, _) = ElGamal::encrypt(&elgamal_param, &pk, &k, &randomness).unwrap();
        let (g_r, k_a) = ElGamal::encrypt(&elgamal_param, &apk, &k, &randomness).unwrap();
        let k_x = k.x().unwrap();
        let k_x = symmetric::SymmetricKey { k: *k_x };

        // ct_bar: ElGamal.Enc_apk(pk, cm, addr, v, sn, o)
        let mut ct_bar = vec![];
        let plain = vec![
            pk_x.clone(),
            pk_y.clone(),
            cm.clone(),
            addr.clone(),
            v.clone(),
            sn.clone(),
            o.clone(),
        ];

        plain.iter().enumerate().for_each(|(i, m)| {
            let random = symmetric::Randomness {
                r: Self::F::from_bigint((i as u64).into()).unwrap(),
            };
            let c = symmetric::SymmetricEncryptionScheme::encrypt(
                hash_params.clone(),
                random,
                k_x.clone(),
                symmetric::Plaintext { m: m.clone() },
            )
            .unwrap();

            ct_bar.push(c.c);
        });

        let data = vec![
            cm.clone().to_string(),
            ct_bar[0].clone().to_string(),
            ct_bar[1].clone().to_string(),
            ct_bar[2].clone().to_string(),
            ct_bar[3].clone().to_string(),
            ct_bar[4].clone().to_string(),
            ct_bar[5].clone().to_string(),
            ct_bar[6].clone().to_string(),
            apk.clone().x().unwrap().clone().to_string(),
            apk.clone().y().unwrap().clone().to_string(),
            g_r.clone().x().unwrap().clone().to_string(),
            g_r.clone().y().unwrap().clone().to_string(),
            k_a.clone().x().unwrap().clone().to_string(),
            k_a.clone().y().unwrap().clone().to_string(),
        ];

        let json_data =
            serde_json::to_string(&data).expect("벡터를 JSON으로 변환하는 데 실패했습니다.");

        // 파일에 저장
        let mut file = File::create("../aegis_contract/result/register.input.json").expect("파일 생성에 실패했습니다.");
        file.write_all(json_data.as_bytes())
            .expect("파일에 JSON 데이터를 쓰는 데 실패했습니다.");

        let instance = RegisterInstance {
            cm: Some(cm),
            ct_bar: Some(ct_bar),
            apk: Some(apk),
            g_r: Some(g_r),
            k_a: Some(k_a),
        };

        let witness = RegisterWitness {
            sk: Some(sk_base),
            pk: Some(pk),
            addr: Some(addr),
            v: Some(v),
            sn: Some(sn),
            o: Some(o),
            k: Some(k),
            r: Some(randomness),
            k_x: Some(k_x),
        };

        let circuit = RegisterCircuit {
            hash_params,
            G: elgamal_param,
            instance,
            witness,
            _curve_var: PhantomData,
        };

        Ok(circuit)
    }
}
