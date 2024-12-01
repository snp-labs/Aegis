use crate::cbdc::circuits::import::*;
use ark_std::{One, Zero};

pub type ConstraintF<C> = <<C as CurveGroup>::BaseField as Field>::BasePrimeField;

#[derive(Clone, Debug)]
pub struct ExchangeInstance<C: CurveGroup> {
    pub rt: Option<C::BaseField>,
    pub ck: Option<Vec<C::Affine>>,
    pub addr_d: Option<C::BaseField>,
    pub sn_cur: Option<C::BaseField>,
    pub cm_new: Option<C::BaseField>,
    pub cm_new_d: Option<C::Affine>,
    pub cm_v_d: Option<C::Affine>,
    pub ct_bar: Option<Vec<C::BaseField>>,
    pub apk: Option<elgamal::PublicKey<C>>,
    pub g_r: Option<C::Affine>,
    pub k_a: Option<C::Affine>,
}

#[derive(Clone, Debug)]
pub struct ExchangeWitness<C: CurveGroup>
where
    C::BaseField: PrimeField + Absorb,
{
    pub sk: Option<C::BaseField>,
    pub pk: Option<elgamal::PublicKey<C>>,
    pub sk_d: Option<Vec<C::BaseField>>,
    pub pk_d: Option<C::Affine>,
    pub addr: Option<C::BaseField>,
    pub v: Option<C::BaseField>,
    pub v_cur: Option<C::BaseField>,
    pub v_cur_d: Option<C::BaseField>,
    pub o_cur: Option<C::BaseField>,
    pub o_cur_d: Option<C::BaseField>,
    pub o_new: Option<C::BaseField>,
    pub o_v_d: Option<C::BaseField>,
    pub sn_new: Option<C::BaseField>,
    pub cm_cur: Option<C::BaseField>,
    pub cm_cur_d: Option<C::Affine>,
    pub flag: Option<bool>,
    pub leaf_pos: Option<u32>,
    pub tree_proof: Option<merkle_tree::Path<MerkleTreeParams<C::BaseField>>>,
    pub k: Option<elgamal::Plaintext<C>>,
    pub r: Option<elgamal::Randomness<C>>,
    pub k_x: Option<symmetric::SymmetricKey<C::BaseField>>,
}

#[allow(non_snake_case)]
#[derive(Clone)]
pub struct ExchangeCircuit<C: CurveGroup, GG: CurveVar<C, ConstraintF<C>>>
where
    <C as CurveGroup>::BaseField: PrimeField + Absorb,
{
    // constant
    pub hash_params: PoseidonConfig<C::BaseField>,
    pub G: elgamal::Parameters<C>,
    
    pub instance: ExchangeInstance<C>,
    pub witness: ExchangeWitness<C>,
    _curve_var: PhantomData<GG>,
}

#[allow(non_snake_case)]
impl<C, GG> ConstraintSynthesizer<C::BaseField> for ExchangeCircuit<C, GG>
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
        let rt = FpVar::<C::BaseField>::new_input(cs.clone(), || {
            self.instance.rt.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let ck = Vec::<GG>::new_input(cs.clone(), || {
            self.instance.ck.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let addr_d = FpVar::<C::BaseField>::new_input(cs.clone(), || {
            self.instance
                .addr_d
                .ok_or(SynthesisError::AssignmentMissing)
        })?;
        let sn_cur = FpVar::<C::BaseField>::new_input(cs.clone(), || {
            self.instance
                .sn_cur
                .ok_or(SynthesisError::AssignmentMissing)
        })?;
        let cm_new = FpVar::<C::BaseField>::new_input(cs.clone(), || {
            self.instance
                .cm_new
                .ok_or(SynthesisError::AssignmentMissing)
        })?;
        let cm_new_d = GG::new_input(cs.clone(), || {
            self.instance
                .cm_new_d
                .ok_or(SynthesisError::AssignmentMissing)
        })?;
        let cm_v_d = GG::new_input(cs.clone(), || {
            self.instance
                .cm_v_d
                .ok_or(SynthesisError::AssignmentMissing)
        })?;
        let ct_bar = Vec::<FpVar<C::BaseField>>::new_input(cs.clone(), || {
            self.instance
                .ct_bar
                .ok_or(SynthesisError::AssignmentMissing)
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
        let sk_d = Vec::<FpVar<C::BaseField>>::new_witness(cs.clone(), || {
            self.witness.sk_d.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let pk_d = GG::new_witness(cs.clone(), || {
            self.witness.pk_d.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let addr = FpVar::<C::BaseField>::new_witness(cs.clone(), || {
            self.witness.addr.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let v = FpVar::<C::BaseField>::new_witness(cs.clone(), || {
            self.witness.v.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let v_cur = FpVar::<C::BaseField>::new_witness(cs.clone(), || {
            self.witness.v_cur.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let v_cur_d = FpVar::<C::BaseField>::new_witness(cs.clone(), || {
            self.witness
                .v_cur_d
                .ok_or(SynthesisError::AssignmentMissing)
        })?;
        let o_cur = FpVar::<C::BaseField>::new_witness(cs.clone(), || {
            self.witness.o_cur.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let o_cur_d = FpVar::<C::BaseField>::new_witness(cs.clone(), || {
            self.witness
                .o_cur_d
                .ok_or(SynthesisError::AssignmentMissing)
        })?;
        let o_new = FpVar::<C::BaseField>::new_witness(cs.clone(), || {
            self.witness.o_new.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let o_v_d = FpVar::<C::BaseField>::new_witness(cs.clone(), || {
            self.witness.o_v_d.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let sn_new = FpVar::<C::BaseField>::new_witness(cs.clone(), || {
            self.witness.sn_new.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let cm_cur = FpVar::<C::BaseField>::new_witness(cs.clone(), || {
            self.witness.cm_cur.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let cm_cur_d = GG::new_witness(cs.clone(), || {
            self.witness
                .cm_cur_d
                .ok_or(SynthesisError::AssignmentMissing)
        })?;
        let flag = Boolean::new_witness(cs.clone(), || {
            self.witness.flag.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let mut cw = merkle_tree::constraints::PathVar::<
            MerkleTreeParams<C::BaseField>,
            C::BaseField,
            MerkleTreeParamsVar<C::BaseField>,
        >::new_witness(cs.clone(), || {
            self.witness
                .tree_proof
                .ok_or(SynthesisError::AssignmentMissing)
        })?;
        let leaf_pos = UInt32::new_witness(cs.clone(), || {
            self.witness
                .leaf_pos
                .ok_or(SynthesisError::AssignmentMissing)
        })?
        .to_bits_le();
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

        // 1. check (pk, sk) is well-formed => pk = g^sk
        let sk_bits = sk.to_non_unique_bits_le()?;
        let pk_computed = G.generator.scalar_mul_le(sk_bits.iter())?;
        pk.pk.enforce_equal(&pk_computed)?;

        // 2. check (pk_d, sk_d) is well-formed => pk_d = ck^sk_d
        let sk_d_bits_0 = sk_d[0].to_non_unique_bits_le()?;
        let ck_0_mul_sk_d_0 = ck[0].scalar_mul_le(sk_d_bits_0.iter())?;
        let sk_d_bits_1 = sk_d[1].to_non_unique_bits_le()?;
        let ck_1_mul_sk_d_1 = ck[1].scalar_mul_le(sk_d_bits_1.iter())?;
        let computed_pk_d = ck_0_mul_sk_d_0 + ck_1_mul_sk_d_1;

        pk_d.enforce_equal(&computed_pk_d)?;

        // 3. check check flag * (flag - 1) = 0: bool type이어도 해당 제약 조건 필요?

        // 4. check addr = CRH(pk)
        let binding = pk.clone().pk.to_bits_le()?;
        let pk_x = Boolean::le_bits_to_fp_var(&binding[..binding.len() / 2])?;
        let pk_y = Boolean::le_bits_to_fp_var(&binding[binding.len() / 2..])?;

        let hash_input = vec![pk_x, pk_y];
        let addr_computed = CRHGadget::<C::BaseField>::evaluate(&hash_params, &hash_input).unwrap();
        addr_computed.enforce_equal(&addr)?;

        // 5. check addr_d = CRH(pk_d)
        let binding = pk_d.clone().to_bits_le()?;
        let pk_d_x = Boolean::le_bits_to_fp_var(&binding[..binding.len() / 2])?;
        let pk_d_y = Boolean::le_bits_to_fp_var(&binding[binding.len() / 2..])?;

        let hash_input = vec![pk_d_x, pk_d_y];
        let addr_d_computed = CRHGadget::<C::BaseField>::evaluate(&hash_params, &hash_input).unwrap();
        addr_d_computed.enforce_equal(&addr_d)?;

        // 6. check v > 0
        v.enforce_not_equal(&zero)?;
        v.enforce_smaller_or_equal_than_mod_minus_one_div_two()?;

        // 7. check v_cur >= 0
        v_cur.enforce_smaller_or_equal_than_mod_minus_one_div_two()?;

        // 8. check v_cur_d >= 0
        v_cur_d.enforce_smaller_or_equal_than_mod_minus_one_div_two()?;

        // 9. check flag * (v_cur_d - v) + (1 - flag) * (v_cur - v) >= 0 -> flag = true ? v_cur_d - v, v_cur - v
        let v_cur_d_minus_v = &v_cur_d - &v;
        let v_cur_minus_v = &v_cur - &v;
        let result = flag.select(&v_cur_d_minus_v, &v_cur_minus_v)?;
        result.enforce_smaller_or_equal_than_mod_minus_one_div_two()?;

        // 10. check cm_cur = CRH(addr, v_cur, sn_cur, o_cur)
        let hash_input = vec![addr.clone(), v_cur.clone(), sn_cur.clone(), o_cur.clone()];
        let cm_cur_computed = CRHGadget::<C::BaseField>::evaluate(&hash_params, &hash_input).unwrap();
        cm_cur_computed.enforce_equal(&cm_cur)?;

        // 11. check MT.verify(cm_cur, path, rt) = true
        let leaf_g: Vec<_> = vec![cm_cur.clone()];
        cw.set_leaf_position(leaf_pos.clone());
        let path_check = cw.verify_membership(&hash_params, &hash_params, &rt, &leaf_g)?;
        path_check.enforce_equal(&Boolean::Constant(true))?;

        // 12. check sn_cur = PRF(sk, o_cur)
        let hash_input = [sk.clone(), o_cur.clone()];
        let sn_cur_computed = CRHGadget::<C::BaseField>::evaluate(&hash_params, &hash_input).unwrap();
        sn_cur_computed.enforce_equal(&sn_cur)?;

        // 13. check sn_new = PRF(sk, o_new)
        let hash_input = [sk.clone(), o_new.clone()];
        let sn_new_computed = CRHGadget::<C::BaseField>::evaluate(&hash_params, &hash_input).unwrap();
        sn_new_computed.enforce_equal(&sn_new)?;

        // 14. check cm_new = CRH(addr, flag * (v_cur + v) + (1 - flag) * (v_cur - v), sn_new, o_new)
        let v_cur_plus_v = &v_cur + &v;
        let cm_new_v = flag.select(&v_cur_plus_v, &v_cur_minus_v)?;
        let hash_input = vec![addr.clone(), cm_new_v, sn_new.clone(), o_new.clone()];
        let cm_new_computed = CRHGadget::<C::BaseField>::evaluate(&hash_params, &hash_input).unwrap();
        cm_new_computed.enforce_equal(&cm_new)?;

        // 15. check cm_cur_d = Ped.Com(ck, v_cur_d, o_cur_d)
        let v_cur_d_bits = v_cur_d.to_non_unique_bits_le()?;
        let o_cur_d_bits = o_cur_d.to_non_unique_bits_le()?;
        let cm_cur_d_computed =
            ck[0].scalar_mul_le(v_cur_d_bits.iter())? + ck[1].scalar_mul_le(o_cur_d_bits.iter())?;
        cm_cur_d.enforce_equal(&cm_cur_d_computed)?;

        // 16. check cm_v_d = Ped.Com(ck, flag * (-v) + (1 - flag) * v, o_v_d)
        let v_d = flag.select(&v.negate()?, &v)?;
        let v_d_bits = v_d.to_non_unique_bits_le()?;
        let o_v_d_bits = o_v_d.to_non_unique_bits_le()?;
        let cm_v_d_computed =
            ck[0].scalar_mul_le(v_d_bits.iter())? + ck[1].scalar_mul_le(o_v_d_bits.iter())?;
        cm_v_d.enforce_equal(&cm_v_d_computed)?;

        // 17. check cm_new_d = cm_cur_d + cm_v_d
        let cm_new_d_computed = &cm_cur_d + &cm_v_d;
        cm_new_d.enforce_equal(&cm_new_d_computed)?;

        // 18. check ct_bar = Elgamal.Enc(apk, pk, addr_d, v, flag, o_v_d)
        let k_a_computed = ElGamalEncGadget::<C, GG>::encrypt(&G, &k, &r, &apk).unwrap();
        k_a.enforce_equal(&k_a_computed)?;

        let bining = pk.clone().pk.to_bits_le()?;
        let pk_x = Boolean::le_bits_to_fp_var(&bining[..bining.len() / 2])?;
        let pk_y = Boolean::le_bits_to_fp_var(&bining[bining.len() / 2..])?;
        let flag_fp_var = flag.clone().select(
            &FpVar::<C::BaseField>::Constant(C::BaseField::one()),
            &FpVar::<C::BaseField>::Constant(C::BaseField::zero()),
        )?;

        let plain: Vec<FpVar<C::BaseField>> = vec![pk_x, pk_y, addr_d, v, flag_fp_var, o_v_d];

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
impl<C, GG> MockingCircuit<C, GG> for ExchangeCircuit<C, GG>
where
    C: CurveGroup,
    GG: CurveVar<C, C::BaseField>,
    <C as CurveGroup>::BaseField: PrimeField + Absorb,
    for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
{
    type F = C::BaseField;
    type HashParam = PoseidonConfig<Self::F>;
    type H = CRH<Self::F>;
    type Output = ExchangeCircuit<C, GG>;
    
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

        // 1. check (pk, sk) is well-formed
        let (pk, sk) = ElGamal::keygen(&elgamal_param, &mut rng).unwrap();
        let (apk, _) = ElGamal::keygen(&elgamal_param, &mut rng).unwrap();
        let ck = vec![C::rand(&mut rng).into(), C::rand(&mut rng).into()];
        let flag = false;
        let flag_fp = if flag {
            Self::F::one()
        } else {
            Self::F::zero()
        };

        // 2. check (pk_d, sk_d) is well-formed
        let sk_d = vec![Self::F::from(3u64), Self::F::from(4u64)];
        let pk_d = (ck[0] + ck[0] + ck[0] + ck[1] + ck[1] + ck[1] + ck[1]).into_affine();

        // randomness for encryption
        let r = C::ScalarField::rand(&mut rng);
        let k = C::rand(&mut rng).into_affine();

        // openings
        let o_cur = Self::F::rand(&mut rng);
        let o_cur_d = Self::F::rand(&mut rng);
        let o_new = Self::F::rand(&mut rng);
        let o_v_d = Self::F::rand(&mut rng);

        let o_cur_d_bigint = o_cur_d.into_bigint();

        // values
        let v = Self::F::from(5u64);
        let v_cur = Self::F::from(100u64);
        let v_cur_d = Self::F::from(200u64);

        let v_bigint = v.into_bigint();
        let minus_v_bigint = (-v).into_bigint();
        let v_cur_d_bigint = v_cur_d.into_bigint();

        // 4. check addr = CRH(pk)
        let (pk_x, pk_y) = pk.xy().unwrap();
        let addr = Self::H::evaluate(&hash_params, vec![pk_x.clone(), pk_y.clone()]).unwrap();

        // 5. check addr_d = CRH(pk_d)
        let (pk_d_x, pk_d_y) = pk_d.xy().unwrap();
        let addr_d = Self::H::evaluate(&hash_params, vec![pk_d_x.clone(), pk_d_y.clone()]).unwrap();
        println!("addr_d: {:?}", addr_d.to_string());

        // 12. check sn_cur = PRF(sk, o_cur)
        let mut bytes = vec![];
        sk.serialize_uncompressed(&mut bytes)?;
        let sk_base = Self::F::from_le_bytes_mod_order(&bytes);
        let sn_cur = Self::H::evaluate(&hash_params.clone(), vec![sk_base.clone(), o_cur.clone()]).unwrap();

        // 13. check sn_new = PRF(sk, o_new)
        let sn_new = Self::H::evaluate(&hash_params.clone(), vec![sk_base.clone(), o_new.clone()]).unwrap();

        // 10. check cm_cur = CRH(addr, v_cur, sn_cur, o_cur)
        let cm_cur = Self::H::evaluate(
            &hash_params,
            vec![addr.clone(), v_cur.clone(), sn_cur.clone(), o_cur.clone()],
        )
        .unwrap();

        // 14. cm_new = CRH(addr, (v_cur + v) or (v_cur - v), sn_new, o_new) -> flag = true ? v_cur + v, v_cur - v
        let cm_new = Self::H::evaluate(
            &hash_params,
            vec![
                addr.clone(),
                (v_cur.clone() - v.clone()),
                sn_new.clone(),
                o_new.clone(),
            ],
        )
        .unwrap();

        // 15. check cm_cur_d = Ped.Com(ck, v_cur_d, o_cur_d)
        let cm_cur_d_0 = ck[0].mul_bigint(&v_cur_d_bigint);
        let cm_cur_d_1 = ck[1].mul_bigint(&o_cur_d_bigint);
        let cm_cur_d = (cm_cur_d_0 + cm_cur_d_1).into_affine();
        println!("cm_cur_d: {:?}", cm_cur_d);

        // 16. check cm_v_d = Ped.Com(ck, flag * (-v) + (1 - flag) * v, o_v_d) -> flag = true ? -v, v
        let cm_cur_d_0 = ck[0].mul_bigint(&v_bigint);
        let cm_cur_d_1 = ck[1].mul_bigint(&o_v_d.into_bigint());
        let cm_v_d = (cm_cur_d_0 + cm_cur_d_1).into_affine();

        // 17. check cm_new_d = cm_cur_d + cm_v_d
        let cm_new_d = (cm_cur_d + cm_v_d).into_affine();

        // merkle tree
        let leaf_crh_params = hash_params.clone();
        let two_to_one_params = hash_params.clone();

        let merkle_proof: merkle_tree::Path<MerkleTreeParams<Self::F>> =
            merkle_tree::mocking::get_mocking_merkle_tree(tree_height);
        let leaf: Self::F = cm_cur.clone();

        let rt = merkle_proof
            .get_test_root(&leaf_crh_params, &two_to_one_params, [leaf])
            .unwrap();

        println!("cm_cur: {:?}", cm_cur.to_string());
        println!("rt: {:?}", rt.to_string());

        let i = 0;
        assert!(merkle_proof
            .verify(&leaf_crh_params, &two_to_one_params, &rt, [leaf])
            .unwrap());

        // encryption symmetric key
        let randomness = elgamal::Randomness { 0: r };
        let (_, _) = ElGamal::encrypt(&elgamal_param, &pk, &k, &randomness).unwrap();
        let (g_r, k_a) = ElGamal::encrypt(&elgamal_param, &apk, &k, &randomness).unwrap();
        let k_x = k.x().unwrap();
        let k_x = symmetric::SymmetricKey { k: *k_x };

        // ct_bar: ElGamal.Enc(apk, pk, addr_d, v, flag, o_v_d)
        let mut ct_bar = vec![];
        let plain = vec![
            pk_x.clone(),
            pk_y.clone(),
            addr_d.clone(),
            v.clone(),
            flag_fp.clone(),
            o_v_d.clone(),
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


        let instance = ExchangeInstance {
            rt: Some(rt),
            ck: Some(ck),
            addr_d: Some(addr_d),
            sn_cur: Some(sn_cur),
            cm_new: Some(cm_new),
            cm_new_d: Some(cm_new_d),
            cm_v_d: Some(cm_v_d),
            ct_bar: Some(ct_bar),
            apk: Some(apk),
            g_r: Some(g_r),
            k_a: Some(k_a),
        };

        let witness = ExchangeWitness {
            sk: Some(sk_base),
            pk: Some(pk),
            sk_d: Some(sk_d),
            pk_d: Some(pk_d),
            addr: Some(addr),
            v: Some(v),
            v_cur: Some(v_cur),
            v_cur_d: Some(v_cur_d),
            o_cur: Some(o_cur),
            o_cur_d: Some(o_cur_d),
            o_new: Some(o_new),
            o_v_d: Some(o_v_d),
            sn_new: Some(sn_new),
            cm_cur: Some(cm_cur),
            cm_cur_d: Some(cm_cur_d),
            flag: Some(flag),
            leaf_pos: Some(i),
            tree_proof: Some(merkle_proof),
            k: Some(k),
            r: Some(randomness),
            k_x: Some(k_x),
        };

        let circuit = ExchangeCircuit {
            hash_params,
            G: elgamal_param,
            instance,
            witness,
            _curve_var: PhantomData,
        };

        Ok(circuit)
    }
}
