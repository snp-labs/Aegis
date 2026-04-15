use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_ff::PrimeField;
use ark_ff::Zero;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::{
    alloc::AllocVar,
    fields::{fp::FpVar, FieldVar},
    prelude::Boolean,
};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use rand::{CryptoRng, RngCore};
use rayon::prelude::*;
use std::fs::{create_dir_all, metadata, File, OpenOptions};
use std::io::Write;
use std::time::{Duration, Instant};

use crate::crypto::commitment;
use crate::solidity::Solidity;
use crate::{
    crypto::commitment::{
        pedersen::{Pedersen, PedersenGadget},
        BatchCommitmentGadget, BatchCommitmentScheme,
    },
    gro::{CCGroth16, Commitment, CommittingKey, Proof, ProvingKey, VerifyingKey},
    snark::{CircuitSpecificSetupCCSNARK, CCSNARK},
    utils::format_duration_2dp,
};

fn test_delta_commitment<F: PrimeField>(num_commitments: usize, length: usize) -> Vec<Vec<F>> {
    let mut commitments = vec![];
    for _ in 0..(num_commitments >> 1) {
        commitments.push(vec![F::one(); length]);
        commitments.push(vec![-F::one(); length]);
    }
    commitments
}

#[derive(Clone)]
struct AegisCircuit<C: CurveGroup> {
    // public input
    pub tau: Option<C::ScalarField>,

    // committed witness
    pub aggregation: Option<Vec<C::ScalarField>>,
    pub curr_commitments: Option<Vec<Vec<C::ScalarField>>>,
    pub prev_commitments: Option<Vec<Vec<C::ScalarField>>>,
}

impl<C: CurveGroup> AegisCircuit<C> {
    pub fn new(
        tau: C::ScalarField,
        curr_commitments: Vec<Vec<C::ScalarField>>,
        prev_commitments: Vec<Vec<C::ScalarField>>,
    ) -> Self {
        let delta_commitments = prev_commitments
            .iter()
            .zip(curr_commitments.iter())
            .map(|(prev, curr)| {
                curr.iter()
                    .zip(prev.iter())
                    .map(|(curr, prev)| *curr - *prev)
                    .collect::<Vec<C::ScalarField>>()
            })
            .collect::<Vec<_>>();
        let commitments = [&curr_commitments[..], &delta_commitments[..]].concat();
        let slices: Vec<&[C::ScalarField]> = commitments.iter().map(|cm| &cm[..]).collect();
        let (aggregation, _) = Pedersen::<C>::scalar_aggregate(&slices[..], tau, None);

        Self {
            tau: Some(tau),
            aggregation: Some(aggregation),
            curr_commitments: Some(curr_commitments),
            prev_commitments: Some(prev_commitments),
        }
    }

    pub fn mock(batch_size: usize) -> Self {
        Self {
            tau: Some(C::ScalarField::zero()),
            aggregation: Some(vec![C::ScalarField::zero(); 2]),
            curr_commitments: Some(vec![vec![C::ScalarField::zero(); 2]; batch_size]),
            prev_commitments: Some(vec![vec![C::ScalarField::zero(); 2]; batch_size]),
        }
    }
}

impl<C: CurveGroup> ConstraintSynthesizer<C::ScalarField> for AegisCircuit<C> {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<C::ScalarField>,
    ) -> ark_relations::r1cs::Result<()> {
        let tau = FpVar::new_input(cs.clone(), || {
            self.tau.ok_or_else(|| SynthesisError::AssignmentMissing)
        })?;

        let aggregation = Vec::<FpVar<C::ScalarField>>::new_witness(cs.clone(), || {
            self.aggregation
                .ok_or_else(|| SynthesisError::AssignmentMissing)
        })?;

        let current_commitments = self
            .curr_commitments
            .ok_or_else(|| SynthesisError::AssignmentMissing)?
            .into_iter()
            .map(|cm| Vec::<FpVar<C::ScalarField>>::new_witness(cs.clone(), || Ok(cm)))
            .collect::<Result<Vec<_>, SynthesisError>>()?;

        let prev_commitments = self
            .prev_commitments
            .ok_or_else(|| SynthesisError::AssignmentMissing)?
            .into_iter()
            .map(|cm| Vec::<FpVar<C::ScalarField>>::new_witness(cs.clone(), || Ok(cm)))
            .collect::<Result<Vec<_>, SynthesisError>>()?;

        let max_bytes: [u8; 8] = (std::u64::MAX - 1).to_le_bytes();
        let constant_max = <C::ScalarField>::from_le_bytes_mod_order(&max_bytes);
        let zero = FpVar::new_constant(cs.clone(), C::ScalarField::zero())?;
        let mut sum = zero.clone();

        let mut delta_commitments =
            Vec::<Vec<FpVar<C::ScalarField>>>::with_capacity(current_commitments.len());
        for (prev, curr) in prev_commitments.iter().zip(current_commitments.iter()) {
            let delta = prev
                .iter()
                .zip(curr.iter())
                .map(|(prev, curr)| curr - prev)
                .collect::<Vec<_>>();
            sum += delta[0].clone();
            delta_commitments.push(delta);

            let (curr_bits_64, _) = curr[0].to_bits_le_with_top_bits_zero(64)?;
            Boolean::enforce_smaller_or_equal_than_le(
                curr_bits_64.as_slice(),
                constant_max.into_bigint(),
            )?;
        }

        let zero = FpVar::<C::ScalarField>::zero();
        sum.enforce_equal(&zero)
            .expect("Summation of delta amounts must be zero.");

        let commitments =
            [current_commitments, delta_commitments].concat::<Vec<FpVar<C::ScalarField>>>();
        PedersenGadget::<C, FpVar<C::ScalarField>>::enforce_equal(
            aggregation,
            commitments,
            tau,
            None,
        )
        .expect("Aggregation Check");

        Ok(())
    }
}

fn aegis_circuit_setup<E: Pairing, R: RngCore + CryptoRng>(
    batch_size: usize,
    rng: &mut R,
) -> (ProvingKey<E>, VerifyingKey<E>, CommittingKey<E>) {
    let num_aggregation_variables = 2;
    let num_committed_witness_variables = num_aggregation_variables * (1 + 2 * batch_size);

    let mock = AegisCircuit::<E::G1>::mock(batch_size);
    CCGroth16::<E>::setup(
        mock,
        num_aggregation_variables,
        num_committed_witness_variables,
        rng,
    )
    .unwrap()
}

fn aegis_circuit_commit<E: Pairing, R: RngCore + CryptoRng>(
    ck: &CommittingKey<E>,
    prev: &Vec<Vec<E::ScalarField>>,
    delta: &Vec<Vec<E::ScalarField>>,
    curr: &Vec<Vec<E::ScalarField>>,
    rng: &mut R,
) -> (Vec<E::G1Affine>, Commitment<E>, E::ScalarField) {
    let batch_size = delta.len();

    // Generage Proof Dependent Commitment
    let commitments = [&curr[..], &prev[..]].concat();
    let committed_witness = cfg_iter!(commitments)
        .flat_map(|cm| cfg_iter!(cm).cloned())
        .collect::<Vec<_>>();
    drop(commitments);

    let proof_dependent_commitment =
        CCGroth16::<E>::commit(&ck, &committed_witness[..], rng).unwrap();

    // Batch Commitment Module
    let commitments = [&curr[..], &delta[..]].concat();
    let slices = cfg_iter!(commitments).map(|cm| &cm[..]).collect::<Vec<_>>();
    let commitments_g1 = Pedersen::<E::G1>::batch_commit(&ck.batch_g1, &slices);
    let tau = Pedersen::<E::G1>::challenge(
        &[],
        &commitments_g1[batch_size..],
        &proof_dependent_commitment.cm,
    );
    (commitments_g1, proof_dependent_commitment, tau)
}

fn batch_commit<E: Pairing>(
    ck: &CommittingKey<E>,
    cm: &Vec<Vec<E::ScalarField>>,
) -> Vec<E::G1Affine> {
    let slices = cfg_iter!(cm).map(|cm| &cm[..]).collect::<Vec<_>>();
    let commitments_g1 = Pedersen::<E::G1>::batch_commit(&ck.batch_g1, &slices);
    commitments_g1
}

fn aegis_circuit_prove_and_verify<E: Pairing, R: RngCore + CryptoRng>(
    pk: &ProvingKey<E>,
    vk: &VerifyingKey<E>,
    circuit: AegisCircuit<E::G1>,
    commitments: &Vec<E::G1Affine>,
    proof_dependent_commitment: &Commitment<E>,
    rng: &mut R,
) -> (Proof<E>, Duration, Duration, Duration) {
    let prove_start = Instant::now();
    let proof = CCGroth16::<E>::prove(&pk, circuit.clone(), &proof_dependent_commitment, rng)
        .expect("Failed: Proof Generation");
    let prove_time = prove_start.elapsed();

    let tau = circuit.tau.unwrap();
    let public_inputs = [tau];

    let aggregate_start = Instant::now();
    let aggregate_timer = start_timer!(|| "Aggregate Commitments");
    let (aggregation_g1, _) = Pedersen::<E::G1>::aggregate(commitments, tau, None);
    end_timer!(aggregate_timer);
    let aggregate_time = aggregate_start.elapsed();

    let mut verify = proof.clone();
    let aggregation = aggregation_g1.into_group();
    let _aggregation = circuit.aggregation.clone().unwrap();
    let _aggregation = vk.ck.batch_g1[0].into_group() * _aggregation[0]
        + vk.ck.batch_g1[1].into_group() * _aggregation[1];
    assert_eq!(
        aggregation.into_affine(),
        _aggregation.into_affine(),
        "Invalid Aggregation"
    );
    verify.d = (aggregation + verify.d.into_group()).into_affine();

    let verify_start = Instant::now();
    assert!(
        CCGroth16::<E>::verify(&vk, &public_inputs, &verify).unwrap(),
        "Invalid Proof"
    );
    let verify_time = verify_start.elapsed();

    (proof, prove_time, aggregate_time, verify_time)
}

fn test_commitments<F: PrimeField>(num_commitments: usize, length: usize) -> Vec<Vec<F>> {
    let mut commitments = vec![];
    for _ in 0..num_commitments {
        // let value = ((i & 1) + 1) as u64;
        let value = 100 as u64;
        commitments.push(vec![F::from(value); length]);
    }
    commitments
}

fn aegis_circuit_solidity<E: Pairing>(
    batch_size: usize,
    cm: &Vec<E::G1Affine>,
    proof: &Proof<E>,
    vk: &VerifyingKey<E>,
    prev_cm: &Vec<E::G1Affine>,
) where
    E::G1Affine: Solidity,
    E::G2Affine: Solidity,
    E::ScalarField: Solidity,
{
    let result_dir = "../aegis_contract/result";
    create_dir_all(result_dir).expect("Unable to create result directory");
    let output_path = format!("{}/dbtData.batch_{}.json", result_dir, batch_size);
    let mut file = File::create(output_path).expect("Unable to create json file");

    let payload = serde_json::json!({
        "batchSize": batch_size,
        "vk": vk.to_solidity(),
        "ck": vk.ck.batch_g1.to_solidity(),
        "dbt": {
            "cm": vec![cm[batch_size], cm[batch_size + 1]].to_solidity(),
            "proof": proof.to_solidity()
        },
        "prevCm": prev_cm[0].to_solidity()
    });
    file.write_all(
        serde_json::to_string_pretty(&payload)
            .expect("Unable to serialize json")
            .as_bytes(),
    )
    .expect("Unable to write json file");
}

pub mod bn254 {
    use std::fs;

    use crate::{
        gro::VerifyingKeyIO,
        tests::{LOG_MAX, LOG_MIN, THREAD},
    };

    use super::*;
    use ark_serialize::CanonicalSerialize;
    use ark_std::{
        rand::{rngs::StdRng, SeedableRng},
        test_rng,
    };

    type C = ark_bn254::G1Projective;
    type E = ark_bn254::Bn254;
    type F = ark_bn254::Fr;
    type R = StdRng;

    use lazy_static::lazy_static;

    lazy_static! {
        pub static ref PK_FILE: String = "dbt.pk.dat".to_string();
        pub static ref VK_FILE: String = "dbt.vk.dat".to_string();
        pub static ref PRF_FILE: String = "dbt.proof.dat".to_string();
    }

    #[test]
    fn aegis_constraint() {
        for n in *LOG_MIN..=*LOG_MAX {
            let batch_size = 1 << n;
            let circuit = AegisCircuit::<C>::mock(batch_size);
            let cs = ark_relations::r1cs::ConstraintSystem::new_ref();
            circuit.generate_constraints(cs.clone()).unwrap();
            assert!(cs.is_satisfied().unwrap());
            println!(
                "batch size: {} Number of constraints: {}",
                batch_size,
                cs.num_constraints()
            );
        }
    }

    #[test]
    fn aegis_pk_vk_size() {
        let path = "./src/keys/";
        let pk_file = format!("{}{}", path, PK_FILE.as_str());
        let vk_file = format!("{}{}", path, VK_FILE.as_str());

        let mut rng = R::seed_from_u64(test_rng().next_u64());

        for n in *LOG_MIN..=*LOG_MAX {
            let batch_size = 1 << n;
            let (pk, vk, _) = aegis_circuit_setup::<E, R>(batch_size, &mut rng);

            let mut pk_bytes = Vec::new();
            pk.serialize_compressed(&mut pk_bytes).unwrap();

            let vk_io = VerifyingKeyIO::from_vk(&vk);
            let mut vk_bytes = Vec::new();

            vk_io.serialize_compressed(&mut vk_bytes).unwrap();

            // Write data in .dat
            fs::write(pk_file.as_str(), pk_bytes).unwrap();
            fs::write(vk_file.as_str(), vk_bytes).unwrap();

            let pk_bytes = fs::read(pk_file.as_str()).unwrap();
            let vk_bytes = fs::read(vk_file.as_str()).unwrap();

            println!("batch size {} pk size: {}", batch_size, pk_bytes.len());
            println!("batch size {} vk size: {}", batch_size, vk_bytes.len());
        }
    }

    #[test]
    fn aegis_circuit_scenario() {
        let mut rng = R::seed_from_u64(test_rng().next_u64());
        let mut file = OpenOptions::new()
            .write(true)
            .append(true)
            .create(true)
            .open("./src/tests/circuit_result.csv")
            .unwrap();
        if metadata("./src/tests/circuit_result.csv")
            .map(|m| m.len() == 0)
            .unwrap_or(true)
        {
            writeln!(
                file,
                "thread,batch_size,constraints,setup,commit,prover,aggregate,verifier"
            )
            .unwrap();
        }

        let thread = rayon::current_num_threads();
        for n in *LOG_MIN..=*LOG_MAX {
            println!("Rayon thread pool size: {}", thread);
            let batch_size = 1 << n;
            println!("batch size: {}", batch_size);

            let cs = ark_relations::r1cs::ConstraintSystem::<F>::new_ref();

            AegisCircuit::<C>::mock(batch_size)
                .generate_constraints(cs.clone())
                .unwrap();
            let constraints = cs.num_constraints();

            let setup_start = Instant::now();
            let (pk, vk, ck) = aegis_circuit_setup::<E, R>(batch_size, &mut rng);
            let setup_time = setup_start.elapsed();

            let cm_prev = test_commitments::<F>(batch_size, 2);
            let cm_delta = test_delta_commitment::<F>(batch_size, 2);
            let cm_curr = cm_prev
                .iter()
                .zip(cm_delta.iter())
                .map(|(prev, delta)| {
                    prev.iter()
                        .zip(delta.iter())
                        .map(|(prev, delta)| *prev + *delta)
                        .collect::<Vec<F>>()
                })
                .collect::<Vec<_>>();

            // commit
            let commit_start = Instant::now();
            let (cm_g1, d, tau) =
                aegis_circuit_commit(&ck, &cm_prev, &cm_delta, &cm_curr, &mut rng);
            let commit_time = commit_start.elapsed();
            // print!("tau: {}\n", tau.to_string());

            let circuit = AegisCircuit::<C>::new(tau, cm_curr, cm_prev.clone());

            let (proof, prove_time, aggregate_time, verify_time) =
                aegis_circuit_prove_and_verify(&pk, &vk, circuit.clone(), &cm_g1, &d, &mut rng);

            // make a prev_cm_g1
            let a_cm_prev = test_commitments(1, 2);
            let prev_cm_g1 = batch_commit(&ck, &a_cm_prev);

            aegis_circuit_solidity(batch_size, &cm_g1, &proof, &vk, &prev_cm_g1);

            writeln!(
                file,
                "{},{},{},{},{},{},{},{}",
                thread,
                batch_size,
                constraints,
                format_duration_2dp(setup_time),
                format_duration_2dp(commit_time),
                format_duration_2dp(prove_time),
                format_duration_2dp(aggregate_time),
                format_duration_2dp(verify_time)
            )
            .unwrap();
        }
        // }
    }
}
