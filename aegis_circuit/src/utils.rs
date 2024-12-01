use std::{fs::File, io::Write, ops::Neg};

use ark_bn254::G2Affine;
use ark_ec::{
    pairing::{prepare_g2, Pairing},
    AffineRepr, CurveGroup,
};
use ark_ff::Field;
use ark_groth16::{Proof, VerifyingKey};
use ark_serialize::CanonicalSerialize;
use regex::Regex;
use serde_json::Value;

pub fn extract_numbers_as_array(input: &str) -> Vec<String> {
    // 정규식을 사용하여 숫자만 추출
    let re = Regex::new(r"\d+").unwrap();
    re.find_iter(input)
        .map(|mat| mat.as_str().to_string())
        .collect::<Vec<_>>() // 숫자를 배열로 수집
}

pub fn process_json(input: &str) -> Value {
    // JSON 파싱
    let parsed_json: Value = serde_json::from_str(input).unwrap();

    // key와 숫자만 배열로 남기는 작업
    let mut output = serde_json::Map::new();

    for (key, value) in parsed_json.as_object().unwrap() {
        // 문자열로 처리하여 숫자 배열만 추출
        let cleaned_values = extract_numbers_as_array(&value.to_string());
        output.insert(
            key.clone(),
            Value::Array(
                cleaned_values
                    .iter()
                    .map(|s| Value::String(s.clone()))
                    .collect(),
            ),
        );
    }

    Value::Object(output)
}

pub fn save_json_to_file(json_data: &String, file_path: &str) {
    let file = File::create(file_path).expect("파일 생성에 실패했습니다.");
    let json_data: Value = serde_json::from_str(json_data).unwrap();
    serde_json::to_writer_pretty(file, &json_data).expect("파일에 JSON 쓰기 실패");
}

pub struct MyVerifyingKey<E: Pairing>(pub VerifyingKey<E>);

impl<E: Pairing> ToString for MyVerifyingKey<E> {
    fn to_string(&self) -> String {
        serde_json::json!({
            "alpha_g1": self.0.alpha_g1.to_sol(),
            "beta_g2_neg": self.0.beta_g2.into_group().neg().into_affine().to_sol(),
            "gamma_g2_neg": self.0.gamma_g2.into_group().neg().into_affine().to_sol(),
            "delta_g2_neg": self.0.delta_g2.into_group().neg().into_affine().to_sol(),
            "gamma_abc_g1":  self.0.gamma_abc_g1.to_sol(),
        })
        .to_string()
    }
}

pub struct MyProof<E: Pairing>(pub Proof<E>);

impl<E: Pairing> ToString for MyProof<E> {
    fn to_string(&self) -> String {
        serde_json::json!({
            "a": self.0.a.to_sol(),
            "b": self.0.b.to_sol(),
            "c": self.0.c.to_sol(),
        })
        .to_string()
    }
}

trait Solidity {
    fn to_sol(&self) -> Vec<String>;
}

impl<A: AffineRepr> Solidity for A {
    fn to_sol(&self) -> Vec<String> {
        let mut str = vec![];
        self.y()
            .unwrap()
            .to_base_prime_field_elements()
            .chain(self.x().unwrap().to_base_prime_field_elements())
            .for_each(|k| {
                str.push(k.to_string());
            });
        str.reverse();
        str
    }
}

impl<A: AffineRepr> Solidity for [A] {
    fn to_sol(&self) -> Vec<String> {
        let mut str = vec![];
        for a in self.iter() {
            str.extend(a.to_sol());
        }
        str
    }
}
