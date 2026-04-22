use ark_serialize::CanonicalSerialize;
use dotenv::dotenv;
use std::{env, str::FromStr, time::Duration};

pub trait Average<T> {
    fn average(&self) -> T;
}

impl Average<u128> for Vec<u128> {
    fn average(&self) -> u128 {
        let sum: u128 = self.iter().sum();
        if self.is_empty() {
            0
        } else {
            sum / (self.len() as u128)
        }
    }
}

pub trait Transpose<T> {
    fn transpose(&self) -> Vec<T>;
}

impl<T: Clone> Transpose<Vec<T>> for Vec<T> {
    fn transpose(&self) -> Vec<Vec<T>> {
        self.into_iter().map(|x| vec![x.clone()]).collect()
    }
}

pub fn format_time(microseconds: u128) -> String {
    let ms = microseconds as f64 / 1_000.0;
    if ms >= 1_000.0 {
        format!("{:.2} s", ms / 1_000.0)
    } else {
        format!("{:.2} ms", ms)
    }
}

pub fn parse_env<T: FromStr>(key: &'static str) -> Result<T, T::Err> {
    dotenv().ok();
    let var = env::var(key).expect(format!("{} not set", key).as_str());
    var.parse()
}

pub fn compressed_key_size<K: CanonicalSerialize>(key: &K) -> usize {
    let mut buffer = vec![];
    key.serialize_compressed(&mut buffer).unwrap();
    buffer.len()
}

pub fn format_duration_s_2dp(duration: Duration) -> String {
    format!("{:.2} s", duration.as_secs_f64())
}
