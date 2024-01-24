use serde::{Deserialize, Serialize};
use crate::curv::elliptic::curves::secp256_k1::FE;

pub mod party1;
pub mod party2;
pub mod test;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Rotation {
    pub scalar: FE,
}