use crate::curv::elliptic::curves::secp256_k1::FE;
use serde::{Deserialize, Serialize};

pub mod party1;
pub mod party2;
pub mod test;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Rotation {
    pub rotation: FE,
}


