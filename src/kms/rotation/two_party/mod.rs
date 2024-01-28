use crate::curv::elliptic::curves::secp256_k1::FE;
use crate::typetag_value;
use crate::typetags::Value;
use serde::{Deserialize, Serialize};

pub mod party1;
pub mod party2;
pub mod test;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Rotation {
    pub rotation: FE,
}

typetag_value!(Rotation);
