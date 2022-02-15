/*
    This file is part of Curv library
    Copyright 2018 by Kzen Networks
    (https://github.com/KZen-networks/curv)
    License MIT: <https://github.com/KZen-networks/curv/blob/master/LICENSE>
*/


pub mod elliptic;

mod secp256k1instance {
    pub use crate::curv::elliptic::curves::secp256_k1::FE;
    pub use crate::curv::elliptic::curves::secp256_k1::GE;
    pub use crate::curv::elliptic::curves::secp256_k1::PK;
    pub use crate::curv::elliptic::curves::secp256_k1::SK;
}

pub use self::secp256k1instance::*;

pub mod arithmetic;
pub use arithmetic::big_gmp::BigInt;

pub mod cryptographic_primitives;

#[derive(Copy, PartialEq, Eq, Clone, Debug)]
pub enum ErrorKey {
    InvalidPublicKey,
}
