/*
    Multi-party ECDSA

    Copyright 2018 by Kzen Networks

    This file is part of Multi-party ECDSA library
    (https://github.com/KZen-networks/multi-party-ecdsa)

    Multi-party ECDSA is free software: you can redistribute
    it and/or modify it under the terms of the GNU General Public
    License as published by the Free Software Foundation, either
    version 3 of the License, or (at your option) any later version.

    @license GPL-3.0+ <https://github.com/KZen-networks/multi-party-ecdsa/blob/master/LICENSE>
*/
const SECURITY_BITS: usize = 256;

// #[macro_use]
// extern crate serde_derive;

pub mod bulletproofs;
pub mod centipede;
pub mod curv;
pub mod paillier;
pub mod party_one;
pub mod party_two;
pub mod zk_paillier;
pub mod kms;

mod test;
mod typetags;

use serde::{Serialize,Deserialize};

pub use crate::centipede::juggling::proof_system::{Helgamal, Helgamalsegmented, Witness};
pub use crate::curv::cryptographic_primitives::proofs::{sigma_ec_ddh::ECDDHProof, ProofError};
pub use crate::curv::elliptic::curves::secp256_k1::{Secp256k1Point, Secp256k1Scalar};
pub use crate::curv::{elliptic::curves::traits::ECPoint, BigInt, FE, GE};
pub use crate::paillier::{
    traits::*, DecryptionKey, EncryptionKey, Paillier, RawCiphertext, RawPlaintext,
};
pub use crate::zk_paillier::zkproofs::{
    CorrectKeyProofError, NICorrectKeyProof, RangeProofError, RangeProofNi,
};
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct PartyPrivate {
    u_i: FE,
    x_i: FE,
    dk: DecryptionKey,
}

impl PartyPrivate {
    // pub fn set_private(key: Keys, shared_key: SharedKeys) -> PartyPrivate {
    //     let key_private = PartyPrivate {
    //         u_i: key.u_i,
    //         x_i: shared_key.x_i,
    //         dk: key.dk,
    //     };
    //     key_private
    // }

    pub fn y_i(&self) -> GE {
        let g: GE = ECPoint::generator();
        g * self.u_i
    }

    pub fn decrypt(&self, ciphertext: BigInt) -> RawPlaintext {
        Paillier::decrypt(&self.dk, &RawCiphertext::from(ciphertext))
    }

    pub fn update_private_key(&self, factor_u_i: &FE, factor_x_i: &FE) -> Self {
        PartyPrivate {
            u_i: self.u_i + factor_u_i,
            x_i: self.x_i + factor_x_i,
            dk: self.dk.clone(),
        }
    }
}

#[derive(Copy, PartialEq, Eq, Clone, Debug)]
pub enum Error {
    InvalidKey,
    InvalidSS,
    InvalidCom,
    InvalidSig,
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
