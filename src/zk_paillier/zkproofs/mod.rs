/*
    zk-paillier

    Copyright 2018 by Kzen Networks

    This file is part of Multisig Schnorr library
    (https://github.com/KZen-networks/multisig-schnorr)

    zk-paillier is free software: you can redistribute
    it and/or modify it under the terms of the GNU General Public
    License as published by the Free Software Foundation, either
    version 3 of the License, or (at your option) any later version.

    @license GPL-3.0+ <https://github.com/KZen-networks/zk-paillier/blob/master/LICENSE>
*/

mod correct_key_ni;
pub use self::correct_key_ni::CorrectKeyProofError;
pub use self::correct_key_ni::NICorrectKeyProof;
mod range_proof;

mod range_proof_ni;
pub use self::range_proof_ni::RangeProofError;
pub use self::range_proof_ni::RangeProofNi;

mod correct_message;
pub use self::correct_message::CorrectMessageProof;
pub use self::correct_message::CorrectMessageProofError;

use crate::curv::BigInt;
use sha2::{Digest, Sha256};
use std::borrow::Borrow;

fn compute_digest<IT>(values: IT) -> Vec<u8>
where
    IT: Iterator,
    IT::Item: Borrow<BigInt>,
{
    let mut digest = Sha256::new();
    for value in values {
        // Assuming BigInt has a method to_bytes() to convert it to a byte vector
        let bytes: Vec<u8> = value.borrow().to_bytes_be();
        digest.update(bytes);
    }
    digest.finalize().to_vec()
}
