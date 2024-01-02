/*
    KMS
    Copyright 2018 by Kzen Networks
    This file is part of KMS library
    (https://github.com/KZen-networks/kms)
    Cryptography utilities is free software: you can redistribute
    it and/or modify it under the terms of the GNU General Public
    License as published by the Free Software Foundation, either
    version 3 of the License, or (at your option) any later version.
    @license GPL-3.0+ <https://github.com/KZen-networks/kms/blob/master/LICENSE>
*/
#![allow(non_snake_case)]
#![cfg(test)]
use sha2::Sha512;
use hmac::{Hmac, Mac};
use zeroize::Zeroize;

pub struct HMacSha512;

use super::{MasterKey1, MasterKey2};
use crate::kms::chain_code::two_party::{party1, party2};
use crate::curv::{BigInt, FE, GE};
pub use crate::kms::rotation::two_party::party1::Rotation1;
pub use crate::kms::rotation::two_party::party2::Rotation2;
pub use crate::kms::rotation::two_party::Rotation;
#[test]
fn test_get_child() {
    // compute master keys:
    let (party_one_master_key, party_two_master_key) = test_key_gen();

    let new_party_two_master_key =
        party_two_master_key.get_child(vec![BigInt::from(10), BigInt::from(5)]);
    let new_party_one_master_key =
        party_one_master_key.get_child(vec![BigInt::from(10), BigInt::from(5)]);
    assert_eq!(
        new_party_one_master_key.public.q,
        new_party_two_master_key.public.q
    );

    //test signing:
    let message = BigInt::from(1234);
    let (sign_party_two_first_message, eph_comm_witness, eph_ec_key_pair_party2) =
        MasterKey2::sign_first_message();
    let (sign_party_one_first_message, eph_ec_key_pair_party1) = MasterKey1::sign_first_message();
    let sign_party_two_second_message = party_two_master_key.sign_second_message(
        &eph_ec_key_pair_party2,
        eph_comm_witness,
        &sign_party_one_first_message,
        &message,
    );
    let sign_party_one_second_message = party_one_master_key.sign_second_message(
        &sign_party_two_second_message,
        &sign_party_two_first_message,
        &eph_ec_key_pair_party1,
        &message,
    );
    sign_party_one_second_message.expect("bad signature");

    // test sign for child
    let message = BigInt::from(1234);
    let (sign_party_two_first_message, eph_comm_witness, eph_ec_key_pair_party2) =
        MasterKey2::sign_first_message();
    let (sign_party_one_first_message, eph_ec_key_pair_party1) = MasterKey1::sign_first_message();
    let sign_party_two_second_message = new_party_two_master_key.sign_second_message(
        &eph_ec_key_pair_party2,
        eph_comm_witness,
        &sign_party_one_first_message,
        &message,
    );
    let sign_party_one_second_message = new_party_one_master_key.sign_second_message(
        &sign_party_two_second_message,
        &sign_party_two_first_message,
        &eph_ec_key_pair_party1,
        &message,
    );
    sign_party_one_second_message.expect("bad signature");
}

pub fn test_key_gen() -> (MasterKey1, MasterKey2) {
    // key gen
    let (kg_party_one_first_message, kg_comm_witness, kg_ec_key_pair_party1) =
        MasterKey1::key_gen_first_message();
    let (kg_party_two_first_message, kg_ec_key_pair_party2) = MasterKey2::key_gen_first_message();
    let (kg_party_one_second_message, party_one_paillier_key_pair, party_one_private) =
        MasterKey1::key_gen_second_message(
            &kg_comm_witness.clone(),
            &kg_ec_key_pair_party1,
            &kg_party_two_first_message.d_log_proof,
        );

    let key_gen_second_message = MasterKey2::key_gen_second_message(
        &kg_party_one_first_message,
        &kg_party_one_second_message,
    );

    assert!(key_gen_second_message.is_ok());

    let (_, party_two_paillier, _) = key_gen_second_message.unwrap();

    // chain code
    let (cc_party_one_first_message, cc_comm_witness, cc_ec_key_pair1) =
        party1::ChainCode1::chain_code_first_message();
    let (cc_party_two_first_message, cc_ec_key_pair2) =
        party2::ChainCode2::chain_code_first_message();
    let cc_party_one_second_message = party1::ChainCode1::chain_code_second_message(
        cc_comm_witness,
        &cc_party_two_first_message.d_log_proof,
    );

    let cc_party_two_second_message = party2::ChainCode2::chain_code_second_message(
        &cc_party_one_first_message,
        &cc_party_one_second_message,
    );
    assert!(cc_party_two_second_message.is_ok());

    let party1_cc = party1::ChainCode1::compute_chain_code(
        &cc_ec_key_pair1,
        &cc_party_two_first_message.public_share,
    );

    let party2_cc = party2::ChainCode2::compute_chain_code(
        &cc_ec_key_pair2,
        &cc_party_one_second_message.comm_witness.public_share,
    );
    // set master keys:
    let party_one_master_key = MasterKey1::set_master_key(
        &party1_cc.chain_code,
        party_one_private,
        &kg_comm_witness.public_share,
        &kg_party_two_first_message.public_share,
        party_one_paillier_key_pair,
    );

    let party_two_master_key = MasterKey2::set_master_key(
        &party2_cc.chain_code,
        &kg_ec_key_pair_party2,
        &kg_party_one_second_message
            .ecdh_second_message
            .comm_witness
            .public_share,
        &party_two_paillier,
    );
    (party_one_master_key, party_two_master_key)
}


fn compute_hmac(key: &BigInt, input: &str) -> BigInt {
    //init key
    let mut key_bytes: Vec<u8> = key.into();
    let mut ctx = Hmac::<Sha512>::new_from_slice(&key_bytes).expect("HMAC can take key of any size");

    //hash input
    ctx.update(input.as_ref());
    key_bytes.zeroize();
    BigInt::from(ctx.finalize().into_bytes().as_ref())
}



