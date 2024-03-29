use std::any::Any;
use std::fmt::{Display, Formatter};
use serde::{Deserialize, Serialize};
use crate::curv::arithmetic::traits::Converter;
use crate::curv::cryptographic_primitives::hashing::{hmac_sha512, traits::KeyedHash};
use crate::curv::elliptic::curves::traits::{ECPoint, ECScalar};
use crate::curv::{BigInt, FE, GE};
use crate::{paillier::EncryptionKey, party_one, party_two};
use crate::kms::chain_code::two_party::party1::ChainCode1;
use crate::party_one::Value;

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct Party1Public {
    pub q: GE,
    pub p1: GE,
    pub p2: GE,
    pub paillier_pub: EncryptionKey,
    pub c_key: BigInt,
}

#[derive(Clone,Debug,Serialize, Deserialize)]
pub struct MasterKey1 {
    pub public: Party1Public,
    // Why is the field below public? See: https://github.com/KZen-networks/kms-secp256k1/issues/20
    pub private: party_one::Party1Private,
    chain_code: BigInt,
}
#[typetag::serde]
impl Value for MasterKey1 {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn type_name(&self) -> &str {
        "MasterKey1"
    }
}

impl Display for MasterKey1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct Party2Public {
    pub q: GE,
    pub p2: GE,
    pub p1: GE,
    pub paillier_pub: EncryptionKey,
    pub c_key: BigInt,
}

#[derive(Serialize, Deserialize)]
pub struct MasterKey2 {
    pub public: Party2Public,
    pub private: party_two::Party2Private,
    pub chain_code: BigInt,
}

pub mod party1;
pub mod party2;
mod test;

pub fn hd_key(
    mut location_in_hir: Vec<BigInt>,
    pubkey: &GE,
    chain_code_bi: &BigInt,
) -> (GE, FE, GE) {
    let mask = BigInt::from(2i32).pow(256) - BigInt::one();
    // let public_key = self.public.q.clone();

    // calc first element:
    let first = location_in_hir.remove(0);
    let pub_key_bi = pubkey.bytes_compressed_to_big_int();
    let f = hmac_sha512::HMacSha512::create_hmac(chain_code_bi, &[&pub_key_bi, &first]);
    let f_l = &f >> 256;
    let f_r = &f & &mask;
    let f_l_fe: FE = ECScalar::from(&f_l);
    let f_r_fe: FE = ECScalar::from(&f_r);

    let bn_to_slice = BigInt::to_vec(chain_code_bi);
    let chain_code = GE::from_bytes(&bn_to_slice[1..33]).unwrap() * f_r_fe;
    let pub_key = pubkey * &f_l_fe;

    let (public_key_new_child, f_l_new, cc_new) =
        location_in_hir
            .iter()
            .fold((pub_key, f_l_fe, chain_code), |acc, index| {
                let pub_key_bi = acc.0.bytes_compressed_to_big_int();
                let f = hmac_sha512::HMacSha512::create_hmac(
                    &acc.2.bytes_compressed_to_big_int(),
                    &[&pub_key_bi, index],
                );
                let f_l = &f >> 256;
                let f_r = &f & &mask;
                let f_l_fe: FE = ECScalar::from(&f_l);
                let f_r_fe: FE = ECScalar::from(&f_r);

                (acc.0 * f_l_fe, f_l_fe * acc.1, acc.2 * f_r_fe)
            });
    (public_key_new_child, f_l_new, cc_new)
}
