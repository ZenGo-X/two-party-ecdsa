#![allow(dead_code)]

use crate::curv::elliptic::curves::traits::{ECPoint, ECScalar};

#[cfg(target_arch = "wasm32")]
use crate::log;

use crate::curv::{
    arithmetic::num_bigint::BigInt,
    arithmetic::traits::Converter,
    elliptic::curves::secp256_k1::{Secp256k1Point as Point, Secp256k1Scalar as Scalar},
};

use serde::{Deserialize, Serialize};

use crate::errors::Result;

pub type Key = String;

#[allow(dead_code)]
pub const AES_KEY_BYTES_LEN: usize = 32;

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct AEAD {
    pub ciphertext: Vec<u8>,
    pub tag: Vec<u8>,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct PartySignup {
    pub number: u16,
    pub uuid: String,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct Index {
    pub key: Key,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct Entry {
    pub key: Key,
    pub value: String,
}

#[derive(Serialize, Deserialize)]
pub struct Params {
    pub parties: String,
    pub threshold: String,
}

#[cfg(target_arch = "wasm32")]
pub async fn sleep(ms: u32) {
    let promise = js_sys::Promise::new(&mut |resolve, _| {
        web_sys::window()
            .unwrap()
            .set_timeout_with_callback_and_timeout_and_arguments_0(&resolve, ms as i32)
            .unwrap();
    });
    wasm_bindgen_futures::JsFuture::from(promise).await;
}

#[cfg(not(target_arch = "wasm32"))]
pub async fn sleep(ms: u32) {
    std::thread::sleep(core::time::Duration::from_millis(ms as u64));
}

pub fn check_sig(r: &Scalar, s: &Scalar, msg: &BigInt, pk: &Point) -> Result<bool> {
    let r_vec = BigInt::to_vec(&r.to_big_int());
    let s_vec = BigInt::to_vec(&s.to_big_int());

    let mut signature_a = [0u8; 64];
    for i in 0..32 {
        signature_a[i] = r_vec[i];
    }
    for i in 0..32 {
        signature_a[i + 32] = s_vec[i];
    }

    let signature = secp256k1::Signature::parse(&signature_a);

    let msg_vec = BigInt::to_vec(msg);

    let message = secp256k1::Message::parse(&msg_vec.try_into().unwrap());

    let pubkey_a = pk.get_element().serialize();

    let pubkey = secp256k1::PublicKey::parse(&pubkey_a)?;

    #[cfg(target_arch = "wasm32")]
    crate::console_log!("pubkey: {:?}", pubkey);
    #[cfg(target_arch = "wasm32")]
    crate::console_log!(
        "address: {:?}",
        checksum(&hex::encode(public_key_address(&pubkey)))
    );
    Ok(secp256k1::verify(&message, &signature, &pubkey))
}
