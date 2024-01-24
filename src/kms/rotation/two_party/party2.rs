use crate::curv::cryptographic_primitives::twoparty::coin_flip_optimal_rounds;
use crate::curv::cryptographic_primitives::twoparty::coin_flip_optimal_rounds::{CoinFlipParty1FirstMsg, CoinFlipParty1SecondMsg, CoinFlipParty2FirstMsg, finalize};
use crate::curv::elliptic::curves::secp256_k1::GE;

use super::Rotation;

pub struct RotationParty2 {}


pub struct RotationParty2FirstMsg {
    pub coin_flip: CoinFlipParty2FirstMsg
}

impl RotationParty2 {
    pub fn key_rotate_first_message(
        party1_first_message: &CoinFlipParty1FirstMsg,
    ) -> RotationParty2FirstMsg {
        let coin_flip = CoinFlipParty2FirstMsg::share(&party1_first_message.proof);
        RotationParty2FirstMsg { coin_flip }
    }

    pub fn key_rotate_second_message(
        party1_second_message: &CoinFlipParty1SecondMsg,
        party2_first_message: &CoinFlipParty2FirstMsg,
        party1_first_message: &CoinFlipParty1FirstMsg,
    ) -> Rotation {
        let rotation = finalize(
            &party1_second_message.proof,
            &party2_first_message.seed,
            &party1_first_message.proof.com,
        );
        Rotation { scalar: rotation }
    }
}