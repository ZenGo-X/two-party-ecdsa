use super::Rotation;
use crate::curv::cryptographic_primitives::twoparty::coin_flip_optimal_rounds;
use crate::curv::cryptographic_primitives::twoparty::coin_flip_optimal_rounds::{CoinFlipParty1FirstMsg, CoinFlipParty1SecondMsg, CoinFlipParty2FirstMsg};
use crate::curv::elliptic::curves::secp256_k1::{Secp256k1Scalar, GE};


pub struct RotationParty1 {}

pub struct RotationParty1FirstMsg {
    pub coin_flip: CoinFlipParty1FirstMsg,
    pub seed: Secp256k1Scalar,
    pub blinding: Secp256k1Scalar
}

pub struct RotationParty1SecondMsg {
    pub coin_flip: CoinFlipParty1SecondMsg,
    pub rotation: Rotation
}



impl RotationParty1 {
    //TODO: implmenet sid / state machine
    pub fn key_rotate_first_message() -> RotationParty1FirstMsg {
        let (coin_flip, seed, blinding) = coin_flip_optimal_rounds::CoinFlipParty1FirstMsg::commit();

        RotationParty1FirstMsg{
            coin_flip,
            seed,
            blinding
        }
    }

    pub fn key_rotate_second_message(
        party2_first_message: &CoinFlipParty2FirstMsg,
        party1_seed: &Secp256k1Scalar,
        party1_blinding: &Secp256k1Scalar,
    ) -> RotationParty1SecondMsg {
        let (coin_flip, result) = CoinFlipParty1SecondMsg::reveal(
            &party2_first_message.seed,
            party1_seed,
            party1_blinding,
        );

        RotationParty1SecondMsg {
            coin_flip,
            rotation: Rotation { scalar: result }
        }
    }
}