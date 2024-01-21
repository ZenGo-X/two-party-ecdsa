use crate::curv::cryptographic_primitives::twoparty::coin_flip_optimal_rounds;
use crate::curv::elliptic::curves::secp256_k1::GE;

use super::Rotation;

pub struct Rotation2 {}

impl Rotation2 {
    pub fn key_rotate_first_message(
        party1_first_message: &coin_flip_optimal_rounds::CoinFlipParty1FirstMessage,
    ) -> coin_flip_optimal_rounds::CoinFlipParty2FirstMessage {
        coin_flip_optimal_rounds::CoinFlipParty2FirstMessage::share(&party1_first_message.proof)
    }

    pub fn key_rotate_second_message(
        party1_second_message: &coin_flip_optimal_rounds::CoinFlipParty1SecondMessage,
        party2_first_message: &coin_flip_optimal_rounds::CoinFlipParty2FirstMessage,
        party1_first_message: &coin_flip_optimal_rounds::CoinFlipParty1FirstMessage,
    ) -> Rotation {
        let rotation = coin_flip_optimal_rounds::finalize(
            &party1_second_message.proof,
            &party2_first_message.seed,
            &party1_first_message.proof.com,
        );
        Rotation { rotation }
    }
}