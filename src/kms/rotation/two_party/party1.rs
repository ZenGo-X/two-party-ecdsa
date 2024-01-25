use super::Rotation;
use crate::curv::cryptographic_primitives::twoparty::coin_flip_optimal_rounds;
use crate::curv::elliptic::curves::secp256_k1::{Secp256k1Scalar, GE};


pub struct Rotation1 {}

impl Rotation1 {
    //TODO: implmenet sid / state machine
    pub fn key_rotate_first_message() -> (
        coin_flip_optimal_rounds::CFParty1FirstMessage,
        Secp256k1Scalar,
        Secp256k1Scalar,
    ) {
        coin_flip_optimal_rounds::CFParty1FirstMessage::commit()
    }

    pub fn key_rotate_second_message(
        party2_first_message: &coin_flip_optimal_rounds::CFParty2FirstMessage,
        m1: &Secp256k1Scalar,
        r1: &Secp256k1Scalar,
    ) -> (coin_flip_optimal_rounds::CFParty1SecondMessage, Rotation) {
        let (res1, res2) = coin_flip_optimal_rounds::CFParty1SecondMessage::reveal(
            &party2_first_message.seed,
            m1,
            r1,
        );

        (res1, Rotation { rotation: res2 })
    }
}