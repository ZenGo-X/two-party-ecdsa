use super::Rotation;
use crate::curv::cryptographic_primitives::twoparty::coin_flip_optimal_rounds;
use crate::curv::elliptic::curves::secp256_k1::{Secp256k1Scalar, GE};
use crate::kms::ecdsa::two_party::party1::RotateCommitMessage1;

pub struct Rotation1 {}

impl Rotation1 {
    //TODO: implmenet sid / state machine
    pub fn key_rotate_first_message() -> (
        coin_flip_optimal_rounds::Party1FirstMessage,
        RotateCommitMessage1
    ) {
        let (party1_first_message, seed, blinding) = coin_flip_optimal_rounds::Party1FirstMessage::commit();
        (
            party1_first_message,
            RotateCommitMessage1 {
                seed,
                blinding
            }
        )
    }

    pub fn key_rotate_second_message(
        party2_first_message: &coin_flip_optimal_rounds::Party2FirstMessage,
        rotate_commit_message: &RotateCommitMessage1
    ) -> (coin_flip_optimal_rounds::Party1SecondMessage, Rotation) {
        let (res1, res2) = coin_flip_optimal_rounds::Party1SecondMessage::reveal(
            &party2_first_message.seed,
            &rotate_commit_message.seed,
            &rotate_commit_message.blinding,
        );

        (res1, Rotation { rotation: res2 })
    }
}
