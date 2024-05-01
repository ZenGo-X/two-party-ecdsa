use serde::{Deserialize, Serialize};
use super::Rotation;
use crate::curv::cryptographic_primitives::twoparty::coin_flip_optimal_rounds;
use crate::curv::elliptic::curves::traits::ECScalar;
use crate::{BigInt, EncryptionKey, NICorrectKeyProof, RangeProofNi, typetag_value};
use crate::typetags::Value;

pub struct Rotation1 {}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RotationParty1Message1 {
    pub ek: EncryptionKey,
    pub c_key: BigInt,
    pub c_key_minus_q_thirds: BigInt,
    pub correct_key_proof: NICorrectKeyProof,
    pub range_proof: RangeProofNi,
}

typetag_value!(RotationParty1Message1);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RotationParty1Message2 {
    pub coin_flip_party1_second_message: Option<coin_flip_optimal_rounds::Party1SecondMessage>,
    pub rotation_party1_prev_message: Option<RotationParty1Message1>,
    pub is_valid: bool
}

typetag_value!(RotationParty1Message2);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RotateCommitMessage1 {
    pub seed: BigInt,
    pub blinding: BigInt
}

typetag_value!(RotateCommitMessage1);

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
                seed: seed.to_big_int(),
                blinding: blinding.to_big_int()
            }
        )
    }

    pub fn key_rotate_second_message(
        party2_first_message: &coin_flip_optimal_rounds::Party2FirstMessage,
        rotate_commit_message: &RotateCommitMessage1
    ) -> (coin_flip_optimal_rounds::Party1SecondMessage, Rotation) {
        let (res1, res2) = coin_flip_optimal_rounds::Party1SecondMessage::reveal(
            &party2_first_message.seed,
            &ECScalar::from(&rotate_commit_message.seed),
            &ECScalar::from(&rotate_commit_message.blinding),
        );

        (res1, Rotation { rotation: res2 })
    }
}
