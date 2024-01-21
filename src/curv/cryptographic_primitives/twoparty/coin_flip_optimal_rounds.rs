/*
    This file is part of Curv library
    Copyright 2018 by Kzen Networks
    (https://github.com/KZen-networks/curv)
    License MIT: <https://github.com/KZen-networks/curv/blob/master/LICENSE>
*/

use crate::curv::cryptographic_primitives::proofs::sigma_valid_pedersen::PedersenProof;
use crate::curv::cryptographic_primitives::proofs::sigma_valid_pedersen::ProvePederesen;
use crate::curv::cryptographic_primitives::proofs::sigma_valid_pedersen_blind::PedersenBlindingProof;
use crate::curv::cryptographic_primitives::proofs::sigma_valid_pedersen_blind::ProvePederesenBlind;
use crate::curv::elliptic::curves::traits::*;
use crate::curv::{FE, GE};
use serde::{Serialize,Deserialize};

/// based on How To Simulate It – A Tutorial on the Simulation
/// Proof Technique. protocol 7.3: Multiple coin tossing. which provide simulatble constant round
/// coin toss
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct CoinFlipParty1FirstMessage {
    pub proof: PedersenProof,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct CoinFlipParty2FirstMessage {
    pub seed: FE,
}
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct CoinFlipParty1SecondMessage {
    pub proof: PedersenBlindingProof,
    pub seed: FE,
}
impl CoinFlipParty1FirstMessage {
    pub fn commit() -> (CoinFlipParty1FirstMessage, FE, FE) {
        let seed: FE = ECScalar::new_random();
        let blinding: FE = ECScalar::new_random();
        let proof = PedersenProof::prove(&seed, &blinding);
        (CoinFlipParty1FirstMessage { proof }, seed, blinding)
    }
}
impl CoinFlipParty2FirstMessage {
    pub fn share(proof: &PedersenProof) -> CoinFlipParty2FirstMessage {
        PedersenProof::verify(&proof).expect("{(m,r),c} proof failed");
        let seed: FE = ECScalar::new_random();
        CoinFlipParty2FirstMessage { seed }
    }
}
impl CoinFlipParty1SecondMessage {
    pub fn reveal(
        party2seed: &FE,
        party1seed: &FE,
        party1blinding: &FE,
    ) -> (CoinFlipParty1SecondMessage, FE) {
        let proof = PedersenBlindingProof::prove(&party1seed, &party1blinding);
        let coin_flip_result = &party1seed.to_big_int() ^ &party2seed.to_big_int();
        (
            CoinFlipParty1SecondMessage {
                proof,
                seed: party1seed.clone(),
            },
            ECScalar::from(&coin_flip_result),
        )
    }
}

// party2 finalize
pub fn finalize(proof: &PedersenBlindingProof, party2seed: &FE, party1comm: &GE) -> FE {
    PedersenBlindingProof::verify(&proof).expect("{r,(m,c)} proof failed");
    assert_eq!(&proof.com, party1comm);
    let coin_flip_result = &proof.m.to_big_int() ^ &party2seed.to_big_int();
    ECScalar::from(&coin_flip_result)
}

#[cfg(test)]
mod tests {
    use crate::curv::cryptographic_primitives::twoparty::coin_flip_optimal_rounds::*;
    #[test]
    pub fn test_coin_toss() {
        let (party1_first_message, m1, r1) = CoinFlipParty1FirstMessage::commit();
        let party2_first_message = CoinFlipParty2FirstMessage::share(&party1_first_message.proof);
        let (party1_second_message, random1) =
            CoinFlipParty1SecondMessage::reveal(&party2_first_message.seed, &m1, &r1);
        let random2 = finalize(
            &party1_second_message.proof,
            &party2_first_message.seed,
            &party1_first_message.proof.com,
        );
        assert_eq!(random1, random2)
    }
}
