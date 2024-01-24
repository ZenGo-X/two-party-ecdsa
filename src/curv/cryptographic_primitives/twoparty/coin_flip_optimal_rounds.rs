/*
    This file is part of Curv library
    Copyright 2018 by Kzen Networks
    (https://github.com/KZen-networks/curv)
    License MIT: <https://github.com/KZen-networks/curv/blob/master/LICENSE>
*/

use std::any::Any;
use std::fmt::{Display, Formatter};
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
pub struct CoinFlipParty1FirstMsg {
    pub proof: PedersenProof,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct CoinFlipParty2FirstMsg {
    pub seed: FE,
}
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct CoinFlipParty1SecondMsg {
    pub proof: PedersenBlindingProof,
    pub seed: FE,
}
impl CoinFlipParty1FirstMsg {
    pub fn commit() -> (CoinFlipParty1FirstMsg, FE, FE) {
        let seed: FE = ECScalar::new_random();
        let blinding: FE = ECScalar::new_random();
        let proof = PedersenProof::prove(&seed, &blinding);
        (CoinFlipParty1FirstMsg { proof }, seed, blinding)
    }
}
impl CoinFlipParty2FirstMsg {
    pub fn share(proof: &PedersenProof) -> CoinFlipParty2FirstMsg {
        PedersenProof::verify(&proof).expect("{(m,r),c} proof failed");
        let seed: FE = ECScalar::new_random();
        CoinFlipParty2FirstMsg { seed }
    }
}
impl CoinFlipParty1SecondMsg {
    pub fn reveal(
        party2seed: &FE,
        party1seed: &FE,
        party1blinding: &FE,
    ) -> (CoinFlipParty1SecondMsg, FE) {
        let proof = PedersenBlindingProof::prove(&party1seed, &party1blinding);
        let coin_flip_result = &party1seed.to_big_int() ^ &party2seed.to_big_int();
        (
            CoinFlipParty1SecondMsg {
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
        let (party1_first_message, m1, r1) = CoinFlipParty1FirstMsg::commit();
        let party2_first_message = CoinFlipParty2FirstMsg::share(&party1_first_message.proof);
        let (party1_second_message, random1) =
            CoinFlipParty1SecondMsg::reveal(&party2_first_message.seed, &m1, &r1);
        let random2 = finalize(
            &party1_second_message.proof,
            &party2_first_message.seed,
            &party1_first_message.proof.com,
        );
        assert_eq!(random1, random2)
    }
}
