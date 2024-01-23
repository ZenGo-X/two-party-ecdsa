use std::any::Any;
use std::fmt::{Display, Formatter};
use serde::{Deserialize, Serialize};
use crate::curv::cryptographic_primitives::{
    proofs::sigma_dlog::DLogProof,
    twoparty::dh_key_exchange_variant_with_pok_comm::{
        compute_pubkey, CommWitnessDHPoK, EcKeyPairDHPoK, Party1FirstMessage, Party1SecondMessage,
    },
};
use crate::curv::{elliptic::curves::traits::ECPoint, BigInt, GE};
use crate::party_one::{PDLdecommit, v};

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct ChainCode1 {
    pub chain_code: BigInt,
}


impl ChainCode1 {
    pub fn chain_code_first_message() -> (Party1FirstMessage, CommWitnessDHPoK, EcKeyPairDHPoK) {
        Party1FirstMessage::create_commitments()
    }
    pub fn chain_code_second_message(
        comm_witness: CommWitnessDHPoK,
        proof: &DLogProof,
    ) -> Party1SecondMessage {
        Party1SecondMessage::verify_and_decommit(comm_witness, proof).expect("")
    }
    pub fn compute_chain_code(
        ec_key_pair: &EcKeyPairDHPoK,
        party2_first_message_public_share: &GE,
    ) -> ChainCode1 {
        ChainCode1 {
            chain_code: compute_pubkey(ec_key_pair, party2_first_message_public_share)
                .bytes_compressed_to_big_int(),
        }
    }
}
