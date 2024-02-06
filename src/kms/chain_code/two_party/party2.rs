use crate::curv::cryptographic_primitives::{
    proofs::ProofError,
    twoparty::dh_key_exchange_variant_with_pok_comm::{
        compute_pubkey, DHPoKEcKeyPair, DHPoKParty1FirstMessage, DHPoKParty1SecondMessage,
        DHPoKParty2FirstMessage, DHPoKParty2SecondMessage,
    },
};
use crate::curv::{elliptic::curves::traits::ECPoint, BigInt, GE};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct ChainCode2 {
    pub chain_code: BigInt,
}

impl ChainCode2 {
    pub fn chain_code_first_message() -> (DHPoKParty2FirstMessage, DHPoKEcKeyPair) {
        DHPoKParty2FirstMessage::create()
    }

    pub fn chain_code_second_message(
        party_one_first_message: &DHPoKParty1FirstMessage,
        party_one_second_message: &DHPoKParty1SecondMessage,
    ) -> Result<DHPoKParty2SecondMessage, ProofError> {
        DHPoKParty2SecondMessage::verify_commitments_and_dlog_proof(
            party_one_first_message,
            party_one_second_message,
        )
    }

    pub fn compute_chain_code(
        ec_key_pair: &DHPoKEcKeyPair,
        party1_second_message_public_share: &GE,
    ) -> ChainCode2 {
        ChainCode2 {
            chain_code: compute_pubkey(ec_key_pair, party1_second_message_public_share)
                .bytes_compressed_to_big_int(),
        }
    }
}
