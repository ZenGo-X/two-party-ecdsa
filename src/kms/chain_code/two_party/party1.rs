use std::any::Any;
use std::fmt::{Display, Formatter};
use serde::{Deserialize, Serialize};
use crate::curv::cryptographic_primitives::{
    proofs::sigma_dlog::DLogProof,
    twoparty::dh_key_exchange_variant_with_pok_comm::{
        compute_pubkey, CommWitness, EcKeyPair, Party1FirstMessage, Party1SecondMessage,
    },
};
use crate::curv::{elliptic::curves::traits::ECPoint, BigInt, GE};
use crate::party_one::{PDLdecommit, v, Value};

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct ChainCode1 {
    pub chain_code: BigInt,
}
#[typetag::serde]
impl Value for ChainCode1 {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl Display for ChainCode1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}
impl ChainCode1 {
    pub fn chain_code_first_message() -> (Party1FirstMessage, CommWitness, EcKeyPair) {
        Party1FirstMessage::create_commitments()
    }
    pub fn chain_code_second_message(
        comm_witness: CommWitness,
        proof: &DLogProof,
    ) -> Party1SecondMessage {
        Party1SecondMessage::verify_and_decommit(comm_witness, proof).expect("")
    }
    pub fn compute_chain_code(
        ec_key_pair: &EcKeyPair,
        party2_first_message_public_share: &GE,
    ) -> ChainCode1 {
        ChainCode1 {
            chain_code: compute_pubkey(ec_key_pair, party2_first_message_public_share)
                .bytes_compressed_to_big_int(),
        }
    }
}
