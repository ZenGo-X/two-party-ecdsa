/*
    This file is part of Curv library
    Copyright 2018 by Kzen Networks
    (https://github.com/KZen-networks/curv)
    License MIT: <https://github.com/KZen-networks/curv/blob/master/LICENSE>
*/

/// in ECDH Alice chooses at random a secret "a" and sends Bob public key A = aG
/// Bob chooses at random a secret "b" and sends to Alice B = bG.
/// Both parties can compute a joint secret: C =aB = bA = abG which cannot be computed by
/// a man in the middle attacker.
///
/// The variant below is to protect not only from man in the middle but also from malicious
/// Alice or Bob that can bias the result. The details of the protocol can be found in
/// https://eprint.iacr.org/2017/552.pdf protocol 3.1 first 3 steps.
use crate::curv::arithmetic::traits::Samplable;
use crate::curv::cryptographic_primitives::commitments::hash_commitment::HashCommitment;
use crate::curv::cryptographic_primitives::commitments::traits::Commitment;
use crate::curv::cryptographic_primitives::proofs::sigma_dlog::*;
use crate::curv::cryptographic_primitives::proofs::ProofError;
use crate::curv::elliptic::curves::traits::*;
use crate::curv::BigInt;
use crate::curv::FE;
use crate::curv::GE;
use crate::typetag_value;
use crate::typetags::Value;
use serde::{Deserialize, Serialize};
use std::any::Any;
use std::fmt::{Display, Formatter};

const SECURITY_BITS: usize = 256;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DHPoKEcKeyPair {
    pub public_share: GE,
    secret_share: FE,
}

typetag_value!(DHPoKEcKeyPair);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DHPoKCommWitness {
    pub pk_commitment_blind_factor: BigInt,
    pub zk_pok_blind_factor: BigInt,
    pub public_share: GE,
    pub d_log_proof: DLogProof,
}

typetag_value!(DHPoKCommWitness);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DHPoKParty1FirstMessage {
    pub pk_commitment: BigInt,
    pub zk_pok_commitment: BigInt,
}

typetag_value!(DHPoKParty1FirstMessage);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DHPoKParty2FirstMessage {
    pub d_log_proof: DLogProof,
    pub public_share: GE,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DHPoKParty1SecondMessage {
    pub comm_witness: DHPoKCommWitness,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DHPoKParty2SecondMessage {}

impl DHPoKParty1FirstMessage {
    pub fn create_commitments() -> (DHPoKParty1FirstMessage, DHPoKCommWitness, DHPoKEcKeyPair) {
        let base: GE = ECPoint::generator();

        let secret_share: FE = ECScalar::new_random();

        let public_share = base.scalar_mul(&secret_share.get_element());

        let d_log_proof = DLogProof::prove(&secret_share);
        // we use hash based commitment
        let pk_commitment_blind_factor = BigInt::sample(SECURITY_BITS);
        let pk_commitment = HashCommitment::create_commitment_with_user_defined_randomness(
            &public_share.bytes_compressed_to_big_int(),
            &pk_commitment_blind_factor,
        );

        let zk_pok_blind_factor = BigInt::sample(SECURITY_BITS);
        let zk_pok_commitment = HashCommitment::create_commitment_with_user_defined_randomness(
            &d_log_proof
                .pk_t_rand_commitment
                .bytes_compressed_to_big_int(),
            &zk_pok_blind_factor,
        );
        let ec_key_pair = DHPoKEcKeyPair {
            public_share,
            secret_share,
        };
        (
            DHPoKParty1FirstMessage {
                pk_commitment,
                zk_pok_commitment,
            },
            DHPoKCommWitness {
                pk_commitment_blind_factor,
                zk_pok_blind_factor,
                public_share: ec_key_pair.public_share,
                d_log_proof,
            },
            ec_key_pair,
        )
    }

    pub fn create_commitments_with_fixed_secret_share(
        secret_share: FE,
    ) -> (DHPoKParty1FirstMessage, DHPoKCommWitness, DHPoKEcKeyPair) {
        let base: GE = ECPoint::generator();
        let public_share = base * secret_share;

        let d_log_proof = DLogProof::prove(&secret_share);

        let pk_commitment_blind_factor = BigInt::sample(SECURITY_BITS);
        let pk_commitment = HashCommitment::create_commitment_with_user_defined_randomness(
            &public_share.bytes_compressed_to_big_int(),
            &pk_commitment_blind_factor,
        );

        let zk_pok_blind_factor = BigInt::sample(SECURITY_BITS);
        let zk_pok_commitment = HashCommitment::create_commitment_with_user_defined_randomness(
            &d_log_proof
                .pk_t_rand_commitment
                .bytes_compressed_to_big_int(),
            &zk_pok_blind_factor,
        );

        let ec_key_pair = DHPoKEcKeyPair {
            public_share,
            secret_share,
        };
        (
            DHPoKParty1FirstMessage {
                pk_commitment,
                zk_pok_commitment,
            },
            DHPoKCommWitness {
                pk_commitment_blind_factor,
                zk_pok_blind_factor,
                public_share: ec_key_pair.public_share,
                d_log_proof,
            },
            ec_key_pair,
        )
    }
}

impl DHPoKParty1SecondMessage {
    pub fn verify_and_decommit(
        comm_witness: DHPoKCommWitness,
        proof: &DLogProof,
    ) -> Result<DHPoKParty1SecondMessage, ProofError> {
        DLogProof::verify(proof)?;
        Ok(DHPoKParty1SecondMessage { comm_witness })
    }
}
impl DHPoKParty2FirstMessage {
    pub fn create() -> (DHPoKParty2FirstMessage, DHPoKEcKeyPair) {
        let base: GE = ECPoint::generator();
        let secret_share: FE = ECScalar::new_random();
        let public_share = base * secret_share;
        let d_log_proof = DLogProof::prove(&secret_share);
        let ec_key_pair = DHPoKEcKeyPair {
            public_share,
            secret_share,
        };
        (
            DHPoKParty2FirstMessage {
                d_log_proof,
                public_share,
            },
            ec_key_pair,
        )
    }

    pub fn create_with_fixed_secret_share(
        secret_share: FE,
    ) -> (DHPoKParty2FirstMessage, DHPoKEcKeyPair) {
        let base: GE = ECPoint::generator();
        let public_share = base * secret_share;
        let d_log_proof = DLogProof::prove(&secret_share);
        let ec_key_pair = DHPoKEcKeyPair {
            public_share,
            secret_share,
        };
        (
            DHPoKParty2FirstMessage {
                d_log_proof,
                public_share,
            },
            ec_key_pair,
        )
    }
}

impl DHPoKParty2SecondMessage {
    pub fn verify_commitments_and_dlog_proof(
        party_one_first_message: &DHPoKParty1FirstMessage,
        party_one_second_message: &DHPoKParty1SecondMessage,
    ) -> Result<DHPoKParty2SecondMessage, ProofError> {
        let party_one_pk_commitment = &party_one_first_message.pk_commitment;
        let party_one_zk_pok_commitment = &party_one_first_message.zk_pok_commitment;
        let party_one_zk_pok_blind_factor =
            &party_one_second_message.comm_witness.zk_pok_blind_factor;
        let party_one_public_share = &party_one_second_message.comm_witness.public_share;
        let party_one_pk_commitment_blind_factor = &party_one_second_message
            .comm_witness
            .pk_commitment_blind_factor;
        let party_one_d_log_proof = &party_one_second_message.comm_witness.d_log_proof;

        let mut flag = true;
        if party_one_pk_commitment
            != &HashCommitment::create_commitment_with_user_defined_randomness(
                &party_one_public_share.bytes_compressed_to_big_int(),
                &party_one_pk_commitment_blind_factor,
            )
        {
            flag = false
        };

        if party_one_zk_pok_commitment
            != &HashCommitment::create_commitment_with_user_defined_randomness(
                &party_one_d_log_proof
                    .pk_t_rand_commitment
                    .bytes_compressed_to_big_int(),
                &party_one_zk_pok_blind_factor,
            )
        {
            flag = false
        };

        assert!(flag);
        DLogProof::verify(&party_one_d_log_proof)?;
        Ok(DHPoKParty2SecondMessage {})
    }
}
pub fn compute_pubkey(local_share: &DHPoKEcKeyPair, other_share_public_share: &GE) -> GE {
    other_share_public_share * &local_share.secret_share
}

#[cfg(test)]
mod tests {
    use crate::curv::cryptographic_primitives::twoparty::dh_key_exchange_variant_with_pok_comm::*;

    #[test]
    fn test_dh_key_exchange() {
        let (kg_party_one_first_message, kg_comm_witness, kg_ec_key_pair_party1) =
            DHPoKParty1FirstMessage::create_commitments();
        let (kg_party_two_first_message, kg_ec_key_pair_party2) = DHPoKParty2FirstMessage::create();
        let kg_party_one_second_message = DHPoKParty1SecondMessage::verify_and_decommit(
            kg_comm_witness,
            &kg_party_two_first_message.d_log_proof,
        )
        .expect("failed to verify and decommit");

        let _kg_party_two_second_message = DHPoKParty2SecondMessage::verify_commitments_and_dlog_proof(
            &kg_party_one_first_message,
            &kg_party_one_second_message,
        )
        .expect("failed to verify commitments and DLog proof");

        assert_eq!(
            compute_pubkey(
                &kg_ec_key_pair_party2,
                &kg_party_one_second_message.comm_witness.public_share
            ),
            compute_pubkey(
                &kg_ec_key_pair_party1,
                &kg_party_two_first_message.public_share
            )
        );
    }
}
