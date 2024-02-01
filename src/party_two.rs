/*
    Multi-party ECDSA

    Copyright 2018 by Kzen Networks

    This file is part of Multi-party ECDSA library
    (https://github.com/KZen-networks/multi-party-ecdsa)

    Multi-party ECDSA is free software: you can redistribute
    it and/or modify it under the terms of the GNU General Public
    License as published by the Free Software Foundation, either
    version 3 of the License, or (at your option) any later version.

    @license GPL-3.0+ <https://github.com/KZen-networks/multi-party-ecdsa/blob/master/LICENSE>
*/
use super::SECURITY_BITS;
use crate::curv::arithmetic::traits::*;
use std::any::Any;
use std::fmt::{Display, Formatter};

use crate::curv::cryptographic_primitives::commitments::hash_commitment::HashCommitment;
use crate::curv::cryptographic_primitives::commitments::traits::Commitment;
use crate::curv::cryptographic_primitives::hashing::hash_sha256::HSha256;
use crate::curv::cryptographic_primitives::hashing::traits::Hash;
use crate::curv::cryptographic_primitives::proofs::sigma_dlog::*;
use crate::curv::cryptographic_primitives::proofs::sigma_ec_ddh::*;
use crate::curv::cryptographic_primitives::proofs::ProofError;
use crate::party_one;
use crate::curv::elliptic::curves::traits::*;

use crate::curv::elliptic::curves::secp256_k1::Secp256k1Point;
use crate::curv::BigInt;
use crate::curv::FE;
use crate::curv::GE;
use crate::paillier::traits::{Add, Encrypt, Mul};
use crate::paillier::{EncryptionKey, Paillier, RawCiphertext, RawPlaintext};
use crate::zk_paillier::zkproofs::{RangeProofError, RangeProofNi};

use crate::centipede::juggling::proof_system::{Helgamalsegmented, Witness};
use crate::centipede::juggling::segmentation::Msegmentation;
use serde::{Deserialize, Serialize};
use std::ops::Shl;

use crate::typetag_value;
use crate::typetags::Value;

//****************** Begin: Party Two structs ******************//

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EcKeyPair {
    pub public_share: GE,
    secret_share: FE,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyGenFirstMsg {
    pub d_log_proof: DLogProof,
    pub public_share: GE,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KeyGenSecondMsg {}

#[derive(Debug, Serialize, Deserialize)]
pub struct PaillierPublic {
    pub ek: EncryptionKey,
    pub encrypted_secret_share: BigInt,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PartialSig {
    pub c3: BigInt,
}

#[derive(Serialize, Debug, Deserialize, Clone)]
pub struct Party2Private {
    x2: FE,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EphEcKeyPair2 {
    pub public_share: GE,
    secret_share: FE,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EphCommWitness {
    pub pk_commitment_blind_factor: BigInt,
    pub zk_pok_blind_factor: BigInt,
    pub public_share: GE,
    pub d_log_proof: ECDDHProof,
    pub c: GE, //c = secret_share * base_point2
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EphKeyGenFirstMsg {
    pub pk_commitment: BigInt,
    pub zk_pok_commitment: BigInt,
}

typetag_value!(EphKeyGenFirstMsg);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EphKeyGenSecondMsg {
    pub comm_witness: EphCommWitness,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Party2PDLFirstMessage {
    pub c_tag: BigInt,
    pub c_tag_tag: BigInt,
}

typetag_value!(Party2PDLFirstMessage);

#[derive(Debug, Serialize, Deserialize)]
pub struct Party2PDLDecommit {
    pub a: BigInt,
    pub b: BigInt,
    pub blindness: BigInt,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Party2PDLSecondMessage {
    pub decommit: Party2PDLDecommit,
}

typetag_value!(Party2PDLSecondMessage);

#[derive(Debug)]
pub struct PDLchallenge {
    pub c_tag: BigInt,
    pub c_tag_tag: BigInt,
    a: BigInt,
    b: BigInt,
    blindness: BigInt,
    q_tag: Secp256k1Point,
}

//****************** End: Party Two structs ******************//

impl KeyGenFirstMsg {
    pub fn create() -> (KeyGenFirstMsg, EcKeyPair) {
        let base: GE = ECPoint::generator();
        let secret_share: FE = ECScalar::new_random();
        let public_share = base * secret_share;
        let d_log_proof = DLogProof::prove(&secret_share);
        let ec_key_pair = EcKeyPair {
            public_share,
            secret_share,
        };
        (
            KeyGenFirstMsg {
                d_log_proof,
                public_share,
            },
            ec_key_pair,
        )
    }

    pub fn create_with_fixed_secret_share(secret_share: FE) -> (KeyGenFirstMsg, EcKeyPair) {
        let base: GE = ECPoint::generator();
        let public_share = base * secret_share;
        let d_log_proof = DLogProof::prove(&secret_share);
        let ec_key_pair = EcKeyPair {
            public_share,
            secret_share,
        };
        (
            KeyGenFirstMsg {
                d_log_proof,
                public_share,
            },
            ec_key_pair,
        )
    }
}

impl KeyGenSecondMsg {
    pub fn verify_commitments_and_dlog_proof(
        party_one_first_message: &party_one::KeyGenFirstMsg,
        party_one_second_message: &party_one::KeyGenSecondMsg,
    ) -> Result<KeyGenSecondMsg, ProofError> {
        let party_one_zk_pok_blind_factor =
            &party_one_second_message.comm_witness.zk_pok_blind_factor;
        let party_one_public_share = &party_one_second_message.comm_witness.public_share;
        let party_one_pk_commitment_blind_factor = &party_one_second_message
            .comm_witness
            .pk_commitment_blind_factor;
        let party_one_d_log_proof = &party_one_second_message.comm_witness.d_log_proof;

        let p1_pk_com = HashCommitment::create_commitment_with_user_defined_randomness(
            &party_one_public_share.bytes_compressed_to_big_int(),
            party_one_pk_commitment_blind_factor,
        );
        let pk1_zk_com = HashCommitment::create_commitment_with_user_defined_randomness(
            &party_one_d_log_proof
                .pk_t_rand_commitment
                .bytes_compressed_to_big_int(),
            party_one_zk_pok_blind_factor,
        );
        let valid_coms = p1_pk_com == party_one_first_message.pk_commitment
            && pk1_zk_com == party_one_first_message.zk_pok_commitment;
        if !valid_coms {
            return Err(ProofError {});
        }

        DLogProof::verify(party_one_d_log_proof)?;
        Ok(KeyGenSecondMsg {})
    }
}

pub fn compute_pubkey(local_share: &EcKeyPair, other_share_public_share: &GE) -> GE {
    let pubkey = other_share_public_share;
    pubkey.scalar_mul(&local_share.secret_share.get_element())
}

impl Party2Private {
    pub fn set_private_key(ec_key: &EcKeyPair) -> Party2Private {
        Party2Private {
            x2: ec_key.secret_share,
        }
    }

    pub fn update_private_key(party_two_private: &Party2Private, factor: &BigInt) -> Party2Private {
        let factor_fe: FE = ECScalar::from(factor);
        Party2Private {
            x2: party_two_private.x2.mul(&factor_fe.get_element()),
        }
    }

    // used for verifiable recovery
    pub fn to_encrypted_segment(
        &self,
        segment_size: &usize,
        num_of_segments: usize,
        pub_ke_y: &GE,
        g: &GE,
    ) -> (Witness, Helgamalsegmented) {
        Msegmentation::to_encrypted_segments(&self.x2, segment_size, num_of_segments, pub_ke_y, g)
    }
}

impl PaillierPublic {
    pub fn verify_range_proof(
        paillier_context: &PaillierPublic,
        range_proof: &RangeProofNi,
    ) -> Result<(), RangeProofError> {
        range_proof.verify(
            &paillier_context.ek,
            &paillier_context.encrypted_secret_share,
        )
    }

    pub fn pdl_challenge(&self, other_share_public_share: &GE) -> (Party2PDLFirstMessage, PDLchallenge) {
        let a_fe: FE = ECScalar::new_random();
        let a = a_fe.to_big_int();
        let q = FE::q();
        let q_sq = q.pow(2);
        let b = BigInt::sample_below(&q_sq);
        let b_fe: FE = ECScalar::from(&b);
        let b_enc = Paillier::encrypt(&self.ek, RawPlaintext::from(b.clone()));
        let ac = Paillier::mul(
            &self.ek,
            RawCiphertext::from(self.encrypted_secret_share.clone()),
            RawPlaintext::from(a.clone()),
        );
        let c_tag = Paillier::add(&self.ek, ac, b_enc).0.into_owned();
        let ab_concat = a.clone() + b.clone().shl(a.bit_length());
        let blindness = BigInt::sample_below(&q);
        let c_tag_tag =
            HashCommitment::create_commitment_with_user_defined_randomness(&ab_concat, &blindness);
        let g: GE = ECPoint::generator();
        let q_tag = other_share_public_share.clone() * a_fe + g * b_fe;

        (
            Party2PDLFirstMessage {
                c_tag: c_tag.clone(),
                c_tag_tag: c_tag_tag.clone(),
            },
            PDLchallenge {
                c_tag,
                c_tag_tag,
                a,
                b,
                blindness,
                q_tag,
            },
        )
    }

    pub fn pdl_decommit_c_tag_tag(pdl_chal: &PDLchallenge) -> Party2PDLSecondMessage {
        let decommit = Party2PDLDecommit {
            a: pdl_chal.a.clone(),
            b: pdl_chal.b.clone(),
            blindness: pdl_chal.blindness.clone(),
        };
        Party2PDLSecondMessage { decommit }
    }

    pub fn verify_pdl(
        pdl_chal: &PDLchallenge,
        party_one_pdl_first_message: &party_one::Party1PDLFirstMessage,
        party_one_pdl_second_message: &party_one::Party1PDLSecondMessage,
    ) -> Result<(), ()> {
        let c_hat = party_one_pdl_first_message.c_hat.clone();
        let q_hat = party_one_pdl_second_message.decommit.q_hat.clone();
        let blindness = party_one_pdl_second_message.decommit.blindness.clone();
        let c_hat_test = HashCommitment::create_commitment_with_user_defined_randomness(
            &q_hat.bytes_compressed_to_big_int(),
            &blindness,
        );
        if c_hat.clone() == c_hat_test
            && q_hat.get_element().clone() == pdl_chal.q_tag.get_element().clone()
        {
            Ok(())
        } else {
            Err(())
        }
    }
}

impl EphKeyGenFirstMsg {
    pub fn create_commitments() -> (EphKeyGenFirstMsg, EphCommWitness, EphEcKeyPair2) {
        let base: GE = ECPoint::generator();

        let secret_share: FE = ECScalar::new_random();

        let public_share = base.scalar_mul(&secret_share.get_element());

        let h: GE = GE::base_point2();
        let w = ECDDHWitness { x: secret_share };
        let c = h * secret_share;
        let delta = ECDDHStatement {
            g1: base,
            h1: public_share,
            g2: h,
            h2: c,
        };
        let d_log_proof = ECDDHProof::prove(&w, &delta);

        // we use hash based commitment
        let pk_commitment_blind_factor = BigInt::sample(SECURITY_BITS);
        let pk_commitment = HashCommitment::create_commitment_with_user_defined_randomness(
            &public_share.bytes_compressed_to_big_int(),
            &pk_commitment_blind_factor,
        );

        let zk_pok_blind_factor = BigInt::sample(SECURITY_BITS);
        let zk_pok_commitment = HashCommitment::create_commitment_with_user_defined_randomness(
            &HSha256::create_hash_from_ge(&[&d_log_proof.a1, &d_log_proof.a2]).to_big_int(),
            &zk_pok_blind_factor,
        );

        let ec_key_pair = EphEcKeyPair2 {
            public_share,
            secret_share,
        };
        (
            EphKeyGenFirstMsg {
                pk_commitment,
                zk_pok_commitment,
            },
            EphCommWitness {
                pk_commitment_blind_factor,
                zk_pok_blind_factor,
                public_share: ec_key_pair.public_share,
                d_log_proof,
                c,
            },
            ec_key_pair,
        )
    }
}

impl EphKeyGenSecondMsg {
    pub fn verify_and_decommit(
        comm_witness: EphCommWitness,
        party_one_first_message: &party_one::EphKeyGenFirstMsg,
    ) -> Result<EphKeyGenSecondMsg, ProofError> {
        let delta = ECDDHStatement {
            g1: GE::generator(),
            h1: party_one_first_message.public_share,
            g2: GE::base_point2(),
            h2: party_one_first_message.c,
        };
        party_one_first_message.d_log_proof.verify(&delta)?;
        Ok(EphKeyGenSecondMsg { comm_witness })
    }
}

impl PartialSig {
    pub fn compute(
        ek: &EncryptionKey,
        encrypted_secret_share: &BigInt,
        local_share: &Party2Private,
        ephemeral_local_share: &EphEcKeyPair2,
        ephemeral_other_public_share: &GE,
        message: &BigInt,
    ) -> PartialSig {
        let q = FE::q();
        //compute r = k2* R1
        let mut r: GE = *ephemeral_other_public_share;
        r = r.scalar_mul(&ephemeral_local_share.secret_share.get_element());

        let rx = r.x_coor().unwrap().mod_floor(&q);
        let rho = BigInt::sample_below(&q.pow(2));
        let k2_inv = ephemeral_local_share
            .secret_share
            .to_big_int()
            .invert(&q)
            .unwrap();
        let partial_sig = rho * &q + BigInt::mod_mul(&k2_inv, message, &q);
        let c1 = Paillier::encrypt(ek, RawPlaintext::from(partial_sig));
        let v = BigInt::mod_mul(
            &k2_inv,
            &BigInt::mod_mul(&rx, &local_share.x2.to_big_int(), &q),
            &q,
        );
        let c2 = Paillier::mul(
            ek,
            RawCiphertext::from(encrypted_secret_share.clone()),
            RawPlaintext::from(v),
        );
        //c3:
        PartialSig {
            c3: Paillier::add(ek, c2, c1).0.into_owned(),
        }
    }
}
