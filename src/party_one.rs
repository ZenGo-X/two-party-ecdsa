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
use crate::paillier::Paillier;
use crate::paillier::{Decrypt, EncryptWithChosenRandomness, KeyGeneration};
use crate::paillier::{DecryptionKey, EncryptionKey, Randomness, RawCiphertext, RawPlaintext};
use crate::zk_paillier::zkproofs::{NICorrectKeyProof, RangeProofNi};
use serde::{Deserialize, Serialize};
use std::cmp;
use std::fmt::{Debug, Display, Formatter};
use std::ops::{Mul, Shl};

use super::{typetag_value, SECURITY_BITS, Secp256k1Scalar};
pub use crate::curv::arithmetic::traits::*;

use crate::curv::elliptic::curves::traits::*;

use crate::curv::cryptographic_primitives::commitments::hash_commitment::HashCommitment;
use crate::curv::cryptographic_primitives::commitments::traits::Commitment;
use crate::curv::cryptographic_primitives::hashing::hash_sha256::HSha256;
use crate::curv::cryptographic_primitives::hashing::traits::Hash;
pub use crate::curv::cryptographic_primitives::proofs::sigma_dlog::*;
use crate::curv::cryptographic_primitives::proofs::sigma_ec_ddh::*;
use crate::curv::cryptographic_primitives::proofs::ProofError;
use crate::party_two::{Party2EphKeyGenFirstMessage, Party2EphKeyGenSecondMessage, Party2PDLFirstMessage, Party2PDLSecondMessage};

use crate::centipede::juggling::proof_system::{Helgamalsegmented, Witness};
use crate::centipede::juggling::segmentation::Msegmentation;

use crate::curv::BigInt;
use crate::curv::FE;
use crate::curv::GE;

use crate::typetags::Value;
use crate::Error::{self, InvalidSig};


#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct Party1HDPos {
    pub pos: u32,
}

typetag_value!(Party1HDPos);

//****************** Begin: Party One structs ******************//
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Party1EcKeyPair {
    pub public_share: GE,
    secret_share: FE,
}

typetag_value!(Party1EcKeyPair);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Party1CommWitness {
    pub pk_commitment_blind_factor: BigInt,
    pub zk_pok_blind_factor: BigInt,
    pub public_share: GE,
    pub d_log_proof: DLogProof,
}

typetag_value!(Party1CommWitness);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Party1KeyGenFirstMessage {
    pub pk_commitment: BigInt,
    pub zk_pok_commitment: BigInt,
}

typetag_value!(Party1KeyGenFirstMessage);

#[derive(Debug, Serialize, Deserialize)]
pub struct Party1KeyGenCommWitness {
    pub comm_witness: Party1CommWitness,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Party1PaillierKeyPair {
    pub ek: EncryptionKey,
    dk: DecryptionKey,
    pub encrypted_share: BigInt,
    pub encrypted_share_minus_q_thirds: Option<BigInt>,
    randomness: BigInt,
    randomness_q: Option<BigInt>,
}

typetag_value!(Party1PaillierKeyPair);

#[derive(Debug, Serialize, Deserialize)]
pub struct Party1KeyGenSecondMessage {
    pub ecdh_second_message: Party1KeyGenCommWitness,
    pub ek: EncryptionKey,
    pub c_key: BigInt,
    pub old_ek: EncryptionKey,
    pub old_c_key: BigInt,
    pub correct_key_proof: NICorrectKeyProof,
    pub range_proof: RangeProofNi,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Party1SignatureRecid {
    pub s: BigInt,
    pub r: BigInt,
    pub recid: u8,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Party1Signature {
    pub s: BigInt,
    pub r: BigInt,
}

#[derive(Serialize, Debug, Deserialize, Clone)]
pub struct Party1Private {
    x1: FE,
    x1_minus_q_thirds: Option<FE>,
    paillier_priv: DecryptionKey,
    c_key_randomness: BigInt,
}

typetag_value!(Party1Private);

#[derive(Debug, Serialize, Deserialize)]
pub struct Party1PDLFirstMessage {
    pub c_hat: BigInt,
}

typetag_value!(Party1PDLFirstMessage);


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Party1PDLDecommit {
    pub q_hat: GE,
    pub blindness: BigInt,
}

typetag_value!(Party1PDLDecommit);

#[derive(Debug, Serialize, Deserialize)]
pub struct Party1PDLSecondMessage {
    pub decommit: Party1PDLDecommit,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Party1EphEcKeyPair {
    pub public_share: GE,
    secret_share: FE,
}

typetag_value!(Party1EphEcKeyPair);

#[derive(Debug, Serialize, Deserialize)]
pub struct Party1EphKeyGenFirstMessage {
    pub d_log_proof: ECDDHProof,
    pub public_share: GE,
    pub c: GE, //c = secret_share * base_point2
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Party1EphKeyGenSecondMessage {}

//****************** End: Party One structs ******************//

impl Party1KeyGenFirstMessage {
    //in Lindell's protocol range proof works only for x1 \in {q/3 , ... , 2q/3}
    pub fn get_lindell_secret_share_bounds() -> (BigInt, BigInt) {
        let lower_bound: BigInt = FE::q().div_floor(&BigInt::from(3));
        let upper_bound: BigInt = lower_bound.clone().mul(&BigInt::from(2));
        (lower_bound, upper_bound)
    }

    pub fn get_secret_share_in_range(lower_bound: &BigInt, upper_bound: &BigInt) -> FE {
        ECScalar::from(&BigInt::sample_range(&lower_bound, &upper_bound))
    }

    pub fn create_commitments() -> (Party1KeyGenFirstMessage, Party1CommWitness, Party1EcKeyPair) {
        let base: GE = ECPoint::generator();
        let bounds = Self::get_lindell_secret_share_bounds();
        let secret_share: FE = Self::get_secret_share_in_range(&bounds.0, &bounds.1);

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
        let ec_key_pair = Party1EcKeyPair {
            public_share,
            secret_share,
        };
        (
            Party1KeyGenFirstMessage {
                pk_commitment,
                zk_pok_commitment,
            },
            Party1CommWitness {
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
    ) -> (Party1KeyGenFirstMessage, Party1CommWitness, Party1EcKeyPair) {
        let bounds: (BigInt, BigInt) = Self::get_lindell_secret_share_bounds();
        assert!(secret_share.to_big_int().gt(&bounds.0) && secret_share.to_big_int().lt(&bounds.1));

        let base: GE = ECPoint::generator();
        let public_share = base.scalar_mul(&secret_share.get_element());

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

        let ec_key_pair = Party1EcKeyPair {
            public_share,
            secret_share,
        };
        (
            Party1KeyGenFirstMessage {
                pk_commitment,
                zk_pok_commitment,
            },
            Party1CommWitness {
                pk_commitment_blind_factor,
                zk_pok_blind_factor,
                public_share: ec_key_pair.public_share,
                d_log_proof,
            },
            ec_key_pair,
        )
    }
}

impl Party1KeyGenCommWitness {
    pub fn verify_and_decommit(
        comm_witness: Party1CommWitness,
        proof: &DLogProof,
    ) -> Result<Party1KeyGenCommWitness, ProofError> {
        DLogProof::verify(proof)?;
        Ok(Party1KeyGenCommWitness { comm_witness })
    }
}

pub fn compute_pubkey(party_one_private: &Party1Private, other_share_public_share: &GE) -> GE {
    other_share_public_share * &party_one_private.x1
}

impl Party1Private {
    pub fn check_rotated_key_bounds(party_one_private: &Party1Private, factor: &BigInt) -> bool {
        let factor_fe: FE = ECScalar::from(factor);
        let x1_new: FE = factor_fe * party_one_private.x1;

        x1_new.to_big_int() >= FE::q().div_floor(&BigInt::from(3))
    }

    pub fn refresh_private_key(
        party_one_private: &Party1Private,
        factor: &BigInt,
    ) -> (
        EncryptionKey,
        BigInt,
        Party1Private,
        NICorrectKeyProof,
        RangeProofNi,
    ) {
        let (ek_new, dk_new) = Paillier::keypair().keys();
        let randomness = Randomness::sample(&ek_new.clone());
        let factor_fe: FE = ECScalar::from(factor);
        let x1_new: FE = *&party_one_private.x1 * factor_fe;
        let c_key_new = Paillier::encrypt_with_chosen_randomness(
            &ek_new.clone(),
            RawPlaintext::from(x1_new.to_big_int()),
            &randomness,
        )
        .0
        .into_owned();

        let order = FE::q();
        let lower_bound: BigInt = order.div_floor(&BigInt::from(3));

        let x1_new_minus_lower_bound = BigInt::mod_sub(
            &x1_new.to_big_int(),
            &lower_bound,
            &order,
        );

        let party_one_private_new = Party1Private {
            x1: x1_new.clone(),
            x1_minus_q_thirds: Some(ECScalar::from(&x1_new_minus_lower_bound)),
            paillier_priv: dk_new.clone(),
            c_key_randomness: randomness.0.clone(),
        };

        //encrypt x1-q/3
        let randomness_q = Randomness::sample(&ek_new);

        let new_encrypted_share_minus_q_thirds = Paillier::encrypt_with_chosen_randomness(
            &ek_new,
            RawPlaintext::from(x1_new_minus_lower_bound.clone()),
            &randomness_q,
        ).0.into_owned();

        let paillier_key_pair = Party1PaillierKeyPair {
            ek: ek_new.clone(),
            dk: dk_new.clone(),
            encrypted_share: c_key_new.clone(),
            encrypted_share_minus_q_thirds: Some(new_encrypted_share_minus_q_thirds),
            randomness: randomness.0.clone(),
            randomness_q: Some(randomness_q.0),
        };

        let correct_key_proof = Party1PaillierKeyPair::generate_ni_proof_correct_key(&paillier_key_pair);

        let range_proof = Party1PaillierKeyPair::generate_range_proof(
            &paillier_key_pair,
            &party_one_private_new,
        );
        (
            ek_new.clone(),
            c_key_new.clone(),
            party_one_private_new,
            correct_key_proof,
            range_proof,
        )
    }

    pub fn set_private_key(ec_key: &Party1EcKeyPair, paillier_key: &Party1PaillierKeyPair) -> Party1Private {
        let order = FE::q();
        let lower_bound: BigInt = order.div_floor(&BigInt::from(3));
        //x1-q/3
        let x1_minus_lower_bound = BigInt::mod_sub(
            &ec_key.secret_share.to_big_int().clone(),
            &lower_bound,
            &order,
        );
        let x1_minus_lower_bound_fe: FE = ECScalar::from(&x1_minus_lower_bound);
        Party1Private {
            x1: ec_key.secret_share,
            x1_minus_q_thirds: Some(x1_minus_lower_bound_fe),
            paillier_priv: paillier_key.dk.clone(),
            c_key_randomness: paillier_key.randomness.clone(),
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
        Msegmentation::to_encrypted_segments(&self.x1, segment_size, num_of_segments, pub_ke_y, g)
    }
}

impl Party1PaillierKeyPair {
    pub fn generate_keypair_and_encrypted_share(keygen: &Party1EcKeyPair) -> Party1PaillierKeyPair {
        let (ek, dk) = Paillier::keypair().keys();
        let order = FE::q();
        let lower_bound: BigInt = order.div_floor(&BigInt::from(3));
        //x1-q/3
        let x1_minus_lower_bound = BigInt::mod_sub(
            &keygen.secret_share.to_big_int().clone(),
            &lower_bound,
            &order,
        );

        let randomness = Randomness::sample(&ek);

        let encrypted_share = Paillier::encrypt_with_chosen_randomness(
            &ek,
            RawPlaintext::from(keygen.secret_share.to_big_int()),
            &randomness,
        )
        .0
        .into_owned();

        //encrypt x1-q/3
        let randomness_q = Randomness::sample(&ek);

        let encrypted_share_minus_q_thirds = Paillier::encrypt_with_chosen_randomness(
            &ek,
            RawPlaintext::from(x1_minus_lower_bound.clone()),
            &randomness_q,
        )
            .0
            .into_owned();

        Party1PaillierKeyPair {
            ek,
            dk,
            encrypted_share,
            encrypted_share_minus_q_thirds: Some(encrypted_share_minus_q_thirds),
            randomness: randomness.0,
            randomness_q: Some(randomness_q.0),
        }
    }

    pub fn generate_range_proof(
        paillier_context: &Party1PaillierKeyPair,
        party_one_private: &Party1Private,
    ) -> RangeProofNi {
        let x1_minus_q_thirds = party_one_private.x1_minus_q_thirds.as_ref()
            .expect("x1_minus_q_thirds is missing in party_one.generate_range_proof").to_big_int();
        let encrypted_share_minus_q_thirds = paillier_context.encrypted_share_minus_q_thirds.as_ref()
            .expect("encrypted_share_minus_q_thirds is missing in party_one.generate_range_proof").clone();
        let randomness_q = paillier_context.randomness_q.as_ref()
            .expect("randomness_q is missing in party_one.generate_range_proof");
        RangeProofNi::prove(
            &paillier_context.ek,
            &FE::q(),
            &encrypted_share_minus_q_thirds,
            &x1_minus_q_thirds,
            randomness_q,
        )
    }

    pub fn generate_ni_proof_correct_key(paillier_context: &Party1PaillierKeyPair) -> NICorrectKeyProof {
        NICorrectKeyProof::proof(&paillier_context.dk)
    }

    pub fn pdl_first_stage(
        party_one_private: &Party1Private,
        pdl_first_message: &Party2PDLFirstMessage,
    ) -> (Party1PDLFirstMessage, Party1PDLDecommit, BigInt) {
        let c_tag = pdl_first_message.c_tag.clone();
        let alpha = Paillier::decrypt(
            &party_one_private.paillier_priv.clone(),
            &RawCiphertext::from(c_tag),
        );
        let alpha_fe: FE = ECScalar::from(&alpha.0);
        let g: GE = ECPoint::generator();
        let q_hat = g * alpha_fe;
        let blindness = BigInt::sample_below(&FE::q());
        let c_hat = HashCommitment::create_commitment_with_user_defined_randomness(
            &q_hat.bytes_compressed_to_big_int(),
            &blindness,
        );
        (
            Party1PDLFirstMessage { c_hat },
            Party1PDLDecommit { blindness, q_hat },
            alpha.0.into_owned(),
        )
    }

    pub fn pdl_second_stage(
        pdl_party_two_first_message: &Party2PDLFirstMessage,
        pdl_party_two_second_message: &Party2PDLSecondMessage,
        party_one_private: Party1Private,
        pdl_decommit: Party1PDLDecommit,
        alpha: BigInt,
    ) -> Result<Party1PDLSecondMessage, ()> {
        let a = pdl_party_two_second_message.decommit.a.clone();
        let b = pdl_party_two_second_message.decommit.b.clone();
        let blindness = pdl_party_two_second_message.decommit.blindness.clone();

        let ab_concat = a.clone() + b.clone().shl(a.bit_length());
        let c_tag_tag_test =
            HashCommitment::create_commitment_with_user_defined_randomness(&ab_concat, &blindness);
        let ax1 = a * party_one_private.x1.to_big_int();
        let alpha_test = ax1 + b;
        if alpha_test == alpha && pdl_party_two_first_message.c_tag_tag.clone() == c_tag_tag_test {
            Ok(Party1PDLSecondMessage {
                decommit: pdl_decommit,
            })
        } else {
            Err(())
        }
    }
}

impl Party1EphKeyGenFirstMessage {
    pub fn create() -> (Party1EphKeyGenFirstMessage, Party1EphEcKeyPair) {
        let base: GE = ECPoint::generator();
        let secret_share: FE = ECScalar::new_random();
        let public_share = base * secret_share;
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
        let ec_key_pair = Party1EphEcKeyPair {
            public_share,
            secret_share,
        };
        (
            Party1EphKeyGenFirstMessage {
                d_log_proof,
                public_share,
                c,
            },
            ec_key_pair,
        )
    }
}

impl Party1EphKeyGenSecondMessage {
    pub fn verify_commitments_and_dlog_proof(
        party_two_first_message: &Party2EphKeyGenFirstMessage,
        party_two_second_message: &Party2EphKeyGenSecondMessage,
    ) -> Result<Party1EphKeyGenSecondMessage, ProofError> {
        let party_two_zk_pok_blind_factor =
            &party_two_second_message.comm_witness.zk_pok_blind_factor;
        let party_two_public_share = &party_two_second_message.comm_witness.public_share;
        let party_two_pk_commitment_blind_factor = &party_two_second_message
            .comm_witness
            .pk_commitment_blind_factor;
        let party_two_d_log_proof = &party_two_second_message.comm_witness.d_log_proof;
        let pk2_pk_com = HashCommitment::create_commitment_with_user_defined_randomness(
            &party_two_public_share.bytes_compressed_to_big_int(),
            party_two_pk_commitment_blind_factor,
        );
        let pk2_zk_com = HashCommitment::create_commitment_with_user_defined_randomness(
            &HSha256::create_hash_from_ge(&[&party_two_d_log_proof.a1, &party_two_d_log_proof.a2])
                .to_big_int(),
            party_two_zk_pok_blind_factor,
        );
        let valid_coms = pk2_pk_com == party_two_first_message.pk_commitment
            && pk2_zk_com == party_two_first_message.zk_pok_commitment;
        if !valid_coms {
            return Err(ProofError {});
        }
        let delta = ECDDHStatement {
            g1: GE::generator(),
            h1: *party_two_public_share,
            g2: GE::base_point2(),
            h2: party_two_second_message.comm_witness.c,
        };
        party_two_d_log_proof.verify(&delta)?;
        Ok(Party1EphKeyGenSecondMessage {})
    }
}

impl Party1Signature {
    pub fn compute(
        party_one_private: &Party1Private,
        partial_sig_c3: &BigInt,
        ephemeral_local_share: &Party1EphEcKeyPair,
        ephemeral_other_public_share: &GE,
    ) -> Party1Signature {
        //compute r = k2* R1
        let mut r = *ephemeral_other_public_share;
        r = r.scalar_mul(&ephemeral_local_share.secret_share.get_element());

        let rx = r.x_coor().unwrap().mod_floor(&FE::q());
        let k1_inv = &ephemeral_local_share
            .secret_share
            .to_big_int()
            .invert(&FE::q())
            .unwrap();
        let s_tag = Paillier::decrypt(
            &party_one_private.paillier_priv,
            &RawCiphertext::from(partial_sig_c3),
        );
        let s_tag_tag = BigInt::mod_mul(k1_inv, &s_tag.0, &FE::q());
        let s = cmp::min(s_tag_tag.clone(), FE::q() - s_tag_tag);
        Party1Signature { s, r: rx }
    }

    pub fn compute_with_recid(
        party_one_private: &Party1Private,
        partial_sig_c3: &BigInt,
        ephemeral_local_share: &Party1EphEcKeyPair,
        ephemeral_other_public_share: &GE,
    ) -> Party1SignatureRecid {
        //compute r = k2* R1
        let mut r = *ephemeral_other_public_share;
        r = r.scalar_mul(&ephemeral_local_share.secret_share.get_element());

        let rx = r.x_coor().unwrap().mod_floor(&FE::q());
        let ry = r.y_coor().unwrap().mod_floor(&FE::q());
        let k1_inv = &ephemeral_local_share
            .secret_share
            .to_big_int()
            .invert(&FE::q())
            .unwrap();
        let s_tag = Paillier::decrypt(
            &party_one_private.paillier_priv,
            &RawCiphertext::from(partial_sig_c3),
        );
        let s_tag_tag = BigInt::mod_mul(k1_inv, &s_tag.0, &FE::q());
        let s = cmp::min(s_tag_tag.clone(), FE::q() - s_tag_tag.clone());

        /*
         Calculate recovery id - it is not possible to compute the public key out of the signature
         itself. Recovery id is used to enable extracting the public key uniquely.
         1. id = R.y & 1
         2. if (s > curve.q / 2) id = id ^ 1
        */
        let is_ry_odd = ry.tstbit(0);
        let mut recid = if is_ry_odd { 1 } else { 0 };
        if s_tag_tag > (FE::q() - &s_tag_tag) {
            recid ^= 1;
        }

        Party1SignatureRecid { s, r: rx, recid }
    }
}

pub fn verify(signature: &Party1Signature, pubkey: &GE, message: &BigInt) -> Result<(), Error> {
    let s_fe: FE = ECScalar::from(&signature.s);
    let rx_fe: FE = ECScalar::from(&signature.r);

    let s_inv_fe = s_fe.invert();
    let e_fe: FE = ECScalar::from(&message.mod_floor(&FE::q()));
    let u1 = GE::generator() * e_fe * s_inv_fe;
    let u2 = *pubkey * rx_fe * s_inv_fe;

    // second condition is against malleability
    let rx_bytes = &BigInt::to_vec(&signature.r)[..];
    let u1_plus_u2_bytes = &BigInt::to_vec(&(u1 + u2).x_coor().unwrap())[..];

    if rx_bytes == u1_plus_u2_bytes && signature.s < FE::q() - signature.s.clone() {
        Ok(())
    } else {
        Err(InvalidSig)
    }
}
