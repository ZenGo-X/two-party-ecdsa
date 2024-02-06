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
use std::cmp;
use std::ops::{Mul, Shl};
use std::fmt::{Debug, Display, Formatter};
use serde::{Serialize, Deserialize};

use super::{party_one, SECURITY_BITS};
pub use crate::curv::arithmetic::traits::*;

use crate::curv::elliptic::curves::traits::*;

use crate::curv::cryptographic_primitives::commitments::hash_commitment::HashCommitment;
use crate::curv::cryptographic_primitives::commitments::traits::Commitment;
use crate::curv::cryptographic_primitives::hashing::hash_sha256::HSha256;
use crate::curv::cryptographic_primitives::hashing::traits::Hash;
pub use crate::curv::cryptographic_primitives::proofs::sigma_dlog::*;
use crate::curv::cryptographic_primitives::proofs::sigma_ec_ddh::*;
use crate::curv::cryptographic_primitives::proofs::ProofError;
use crate::party_two::EphKeyGenFirstMsg as Party2EphKeyGenFirstMessage;
use crate::party_two::EphKeyGenSecondMsg as Party2EphKeyGenSecondMessage;
use crate::party_two::{
    PDLFirstMessage as Party2PDLFirstMessage, PDLSecondMessage as Party2PDLSecondMessage,
};

use crate::centipede::juggling::proof_system::{Helgamalsegmented, Witness};
use crate::centipede::juggling::segmentation::Msegmentation;

use crate::curv::BigInt;
use crate::curv::FE;
use crate::curv::GE;
use std::any::{Any};
use secp256k1::Secp256k1;

use crate::Error::{self, InvalidSig};

#[typetag::serde]
pub trait Value: Sync + Send + Any {
    fn as_any(&self) -> &dyn Any;
    fn type_name(&self) -> &str;
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct HDPos {
    pub pos: u32,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct v {
    pub value: String,
}

#[typetag::serde]
impl Value for HDPos {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn type_name(&self) -> &str {
        "HDPos"
    }
}

#[typetag::serde]
impl Value for KeyGenFirstMsg {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn type_name(&self) -> &str {
        "KeyGenFirstMsg"
    }
}

#[typetag::serde]
impl Value for CommWitness {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn type_name(&self) -> &str {
        "CommWitness"
    }
}

#[typetag::serde]
impl Value for EcKeyPair {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn type_name(&self) -> &str {
        "EcKeyPair"
    }
}

#[typetag::serde]
impl Value for v {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn type_name(&self) -> &str {
        "v"
    }
}

#[typetag::serde]
impl Value for PaillierKeyPair {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn type_name(&self) -> &str {
        "PaillierKeyPair"
    }
}

#[typetag::serde]
impl Value for Party1Private {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn type_name(&self) -> &str {
        "Party1Private"
    }
}

#[typetag::serde]
impl Value for PDLdecommit {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn type_name(&self) -> &str {
        "PDLdecommit"
    }
}

#[typetag::serde]
impl Value for EphEcKeyPair {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn type_name(&self) -> &str {
        "EphEcKeyPair"
    }
}

impl Display for EphEcKeyPair {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl Display for v {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl Display for CommWitness {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}


impl Display for PDLdecommit {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl Display for KeyGenFirstMsg {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl Display for EcKeyPair {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl Display for PaillierKeyPair {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl Display for Party1Private {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl Display for HDPos {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

//****************** Begin: Party One structs ******************//
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EcKeyPair {
    pub public_share: GE,
    secret_share: FE,
}


#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommWitness {
    pub pk_commitment_blind_factor: BigInt,
    pub zk_pok_blind_factor: BigInt,
    pub public_share: GE,
    pub d_log_proof: DLogProof,
}


#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyGenFirstMsg {
    pub pk_commitment: BigInt,
    pub zk_pok_commitment: BigInt,
}


#[derive(Debug, Serialize, Deserialize)]
pub struct KeyGenSecondMsg {
    pub comm_witness: CommWitness,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PaillierKeyPair {
    pub ek: EncryptionKey,
    dk: DecryptionKey,
    pub encrypted_share: BigInt,
    pub encrypted_share_minus_q_thirds: Option<BigInt>,
    randomness: BigInt,
    randomness_q: Option<BigInt>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignatureRecid {
    pub s: BigInt,
    pub r: BigInt,
    pub recid: u8,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Signature {
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


#[derive(Debug, Serialize, Deserialize)]
pub struct PDLFirstMessage {
    pub c_hat: BigInt,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PDLdecommit {
    pub q_hat: GE,
    pub blindness: BigInt,
}


#[derive(Debug, Serialize, Deserialize)]
pub struct PDLSecondMessage {
    pub decommit: PDLdecommit,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EphEcKeyPair {
    pub public_share: GE,
    secret_share: FE,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EphKeyGenFirstMsg {
    pub d_log_proof: ECDDHProof,
    pub public_share: GE,
    pub c: GE, //c = secret_share * base_point2
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EphKeyGenSecondMsg {}

//****************** End: Party One structs ******************//

impl KeyGenFirstMsg {
    //in Lindell's protocol range proof works only for x1 \in {q/3 , ... , 2q/3}
    pub fn get_lindell_secret_share_bounds() -> (BigInt, BigInt) {
        let lower_bound: BigInt = FE::q().div_floor(&BigInt::from(3));
        let upper_bound: BigInt = lower_bound.clone().mul(&BigInt::from(2));
        (lower_bound, upper_bound)
    }

    pub fn get_secret_share_in_range(lower_bound: &BigInt, upper_bound: &BigInt) -> FE {
        ECScalar::from(&BigInt::sample_range(&lower_bound, &upper_bound))
    }

    pub fn create_commitments() -> (KeyGenFirstMsg, CommWitness, EcKeyPair) {
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
        let ec_key_pair = EcKeyPair {
            public_share,
            secret_share,
        };
        (
            KeyGenFirstMsg {
                pk_commitment,
                zk_pok_commitment,
            },
            CommWitness {
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
    ) -> (KeyGenFirstMsg, CommWitness, EcKeyPair) {
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

        let ec_key_pair = EcKeyPair {
            public_share,
            secret_share,
        };
        (
            KeyGenFirstMsg {
                pk_commitment,
                zk_pok_commitment,
            },
            CommWitness {
                pk_commitment_blind_factor,
                zk_pok_blind_factor,
                public_share: ec_key_pair.public_share,
                d_log_proof,
            },
            ec_key_pair,
        )
    }
}

impl KeyGenSecondMsg {
    pub fn verify_and_decommit(
        comm_witness: CommWitness,
        proof: &DLogProof,
    ) -> Result<KeyGenSecondMsg, ProofError> {
        DLogProof::verify(proof)?;
        Ok(KeyGenSecondMsg { comm_witness })
    }
}

pub fn compute_pubkey(party_one_private: &Party1Private, other_share_public_share: &GE) -> GE {
    other_share_public_share * &party_one_private.x1
}

impl Party1Private {
    pub fn check_rotated_key_bounds(
        party_one_private: &Party1Private,
        factor: &BigInt,
    ) -> bool {
        let factor_fe: FE = ECScalar::from(factor);
        let x1_new: FE = factor_fe * party_one_private.x1;

        x1_new.to_big_int() >= FE::q().div_floor(&BigInt::from(3))
    }

    pub fn set_private_key(ec_key: &EcKeyPair, paillier_key: &PaillierKeyPair) -> Party1Private {
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

impl PaillierKeyPair {
    pub fn generate_keypair_and_encrypted_share(keygen: &EcKeyPair) -> PaillierKeyPair {
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

        //encrypt x1
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

        PaillierKeyPair {
            ek,
            dk,
            encrypted_share,
            encrypted_share_minus_q_thirds: Some(encrypted_share_minus_q_thirds),
            randomness: randomness.0,
            randomness_q: Some(randomness_q.0),
        }
    }

    pub fn generate_range_proof(
        paillier_context: &PaillierKeyPair,
        party_one_private: &Party1Private,
    ) -> RangeProofNi {
        let x1_minus_q_thirds = party_one_private.x1_minus_q_thirds.as_ref().expect("x1_minus_q_thirds").to_big_int();
        let encrypted_share_minus_q_thirds = paillier_context.encrypted_share_minus_q_thirds.as_ref().expect("encrypted_share_minus_q_thirds").clone();
        let randomness_q = paillier_context.randomness_q.as_ref().expect("randomness_q");
        RangeProofNi::prove(
            &paillier_context.ek,
            &FE::q(),
            &encrypted_share_minus_q_thirds,
            &x1_minus_q_thirds,
            randomness_q,
        )
    }

    pub fn generate_ni_proof_correct_key(paillier_context: &PaillierKeyPair) -> NICorrectKeyProof {
        NICorrectKeyProof::proof(&paillier_context.dk)
    }

    pub fn pdl_first_stage(
        party_one_private: &Party1Private,
        pdl_first_message: &Party2PDLFirstMessage,
    ) -> (PDLFirstMessage, PDLdecommit, BigInt) {
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
            PDLFirstMessage { c_hat },
            PDLdecommit { blindness, q_hat },
            alpha.0.into_owned(),
        )
    }

    pub fn pdl_second_stage(
        pdl_party_two_first_message: &Party2PDLFirstMessage,
        pdl_party_two_second_message: &Party2PDLSecondMessage,
        party_one_private: Party1Private,
        pdl_decommit: PDLdecommit,
        alpha: BigInt,
    ) -> Result<PDLSecondMessage, ()> {
        let a = pdl_party_two_second_message.decommit.a.clone();
        let b = pdl_party_two_second_message.decommit.b.clone();
        let blindness = pdl_party_two_second_message.decommit.blindness.clone();

        let ab_concat = a.clone() + b.clone().shl(a.bit_length());
        let c_tag_tag_test =
            HashCommitment::create_commitment_with_user_defined_randomness(&ab_concat, &blindness);
        let ax1 = a * party_one_private.x1.to_big_int();
        let alpha_test = ax1 + b;
        if alpha_test == alpha && pdl_party_two_first_message.c_tag_tag.clone() == c_tag_tag_test {
            Ok(PDLSecondMessage {
                decommit: pdl_decommit,
            })
        } else {
            Err(())
        }
    }
}

impl EphKeyGenFirstMsg {
    pub fn create() -> (EphKeyGenFirstMsg, EphEcKeyPair) {
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
        let ec_key_pair = EphEcKeyPair {
            public_share,
            secret_share,
        };
        (
            EphKeyGenFirstMsg {
                d_log_proof,
                public_share,
                c,
            },
            ec_key_pair,
        )
    }
}

impl EphKeyGenSecondMsg {
    pub fn verify_commitments_and_dlog_proof(
        party_two_first_message: &Party2EphKeyGenFirstMessage,
        party_two_second_message: &Party2EphKeyGenSecondMessage,
    ) -> Result<EphKeyGenSecondMsg, ProofError> {
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
        Ok(EphKeyGenSecondMsg {})
    }
}

impl Signature {
    pub fn compute(
        party_one_private: &Party1Private,
        partial_sig_c3: &BigInt,
        ephemeral_local_share: &EphEcKeyPair,
        ephemeral_other_public_share: &GE,
    ) -> Signature {
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
        Signature { s, r: rx }
    }

    pub fn compute_with_recid(
        party_one_private: &Party1Private,
        partial_sig_c3: &BigInt,
        ephemeral_local_share: &EphEcKeyPair,
        ephemeral_other_public_share: &GE,
    ) -> SignatureRecid {
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

        SignatureRecid { s, r: rx, recid }
    }
}

pub fn verify(signature: &Signature, pubkey: &GE, message: &BigInt) -> Result<(), Error> {
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
