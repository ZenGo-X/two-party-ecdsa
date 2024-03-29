use super::{hd_key, party1::KeyGenParty1Message2, MasterKey1, MasterKey2, Party2Public};

use serde::{Deserialize, Serialize};
use crate::curv::{
    elliptic::curves::traits::{ECPoint, ECScalar},
    BigInt, FE, GE,
};
use crate::party_one::{
    EphKeyGenFirstMsg as Party1EphKeyGenFirstMsg, KeyGenFirstMsg as Party1KeyGenFirstMsg,
    PDLFirstMessage as Party1PDLFirstMsg, PDLSecondMessage as Party1PDLSecondMsg,
};
use crate::{party_one, party_two};

#[derive(Debug, Serialize, Deserialize)]
pub struct SignMessage {
    pub partial_sig: party_two::PartialSig,
    pub second_message: party_two::EphKeyGenSecondMsg,
}

#[derive(Debug, Serialize, Deserialize)]

pub struct Party2SecondMessage {
    pub key_gen_second_message: party_two::KeyGenSecondMsg,
    pub pdl_first_message: party_two::PDLFirstMessage,
}

impl MasterKey2 {
    pub fn get_child(&self, location_in_hir: Vec<BigInt>) -> MasterKey2 {
        let (public_key_new_child, f_l_new, cc_new) =
            hd_key(location_in_hir, &self.public.q, &self.chain_code);

        let public = Party2Public {
            q: public_key_new_child,
            p2: self.public.p2 * f_l_new,
            p1: self.public.p1,
            paillier_pub: self.public.paillier_pub.clone(),
            c_key: self.public.c_key.clone(),
        };
        MasterKey2 {
            public,
            private: party_two::Party2Private::update_private_key(
                &self.private,
                &f_l_new.to_big_int(),
            ),
            chain_code: cc_new.bytes_compressed_to_big_int(),
        }
    }

    pub fn set_master_key(
        chain_code: &BigInt,
        ec_key_pair_party2: &party_two::EcKeyPair,
        party1_second_message_public_share: &GE,
        paillier_public: &party_two::PaillierPublic,
    ) -> MasterKey2 {
        let party2_public = Party2Public {
            q: party_two::compute_pubkey(ec_key_pair_party2, party1_second_message_public_share),
            p2: ec_key_pair_party2.public_share,
            p1: *party1_second_message_public_share,
            paillier_pub: paillier_public.ek.clone(),
            c_key: paillier_public.encrypted_secret_share.clone(),
        };
        let party2_private = party_two::Party2Private::set_private_key(ec_key_pair_party2);
        MasterKey2 {
            public: party2_public,
            private: party2_private,
            chain_code: chain_code.clone(),
        }
    }

    //  master key of party one from counter party recovery (party two recovers party one secret share)
    pub fn counter_master_key_from_recovered_secret(&self, party_one_secret: FE) -> MasterKey1 {
        let (_, _, ec_key_pair_party1) =
            party_one::KeyGenFirstMsg::create_commitments_with_fixed_secret_share(party_one_secret);
        let paillier_key_pair =
            party_one::PaillierKeyPair::generate_keypair_and_encrypted_share(&ec_key_pair_party1);

        let party_one_private =
            party_one::Party1Private::set_private_key(&ec_key_pair_party1, &paillier_key_pair);

        // set master keys:
        MasterKey1::set_master_key(
            &self.chain_code,
            party_one_private,
            &ec_key_pair_party1.public_share,
            &self.public.p2,
            paillier_key_pair,
        )
    }

    pub fn key_gen_first_message() -> (party_two::KeyGenFirstMsg, party_two::EcKeyPair) {
        party_two::KeyGenFirstMsg::create()
    }

    pub fn key_gen_second_message(
        party_one_first_message: &Party1KeyGenFirstMsg,
        party_one_second_message: &KeyGenParty1Message2,
    ) -> Result<
        (
            Party2SecondMessage,
            party_two::PaillierPublic,
            party_two::PDLchallenge,
        ),
        (),
    > {
        let paillier_encryption_key = party_one_second_message.ek.clone();
        let paillier_encrypted_share = party_one_second_message.c_key.clone();

        let party_two_second_message =
            party_two::KeyGenSecondMsg::verify_commitments_and_dlog_proof(
                &party_one_first_message,
                &party_one_second_message.ecdh_second_message,
            );

        let party_two_paillier = party_two::PaillierPublic {
            ek: paillier_encryption_key.clone(),
            encrypted_secret_share: paillier_encrypted_share.clone(),
        };

        let range_proof_verify = party_two::PaillierPublic::verify_range_proof(
            &party_two_paillier,
            &party_one_second_message.range_proof,
        );

        let (pdl_first_message, pdl_chal) = party_two_paillier.pdl_challenge(
            &party_one_second_message
                .ecdh_second_message
                .comm_witness
                .public_share,
        );

        let correct_key_verify = party_one_second_message
            .correct_key_proof
            .verify(&party_two_paillier.ek);

        match range_proof_verify {
            Ok(_proof) => match correct_key_verify {
                Ok(_proof) => match party_two_second_message {
                    Ok(t) => Ok((
                        Party2SecondMessage {
                            key_gen_second_message: t,
                            pdl_first_message,
                        },
                        party_two_paillier,
                        pdl_chal,
                    )),
                    Err(_verify_com_and_dlog_party_one) => Err(()),
                },
                Err(_correct_key_error) => Err(()),
            },
            Err(_range_proof_error) => Err(()),
        }
    }

    pub fn key_gen_third_message(
        pdl_chal: &party_two::PDLchallenge,
    ) -> party_two::PDLSecondMessage {
        party_two::PaillierPublic::pdl_decommit_c_tag_tag(&pdl_chal)
    }

    pub fn key_gen_fourth_message(
        pdl_chal: &party_two::PDLchallenge,
        party_one_pdl_first_message: &Party1PDLFirstMsg,
        party_one_pdl_second_message: &Party1PDLSecondMsg,
    ) -> Result<(), ()> {
        party_two::PaillierPublic::verify_pdl(
            pdl_chal,
            party_one_pdl_first_message,
            party_one_pdl_second_message,
        )
    }

    pub fn sign_first_message() -> (
        party_two::EphKeyGenFirstMsg,
        party_two::EphCommWitness,
        party_two::EphEcKeyPair2,
    ) {
        party_two::EphKeyGenFirstMsg::create_commitments()
    }
    pub fn sign_second_message(
        &self,
        ec_key_pair_party2: &party_two::EphEcKeyPair2,
        eph_comm_witness: party_two::EphCommWitness,
        eph_party1_first_message: &Party1EphKeyGenFirstMsg,
        message: &BigInt,
    ) -> SignMessage {
        let eph_key_gen_second_message = party_two::EphKeyGenSecondMsg::verify_and_decommit(
            eph_comm_witness,
            eph_party1_first_message,
        )
        .expect("");

        let partial_sig = party_two::PartialSig::compute(
            &self.public.paillier_pub,
            &self.public.c_key,
            &self.private,
            ec_key_pair_party2,
            &eph_party1_first_message.public_share,
            message,
        );
        SignMessage {
            partial_sig,
            second_message: eph_key_gen_second_message,
        }
    }
}
