use super::{hd_key, MasterKey1, MasterKey2, Party2Public};

use crate::curv::{
    elliptic::curves::traits::{ECPoint, ECScalar},
    BigInt, FE, GE,
};

use crate::kms::rotation::two_party::{Rotation};

use serde::{Deserialize, Serialize};
use crate::kms::rotation::two_party::party1::RotationParty1Message1;
use crate::party_one::{Party1EphKeyGenFirstMessage, Party1KeyGenFirstMessage, Party1KeyGenMessage2, Party1PaillierKeyPair, Party1PDLFirstMessage, Party1PDLSecondMessage, Party1Private};
use crate::party_two::{compute_pubkey, Party2EcKeyPair, Party2EphCommWitness, Party2EphEcKeyPair2, Party2EphKeyGenFirstMessage, Party2EphKeyGenSecondMessage, Party2KeyGenFirstMessage, Party2KeyGenSecondMessage, Party2PaillierPublic, Party2PartialSig, Party2PDLchallenge, Party2PDLFirstMessage, Party2PDLSecondMessage, Party2Private};

#[derive(Debug, Serialize, Deserialize)]
pub struct Party2SignMessage {
    pub partial_sig: Party2PartialSig,
    pub second_message: Party2EphKeyGenSecondMessage,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Party2SecondMessage {
    pub key_gen_second_message: Party2KeyGenSecondMessage,
    pub pdl_first_message: Party2PDLFirstMessage,
}

impl MasterKey2 {
    pub fn rotate(&self, cf: &Rotation, new_paillier: &Party2PaillierPublic) -> MasterKey2 {
        let rand_str_invert_fe = cf.rotation.invert();
        let c_key_new = new_paillier.encrypted_secret_share.clone();

        //TODO: use proper set functions
        let public = Party2Public {
            q: self.public.q,
            p1: self.public.p1.clone() * &cf.rotation,
            p2: &self.public.p2 * &cf.rotation.invert(),
            paillier_pub: new_paillier.ek.clone(),
            c_key: c_key_new,
        };
        MasterKey2 {
            public,
            private: Party2Private::update_private_key(
                &self.private,
                &rand_str_invert_fe.to_big_int(),
            ),
            chain_code: self.chain_code.clone(),
        }
    }
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
            private: Party2Private::update_private_key(
                &self.private,
                &f_l_new.to_big_int(),
            ),
            chain_code: cc_new.bytes_compressed_to_big_int(),
        }
    }

    pub fn set_master_key(
        chain_code: &BigInt,
        ec_key_pair_party2: &Party2EcKeyPair,
        party1_second_message_public_share: &GE,
        paillier_public: &Party2PaillierPublic,
    ) -> MasterKey2 {
        let party2_public = Party2Public {
            q: compute_pubkey(ec_key_pair_party2, party1_second_message_public_share),
            p2: ec_key_pair_party2.public_share,
            p1: *party1_second_message_public_share,
            paillier_pub: paillier_public.ek.clone(),
            c_key: paillier_public.encrypted_secret_share.clone(),
        };
        let party2_private = Party2Private::set_private_key(ec_key_pair_party2);
        MasterKey2 {
            public: party2_public,
            private: party2_private,
            chain_code: chain_code.clone(),
        }
    }

    //  master key of party one from counter party recovery (party two recovers party one secret share)
    pub fn counter_master_key_from_recovered_secret(&self, party_one_secret: FE) -> MasterKey1 {
        let (_, _, ec_key_pair_party1) =
            Party1KeyGenFirstMessage::create_commitments_with_fixed_secret_share(party_one_secret);
        let paillier_key_pair =
            Party1PaillierKeyPair::generate_keypair_and_encrypted_share(&ec_key_pair_party1);

        let party_one_private =
            Party1Private::set_private_key(&ec_key_pair_party1, &paillier_key_pair);

        // set master keys:
        MasterKey1::set_master_key(
            &self.chain_code,
            party_one_private,
            &ec_key_pair_party1.public_share,
            &self.public.p2,
            paillier_key_pair,
        )
    }

    pub fn key_gen_first_message() -> (Party2KeyGenFirstMessage, Party2EcKeyPair) {
        Party2KeyGenFirstMessage::create()
    }

    pub fn key_gen_second_message(
        party_one_first_message: &Party1KeyGenFirstMessage,
        party_one_second_message: &Party1KeyGenMessage2,
    ) -> Result<
        (
            Party2SecondMessage,
            Party2PaillierPublic,
            Party2PDLchallenge,
        ),
        (),
    > {
        let paillier_encryption_key = party_one_second_message.ek.clone();
        let paillier_encrypted_share = party_one_second_message.c_key.clone();

        let party_two_second_message =
            Party2KeyGenSecondMessage::verify_commitments_and_dlog_proof(
                &party_one_first_message,
                &party_one_second_message.ecdh_second_message,
            );

        let party_two_paillier = Party2PaillierPublic {
            ek: paillier_encryption_key.clone(),
            encrypted_secret_share: paillier_encrypted_share.clone(),
        };

        let range_proof_verify = Party2PaillierPublic::verify_range_proof(
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
        pdl_chal: &Party2PDLchallenge,
    ) -> Party2PDLSecondMessage {
        Party2PaillierPublic::pdl_decommit_c_tag_tag(&pdl_chal)
    }

    pub fn key_gen_fourth_message(
        pdl_chal: &Party2PDLchallenge,
        party_one_pdl_first_message: &Party1PDLFirstMessage,
        party_one_pdl_second_message: &Party1PDLSecondMessage,
    ) -> Result<(), ()> {
        Party2PaillierPublic::verify_pdl(
            pdl_chal,
            party_one_pdl_first_message,
            party_one_pdl_second_message,
        )
    }

    pub fn sign_first_message() -> (
        Party2EphKeyGenFirstMessage,
        Party2EphCommWitness,
        Party2EphEcKeyPair2,
    ) {
        Party2EphKeyGenFirstMessage::create_commitments()
    }
    pub fn sign_second_message(
        &self,
        ec_key_pair_party2: &Party2EphEcKeyPair2,
        eph_comm_witness: Party2EphCommWitness,
        eph_party1_first_message: &Party1EphKeyGenFirstMessage,
        message: &BigInt,
    ) -> Party2SignMessage {
        let eph_key_gen_second_message = Party2EphKeyGenSecondMessage::verify_and_decommit(
            eph_comm_witness,
            eph_party1_first_message,
        )
        .expect("");

        let partial_sig = Party2PartialSig::compute(
            &self.public.paillier_pub,
            &self.public.c_key,
            &self.private,
            ec_key_pair_party2,
            &eph_party1_first_message.public_share,
            message,
        );
        Party2SignMessage {
            partial_sig,
            second_message: eph_key_gen_second_message,
        }
    }
    // party2 receives new paillier key and new c_key = Enc(x1_new) = Enc(r*x_1).
    // party2 can compute locally the updated Q1. This is why this set of messages
    // is rotation and not new key gen.
    // party2 needs to verify range proof on c_key_new and correct key proof on the new paillier keys
    pub fn rotate_first_message(
        &self,
        cf: &Rotation,
        party_one_rotation_first_message: &RotationParty1Message1,
    ) -> Result<
        (
            Party2PDLFirstMessage,
            Party2PDLchallenge,
            Party2PaillierPublic,
        ),
        (),
    > {
        let party_two_paillier = Party2PaillierPublic {
            ek: party_one_rotation_first_message.ek_new.clone(),
            encrypted_secret_share: party_one_rotation_first_message.c_key_new.clone(),
        };

        let range_proof_verify = Party2PaillierPublic::verify_range_proof(
            &party_two_paillier,
            &party_one_rotation_first_message.range_proof,
        );

        println!("range_proof_verify = {:?}", range_proof_verify);

        let correct_key_verify = party_one_rotation_first_message
            .correct_key_proof
            .verify(&party_two_paillier.ek);

        println!("correct_key_verify = {:?}", correct_key_verify);

        // let master_key = self.rotate(cf, &party_two_paillier);
        let (pdl_first_message, pdl_chal) =
            party_two_paillier.pdl_challenge(&(&self.public.p1 * &cf.rotation));

        match range_proof_verify {
            Ok(_proof) => match correct_key_verify {
                Ok(_proof) => Ok((pdl_first_message, pdl_chal, party_two_paillier)),
                Err(_correct_key_error) => Err(()),
            },
            Err(_range_proof_error) => Err(()),
        }
    }
    pub fn rotate_second_message(
        pdl_chal: &Party2PDLchallenge,
    ) -> Party2PDLSecondMessage {
        Party2PaillierPublic::pdl_decommit_c_tag_tag(&pdl_chal)
    }

    pub fn rotate_third_message(
        &self,
        cf: &Rotation,
        party_two_paillier: &Party2PaillierPublic,
        pdl_chal: &Party2PDLchallenge,
        party_one_pdl_first_message: &Party1PDLFirstMessage,
        party_one_pdl_second_message: &Party1PDLSecondMessage,
    ) -> Result<MasterKey2, ()> {
        match Party2PaillierPublic::verify_pdl(
            pdl_chal,
            party_one_pdl_first_message,
            party_one_pdl_second_message,
        ) {
            Ok(_) => {
                let master_key = self.rotate(cf, party_two_paillier);
                Ok(master_key)
            }
            Err(_) => Err(()),
        }
    }
}
