use super::hd_key;
use super::party2::Party2SignFirstMessage;
use super::{MasterKey1, MasterKey2, Party1Public};
use crate::curv::cryptographic_primitives::proofs::sigma_dlog::DLogProof;
use crate::curv::{elliptic::curves::traits::ECPoint, BigInt, FE, GE};
use crate::kms::Errors::{self, SignError};
use crate::EncryptionKey;

use crate::curv::elliptic::curves::traits::ECScalar;
use crate::kms::rotation::two_party::{Rotation};
use crate::kms::rotation::two_party::party1::RotationParty1Message1;
use crate::party_one::{Party1EphKeyGenFirstMessage, Party1CommWitness, Party1EcKeyPair, Party1EphEcKeyPair, Party1EphKeyGenSecondMessage, Party1KeyGenFirstMessage, Party1KeyGenSecondMessage, Party1KeyGenCommWitness, Party1PaillierKeyPair, Party1PDLDecommit, Party1PDLFirstMessage, Party1PDLSecondMessage, Party1Private, Signature, SignatureRecid, verify, compute_pubkey};
use crate::party_two::{Party2EphKeyGenFirstMessage, Party2KeyGenFirstMessage, Party2PaillierPublic, Party2PDLFirstMessage, Party2PDLSecondMessage};

impl MasterKey1 {
    // before rotation make sure both parties have the same key
    pub fn rotate(
        &self,
        cf: &Rotation,
        party_one_private: Party1Private,
        ek_new: &EncryptionKey,
        c_key_new: &BigInt,
    ) -> MasterKey1 {
        let public = Party1Public {
            q: self.public.q,
            p1: &self.public.p1 * &cf.rotation,
            p2: &self.public.p2 * &cf.rotation.invert(),
            paillier_pub: ek_new.clone(),
            c_key: c_key_new.clone(),
        };
        MasterKey1 {
            public,
            private: party_one_private,
            chain_code: self.chain_code.clone(),
        }
    }
    pub fn get_child(&self, location_in_hir: Vec<BigInt>) -> MasterKey1 {
        let (public_key_new_child, f_l_new, cc_new) =
            hd_key(location_in_hir, &self.public.q, &self.chain_code);

        let public = Party1Public {
            q: public_key_new_child,
            p1: self.public.p1,
            p2: self.public.p2 * f_l_new,
            paillier_pub: self.public.paillier_pub.clone(),
            c_key: self.public.c_key.clone(),
        };
        MasterKey1 {
            public,
            private: self.private.clone(),
            chain_code: cc_new.bytes_compressed_to_big_int(),
        }
    }

    pub fn set_master_key(
        chain_code: &BigInt,
        party_one_private: Party1Private,
        party_one_public_ec_key: &GE,
        party2_first_message_public_share: &GE,
        paillier_key_pair: Party1PaillierKeyPair,
    ) -> MasterKey1 {
        let party1_public = Party1Public {
            q: compute_pubkey(&party_one_private, party2_first_message_public_share),
            p1: *party_one_public_ec_key,
            p2: *party2_first_message_public_share,
            paillier_pub: paillier_key_pair.ek.clone(),
            c_key: paillier_key_pair.encrypted_share,
        };

        MasterKey1 {
            public: party1_public,
            private: party_one_private,
            chain_code: chain_code.clone(),
        }
    }

    //  master key of party two from counter party recovery (party one recovers party two secret share)
    pub fn counter_master_key_from_recovered_secret(&self, party_two_secret: FE) -> MasterKey2 {
        let (_, ec_key_pair_party2) =
            Party2KeyGenFirstMessage::create_with_fixed_secret_share(party_two_secret);
        let party_two_paillier = Party2PaillierPublic {
            ek: self.public.paillier_pub.clone(),
            encrypted_secret_share: self.public.c_key.clone(),
        };
        // set master keys:
        MasterKey2::set_master_key(
            &self.chain_code,
            &ec_key_pair_party2,
            &ec_key_pair_party2.public_share,
            &party_two_paillier,
        )
    }

    pub fn key_gen_first_message() -> (
        Party1KeyGenFirstMessage,
        Party1CommWitness,
        Party1EcKeyPair,
    ) {
        Party1KeyGenFirstMessage::create_commitments()
    }
    pub fn key_gen_second_message(
        comm_witness: &Party1CommWitness,
        ec_key_pair_party1: &Party1EcKeyPair,
        proof: &DLogProof,
    ) -> (
        Party1KeyGenSecondMessage,
        Party1PaillierKeyPair,
        Party1Private,
    ) {
        let key_gen_second_message =
            Party1KeyGenCommWitness::verify_and_decommit(comm_witness.clone(), proof).expect("");

        let paillier_key_pair =
            Party1PaillierKeyPair::generate_keypair_and_encrypted_share(ec_key_pair_party1);

        // party one set her private key:
        let party_one_private =
            Party1Private::set_private_key(ec_key_pair_party1, &paillier_key_pair);

        let range_proof = Party1PaillierKeyPair::generate_range_proof(
            &paillier_key_pair,
            &party_one_private,
        );
        let correct_key_proof =
            Party1PaillierKeyPair::generate_ni_proof_correct_key(&paillier_key_pair);
        (
            Party1KeyGenSecondMessage {
                ecdh_second_message: key_gen_second_message,
                ek: paillier_key_pair.ek.clone(),
                c_key: paillier_key_pair.encrypted_share.clone(),
                correct_key_proof,
                range_proof,
            },
            paillier_key_pair,
            party_one_private,
        )
    }

    pub fn sign_first_message() -> (Party1EphKeyGenFirstMessage, Party1EphEcKeyPair) {
        Party1EphKeyGenFirstMessage::create()
    }

    pub fn sign_second_message(
        &self,
        party_two_sign_message: &Party2SignFirstMessage,
        eph_key_gen_first_message_party_two: &Party2EphKeyGenFirstMessage,
        eph_ec_key_pair_party1: &Party1EphEcKeyPair,
        message: &BigInt,
    ) -> Result<SignatureRecid, Errors> {
        let verify_party_two_second_message =
            Party1EphKeyGenSecondMessage::verify_commitments_and_dlog_proof(
                eph_key_gen_first_message_party_two,
                &party_two_sign_message.second_message,
            )
            .is_ok();

        let signature_with_recid = Signature::compute_with_recid(
            &self.private,
            &party_two_sign_message.partial_sig.c3,
            eph_ec_key_pair_party1,
            &party_two_sign_message
                .second_message
                .comm_witness
                .public_share,
        );

        // Creating a standard signature for the verification, currently discarding recid
        // TODO: Investigate what verification could be done with recid
        let signature = Signature {
            r: signature_with_recid.r.clone(),
            s: signature_with_recid.s.clone(),
        };

        let verify = verify(&signature, &self.public.q, message).is_ok();
        if verify {
            if verify_party_two_second_message {
                Ok(signature_with_recid)
            } else {
                println!(
                    "Invalid commitments:{:?}",
                    eph_key_gen_first_message_party_two
                );
                println!(
                    "party_two_sign_message.second_message:{:?}",
                    party_two_sign_message.second_message
                );
                println!("sig_r: {}", signature.r);
                println!("sig_s: {}", signature.s);
                Err(SignError)
            }
        } else {
            println!("Sig does not verify");
            println!("sig_r: {}", signature.r);
            println!("sig_s: {}", signature.s);
            Err(SignError)
        }
    }

    pub fn key_gen_third_message(
        party_two_pdl_first_message: &Party2PDLFirstMessage,
        party_one_private: &Party1Private,
    ) -> (Party1PDLFirstMessage, Party1PDLDecommit, BigInt) {
        Party1PaillierKeyPair::pdl_first_stage(
            &party_one_private,
            &party_two_pdl_first_message,
        )
    }

    pub fn key_gen_fourth_message(
        pdl_party_two_first_message: &Party2PDLFirstMessage,
        pdl_party_two_second_message: &Party2PDLSecondMessage,
        party_one_private: Party1Private,
        pdl_decommit: Party1PDLDecommit,
        alpha: BigInt,
    ) -> Result<Party1PDLSecondMessage, ()> {
        Party1PaillierKeyPair::pdl_second_stage(
            pdl_party_two_first_message,
            pdl_party_two_second_message,
            party_one_private,
            pdl_decommit,
            alpha,
        )
    }
    pub fn rotation_first_message(&self, cf: &Rotation) -> (RotationParty1Message1, Party1Private) {
        let (ek_new, c_key_new, new_private, correct_key_proof, range_proof) =
            Party1Private::refresh_private_key(&self.private, &cf.rotation.to_big_int());
        // let master_key_new = self.rotate(cf, new_private, &ek_new, &c_key_new);
        (
            RotationParty1Message1 {
                ek_new,
                c_key_new,
                correct_key_proof,
                range_proof,
            },
            new_private.clone(),
        )
    }
    pub fn rotation_second_message(
        rotate_party_two_message_one: &Party2PDLFirstMessage,
        party_one_private: &Party1Private,
    ) -> (Party1PDLFirstMessage, Party1PDLDecommit, BigInt) {
        Party1PaillierKeyPair::pdl_first_stage(
            &party_one_private,
            &rotate_party_two_message_one,
        )
    }

    pub fn rotation_third_message(
        &self,
        rotation_first_message: &RotationParty1Message1,
        party_one_private_new: Party1Private,
        cf: &Rotation,
        rotate_party_two_first_message: &Party2PDLFirstMessage,
        rotate_party_two_second_message: &Party2PDLSecondMessage,
        pdl_decommit: Party1PDLDecommit,
        alpha: BigInt,
    ) -> Result<(Party1PDLSecondMessage, MasterKey1), ()> {
        let rotate_party_one_third_message = Party1PaillierKeyPair::pdl_second_stage(
            rotate_party_two_first_message,
            rotate_party_two_second_message,
            party_one_private_new.clone(),
            pdl_decommit,
            alpha,
        );
        let master_key_new = self.rotate(
            cf,
            party_one_private_new,
            &rotation_first_message.ek_new,
            &rotation_first_message.c_key_new,
        );
        match rotate_party_one_third_message {
            Ok(x) => Ok((x, master_key_new)),
            Err(_) => Err(()),
        }
    }
}
