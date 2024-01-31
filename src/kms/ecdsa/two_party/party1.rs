use super::hd_key;
use super::party2::SignMessage;
use super::{MasterKey1, MasterKey2, Party1Public};
use crate::curv::cryptographic_primitives::proofs::sigma_dlog::DLogProof;
use crate::curv::{elliptic::curves::traits::ECPoint, BigInt, FE, GE};
use crate::kms::Errors::{self, SignError};
use crate::party_two::{
    Party2PDLFirstMessage as Party2PDLFirstMsg, Party2PDLSecondMessage as Party2PDLSecondMsg,
};
use crate::typetags::Value;
use crate::zk_paillier::zkproofs::{NICorrectKeyProof, RangeProofNi};
use crate::{
    party_one,
    party_two::{self, EphKeyGenFirstMsg},
    typetag_value, EncryptionKey,
};

use crate::curv::elliptic::curves::traits::ECScalar;
use crate::kms::rotation::two_party::Rotation;
use crate::party_one::Party1Private;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct KeyGenParty1Message2 {
    pub ecdh_second_message: party_one::KeyGenSecondMsg,
    pub ek: EncryptionKey,
    pub c_key: BigInt,
    pub correct_key_proof: NICorrectKeyProof,
    pub range_proof: RangeProofNi,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RotationParty1Message1 {
    pub ek_new: EncryptionKey,
    pub c_key_new: BigInt,
    pub correct_key_proof: NICorrectKeyProof,
    pub range_proof: RangeProofNi,
}

typetag_value!(RotationParty1Message1);

#[derive(Debug, Serialize, Deserialize)]
pub struct RotateCommitMessage1 {
    pub seed: FE,
    pub blinding: FE
}

typetag_value!(RotateCommitMessage1);


impl MasterKey1 {
    // before rotation make sure both parties have the same key
    pub fn rotate(
        &self,
        cf: &Rotation,
        party_one_private: party_one::Party1Private,
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
        party_one_private: party_one::Party1Private,
        party_one_public_ec_key: &GE,
        party2_first_message_public_share: &GE,
        paillier_key_pair: party_one::PaillierKeyPair,
    ) -> MasterKey1 {
        let party1_public = Party1Public {
            q: party_one::compute_pubkey(&party_one_private, party2_first_message_public_share),
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
            party_two::KeyGenFirstMsg::create_with_fixed_secret_share(party_two_secret);
        let party_two_paillier = party_two::PaillierPublic {
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
        party_one::KeyGenFirstMsg,
        party_one::CommWitness,
        party_one::EcKeyPair,
    ) {
        party_one::KeyGenFirstMsg::create_commitments()
    }
    pub fn key_gen_second_message(
        comm_witness: &party_one::CommWitness,
        ec_key_pair_party1: &party_one::EcKeyPair,
        proof: &DLogProof,
    ) -> (
        KeyGenParty1Message2,
        party_one::PaillierKeyPair,
        party_one::Party1Private,
    ) {
        let key_gen_second_message =
            party_one::KeyGenSecondMsg::verify_and_decommit(comm_witness.clone(), proof).expect("");

        let paillier_key_pair =
            party_one::PaillierKeyPair::generate_keypair_and_encrypted_share(ec_key_pair_party1);

        // party one set her private key:
        let party_one_private =
            party_one::Party1Private::set_private_key(ec_key_pair_party1, &paillier_key_pair);

        let range_proof = party_one::PaillierKeyPair::generate_range_proof(
            &paillier_key_pair,
            &party_one_private,
        );
        let correct_key_proof =
            party_one::PaillierKeyPair::generate_ni_proof_correct_key(&paillier_key_pair);
        (
            KeyGenParty1Message2 {
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

    pub fn sign_first_message() -> (party_one::EphKeyGenFirstMsg, party_one::EphEcKeyPair) {
        party_one::EphKeyGenFirstMsg::create()
    }

    pub fn sign_second_message(
        &self,
        party_two_sign_message: &SignMessage,
        eph_key_gen_first_message_party_two: &EphKeyGenFirstMsg,
        eph_ec_key_pair_party1: &party_one::EphEcKeyPair,
        message: &BigInt,
    ) -> Result<party_one::SignatureRecid, Errors> {
        let verify_party_two_second_message =
            party_one::EphKeyGenSecondMsg::verify_commitments_and_dlog_proof(
                eph_key_gen_first_message_party_two,
                &party_two_sign_message.second_message,
            )
            .is_ok();

        let signature_with_recid = party_one::Signature::compute_with_recid(
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
        let signature = party_one::Signature {
            r: signature_with_recid.r.clone(),
            s: signature_with_recid.s.clone(),
        };

        let verify = party_one::verify(&signature, &self.public.q, message).is_ok();
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
        party_two_pdl_first_message: &Party2PDLFirstMsg,
        party_one_private: &party_one::Party1Private,
    ) -> (party_one::Party1PDLFirstMessage, party_one::Party1PDLDecommit, BigInt) {
        party_one::PaillierKeyPair::pdl_first_stage(
            &party_one_private,
            &party_two_pdl_first_message,
        )
    }

    pub fn key_gen_fourth_message(
        pdl_party_two_first_message: &Party2PDLFirstMsg,
        pdl_party_two_second_message: &Party2PDLSecondMsg,
        party_one_private: party_one::Party1Private,
        pdl_decommit: party_one::Party1PDLDecommit,
        alpha: BigInt,
    ) -> Result<party_one::Party1PDLSecondMessage, ()> {
        party_one::PaillierKeyPair::pdl_second_stage(
            pdl_party_two_first_message,
            pdl_party_two_second_message,
            party_one_private,
            pdl_decommit,
            alpha,
        )
    }
    pub fn rotation_first_message(&self, cf: &Rotation) -> (RotationParty1Message1, Party1Private) {
        let (ek_new, c_key_new, new_private, correct_key_proof, range_proof) =
            party_one::Party1Private::refresh_private_key(&self.private, &cf.rotation.to_big_int());
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
        rotate_party_two_message_one: &Party2PDLFirstMsg,
        party_one_private: &party_one::Party1Private,
    ) -> (party_one::Party1PDLFirstMessage, party_one::Party1PDLDecommit, BigInt) {
        party_one::PaillierKeyPair::pdl_first_stage(
            &party_one_private,
            &rotate_party_two_message_one,
        )
    }

    pub fn rotation_third_message(
        &self,
        rotation_first_message: &RotationParty1Message1,
        party_one_private_new: party_one::Party1Private,
        cf: &Rotation,
        rotate_party_two_first_message: &Party2PDLFirstMsg,
        rotate_party_two_second_message: &Party2PDLSecondMsg,
        pdl_decommit: party_one::Party1PDLDecommit,
        alpha: BigInt,
    ) -> Result<(party_one::Party1PDLSecondMessage, MasterKey1), ()> {
        let rotate_party_one_third_message = party_one::PaillierKeyPair::pdl_second_stage(
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
