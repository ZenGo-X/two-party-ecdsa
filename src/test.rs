// For integration tests, please add your tests in /tests instead

#[cfg(test)]
mod tests {

    use crate::curv::arithmetic::traits::Samplable;
    use crate::curv::elliptic::curves::traits::*;
    use crate::curv::BigInt;
    use crate::party_one::{compute_pubkey, Party1EphKeyGenFirstMessage, Party1EphKeyGenSecondMessage, Party1KeyGenCommWitness, Party1KeyGenFirstMessage, Party1PaillierKeyPair, Party1Private, Party1Signature, verify};
    use crate::party_two::{Party2EphKeyGenFirstMessage, Party2EphKeyGenSecondMessage, Party2KeyGenFirstMessage, Party2KeyGenSecondMessage, Party2PaillierPublic, Party2PartialSig, Party2Private};

    #[test]
    fn test_d_log_proof_party_two_party_one() {
        let (party_one_first_message, comm_witness, _ec_key_pair_party1) =
            Party1KeyGenFirstMessage::create_commitments();
        let (party_two_first_message, _ec_key_pair_party2) = Party2KeyGenFirstMessage::create();
        let party_one_second_message = Party1KeyGenCommWitness::verify_and_decommit(
            comm_witness,
            &party_two_first_message.d_log_proof,
        )
        .expect("failed to verify and decommit");

        let _party_two_second_message =
            Party2KeyGenSecondMessage::verify_commitments_and_dlog_proof(
                &party_one_first_message,
                &party_one_second_message,
            )
            .expect("failed to verify commitments and DLog proof");
    }

    #[test]

    fn test_full_key_gen() {
        let bounds = Party1KeyGenFirstMessage::get_lindell_secret_share_bounds();
        let (party_one_first_message, comm_witness, ec_key_pair_party1) =
            Party1KeyGenFirstMessage::create_commitments_with_fixed_secret_share(ECScalar::from(
                &Party1KeyGenFirstMessage::get_secret_share_in_range(&bounds.0, &bounds.1)
                    .to_big_int(),
            ));
        let (party_two_first_message, _ec_key_pair_party2) =
            Party2KeyGenFirstMessage::create_with_fixed_secret_share(ECScalar::from(
                &BigInt::from(10_i32),
            ));
        let party_one_second_message = Party1KeyGenCommWitness::verify_and_decommit(
            comm_witness,
            &party_two_first_message.d_log_proof,
        )
        .expect("failed to verify and decommit");

        let _party_two_second_message =
            Party2KeyGenSecondMessage::verify_commitments_and_dlog_proof(
                &party_one_first_message,
                &party_one_second_message,
            )
            .expect("failed to verify commitments and DLog proof");

        // init paillier keypair:
        let paillier_key_pair =
            Party1PaillierKeyPair::generate_keypair_and_encrypted_share(&ec_key_pair_party1);

        let party_one_private =
            Party1Private::set_private_key(&ec_key_pair_party1, &paillier_key_pair);

        let party_two_paillier = Party2PaillierPublic {
            ek: paillier_key_pair.ek.clone(),
            encrypted_secret_share: paillier_key_pair.encrypted_share.clone(),
        };

        let correct_key_proof =
            Party1PaillierKeyPair::generate_ni_proof_correct_key(&paillier_key_pair);

        correct_key_proof
            .verify(&party_two_paillier.ek)
            .expect("bad paillier key");

        // zk proof of correct paillier key

        // zk range proof
        let range_proof = Party1PaillierKeyPair::generate_range_proof(
            &paillier_key_pair,
            &party_one_private,
        );
        Party2PaillierPublic::verify_range_proof(&party_two_paillier, &range_proof)
            .expect("range proof error");
    }

    #[test]
    fn test_two_party_sign() {
        // assume party1 and party2 engaged with KeyGen in the past resulting in
        // party1 owning private share and paillier key-pair
        // party2 owning private share and paillier encryption of party1 share
        let (_party_one_private_share_gen, _comm_witness, ec_key_pair_party1) =
            Party1KeyGenFirstMessage::create_commitments();
        let (party_two_private_share_gen, ec_key_pair_party2) = Party2KeyGenFirstMessage::create();

        let keypair =
            Party1PaillierKeyPair::generate_keypair_and_encrypted_share(&ec_key_pair_party1);

        // creating the ephemeral private shares:

        let (eph_party_two_first_message, eph_comm_witness, eph_ec_key_pair_party2) =
            Party2EphKeyGenFirstMessage::create_commitments();
        let (eph_party_one_first_message, eph_ec_key_pair_party1) =
            Party1EphKeyGenFirstMessage::create();
        let eph_party_two_second_message = Party2EphKeyGenSecondMessage::verify_and_decommit(
            eph_comm_witness,
            &eph_party_one_first_message,
        )
        .expect("party1 DLog proof failed");

        let _eph_party_one_second_message =
            Party1EphKeyGenSecondMessage::verify_commitments_and_dlog_proof(
                &eph_party_two_first_message,
                &eph_party_two_second_message,
            )
            .expect("failed to verify commitments and DLog proof");
        let party2_private = Party2Private::set_private_key(&ec_key_pair_party2);
        let message = BigInt::from(1234);
        let partial_sig = Party2PartialSig::compute(
            &keypair.ek,
            &keypair.encrypted_share,
            &party2_private,
            &eph_ec_key_pair_party2,
            &eph_party_one_first_message.public_share,
            &message,
        );

        let party1_private =
            Party1Private::set_private_key(&ec_key_pair_party1, &keypair);

        let signature = Party1Signature::compute(
            &party1_private,
            &partial_sig.c3,
            &eph_ec_key_pair_party1,
            &eph_party_two_second_message.comm_witness.public_share,
        );

        let pubkey =
            compute_pubkey(&party1_private, &party_two_private_share_gen.public_share);
        verify(&signature, &pubkey, &message).expect("Invalid signature")
    }
}
