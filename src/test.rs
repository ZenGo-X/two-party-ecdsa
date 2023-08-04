// For integration tests, please add your tests in /tests instead

#[cfg(test)]
mod tests {
    use crate::curv::elliptic::curves::traits::*;
    use crate::curv::BigInt;
    use crate::paillier::{Paillier, Randomness, RawCiphertext, RawPlaintext};
    use crate::party_one::{Modulo, Party1Private};
    use crate::*;
    use std::borrow::Borrow;
    #[test]
    fn test_d_log_proof_party_two_party_one() {
        let (party_one_first_message, comm_witness, _ec_key_pair_party1) =
            party_one::KeyGenFirstMsg::create_commitments();
        let (party_two_first_message, _ec_key_pair_party2) = party_two::KeyGenFirstMsg::create();
        let party_one_second_message = party_one::KeyGenSecondMsg::verify_and_decommit(
            comm_witness,
            &party_two_first_message.d_log_proof,
        )
        .expect("failed to verify and decommit");

        let _party_two_second_message =
            party_two::KeyGenSecondMsg::verify_commitments_and_dlog_proof(
                &party_one_first_message,
                &party_one_second_message,
            )
            .expect("failed to verify commitments and DLog proof");
    }

    #[test]

    fn test_full_key_gen() {
        let bounds = party_one::KeyGenFirstMsg::get_lindell_secret_share_bounds();
        let (party_one_first_message, comm_witness, ec_key_pair_party1) =
            party_one::KeyGenFirstMsg::create_commitments_with_fixed_secret_share(ECScalar::from(
                &party_one::KeyGenFirstMsg::get_secret_share_in_range(&bounds.0, &bounds.1)
                    .to_big_int(),
            ));
        let (party_two_first_message, _ec_key_pair_party2) =
            party_two::KeyGenFirstMsg::create_with_fixed_secret_share(ECScalar::from(
                &BigInt::from(10_i32),
            ));
        let party_one_second_message = party_one::KeyGenSecondMsg::verify_and_decommit(
            comm_witness,
            &party_two_first_message.d_log_proof,
        )
        .expect("failed to verify and decommit");

        let _party_two_second_message =
            party_two::KeyGenSecondMsg::verify_commitments_and_dlog_proof(
                &party_one_first_message,
                &party_one_second_message,
            )
            .expect("failed to verify commitments and DLog proof");

        // init paillier keypair:
        let mut paillier_key_pair =
            party_one::PaillierKeyPair::generate_keypair_and_encrypted_share(&ec_key_pair_party1);

        let party_one_private =
            Party1Private::set_private_key(&ec_key_pair_party1, &paillier_key_pair);

        let mut party_two_paillier = party_two::PaillierPublic {
            ek: paillier_key_pair.ek.clone(),
            encrypted_secret_share: paillier_key_pair.encrypted_share.clone(),
        };

        // zk proof of correct paillier key
        let correct_key_proof =
            party_one::PaillierKeyPair::generate_ni_proof_correct_key(&paillier_key_pair);

        correct_key_proof
            .verify(&party_two_paillier.ek)
            .expect("bad paillier key");

        //order of curve
        let order = FE::q();

        //Big int q/3
        let lower_bound: BigInt = order.div_floor(&BigInt::from(3));

        //Bigint -q/3
        let minus_lower_bound = BigInt::mod_sub(&order, &lower_bound, &order);

        //encrypt -q/3
        // let c1 = Paillier::encrypt(&paillier_key_pair.ek, RawPlaintext::from(minus_lower_bound));
        // put chosen randomness because it is needed raw in the proof generation
        let randomness = Randomness::sample(&paillier_key_pair.ek);

        let c1 = Paillier::encrypt_with_chosen_randomness(
            &paillier_key_pair.ek,
            RawPlaintext::from(minus_lower_bound.clone()),
            &randomness,
        );

        //compute x1-q/3 in the ciphertext space
        let new_cipher_x1_minus_q_thirds = Paillier::add(
            &paillier_key_pair.ek,
            RawCiphertext::from(paillier_key_pair.encrypted_share.clone()),
            c1,
        );

        //tweak c to c-q/3 for the soundness proof
        paillier_key_pair.encrypted_share = new_cipher_x1_minus_q_thirds.clone().0.into_owned();
        //tweak r to r*r' where r' is the randomness used to encrypt -q/3
        paillier_key_pair.randomness = BigInt::mod_mul(
            paillier_key_pair.randomness.borrow(),
            &randomness.0,
            &paillier_key_pair.ek.n,
        );
        //tweak c to c-q/3 for the soundness proof
        //TODO duplicate element here, is it needed?
        party_two_paillier.encrypted_secret_share =
            new_cipher_x1_minus_q_thirds.clone().0.into_owned();

        let party_one_private_for_range_proof =
            Party1Private::tweak_x1_for_range_proof(&ec_key_pair_party1, &paillier_key_pair);

        // zk range proof
        let range_proof = party_one::PaillierKeyPair::generate_range_proof(
            &paillier_key_pair,
            &party_one_private_for_range_proof,
        );
        party_two::PaillierPublic::verify_range_proof(&party_two_paillier, &range_proof)
            .expect("range proof error");
    }

    #[test]
    fn test_two_party_sign() {
        // assume party1 and party2 engaged with KeyGen in the past resulting in
        // party1 owning private share and paillier key-pair
        // party2 owning private share and paillier encryption of party1 share
        let (_party_one_private_share_gen, _comm_witness, ec_key_pair_party1) =
            party_one::KeyGenFirstMsg::create_commitments();
        let (party_two_private_share_gen, ec_key_pair_party2) = party_two::KeyGenFirstMsg::create();

        let keypair =
            party_one::PaillierKeyPair::generate_keypair_and_encrypted_share(&ec_key_pair_party1);

        // creating the ephemeral private shares:

        let (eph_party_two_first_message, eph_comm_witness, eph_ec_key_pair_party2) =
            party_two::EphKeyGenFirstMsg::create_commitments();
        let (eph_party_one_first_message, eph_ec_key_pair_party1) =
            party_one::EphKeyGenFirstMsg::create();
        let eph_party_two_second_message = party_two::EphKeyGenSecondMsg::verify_and_decommit(
            eph_comm_witness,
            &eph_party_one_first_message,
        )
        .expect("party1 DLog proof failed");

        let _eph_party_one_second_message =
            party_one::EphKeyGenSecondMsg::verify_commitments_and_dlog_proof(
                &eph_party_two_first_message,
                &eph_party_two_second_message,
            )
            .expect("failed to verify commitments and DLog proof");
        let party2_private = party_two::Party2Private::set_private_key(&ec_key_pair_party2);
        let message = BigInt::from(1234);
        let partial_sig = party_two::PartialSig::compute(
            &keypair.ek,
            &keypair.encrypted_share,
            &party2_private,
            &eph_ec_key_pair_party2,
            &eph_party_one_first_message.public_share,
            &message,
        );

        let party1_private =
            party_one::Party1Private::set_private_key(&ec_key_pair_party1, &keypair);

        let signature = party_one::Signature::compute(
            &party1_private,
            &partial_sig.c3,
            &eph_ec_key_pair_party1,
            &eph_party_two_second_message.comm_witness.public_share,
        );

        let pubkey =
            party_one::compute_pubkey(&party1_private, &party_two_private_share_gen.public_share);
        party_one::verify(&signature, &pubkey, &message).expect("Invalid signature")
    }
}
