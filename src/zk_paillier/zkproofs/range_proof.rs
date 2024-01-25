/*
    zk-paillier

    Copyright 2018 by Kzen Networks

    This file is part of Multisig Schnorr library
    (https://github.com/KZen-networks/multisig-schnorr)

    zk-paillier is free software: you can redistribute
    it and/or modify it under the terms of the GNU General Public
    License as published by the Free Software Foundation, either
    version 3 of the License, or (at your option) any later version.

    @license GPL-3.0+ <https://github.com/KZen-networks/zk-paillier/blob/master/LICENSE>
*/
use crate::curv::arithmetic::traits::Samplable;
use std::borrow::Borrow;
use std::mem;

use bit_vec::BitVec;
use rand::prelude::*;
use rayon::prelude::*;

use super::CorrectKeyProofError;
use crate::curv::BigInt;
use crate::paillier::EncryptWithChosenRandomness;
use crate::paillier::Paillier;
use crate::paillier::{EncryptionKey, Randomness, RawCiphertext, RawPlaintext};
use serde::{Serialize,Deserialize};

#[derive(Default, Debug, Serialize, Deserialize)]
pub struct EncryptedPairs {
    #[serde(with = "crate::zk_paillier::serialize::vecbigint")]
    pub c1: Vec<BigInt>, // TODO[Morten] should not need to be public

    #[serde(with = "crate::zk_paillier::serialize::vecbigint")]
    pub c2: Vec<BigInt>, // TODO[Morten] should not need to be public
}

#[derive(Default)]
pub struct DataRandomnessPairs {
    w1: Vec<BigInt>,
    w2: Vec<BigInt>,
    r1: Vec<BigInt>,
    r2: Vec<BigInt>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ChallengeBits(Vec<u8>);

// TODO[Morten] find better name
#[derive(Debug, Serialize, Deserialize)]
pub enum Response {
    Open {
        #[serde(with = "crate::zk_paillier::serialize::bigint")]
        w1: BigInt,

        #[serde(with = "crate::zk_paillier::serialize::bigint")]
        r1: BigInt,

        #[serde(with = "crate::zk_paillier::serialize::bigint")]
        w2: BigInt,

        #[serde(with = "crate::zk_paillier::serialize::bigint")]
        r2: BigInt,
    },

    Mask {
        j: u8,

        #[serde(with = "crate::zk_paillier::serialize::bigint")]
        masked_x: BigInt,

        #[serde(with = "crate::zk_paillier::serialize::bigint")]
        masked_r: BigInt,
    },
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Proof(Vec<Response>);

impl From<Vec<u8>> for ChallengeBits {
    fn from(x: Vec<u8>) -> Self {
        ChallengeBits(x)
    }
}

/// Zero-knowledge range proof that a value x<q/3 lies in interval [0,q].
///
/// The verifier is given only c = ENC(ek,x).
/// The prover has input x, dk, r (randomness used for calculating c)
/// It is assumed that q is known to both.
///
/// References:
/// - Appendix A in [Lindell'17](https://eprint.iacr.org/2017/552)
/// - Section 1.2.2 in [Boudot '00](https://www.iacr.org/archive/eurocrypt2000/1807/18070437-new.pdf)
///
/// /// This is an interactive version of the proof, assuming only DCRA which is alreasy assumed for Paillier cryptosystem security
pub trait RangeProofTrait {
    /// Prover generates t random pairs, each pair encrypts a number in {q/3, 2q/3} and a number in {0, q/3}
    fn generate_encrypted_pairs(
        ek: &EncryptionKey,
        range: &BigInt,
        error_factor: usize,
    ) -> (EncryptedPairs, DataRandomnessPairs);

    /// Prover calcuate z_i according to bit e_i and returns a vector z
    fn generate_proof(
        ek: &EncryptionKey,
        secret_x: &BigInt,
        secret_r: &BigInt,
        e: &ChallengeBits,
        range: &BigInt,
        data: &DataRandomnessPairs,
        error_factor: usize,
    ) -> Proof;

    /// Verifier verifies the proof
    fn verifier_output(
        ek: &EncryptionKey,
        e: &ChallengeBits,
        encrypted_pairs: &EncryptedPairs,
        z: &Proof,
        range: &BigInt,
        cipher_x: &BigInt,
        error_factor: usize,
    ) -> Result<(), CorrectKeyProofError>;
}
pub struct RangeProof;

impl RangeProofTrait for RangeProof {
    fn generate_encrypted_pairs(
        ek: &EncryptionKey,
        range: &BigInt,
        error_factor: usize,
    ) -> (EncryptedPairs, DataRandomnessPairs) {
        let range_scaled_third = range.div_floor(&BigInt::from(3));
        let range_scaled_two_thirds = BigInt::from(2) * &range_scaled_third;

        let mut w1: Vec<_> = (0..error_factor)
            .into_par_iter()
            .map(|_| BigInt::sample_range(&range_scaled_third, &range_scaled_two_thirds))
            .collect();

        let mut w2: Vec<_> = w1.par_iter().map(|x| x - &range_scaled_third).collect();

        // with probability 1/2 switch between w1i and w2i
        for i in 0..error_factor {
            // TODO[Morten] need secure randomness?
            if random() {
                mem::swap(&mut w2[i], &mut w1[i]);
            }
        }

        let r1: Vec<_> = (0..error_factor)
            .into_par_iter()
            .map(|_| BigInt::sample_below(&ek.n))
            .collect();

        let r2: Vec<_> = (0..error_factor)
            .into_par_iter()
            .map(|_| BigInt::sample_below(&ek.n))
            .collect();

        let c1: Vec<_> = w1
            .par_iter()
            .zip(&r1)
            .map(|(wi, ri)| {
                Paillier::encrypt_with_chosen_randomness(
                    ek,
                    RawPlaintext::from(wi),
                    &Randomness::from(ri),
                )
                .0
                .into_owned()
            })
            .collect();

        let c2: Vec<_> = w2
            .par_iter()
            .zip(&r2)
            .map(|(wi, ri)| {
                Paillier::encrypt_with_chosen_randomness(
                    ek,
                    RawPlaintext::from(wi),
                    &Randomness::from(ri),
                )
                .0
                .into_owned()
            })
            .collect();

        (
            EncryptedPairs { c1, c2 },
            DataRandomnessPairs { w1, w2, r1, r2 },
        )
    }

    fn generate_proof(
        ek: &EncryptionKey,
        secret_x: &BigInt,
        secret_r: &BigInt,
        e: &ChallengeBits,
        range: &BigInt,
        data: &DataRandomnessPairs,
        error_factor: usize,
    ) -> Proof {
        let range_scaled_third: BigInt = range.div_floor(&BigInt::from(3));
        let range_scaled_two_thirds = BigInt::from(2) * &range_scaled_third;
        let bits_of_e = BitVec::from_bytes(&e.0);
        let reponses: Vec<_> = (0..error_factor)
            .into_par_iter()
            .map(|i| {
                let ei = bits_of_e[i];
                if !ei {
                    Response::Open {
                        w1: data.w1[i].clone(),
                        r1: data.r1[i].clone(),
                        w2: data.w2[i].clone(),
                        r2: data.r2[i].clone(),
                    }
                } else if secret_x + &data.w1[i] > range_scaled_third
                    && secret_x + &data.w1[i] < range_scaled_two_thirds
                {
                    Response::Mask {
                        j: 1,
                        masked_x: secret_x + &data.w1[i],
                        masked_r: secret_r * &data.r1[i] % &ek.n,
                    }
                } else {
                    Response::Mask {
                        j: 2,
                        masked_x: secret_x + &data.w2[i],
                        masked_r: secret_r * &data.r2[i] % &ek.n,
                    }
                }
            })
            .collect();

        Proof(reponses)
    }

    fn verifier_output(
        ek: &EncryptionKey,
        e: &ChallengeBits,
        encrypted_pairs: &EncryptedPairs,
        proof: &Proof,
        range: &BigInt,
        cipher_x: &BigInt,
        error_factor: usize,
    ) -> Result<(), CorrectKeyProofError> {
        let cipher_x_raw = RawCiphertext::from(cipher_x);
        let range_scaled_third: BigInt = range.div_floor(&BigInt::from(3i32));
        let range_scaled_two_thirds: BigInt = BigInt::from(2i32) * &range_scaled_third;

        let bits_of_e = BitVec::from_bytes(&e.0);
        let responses = &proof.0;

        let verifications: Vec<bool> = (0..error_factor)
            .into_par_iter()
            .map(|i| {
                let ei = bits_of_e[i];
                let response = &responses[i];

                match (ei, response) {
                    (false, Response::Open { w1, r1, w2, r2 }) => {
                        let mut res = true;

                        let expected_c1i: BigInt = Paillier::encrypt_with_chosen_randomness(
                            ek,
                            RawPlaintext::from(w1),
                            &Randomness::from(r1),
                        )
                        .into();
                        let expected_c2i: BigInt = Paillier::encrypt_with_chosen_randomness(
                            ek,
                            RawPlaintext::from(w2),
                            &Randomness::from(r2),
                        )
                        .into();

                        if expected_c1i != encrypted_pairs.c1[i] {
                            res = false;
                        }
                        if expected_c2i != encrypted_pairs.c2[i] {
                            res = false;
                        }

                        let mut flag = false;

                        if w1 < &range_scaled_third
                            && w2 > &range_scaled_third
                            && w2 < &range_scaled_two_thirds
                        {
                            flag = true;
                        }
                        if w2 < &range_scaled_third
                            && w1 > &range_scaled_third
                            && w1 < &range_scaled_two_thirds
                        {
                            flag = true;
                        }
                        if !flag {
                            res = false;
                        }

                        res
                    }

                    (
                        true,
                        Response::Mask {
                            j,
                            masked_x,
                            masked_r,
                        },
                    ) => {
                        let mut res = true;

                        let c = if *j == 1 {
                            &encrypted_pairs.c1[i] * cipher_x_raw.0.borrow() % &ek.nn
                        } else {
                            &encrypted_pairs.c2[i] * cipher_x_raw.0.borrow() % &ek.nn
                        };

                        let enc_zi = Paillier::encrypt_with_chosen_randomness(
                            ek,
                            RawPlaintext::from(masked_x),
                            &Randomness::from(masked_r.clone()),
                        );
                        if &c != enc_zi.0.borrow() {
                            res = false;
                        }
                        if masked_x < &range_scaled_third || masked_x > &range_scaled_two_thirds {
                            res = false;
                        }

                        res
                    }

                    _ => false,
                }
            })
            .collect();

        if verifications.iter().all(|b| *b) {
            Ok(())
        } else {
            Err(CorrectKeyProofError)
        }
    }
}

#[cfg(test)]
mod tests {
    const RANGE_BITS: usize = 256; //for elliptic curves with 256bits for example
    const STATISTICAL_ERROR_FACTOR: usize = 128;

    use super::*;
    use crate::paillier::{Keypair, Randomness};

    fn test_keypair() -> Keypair {
        let p = str::parse("148677972634832330983979593310074301486537017973460461278300587514468301043894574906886127642530475786889672304776052879927627556769456140664043088700743909632312483413393134504352834240399191134336344285483935856491230340093391784574980688823380828143810804684752914935441384845195613674104960646037368551517").unwrap();
        let q = str::parse("158741574437007245654463598139927898730476924736461654463975966787719309357536545869203069369466212089132653564188443272208127277664424448947476335413293018778018615899291704693105620242763173357203898195318179150836424196645745308205164116144020613415407736216097185962171301808761138424668335445923774195463").unwrap();
        Keypair { p, q }
    }

    #[test]
    fn test_range_proof_correct_proof() {
        // common:
        let range = BigInt::sample(RANGE_BITS);
        // prover:
        let (ek, _dk) = test_keypair().keys();
        let (_verifier_ek, _verifier_dk) = test_keypair().keys();
        // prover:
        let (encrypted_pairs, data_and_randmoness_pairs) =
            RangeProof::generate_encrypted_pairs(&ek, &range, STATISTICAL_ERROR_FACTOR);
        // prover:
        let secret_r = BigInt::sample_below(&ek.n);
        let secret_x = BigInt::sample_below(&range.div_floor(&BigInt::from(3)));
        // common:
        let cipher_x = Paillier::encrypt_with_chosen_randomness(
            &ek,
            RawPlaintext::from(&secret_x),
            &Randomness(secret_r.clone()),
        );
        let mut v = vec![ek.n.clone()];
        v.extend_from_slice(&encrypted_pairs.c1);
        v.extend_from_slice(&encrypted_pairs.c2);
        let e = ChallengeBits::from(super::super::compute_digest(v.iter()));

        // verifer decommits (tested in test_commit_decommit)
        // prover:
        let z_vector = RangeProof::generate_proof(
            &ek,
            &secret_x,
            &secret_r,
            &e,
            &range,
            &data_and_randmoness_pairs,
            STATISTICAL_ERROR_FACTOR,
        );
        // verifier:
        let result = RangeProof::verifier_output(
            &ek,
            &e,
            &encrypted_pairs,
            &z_vector,
            &range,
            &cipher_x.0,
            STATISTICAL_ERROR_FACTOR,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_range_proof_incorrect_proof() {
        // common:
        let range = BigInt::sample(RANGE_BITS);
        // prover:
        let (ek, _dk) = test_keypair().keys();
        let (_verifier_ek, _verifier_dk) = test_keypair().keys();
        // prover:
        let (encrypted_pairs, data_and_randmoness_pairs) =
            RangeProof::generate_encrypted_pairs(&ek, &range, STATISTICAL_ERROR_FACTOR);
        // prover:
        let secret_r = BigInt::sample_below(&ek.n);
        let secret_x = BigInt::sample_range(
            &(BigInt::from(100i32) * &range),
            &(BigInt::from(10000i32) * &range),
        );
        // common:
        let cipher_x = Paillier::encrypt_with_chosen_randomness(
            &ek,
            RawPlaintext::from(&secret_x),
            &Randomness(secret_r.clone()),
        );
        // verifer decommits (tested in test_commit_decommit)
        // prover:
        let mut v = vec![ek.n.clone()];
        v.extend_from_slice(&encrypted_pairs.c1);
        v.extend_from_slice(&encrypted_pairs.c2);
        let e = ChallengeBits::from(super::super::compute_digest(v.iter()));
        let z_vector = RangeProof::generate_proof(
            &ek,
            &secret_x,
            &secret_r,
            &e,
            &range,
            &data_and_randmoness_pairs,
            STATISTICAL_ERROR_FACTOR,
        );
        // verifier:
        let result = RangeProof::verifier_output(
            &ek,
            &e,
            &encrypted_pairs,
            &z_vector,
            &range,
            &cipher_x.0,
            STATISTICAL_ERROR_FACTOR,
        );
        assert!(result.is_err());
    }

    // #[bench]
    // fn bench_range_proof(b: &mut Bencher) {
    //     // TODO: bench range for 256bit range.
    //     b.iter(|| {
    //         // common:
    //         let range = BigInt::sample(RANGE_BITS);
    //         // prover:
    //         let (ek, _dk) = test_keypair().keys();
    //         let (verifier_ek, _verifier_dk) = test_keypair().keys();
    //         // verifier:
    //         let (_com, _r, e) = RangeProof::verifier_commit(&verifier_ek);
    //         // prover:
    //         let (encrypted_pairs, data_and_randmoness_pairs) =
    //             RangeProof::generate_encrypted_pairs(&ek, &range, STATISTICAL_ERROR_FACTOR);
    //         // prover:
    //         let secret_r = BigInt::sample_below(&ek.n);
    //         let secret_x = BigInt::sample_below(&range.div_floor(&BigInt::from(3)));
    //         //let secret_x = BigInt::from(0xFFFFFFFi64);
    //         // common:
    //         let cipher_x = Paillier::encrypt_with_chosen_randomness(
    //             &ek,
    //             RawPlaintext::from(&secret_x),
    //             &Randomness(secret_r.clone()),
    //         );
    //         // verifer decommits (tested in test_commit_decommit)
    //         // prover:
    //         let z_vector = RangeProof::generate_proof(
    //             &ek,
    //             &secret_x,
    //             &secret_r,
    //             &e,
    //             &range,
    //             &data_and_randmoness_pairs,
    //             STATISTICAL_ERROR_FACTOR,
    //         );
    //         // verifier:
    //         let _result = RangeProof::verifier_output(
    //             &ek,
    //             &e,
    //             &encrypted_pairs,
    //             &z_vector,
    //             &range,
    //             &cipher_x.0,
    //             STATISTICAL_ERROR_FACTOR,
    //         );
    //     });
    // }
}
