#![allow(non_snake_case)]
/*
centipede

Copyright 2018 by Kzen Networks

This file is part of centipede library
(https://github.com/KZen-networks/centipede)

Escrow-recovery is free software: you can redistribute
it and/or modify it under the terms of the GNU General Public
License as published by the Free Software Foundation, either
version 3 of the License, or (at your option) any later version.

@license GPL-3.0+ <https://github.com/KZen-networks/centipede/blob/master/LICENSE>
*/
const SECRETBITS: usize = 256;
use crate::curv::elliptic::curves::traits::*;
use crate::curv::{BigInt, FE, GE};
use rayon::prelude::*;
use std::ops::{Shl, Shr};
use super::proof_system::{Helgamal, Helgamalsegmented, Witness};
use crate::centipede::Errors::{self, ErrorDecrypting};

pub struct Msegmentation;

impl Msegmentation {
    pub fn get_segment_k(secret: &FE, segment_size: &usize, k: u8) -> FE {
        let ss_bn = secret.to_big_int();
        let segment_size_u32 = *segment_size as u32;
        let msb = segment_size_u32 * (k as u32 + 1);
        let lsb = segment_size_u32 * k as u32;
        let two_bn = BigInt::from(2);
        let max = BigInt::pow(&two_bn, msb) - BigInt::from(1);
        let min = BigInt::pow(&two_bn, lsb) - BigInt::from(1);
        let mask = max - min;
        let segment_k_bn = mask & ss_bn;
        let segment_k_bn_rotated =
            BigInt::shr(segment_k_bn, (k * (*segment_size) as u8) as usize);
        // println!("test = {:?}", test.to_str_radix(16));
        if segment_k_bn_rotated == BigInt::zero() {
            ECScalar::zero()
        } else {
            ECScalar::from(&segment_k_bn_rotated)
        }
    }
    //returns r_k,{D_k,E_k}
    pub fn encrypt_segment_k(
        secret: &FE,
        random: &FE,
        segment_size: &usize,
        k: u8,
        pub_ke_y: &GE,
        G: &GE,
    ) -> Helgamal {
        let segment_k = Msegmentation::get_segment_k(secret, segment_size, k);
        let E_k = G * random;
        let r_kY = pub_ke_y * random;
        if segment_k == ECScalar::zero() {
            let D_k = r_kY;
            Helgamal { D: D_k, E: E_k }
        } else {
            let x_kG = G * &segment_k;
            let D_k = r_kY + x_kG;
            Helgamal { D: D_k, E: E_k }
        }
    }

    // TODO: find a way using generics to combine the following two fn's
    pub fn assemble_fe(segments: &[FE], segment_size: &usize) -> FE {
        let two = BigInt::from(2);
        let mut segments_2n = segments.to_vec();
        let seg1 = segments_2n.remove(0);
        segments_2n
            .iter()
            .enumerate()
            .fold(seg1, |acc, x| {
                if x.1 == &FE::zero() {
                    acc
                } else {
                    let two_to_the_n = two.pow(*segment_size as u32);
                    let two_to_the_n_shifted = two_to_the_n.shl(x.0 * segment_size);
                    let two_to_the_n_shifted_fe: FE = ECScalar::from(&two_to_the_n_shifted);
                    let shifted_segment = *x.1 * two_to_the_n_shifted_fe;
                    acc + shifted_segment
                }
            })
    }

    pub fn assemble_ge(segments: &[GE], segment_size: &usize) -> GE {
        let two = BigInt::from(2);
        let mut segments_2n = segments.to_vec();
        let seg1 = segments_2n.remove(0);
        segments_2n
            .iter()
            .enumerate()
            .fold(seg1, |acc, x| {
                let two_to_the_n = two.pow(*segment_size as u32);
                let two_to_the_n_shifted = two_to_the_n.shl(x.0 * segment_size);
                let two_to_the_n_shifted_fe: FE = ECScalar::from(&two_to_the_n_shifted);
                let shifted_segment = x.1 * &two_to_the_n_shifted_fe;
                acc + shifted_segment
            })

    }

    pub fn to_encrypted_segments(
        secret: &FE,
        segment_size: &usize,
        num_of_segments: usize,
        pub_ke_y: &GE,
        G: &GE,
    ) -> (Witness, Helgamalsegmented) {
        assert_eq!(*segment_size * num_of_segments, SECRETBITS);
        let r_vec = (0..num_of_segments)
            .map(|_| ECScalar::new_random())
            .collect::<Vec<FE>>();
        let segmented_enc = (0..num_of_segments)
            .into_par_iter()
            .map(|i| {
                //  let segment_i = mSegmentation::get_segment_k(secret,segment_size,i as u8);
                Msegmentation::encrypt_segment_k(
                    secret,
                    &r_vec[i],
                    segment_size,
                    i as u8,
                    pub_ke_y,
                    G,
                )
            })
            .collect::<Vec<Helgamal>>();
        let x_vec = (0..num_of_segments)
            .map(|i| Msegmentation::get_segment_k(secret, segment_size, i as u8))
            .collect::<Vec<FE>>();
        let w = Witness { x_vec, r_vec };
        let heg_segmented = Helgamalsegmented { DE: segmented_enc };
        (w, heg_segmented)
    }

    //TODO: implement a more advance algorithm for dlog
    pub fn decrypt_segment(
        DE: &Helgamal,
        G: &GE,
        private_key: &FE,
        limit: &u32,
        table: &[GE],
    ) -> Result<FE, Errors> {
        let mut result = None;

        let limit_plus_one = *limit + 1u32;
        let out_of_limit_fe: FE = ECScalar::from(&BigInt::from(limit_plus_one));
        let out_of_limit_ge: GE = G * &out_of_limit_fe;
        let yE = DE.E * private_key;
        // handling 0 segment
        let mut D_minus_yE: GE = out_of_limit_ge;
        if yE == DE.D {
            result = Some(());
        } else {
            D_minus_yE = DE.D.sub_point(&yE.get_element());
        }
        // TODO: make bound bigger then 32
        let mut table_iter = table.iter().enumerate();
        // find is short-circuting //TODO: counter measure against side channel attacks
        let matched_value_index = table_iter.find(|&x| x.1 == &D_minus_yE);
        match matched_value_index {
            Some(x) => Ok(ECScalar::from(&BigInt::from(x.0 as u32 + 1))),
            None => {
                if result.is_some() {
                    Ok(ECScalar::zero())
                } else {
                    Err(ErrorDecrypting)
                }
            }
        }
    }

    pub fn decrypt(
        DE_vec: &Helgamalsegmented,
        G: &GE,
        private_key: &FE,
        segment_size: &usize,
    ) -> Result<FE, Errors> {
        let limit = 2u32.pow(*segment_size as u32);
        let test_ge_table = (1..limit)
            .into_par_iter()
            .map(|i| {
                let test_fe = ECScalar::from(&BigInt::from(i));
                G * &test_fe
            })
            .collect::<Vec<GE>>();
        let vec_secret = (0..DE_vec.DE.len())
            .into_par_iter()
            .map(|i| {
                Msegmentation::decrypt_segment(
                    &DE_vec.DE[i],
                    G,
                    private_key,
                    &limit,
                    &test_ge_table,
                )
            })
            .collect::<Vec<Result<FE, Errors>>>();
        let mut flag = true;
        let vec_secret_unwrap = (0..vec_secret.len())
            .into_iter()
            .map(|i| {
                if vec_secret[i].is_err() {
                    flag = false;
                    FE::zero()
                } else {
                    vec_secret[i].unwrap()
                }
            })
            .collect::<Vec<FE>>();
        match flag {
            false => Err(ErrorDecrypting),
            true => Ok(Msegmentation::assemble_fe(
                &vec_secret_unwrap,
                segment_size,
            )),
        }
    }
}
