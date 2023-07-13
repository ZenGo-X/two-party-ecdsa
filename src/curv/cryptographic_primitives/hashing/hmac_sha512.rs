/*
    This file is part of Curv library
    Copyright 2018 by Kzen Networks
    (https://github.com/KZen-networks/curv)
    License MIT: https://github.com/KZen-networks/curv/blob/master/LICENSE
*/

use crate::curv::BigInt;

use super::traits::KeyedHash;
use crate::curv::arithmetic::traits::Converter;
use zeroize::Zeroize;
use sha2::Sha512;
use hmac::{Hmac, Mac};
pub struct HMacSha512;

impl KeyedHash for HMacSha512 {
    fn create_hmac(key: &BigInt, data: &[&BigInt]) -> BigInt {
        let mut key_bytes: Vec<u8> = key.into();

        let mut ctx = Hmac::<Sha512>::new_from_slice(&key_bytes).expect("HMAC can take key of any size");
        for value in data {
            ctx.update(&BigInt::to_vec(value));
        }
        key_bytes.zeroize();
        BigInt::from(ctx.finalize().into_bytes().as_ref())
    }
}

#[cfg(test)]
mod tests {

    use super::HMacSha512;
    use crate::curv::arithmetic::traits::Converter;
    use crate::curv::arithmetic::traits::Samplable;
    use crate::curv::cryptographic_primitives::hashing::traits::KeyedHash;
    use crate::curv::BigInt;

    #[test]
    fn create_hmac_test() {
        let key = BigInt::sample(512);
        let result1 = HMacSha512::create_hmac(&key, &vec![&BigInt::from(10)]);
        let key2 = BigInt::sample(512);
        // same data , different key
        let result2 = HMacSha512::create_hmac(&key2, &vec![&BigInt::from(10)]);
        assert_ne!(result1, result2);
        // same key , different data
        let result3 = HMacSha512::create_hmac(&key, &vec![&BigInt::from(10), &BigInt::from(11)]);
        assert_ne!(result1, result3);
        // same key, same data
        let result4 = HMacSha512::create_hmac(&key, &vec![&BigInt::from(10)]);
        assert_eq!(result1, result4)
    }

    #[test]
    fn test_malleability() {
        let key = BigInt::from(42u64);
        let hash_two_ones =
            HMacSha512::create_hmac(&key, &[&BigInt::from(1u64), &BigInt::from(1u64)]);
        let hash_257 = HMacSha512::create_hmac(&key, &[&BigInt::from((1u64 << 8) | 1u64)]);
        assert_eq!(hash_two_ones, hash_257);
    }

    #[test]
    fn hard_coded_tests_bigint() {
        let key42 = BigInt::from(42_i32);
        let key0 = BigInt::zero();
        {
            let zero_to_ten_thousand_hash_result_key42 = "a1ca4d9712b4dfc39871411edf1386ef735646a2d66e85aaa19b2236a351a8ccdfaf919b99b7bd20cfcfc69d9af776b67db4195e33fd22bdb8d5f2fdfdebec5";
            let zero_to_ten_thousand_hash_result_key0 = "ae513fc45b39fa6f5f1e969b77b5d050aaf065f2112e1ea3d402d155d5263bfb4a33880ab85cda3f9f64a0fa26bd1026489d07747515b46652dae48ccdc31d6d";
            let zero_to_ten_thousand: Vec<_> = (0..10_000i32).map(BigInt::from).collect();
            let refs: Vec<_> = zero_to_ten_thousand.iter().collect();
            let zero_to_ten_thousand_hash_key42 = HMacSha512::create_hmac(&key42, &refs);
            let zero_to_ten_thousand_hash_key0 = HMacSha512::create_hmac(&key0, &refs);
            assert_eq!(
                zero_to_ten_thousand_hash_key42.to_hex(),
                zero_to_ten_thousand_hash_result_key42
            );
            assert_eq!(
                zero_to_ten_thousand_hash_key0.to_hex(),
                zero_to_ten_thousand_hash_result_key0
            );
        }
        {
            let zero_to_2_512_result_key42 = "448506d680431d51e3c4b2aebe39c704c093afd15c5c98a3f2a66a9389acb749adbbd889e4cb5a3e0f798bf4b2805874c8ef243cccb6bc131ae5e331cd559808";
            let zero_to_2_512_result_key0 = "36c8f26854b6ca6fa3ec35195a41fcfc707aa748a2cc320b6553846c805c7e5530eb7ed76cb9b439b25d047eee7c9f6aab94c0c6f49ac34a1ffcb0a532c89a7e";
            let zero_to_2_512: Vec<_> = (0..1024usize).map(|i| BigInt::from(1) << i).collect();
            let refs: Vec<_> = zero_to_2_512.iter().collect();
            let zero_to_2_512_hash_key42 = HMacSha512::create_hmac(&key42, &refs);
            let zero_to_2_512_hash_key0 = HMacSha512::create_hmac(&key0, &refs);
            assert_eq!(
                zero_to_2_512_hash_key42.to_hex(),
                zero_to_2_512_result_key42
            );
            assert_eq!(zero_to_2_512_hash_key0.to_hex(), zero_to_2_512_result_key0);
        }
        {
            let empty_hash_result_key42 = "abb7e161d9ca3c1c60f6fd65c610a8c867b8f82342d4a2fdd9487e2df14c594206cabe73f9f5fbe1312138aacb89c765bd95789326dea1b5979a6ba2b98e89b6";
            let empty_hash_result_key0 = "b936cee86c9f87aa5d3c6f2e84cb5a4239a5fe50480a6ec66b70ab5b1f4ac6730c6c515421b327ec1d69402e53dfb49ad7381eb067b338fd7b0cb22247225d47";
            let empty_hash_key42 = HMacSha512::create_hmac(&key42, &[]);
            let empty_hash_key0 = HMacSha512::create_hmac(&key0, &[]);
            assert_eq!(empty_hash_key42.to_hex(), empty_hash_result_key42);
            assert_eq!(empty_hash_key0.to_hex(), empty_hash_result_key0);
        }
    }
}
