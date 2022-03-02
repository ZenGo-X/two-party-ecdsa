/*
    This file is part of Curv library
    Copyright 2018 by Kzen Networks
    (https://github.com/KZen-networks/curv)
    License MIT: https://github.com/KZen-networks/curv/blob/master/LICENSE
*/

use super::traits::Hash;
use crate::curv::arithmetic::traits::Converter;
use crate::curv::elliptic::curves::traits::{ECPoint, ECScalar};
use crate::curv::BigInt;
use crate::curv::{FE, GE};
use sha2::{Digest, Sha256};

pub struct HSha256;

impl Hash for HSha256 {
    fn create_hash(big_ints: &[&BigInt]) -> BigInt {
        let mut digest = Sha256::new();

        for value in big_ints {
            digest.update(&BigInt::to_vec(value));
        }

        BigInt::from(digest.finalize().as_ref())
    }

    fn create_hash_from_ge(ge_vec: &[&GE]) -> FE {
        let mut digest = Sha256::new();

        for value in ge_vec {
            digest.update(&value.pk_to_key_slice());
        }

        let result = BigInt::from(digest.finalize().as_ref());
        ECScalar::from(&result)
    }
}

#[cfg(test)]
mod tests {
    use super::HSha256;
    use super::Hash;
    use crate::curv::arithmetic::traits::Converter;
    use crate::curv::elliptic::curves::traits::ECPoint;
    use crate::curv::elliptic::curves::traits::ECScalar;
    use crate::curv::BigInt;
    use crate::curv::{GE, SK};
    use crate::Secp256k1Scalar;

    #[test]
    // Very basic test here, TODO: suggest better testing
    fn create_hash_test() {
        let result = HSha256::create_hash(&[&BigInt::one(), &BigInt::zero()]);
        assert!(result > BigInt::zero());
    }

    #[test]
    fn create_hash_from_ge_test() {
        let point = GE::base_point2();
        let result1 = HSha256::create_hash_from_ge(&[&point, &GE::generator()]);
        assert!(result1.to_big_int().to_str_radix(2).len() > 240);
        let result2 = HSha256::create_hash_from_ge(&[&GE::generator(), &point]);
        assert_ne!(result1, result2);
        let result3 = HSha256::create_hash_from_ge(&[&GE::generator(), &point]);
        assert_eq!(result2, result3);
    }

    #[test]
    fn test_malleability() {
        let hash_two_ones = HSha256::create_hash(&[&BigInt::from(1u64), &BigInt::from(1u64)]);
        let hash_257 = HSha256::create_hash(&[&BigInt::from((1u64 << 8) | 1u64)]);
        assert_eq!(hash_two_ones, hash_257);
    }

    #[test]
    fn hard_coded_tests_bigint() {
        {
            let zero_to_ten_thousand_hash_result =
                "c352894bc8afc9ba17966530e1a168f057ee3eee8b240ad481d6cf8979caa766";
            let zero_to_ten_thousand: Vec<_> = (0..10_000i32).map(BigInt::from).collect();
            let refs: Vec<_> = zero_to_ten_thousand.iter().collect();
            let zero_to_ten_thousand_hash = HSha256::create_hash(&refs);
            assert_eq!(
                zero_to_ten_thousand_hash.to_hex(),
                zero_to_ten_thousand_hash_result
            );
        }
        {
            let zero_to_2_512_result =
                "8f7f29658a2b3dea46eff628c3ceae7202938384a7951b9db406fe7fc33b7684";
            let zero_to_2_512: Vec<_> = (0..1024usize).map(|i| BigInt::from(1) << i).collect();
            let refs: Vec<_> = zero_to_2_512.iter().collect();
            let zero_to_2_512_hash = HSha256::create_hash(&refs);
            assert_eq!(zero_to_2_512_hash.to_hex(), zero_to_2_512_result);
        }
        {
            let empty_hash_result =
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
            let empty_hash = HSha256::create_hash(&[]);
            assert_eq!(empty_hash.to_hex(), empty_hash_result);
        }
    }
    #[test]
    fn hard_coded_tests_ge() {
        let bigint_to_scalar = |b| GE::generator() * <Secp256k1Scalar as ECScalar<SK>>::from(&b);
        {
            let one_to_500_hash_result = [
                170, 105, 214, 27, 254, 73, 137, 65, 49, 125, 204, 178, 16, 81, 95, 43, 71, 180,
                90, 134, 224, 77, 64, 139, 80, 240, 12, 24, 80, 177, 221, 70,
            ];
            let one_to_500: Vec<GE> = (1..500i32)
                .map(BigInt::from)
                .map(bigint_to_scalar)
                .collect();
            let refs: Vec<_> = one_to_500.iter().collect();
            let one_to_500_hash = HSha256::create_hash_from_ge(&refs);
            assert_eq!(
                one_to_500_hash.get_element().serialize_secret(),
                one_to_500_hash_result
            );
        }
        {
            let one_to_2_256_result = [
                241, 174, 75, 140, 102, 249, 217, 185, 218, 180, 114, 118, 35, 254, 21, 58, 103,
                127, 243, 177, 145, 36, 209, 1, 51, 243, 4, 174, 93, 15, 202, 35,
            ];
            let one_to_2_256: Vec<GE> = (0..256usize)
                .map(|i| BigInt::from(1) << i)
                .map(bigint_to_scalar)
                .collect();
            let refs: Vec<_> = one_to_2_256.iter().collect();
            let one_to_2_256_hash = HSha256::create_hash_from_ge(&refs);
            assert_eq!(
                one_to_2_256_hash.get_element().serialize_secret(),
                one_to_2_256_result
            );
        }
        {
            let empty_hash_result = [
                227, 176, 196, 66, 152, 252, 28, 20, 154, 251, 244, 200, 153, 111, 185, 36, 39,
                174, 65, 228, 100, 155, 147, 76, 164, 149, 153, 27, 120, 82, 184, 85,
            ];
            let empty_hash = HSha256::create_hash_from_ge(&[]);
            assert_eq!(
                empty_hash.get_element().serialize_secret(),
                empty_hash_result
            );
        }
        {
            let gen_hash_result = [
                80, 146, 155, 116, 193, 160, 73, 84, 183, 139, 75, 96, 53, 233, 122, 94, 7, 138,
                90, 15, 40, 236, 150, 213, 71, 191, 238, 154, 206, 128, 58, 192,
            ];
            let gen_hash = HSha256::create_hash_from_ge(&[&GE::generator()]);
            assert_eq!(gen_hash.get_element().serialize_secret(), gen_hash_result);
        }
    }
}
