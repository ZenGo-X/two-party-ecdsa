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
use ring::digest::{Context, SHA512};

pub struct HSha512;

impl Hash for HSha512 {
    fn create_hash(big_ints: &[&BigInt]) -> BigInt {
        let mut digest = Context::new(&SHA512);

        for value in big_ints {
            digest.update(&BigInt::to_vec(value));
        }

        BigInt::from(digest.finish().as_ref())
    }

    fn create_hash_from_ge(ge_vec: &[&GE]) -> FE {
        let mut digest = Context::new(&SHA512);

        for value in ge_vec {
            digest.update(&value.pk_to_key_slice());
        }

        let result = BigInt::from(digest.finish().as_ref());
        ECScalar::from(&result)
    }
}

#[cfg(test)]
mod tests {
    use super::HSha512;
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
        let result = HSha512::create_hash(&[&BigInt::one(), &BigInt::zero()]);
        assert!(result > BigInt::zero());
    }

    #[test]
    fn create_hash_from_ge_test() {
        let point = GE::base_point2();
        let result1 = HSha512::create_hash_from_ge(&[&point, &GE::generator()]);
        assert!(result1.to_big_int().to_str_radix(2).len() > 240);
        let result2 = HSha512::create_hash_from_ge(&[&GE::generator(), &point]);
        assert_ne!(result1, result2);
        let result3 = HSha512::create_hash_from_ge(&[&GE::generator(), &point]);
        assert_eq!(result2, result3);
    }

    #[test]
    fn test_malleability() {
        let hash_two_ones = HSha512::create_hash(&[&BigInt::from(1u64), &BigInt::from(1u64)]);
        let hash_257 = HSha512::create_hash(&[&BigInt::from((1u64 << 8) | 1u64)]);
        assert_eq!(hash_two_ones, hash_257);
    }

    #[test]
    fn hard_coded_tests_bigint() {
        {
            let zero_to_ten_thousand_hash_result = "8c0cac3aaeaecb57da4d85a315d670e02b994d728b19435be8c467ec4cd1cb9e38b7570bfa57d28bc2e1aafc3839c3174faab31b926e5855c992b13028c83aa6";
            let zero_to_ten_thousand: Vec<_> = (0..10_000i32).map(BigInt::from).collect();
            let refs: Vec<_> = zero_to_ten_thousand.iter().collect();
            let zero_to_ten_thousand_hash = HSha512::create_hash(&refs);
            assert_eq!(
                zero_to_ten_thousand_hash.to_hex(),
                zero_to_ten_thousand_hash_result
            );
        }
        {
            let zero_to_2_512_result = "7952581f501695b95430e447516c79682011069b44c27354f7f0dec2a25218a218316a973af527e057ba1ac1f78e09312643118cc5b0d34e45029ca21565aaa5";
            let zero_to_2_512: Vec<_> = (0..1024usize).map(|i| BigInt::from(1) << i).collect();
            let refs: Vec<_> = zero_to_2_512.iter().collect();
            let zero_to_2_512_hash = HSha512::create_hash(&refs);
            assert_eq!(zero_to_2_512_hash.to_hex(), zero_to_2_512_result);
        }
        {
            let empty_hash_result = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e";
            let empty_hash = HSha512::create_hash(&[]);
            assert_eq!(empty_hash.to_hex(), empty_hash_result);
        }
    }
    #[test]
    fn hard_coded_tests_ge() {
        let bigint_to_scalar = |b| GE::generator() * <Secp256k1Scalar as ECScalar<SK>>::from(&b);
        {
            let one_to_500_hash_result = [
                154, 56, 207, 106, 123, 234, 190, 69, 153, 220, 145, 123, 60, 139, 218, 185, 213,
                139, 130, 51, 101, 61, 249, 115, 151, 206, 43, 62, 90, 205, 31, 16,
            ];
            let one_to_500: Vec<GE> = (1..500i32)
                .map(BigInt::from)
                .map(bigint_to_scalar)
                .collect();
            let refs: Vec<_> = one_to_500.iter().collect();
            let one_to_500_hash = HSha512::create_hash_from_ge(&refs);
            assert_eq!(
                one_to_500_hash.get_element().serialize_secret(),
                one_to_500_hash_result
            );
        }
        {
            let one_to_2_256_result = [
                66, 69, 86, 129, 100, 229, 205, 151, 190, 63, 130, 109, 122, 30, 7, 227, 164, 6,
                224, 48, 79, 212, 1, 143, 254, 146, 197, 198, 17, 194, 233, 164,
            ];
            let one_to_2_256: Vec<GE> = (0..256usize)
                .map(|i| BigInt::from(1) << i)
                .map(bigint_to_scalar)
                .collect();
            let refs: Vec<_> = one_to_2_256.iter().collect();
            let one_to_2_256_hash = HSha512::create_hash_from_ge(&refs);
            assert_eq!(
                one_to_2_256_hash.get_element().serialize_secret(),
                one_to_2_256_result
            );
        }
        {
            let empty_hash_result = [
                34, 18, 235, 230, 177, 4, 147, 164, 69, 239, 9, 230, 147, 26, 24, 85, 142, 53, 158,
                171, 78, 240, 12, 116, 50, 115, 140, 216, 225, 142, 253, 89,
            ];
            let empty_hash = HSha512::create_hash_from_ge(&[]);
            assert_eq!(
                empty_hash.get_element().serialize_secret(),
                empty_hash_result
            );
        }
        {
            let gen_hash_result = [
                153, 3, 137, 213, 218, 128, 147, 189, 18, 164, 34, 58, 46, 132, 171, 246, 248, 188,
                11, 0, 138, 8, 152, 160, 100, 230, 18, 58, 88, 83, 75, 253,
            ];
            let gen_hash = HSha512::create_hash_from_ge(&[&GE::generator()]);
            assert_eq!(gen_hash.get_element().serialize_secret(), gen_hash_result);
        }
    }
}
