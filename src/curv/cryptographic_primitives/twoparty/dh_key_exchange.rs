/*
    This file is part of Curv library
    Copyright 2018 by Kzen Networks
    (https://github.com/KZen-networks/curv)
    License MIT: <https://github.com/KZen-networks/curv/blob/master/LICENSE>
*/

/// in ECDH Alice chooses at random a secret "a" and sends Bob public key A = aG
/// Bob chooses at random a secret "b" and sends to Alice B = bG.
/// Both parties can compute a joint secret: C =aB = bA = abG which cannot be computed by
/// a man in the middle attacker.
use crate::curv::elliptic::curves::traits::*;
use crate::curv::FE;
use crate::curv::GE;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EcKeyPair {
    pub public_share: GE,
    secret_share: FE,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Party1FirstMessage {
    pub public_share: GE,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Party2FirstMessage {
    pub public_share: GE,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Party2SecondMessage {}

impl Party1FirstMessage {
    pub fn first() -> (Party1FirstMessage, EcKeyPair) {
        let base: GE = ECPoint::generator();

        let secret_share: FE = ECScalar::new_random();

        let public_share = base * secret_share;

        let ec_key_pair = EcKeyPair {
            public_share,
            secret_share,
        };
        (Party1FirstMessage { public_share }, ec_key_pair)
    }

    pub fn first_with_fixed_secret_share(secret_share: FE) -> (Party1FirstMessage, EcKeyPair) {
        let base: GE = ECPoint::generator();
        let public_share = base * secret_share;

        let ec_key_pair = EcKeyPair {
            public_share,
            secret_share,
        };
        (Party1FirstMessage { public_share }, ec_key_pair)
    }
}

impl Party2FirstMessage {
    pub fn first() -> (Party2FirstMessage, EcKeyPair) {
        let base: GE = ECPoint::generator();
        let secret_share: FE = ECScalar::new_random();
        let public_share = base * secret_share;
        let ec_key_pair = EcKeyPair {
            public_share,
            secret_share,
        };
        (Party2FirstMessage { public_share }, ec_key_pair)
    }

    pub fn first_with_fixed_secret_share(secret_share: FE) -> (Party2FirstMessage, EcKeyPair) {
        let base: GE = ECPoint::generator();
        let public_share = base * secret_share;
        let ec_key_pair = EcKeyPair {
            public_share,
            secret_share,
        };
        (Party2FirstMessage { public_share }, ec_key_pair)
    }
}

pub fn compute_pubkey(local_share: &EcKeyPair, other_share_public_share: &GE) -> GE {
    other_share_public_share * &local_share.secret_share
}

#[cfg(test)]
mod tests {
    use crate::curv::cryptographic_primitives::twoparty::dh_key_exchange::*;
    use crate::curv::elliptic::curves::traits::ECScalar;
    use crate::curv::BigInt;
    use crate::curv::{FE, GE};

    #[test]
    fn test_dh_key_exchange_random_shares() {
        let (kg_party_one_first_message, kg_ec_key_pair_party1) = Party1FirstMessage::first();
        let (kg_party_two_first_message, kg_ec_key_pair_party2) = Party2FirstMessage::first();

        assert_eq!(
            compute_pubkey(
                &kg_ec_key_pair_party2,
                &kg_party_one_first_message.public_share
            ),
            compute_pubkey(
                &kg_ec_key_pair_party1,
                &kg_party_two_first_message.public_share
            )
        );
    }

    #[test]
    fn test_dh_key_exchange_fixed_shares() {
        let secret_party_1: FE = ECScalar::from(&BigInt::one());
        let (kg_party_one_first_message, kg_ec_key_pair_party1) =
            Party1FirstMessage::first_with_fixed_secret_share(secret_party_1);
        let secret_party_2: FE = ECScalar::from(&BigInt::from(2));

        let (kg_party_two_first_message, kg_ec_key_pair_party2) =
            Party2FirstMessage::first_with_fixed_secret_share(secret_party_2);

        assert_eq!(
            compute_pubkey(
                &kg_ec_key_pair_party2,
                &kg_party_one_first_message.public_share
            ),
            compute_pubkey(
                &kg_ec_key_pair_party1,
                &kg_party_two_first_message.public_share
            )
        );
        let g: GE = GE::generator();
        assert_eq!(
            compute_pubkey(
                &kg_ec_key_pair_party2,
                &kg_party_one_first_message.public_share
            ),
            g * secret_party_2
        );
    }
}
