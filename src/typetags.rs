use std::any::Any;
use std::fmt::{Display, Formatter};
use crate::curv::cryptographic_primitives::twoparty::coin_flip_optimal_rounds::{CoinFlipParty1FirstMsg, CoinFlipParty2FirstMsg};
use crate::curv::cryptographic_primitives::twoparty::dh_key_exchange_variant_with_pok_comm::{CommWitnessDHPoK, EcKeyPairDHPoK, Party1FirstMessage};
use crate::kms::chain_code::two_party::party1::ChainCode1;
use crate::kms::ecdsa::two_party::MasterKey1;
use crate::party_one::{CommWitness, EcKeyPair, EphEcKeyPair, HDPos, KeyGenFirstMsg, PaillierKeyPair, Party1Private, PDLdecommit, v};
use crate::party_two::{EphEcKeyPair2, EphKeyGenFirstMsg, PDL2decommit, PDLFirstMessage, PDLSecondMessage};
use crate::{Secp256k1Point, Secp256k1Scalar};
use crate::kms::rotation::two_party::Rotation;


#[typetag::serde]
pub trait Value: Sync + Send + Any {
    fn as_any(&self) -> &dyn Any;
    fn type_name(&self) -> &str;
}

#[macro_export]
macro_rules! typetag_value {
    ($struct_name:ident) => {
        #[typetag::serde]
        impl Value for $struct_name {
            fn as_any(&self) -> &dyn std::any::Any {
                self
            }

            fn type_name(&self) -> &str {
                stringify!($struct_name)
            }
        }

        impl Display for $struct_name {
            fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
                write!(f, "{:?}", self)
            }
        }
    };
}

typetag_value!(Secp256k1Point);
typetag_value!(Secp256k1Scalar);
typetag_value!(HDPos);
typetag_value!(KeyGenFirstMsg);
typetag_value!(CommWitness);
typetag_value!(EcKeyPair);
typetag_value!(v);
typetag_value!(PaillierKeyPair);
typetag_value!(Party1Private);
typetag_value!(PDLdecommit);
typetag_value!(EphEcKeyPair);
typetag_value!(EphEcKeyPair2);
typetag_value!(EphKeyGenFirstMsg);
typetag_value!(PDLFirstMessage);
typetag_value!(PDL2decommit);
typetag_value!(PDLSecondMessage);
typetag_value!(EcKeyPairDHPoK);
typetag_value!(CommWitnessDHPoK);
typetag_value!(Party1FirstMessage);
typetag_value!(ChainCode1);
typetag_value!(MasterKey1);
typetag_value!(CoinFlipParty1FirstMsg);
typetag_value!(CoinFlipParty2FirstMsg);
typetag_value!(Rotation);






