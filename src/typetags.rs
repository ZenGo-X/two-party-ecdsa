use std::any::Any;
use std::fmt::{Display, Formatter};
use crate::party_one;
use crate::party_two;
use crate::{Secp256k1Point, Secp256k1Scalar};
use crate::curv::cryptographic_primitives::twoparty::dh_key_exchange_variant_with_pok_comm;
use crate::kms::chain_code::two_party::party1;
use crate::kms::ecdsa::two_party::MasterKey1;
use crate::kms::rotation::two_party::Rotation;
use crate::kms::ecdsa::two_party::party1 as rotation_party_one;


#[typetag::serde]
pub trait Value: Sync + Send + Any {
    fn as_any(&self) -> &dyn Any;
    fn type_name(&self) -> &str;
}

#[macro_export]
macro_rules! typetag_value {
    ($struct_name:ty) => {
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

typetag_value!(party_one::HDPos);
typetag_value!(party_one::KeyGenFirstMsg);
typetag_value!(party_one::CommWitness);
typetag_value!(party_one::EcKeyPair);
typetag_value!(party_one::PaillierKeyPair);
typetag_value!(party_one::Party1Private);
typetag_value!(party_one::PDLdecommit);
typetag_value!(party_one::EphEcKeyPair);
typetag_value!(party_one::PDLFirstMessage);
typetag_value!(party_one::v);


typetag_value!(party1::ChainCode1);

typetag_value!(MasterKey1);

typetag_value!(party_two::PDLFirstMessage);
typetag_value!(party_two::EphKeyGenFirstMsg);

typetag_value!(dh_key_exchange_variant_with_pok_comm::CommWitnessDHPoK);
typetag_value!(dh_key_exchange_variant_with_pok_comm::Party1FirstMessage);
typetag_value!(dh_key_exchange_variant_with_pok_comm::EcKeyPairDHPoK);


typetag_value!(Rotation);

typetag_value!(rotation_party_one::RotationParty1Message1);







