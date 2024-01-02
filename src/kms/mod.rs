pub mod chain_code;
pub mod ecdsa;

pub mod poc;

#[derive(Copy, PartialEq, Eq, Clone, Debug)]
pub enum Errors {
    KeyGenError,
    SignError,
}