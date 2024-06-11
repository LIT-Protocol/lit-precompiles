// Allow `cargo stylus export-abi` to generate a main function.
#![cfg_attr(not(feature = "export-abi"), no_main)]
extern crate alloc;

/// Import items from the SDK. The prelude contains common traits and macros.
use stylus_sdk::{abi::Bytes, prelude::*};

use precompiles_core::{contract_traits::HDKDFPrecompile, p256};

#[solidity_storage]
#[entrypoint]
pub struct HDKDFP256;

#[external]
impl HDKDFPrecompile for HDKDFP256 {
    fn hd_key_derive(&self, data: Bytes) -> Result<Bytes, Vec<u8>> {
        Ok(Bytes::from(p256::hd_key_derive(data.0)?))
    }
}
