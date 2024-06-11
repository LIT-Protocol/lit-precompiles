// Allow `cargo stylus export-abi` to generate a main function.
#![cfg_attr(not(feature = "export-abi"), no_main)]
extern crate alloc;

/// Import items from the SDK. The prelude contains common traits and macros.
use stylus_sdk::prelude::*;

use precompiles_core::{contract_traits::HDKDFPrecompile, k256};

#[solidity_storage]
#[entrypoint]
pub struct HDKDFK256;

#[external]
impl HDKDFPrecompile for HDKDFK256 {
    fn hd_key_derive(&self, data: Vec<u8>) -> Result<Vec<u8>, Vec<u8>> {
        k256::hd_key_derive(data)
    }
}
