// Allow `cargo stylus export-abi` to generate a main function.
#![cfg_attr(not(feature = "export-abi"), no_main)]
extern crate alloc;

/// Import items from the SDK. The prelude contains common traits and macros.
use stylus_sdk::{abi::Bytes, prelude::*};

use precompiles_core::{contract_traits::HDKDFPrecompile, hd_key_derive};

sol_storage! {
    #[entrypoint]
    pub struct HDKDFED25519 {}
}

#[public]
impl HDKDFPrecompile for HDKDFED25519 {
    fn hd_key_derive(&self, data: Bytes) -> Result<Bytes, Vec<u8>> {
        Ok(Bytes::from(hd_key_derive(data.0)?))
    }
}
