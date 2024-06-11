use stylus_sdk::abi::Bytes;

// This trait is intended for the precompiles to implement as a unified interface.
pub trait HDKDFPrecompile {
    fn hd_key_derive(&self, data: Bytes) -> Result<Bytes, Vec<u8>>;
}
