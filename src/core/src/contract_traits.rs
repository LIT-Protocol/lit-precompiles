// This trait is intended for the precompiles to implement as a unified interface.
pub trait HDKDFPrecompile {
    fn hd_key_derive(&self, data: Vec<u8>) -> Result<Vec<u8>, Vec<u8>>;
}
