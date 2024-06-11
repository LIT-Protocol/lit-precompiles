/// Use an efficient WASM allocator.
#[global_allocator]
static ALLOC: mini_alloc::MiniAlloc = mini_alloc::MiniAlloc::INIT;

pub mod contract_traits;
#[cfg(feature = "k256")]
pub mod k256;
#[cfg(feature = "p256")]
pub mod p256;
pub mod utils;
