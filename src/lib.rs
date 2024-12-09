//!
//! Stylus Hello World
//!
//! The following contract implements the Counter example from Foundry.
//!
//! ```
//! contract Counter {
//!     uint256 public number;
//!     function setNumber(uint256 newNumber) public {
//!         number = newNumber;
//!     }
//!     function increment() public {
//!         number++;
//!     }
//! }
//! ```
//!
//! The program is ABI-equivalent with Solidity, which means you can call it from both Solidity and Rust.
//! To do this, run `cargo stylus export-abi`.
//!
//! Note: this code is a template-only and has not been audited.
//!

// Allow `cargo stylus export-abi` to generate a main function.
#![cfg_attr(not(feature = "export-abi"), no_main)]
extern crate alloc;

/// Import items from the SDK. The prelude contains common traits and macros.
use stylus_sdk::{alloy_primitives::*, prelude::*};

use hd_keys_curves_wasm::{EcCurve, HDDeriver};
use k256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};

// Define some persistent storage using the Solidity ABI.
// `Counter` will be the entrypoint.
sol_storage! {
    #[entrypoint]
    pub struct EcOpsContract{}
}

#[public]
impl EcOpsContract {
    pub fn hd_key_derive(&self, data: Vec<u8>) -> Result<Vec<u8>, Vec<u8>> {
        // 1st arg is a byte for the curve type, 0 is Nist Prime256, 1 is secp256k1
        // 2nd arg is a 4 byte big-endian integer for the number of bytes in id
        // 3rd arg is the byte sequence for id
        // 4th arg is a 4 byte big-endian integer for the number of bytes in cxt
        // 5th arg is the byte sequence for cxt
        // 6th arg is a 4 byte big-endian integer for the number of root keys
        // 7th arg is a variable number of root keys each 64 bytes in length
        match data[0] {
            // 0 => {
            //     let id_len = u32::from_be_bytes(data[1..5].try_into().unwrap()) as usize;
            //     let id = &data[5..5 + id_len];
            //     let cxt_len =
            //         u32::from_be_bytes(data[5 + id_len..9 + id_len].try_into().unwrap()) as usize;
            //     let cxt = &data[9 + id_len..9 + id_len + cxt_len];
            //     let root_keys_len = u32::from_be_bytes(
            //         data[9 + id_len + cxt_len..13 + id_len + cxt_len]
            //             .try_into()
            //             .unwrap(),
            //     ) as usize;
            //     if root_keys_len % 64 != 0 {
            //         return Err(Vec::new());
            //     }
            //     let root_keys = &data[13 + id_len + cxt_len..13 + id_len + cxt_len + root_keys_len];
            //     let mut hd_root_keys = vec![p256::ProjectivePoint::IDENTITY; root_keys_len];
            //     for (hd_i, chunk) in hd_root_keys.iter_mut().zip(root_keys.chunks(64)) {
            //         let mut bytes = [4u8; 65];
            //         bytes[1..].copy_from_slice(chunk);
            //         let encoded_point =
            //             p256::EncodedPoint::from_bytes(bytes).map_err(|_| Vec::new())?;

            //         let hd_key = p256::AffinePoint::from_encoded_point(&encoded_point)
            //             .map(p256::ProjectivePoint::from);
            //         *hd_i = Option::<p256::ProjectivePoint>::from(hd_key).ok_or(Vec::new())?;
            //     }
            //     let hd_deriver = <p256::Scalar as HDDeriver>::create(id, cxt);
            //     let hd_key =
            //         hd_deriver.hd_derive_public_key::<p256::ProjectivePoint>(&hd_root_keys);
            //     Ok(hd_key.to_encoded_point(false).as_bytes()[1..].to_vec())
            // }
            1 => {
                let id_len = u32::from_be_bytes(data[1..5].try_into().unwrap()) as usize;
                let id = &data[5..5 + id_len];
                let cxt_len =
                    u32::from_be_bytes(data[5 + id_len..9 + id_len].try_into().unwrap()) as usize;
                let cxt = &data[9 + id_len..9 + id_len + cxt_len];
                let root_keys_len = u32::from_be_bytes(
                    data[9 + id_len + cxt_len..13 + id_len + cxt_len]
                        .try_into()
                        .unwrap(),
                ) as usize;
                if root_keys_len % 64 != 0 {
                    return Err(Vec::new());
                }
                let root_keys = &data[13 + id_len + cxt_len..13 + id_len + cxt_len + root_keys_len];

                let mut hd_root_keys = vec![k256::ProjectivePoint::IDENTITY; root_keys_len];
                for (hd_i, chunk) in hd_root_keys.iter_mut().zip(root_keys.chunks(64)) {
                    let mut bytes = [4u8; 65];
                    bytes[1..].copy_from_slice(chunk);
                    let encoded_point =
                        k256::EncodedPoint::from_bytes(bytes).map_err(|_| Vec::new())?;

                    let hd_key = k256::AffinePoint::from_encoded_point(&encoded_point)
                        .map(k256::ProjectivePoint::from);
                    *hd_i = Option::<k256::ProjectivePoint>::from(hd_key).ok_or(Vec::new())?;
                }
                let hd_deriver = <k256::Scalar as HDDeriver>::create(id, cxt);
                let hd_key =
                    hd_deriver.hd_derive_public_key::<k256::ProjectivePoint>(&hd_root_keys);
                Ok(hd_key.to_encoded_point(false).as_bytes()[1..].to_vec())
            }
            _ => Err(Vec::new()),
        }
    }

    pub fn ec_mul(
        &self,
        curve: FixedBytes<32>,
        point: Vec<u8>,
        scalar: Vec<u8>,
    ) -> Result<Vec<u8>, Vec<u8>> {
        let ec_curve = EcCurve::try_from(curve.as_slice()).map_err(|_| Vec::new())?;
        let input = point
            .iter()
            .chain(scalar.iter())
            .copied()
            .collect::<Vec<_>>();
        ec_curve.ec_mul(&input).map_err(|_| Vec::new())
    }
}
