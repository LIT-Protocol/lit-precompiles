use hd_keys_curves_wasm::HDDeriver;
use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};

use crate::utils::read_4_byte_be;

pub fn hd_key_derive(data: Vec<u8>) -> Result<Vec<u8>, Vec<u8>> {
    // 1st arg is a byte for the curve type, 0 is Nist Prime256, 1 is secp256k1
    // 2nd arg is a 4 byte big-endian integer for the number of bytes in id
    // 3rd arg is the byte sequence for id
    // 4th arg is a 4 byte big-endian integer for the number of bytes in cxt
    // 5th arg is the byte sequence for cxt
    // 6th arg is a 4 byte big-endian integer for the number of root keys
    // 7th arg is a variable number of root keys each 64 bytes in length
    let mut offset = 1;

    let id_len = read_4_byte_be(&data, &mut offset)? as usize;
    let id = &data[offset..offset + id_len];
    offset += id_len;

    let cxt_len = read_4_byte_be(&data, &mut offset)? as usize;
    let cxt = &data[offset..offset + cxt_len];
    offset += cxt_len;

    let root_keys_len = read_4_byte_be(&data, &mut offset)? as usize;
    let buffer = &data[offset..];

    if root_keys_len < 2 || (root_keys_len * 33) > buffer.len() {
        return Err(Vec::new());
    }

    let mut offset = 0;
    let mut hd_root_keys = vec![p256::ProjectivePoint::IDENTITY; root_keys_len];
    for hd_i in hd_root_keys.iter_mut() {
        let encoded_point = match buffer[offset] {
            0x04 => {
                // Uncompressed form
                let bytes_to_read = 65;
                if offset + bytes_to_read > buffer.len() {
                    let err = format!("invalid length for uncompressed point: {}", data.len());
                    return Err(err.as_bytes().to_vec());
                }

                let encoded_point =
                    p256::EncodedPoint::from_bytes(&buffer[offset..offset + bytes_to_read])
                        .map_err(|_| Vec::new())?;

                offset += bytes_to_read;
                encoded_point
            }
            0x03 | 0x02 => {
                // Compressed form
                let bytes_to_read = 33;
                if offset + bytes_to_read > data.len() {
                    let err = format!("invalid length for compressed point: {}", data.len());
                    return Err(err.as_bytes().to_vec());
                }

                let encoded_point =
                    p256::EncodedPoint::from_bytes(&buffer[offset..offset + bytes_to_read])
                        .map_err(|_| Vec::new())?;

                offset += bytes_to_read;
                encoded_point
            }
            _ => {
                let bytes_to_read = 64;
                if offset + bytes_to_read > data.len() {
                    let err = format!("invalid length for hybrid point: {}", data.len());
                    return Err(err.as_bytes().to_vec());
                }
                let mut tmp = [4u8; 65];
                tmp[1..].copy_from_slice(&data[offset..offset + bytes_to_read]);

                let encoded_point =
                    p256::EncodedPoint::from_bytes(&tmp[..]).map_err(|_| Vec::new())?;

                offset += bytes_to_read;
                encoded_point
            }
        };

        let hd_key =
            p256::AffinePoint::from_encoded_point(&encoded_point).map(p256::ProjectivePoint::from);
        *hd_i = Option::<p256::ProjectivePoint>::from(hd_key).ok_or(Vec::new())?;
    }

    let hd_deriver = <p256::Scalar as HDDeriver>::create(id, cxt);
    let hd_key = hd_deriver.hd_derive_public_key::<p256::ProjectivePoint>(&hd_root_keys);
    Ok(hd_key.to_encoded_point(false).as_bytes().to_vec())
}
