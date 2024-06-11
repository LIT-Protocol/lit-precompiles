use hd_keys_curves_wasm::HDDeriver;
use k256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};

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
    let mut hd_root_keys = vec![k256::ProjectivePoint::IDENTITY; root_keys_len];
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
                    k256::EncodedPoint::from_bytes(&buffer[offset..offset + bytes_to_read])
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
                    k256::EncodedPoint::from_bytes(&buffer[offset..offset + bytes_to_read])
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
                    k256::EncodedPoint::from_bytes(&tmp[..]).map_err(|_| Vec::new())?;

                offset += bytes_to_read;
                encoded_point
            }
        };

        let hd_key =
            k256::AffinePoint::from_encoded_point(&encoded_point).map(k256::ProjectivePoint::from);
        *hd_i = Option::<k256::ProjectivePoint>::from(hd_key).ok_or(Vec::new())?;
    }

    let hd_deriver = <k256::Scalar as HDDeriver>::create(id, cxt);
    let hd_key = hd_deriver.hd_derive_public_key::<k256::ProjectivePoint>(&hd_root_keys);
    Ok(hd_key.to_encoded_point(false).as_bytes().to_vec())
}

#[cfg(test)]
mod test {
    use hex::decode_to_slice;

    use super::*;

    #[test]
    fn test_hd_key_derive() {
        let mut b = [0u8; 418];
        decode_to_slice("0100000020fdb545b1b3d125d517148099c3403c7b1dd3f4cf3b012522afb7d12d07ba0b130000002b4c49545f48445f4b45595f49445f4b3235365f584d443a5348412d3235365f535357555f524f5f4e554c5f0000000a028506cbedca1d12788d6bc74627d99263c93204d2e9565d861b7c1270736b007102a89cb5090c0aaee9c5831df939abbeab2e0f62b5d54ceae6e816a9fe87c8ca32033e0c9d93b41414c3a8d287bb40ab024fbf176cb45c6616a3bf74e97bb68b516503a0c18f5d9db21fec597edef52f7a26449cdd90357532704a1ede6c27981a31b802794db35a0b6a6968ba4ed059630d788d591f083778dac9a45935549ca5f75ea603b398a663086dc7f1b5948d2195b176a7705fe71b0ad07110f57975254e6015980215f2cddeb89428f74132a84acf7e1a344f2ed9a39768f7006c9b8843e513dc550297d2a91f5a52e98873b7a4946c47d7736d6661cebace9c160d955999be97149203d2ee101c65ca0d60b5bc27ca1859c968984b1096d742874649bdc4fac6e9498a02bb0deb45aefb171e7117390991c2a230218fda04d9bb3cfd343f56ab61c3e390", &mut b).expect("Failed to decode hex");
        let result = hd_key_derive(b.to_vec());
        assert!(result.is_ok());
    }
}
