pub mod contract_traits;

#[cfg(any(
    feature = "k256",
    feature = "p256",
    feature = "ed25519",
    feature = "ristretto25519",
    feature = "bls",
    feature = "p384",
    feature = "jubjub",
    feature = "decaf377",
    feature = "ed448",
))]
use hd_keys_curves_wasm::{HDDerivable, HDDeriver};

pub fn hd_key_derive(data: Vec<u8>) -> Result<Vec<u8>, Vec<u8>> {
    // 1st arg is a byte for the curve type,
    // 0 is Nist Prime256,
    // 1 is secp256k1,
    // 2 is ed25519
    // 3 is ristretto25519
    // 4 is blsg1
    // 5 is p384
    // 6 is jubjub
    // 7 is decaf377
    // 8 is ed448
    // 2nd arg is a 4 byte big-endian integer for the number of bytes in id
    // 3rd arg is the byte sequence for id
    // 4th arg is a 4 byte big-endian integer for the number of bytes in cxt
    // 5th arg is the byte sequence for cxt
    // 6th arg is a 4 byte big-endian integer for the number of root keys
    // 7th arg is a variable number of root keys each 64 bytes in length
    let curve = data[0];
    let (id_len, data) = try_read_u32(&data[1..])?;
    let id = &data[..id_len];
    let (cxt_len, data) = try_read_u32(&data[id_len..])?;
    let cxt = &data[..cxt_len];
    let (root_keys_len, data) = try_read_u32(&data[cxt_len..])?;

    if root_keys_len < 2 {
        return Err(Vec::new());
    }
    match curve {
        0 => parse_p256(id, cxt, root_keys_len, data),
        1 => parse_k256(id, cxt, root_keys_len, data),
        2 => parse_ed25519(id, cxt, root_keys_len, data),
        3 => parse_ristretto25519(id, cxt, root_keys_len, data),
        4 => parse_bls(id, cxt, root_keys_len, data),
        5 => parse_p384(id, cxt, root_keys_len, data),
        6 => parse_jubjub(id, cxt, root_keys_len, data),
        7 => parse_decaf377(id, cxt, root_keys_len, data),
        8 => parse_ed448(id, cxt, root_keys_len, data),
        _ => Err(format!("Unsupported curve type: {}", curve)
            .as_bytes()
            .to_vec()),
    }
}

#[cfg(feature = "k256")]
fn parse_k256(
    id: &[u8],
    cxt: &[u8],
    root_keys_len: usize,
    data: &[u8],
) -> Result<Vec<u8>, Vec<u8>> {
    use hd_keys_curves_wasm::k256::{
        elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint},
        AffinePoint, EncodedPoint, ProjectivePoint,
    };

    parse_point(
        id,
        cxt,
        root_keys_len,
        data,
        |buffer| {
            let (pt, data) = match buffer[0] {
                0x04 => {
                    // Uncompressed form
                    const BYTES_TO_READ: usize = 65;
                    if BYTES_TO_READ > buffer.len() {
                        return Err(format!(
                            "Expected to read 65 bytes but only found {}",
                            buffer.len()
                        )
                        .as_bytes()
                        .to_vec());
                    }

                    let encoded_point = EncodedPoint::from_bytes(&buffer[..BYTES_TO_READ])
                        .map_err(|_| Vec::new())?;
                    let pt: AffinePoint =
                        Option::from(AffinePoint::from_encoded_point(&encoded_point))
                            .ok_or(Vec::new())?;
                    (pt, &buffer[BYTES_TO_READ..])
                }
                0x03 | 0x02 => {
                    // Compressed form
                    const BYTES_TO_READ: usize = 33;
                    if BYTES_TO_READ > buffer.len() {
                        return Err(format!(
                            "Expected to read 33 bytes but only found {}",
                            buffer.len()
                        )
                        .as_bytes()
                        .to_vec());
                    }

                    let encoded_point = EncodedPoint::from_bytes(&buffer[..BYTES_TO_READ])
                        .map_err(|_| Vec::new())?;
                    let pt: AffinePoint =
                        Option::from(AffinePoint::from_encoded_point(&encoded_point))
                            .ok_or(Vec::new())?;
                    (pt, &buffer[BYTES_TO_READ..])
                }
                _ => {
                    const BYTES_TO_READ: usize = 64;
                    if BYTES_TO_READ > data.len() {
                        return Err(format!(
                            "Expected to read 64 bytes but only found {}",
                            buffer.len()
                        )
                        .as_bytes()
                        .to_vec());
                    }
                    let mut tmp = [4u8; 65];
                    tmp[1..].copy_from_slice(&data[..BYTES_TO_READ]);

                    let encoded_point = EncodedPoint::from_bytes(&buffer[..BYTES_TO_READ])
                        .map_err(|_| Vec::new())?;
                    let pt: AffinePoint =
                        Option::from(AffinePoint::from_encoded_point(&encoded_point))
                            .ok_or(Vec::new())?;
                    (pt, &buffer[BYTES_TO_READ..])
                }
            };
            Ok((ProjectivePoint::from(pt), data))
        },
        |point| point.to_encoded_point(false).as_bytes().to_vec(),
    )
}
#[cfg(not(feature = "k256"))]
#[inline]
fn parse_k256(
    _id: &[u8],
    _cxt: &[u8],
    _root_keys_len: usize,
    _data: &[u8],
) -> Result<Vec<u8>, Vec<u8>> {
    Err(format!("k256 feature not enabled").as_bytes().to_vec())
}

#[cfg(feature = "p256")]
fn parse_p256(
    id: &[u8],
    cxt: &[u8],
    root_keys_len: usize,
    data: &[u8],
) -> Result<Vec<u8>, Vec<u8>> {
    use hd_keys_curves_wasm::p256::{
        elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint},
        AffinePoint, EncodedPoint, ProjectivePoint,
    };

    parse_point(
        id,
        cxt,
        root_keys_len,
        data,
        |buffer| {
            let (pt, data) = match buffer[0] {
                0x04 => {
                    // Uncompressed form
                    const BYTES_TO_READ: usize = 65;
                    if BYTES_TO_READ > buffer.len() {
                        return Err(format!(
                            "Expected to read 65 bytes but only found {}",
                            buffer.len()
                        )
                        .as_bytes()
                        .to_vec());
                    }

                    let encoded_point = EncodedPoint::from_bytes(&buffer[..BYTES_TO_READ])
                        .map_err(|_| Vec::new())?;
                    let pt: AffinePoint =
                        Option::from(AffinePoint::from_encoded_point(&encoded_point))
                            .ok_or(Vec::new())?;
                    (pt, &buffer[BYTES_TO_READ..])
                }
                0x03 | 0x02 => {
                    // Compressed form
                    const BYTES_TO_READ: usize = 33;
                    if BYTES_TO_READ > buffer.len() {
                        return Err(format!(
                            "Expected to read 33 bytes but only found {}",
                            buffer.len()
                        )
                        .as_bytes()
                        .to_vec());
                    }

                    let encoded_point = EncodedPoint::from_bytes(&buffer[..BYTES_TO_READ])
                        .map_err(|_| Vec::new())?;
                    let pt: AffinePoint =
                        Option::from(AffinePoint::from_encoded_point(&encoded_point))
                            .ok_or(Vec::new())?;
                    (pt, &buffer[BYTES_TO_READ..])
                }
                _ => {
                    const BYTES_TO_READ: usize = 64;
                    if BYTES_TO_READ > data.len() {
                        return Err(format!(
                            "Expected to read 64 bytes but only found {}",
                            buffer.len()
                        )
                        .as_bytes()
                        .to_vec());
                    }
                    let mut tmp = [4u8; 65];
                    tmp[1..].copy_from_slice(&data[..BYTES_TO_READ]);

                    let encoded_point = EncodedPoint::from_bytes(&buffer[..BYTES_TO_READ])
                        .map_err(|_| Vec::new())?;
                    let pt: AffinePoint =
                        Option::from(AffinePoint::from_encoded_point(&encoded_point))
                            .ok_or(Vec::new())?;
                    (pt, &buffer[BYTES_TO_READ..])
                }
            };
            Ok((ProjectivePoint::from(pt), data))
        },
        |point| point.to_encoded_point(false).as_bytes().to_vec(),
    )
}
#[cfg(not(feature = "p256"))]
#[inline]
fn parse_p256(
    _id: &[u8],
    _cxt: &[u8],
    _root_keys_len: usize,
    _data: &[u8],
) -> Result<Vec<u8>, Vec<u8>> {
    Err(format!("p256 feature not enabled").as_bytes().to_vec())
}

#[cfg(feature = "p384")]
fn parse_p384(
    id: &[u8],
    cxt: &[u8],
    root_keys_len: usize,
    data: &[u8],
) -> Result<Vec<u8>, Vec<u8>> {
    use hd_keys_curves_wasm::p384::{
        elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint},
        AffinePoint, EncodedPoint, ProjectivePoint,
    };

    parse_point(
        id,
        cxt,
        root_keys_len,
        data,
        |buffer| {
            let (pt, data) = match buffer[0] {
                0x04 => {
                    // Uncompressed form
                    const BYTES_TO_READ: usize = 97;
                    if BYTES_TO_READ > buffer.len() {
                        return Err(format!(
                            "Expected to read 97 bytes but only found {}",
                            buffer.len()
                        )
                        .as_bytes()
                        .to_vec());
                    }

                    let encoded_point = EncodedPoint::from_bytes(&buffer[..BYTES_TO_READ])
                        .map_err(|_| Vec::new())?;
                    let pt: AffinePoint =
                        Option::from(AffinePoint::from_encoded_point(&encoded_point))
                            .ok_or(Vec::new())?;
                    (pt, &buffer[BYTES_TO_READ..])
                }
                0x03 | 0x02 => {
                    // Compressed form
                    const BYTES_TO_READ: usize = 49;
                    if BYTES_TO_READ > buffer.len() {
                        return Err(format!(
                            "Expected to read 49 bytes but only found {}",
                            buffer.len()
                        )
                        .as_bytes()
                        .to_vec());
                    }

                    let encoded_point = EncodedPoint::from_bytes(&buffer[..BYTES_TO_READ])
                        .map_err(|_| Vec::new())?;
                    let pt: AffinePoint =
                        Option::from(AffinePoint::from_encoded_point(&encoded_point))
                            .ok_or(Vec::new())?;
                    (pt, &buffer[BYTES_TO_READ..])
                }
                _ => {
                    const BYTES_TO_READ: usize = 96;
                    if BYTES_TO_READ > data.len() {
                        return Err(format!(
                            "Expected to read 96 bytes but only found {}",
                            buffer.len()
                        )
                        .as_bytes()
                        .to_vec());
                    }
                    let mut tmp = [4u8; 97];
                    tmp[1..].copy_from_slice(&data[..BYTES_TO_READ]);

                    let encoded_point = EncodedPoint::from_bytes(&buffer[..BYTES_TO_READ])
                        .map_err(|_| Vec::new())?;
                    let pt: AffinePoint =
                        Option::from(AffinePoint::from_encoded_point(&encoded_point))
                            .ok_or(Vec::new())?;
                    (pt, &buffer[BYTES_TO_READ..])
                }
            };
            Ok((ProjectivePoint::from(pt), data))
        },
        |point| point.to_encoded_point(false).as_bytes().to_vec(),
    )
}
#[cfg(not(feature = "p384"))]
#[inline]
fn parse_p384(
    _id: &[u8],
    _cxt: &[u8],
    _root_keys_len: usize,
    _data: &[u8],
) -> Result<Vec<u8>, Vec<u8>> {
    Err(format!("p384 feature not enabled").as_bytes().to_vec())
}

#[cfg(feature = "bls")]
fn parse_bls(id: &[u8], cxt: &[u8], root_keys_len: usize, data: &[u8]) -> Result<Vec<u8>, Vec<u8>> {
    use hd_keys_curves_wasm::blsful::inner_types::G1Projective;

    parse_point(
        id,
        cxt,
        root_keys_len,
        data,
        |buffer| {
            if buffer.len() < G1Projective::COMPRESSED_BYTES {
                return Err(format!(
                    "Expected to read {} bytes but only found {}",
                    G1Projective::COMPRESSED_BYTES,
                    buffer.len()
                )
                .as_bytes()
                .to_vec());
            }

            let data = <[u8; G1Projective::COMPRESSED_BYTES]>::try_from(
                &buffer[..G1Projective::COMPRESSED_BYTES],
            )
            .map_err(|_| Vec::new())?;
            Option::<G1Projective>::from(G1Projective::from_compressed(&data))
                .ok_or(Vec::new())
                .map(|pt| (pt, &buffer[G1Projective::COMPRESSED_BYTES..]))
        },
        |point| point.to_compressed().to_vec(),
    )
}
#[cfg(not(feature = "bls"))]
#[inline]
fn parse_bls(
    _id: &[u8],
    _cxt: &[u8],
    _root_keys_len: usize,
    _data: &[u8],
) -> Result<Vec<u8>, Vec<u8>> {
    Err(format!("bls feature not enabled").as_bytes().to_vec())
}

#[cfg(feature = "ed25519")]
fn parse_ed25519(
    id: &[u8],
    cxt: &[u8],
    root_keys_len: usize,
    data: &[u8],
) -> Result<Vec<u8>, Vec<u8>> {
    use hd_keys_curves_wasm::{
        curve25519::WrappedEdwards, curve25519_dalek::edwards::CompressedEdwardsY,
    };

    parse_point(
        id,
        cxt,
        root_keys_len,
        data,
        |buffer| {
            if buffer.len() < 32 {
                return Err(
                    format!("Expected to read 32 bytes but only found {}", buffer.len())
                        .as_bytes()
                        .to_vec(),
                );
            }

            let data = <[u8; 32]>::try_from(&buffer[..32]).map_err(|_| Vec::new())?;
            CompressedEdwardsY(data)
                .decompress()
                .map(|pt| (WrappedEdwards(pt), &buffer[32..]))
                .ok_or(Vec::new())
        },
        |point| point.0.compress().as_bytes().to_vec(),
    )
}
#[cfg(not(feature = "ed25519"))]
#[inline]
fn parse_ed25519(
    _id: &[u8],
    _cxt: &[u8],
    _root_keys_len: usize,
    _data: &[u8],
) -> Result<Vec<u8>, Vec<u8>> {
    Err(format!("ed25519 feature not enabled").as_bytes().to_vec())
}

#[cfg(feature = "ristretto25519")]
fn parse_ristretto25519(
    id: &[u8],
    cxt: &[u8],
    root_keys_len: usize,
    data: &[u8],
) -> Result<Vec<u8>, Vec<u8>> {
    use hd_keys_curves_wasm::{
        curve25519::WrappedRistretto, curve25519_dalek::ristretto::CompressedRistretto,
    };

    parse_point(
        id,
        cxt,
        root_keys_len,
        data,
        |buffer| {
            if buffer.len() < 32 {
                return Err(
                    format!("Expected to read 32 bytes but only found {}", buffer.len())
                        .as_bytes()
                        .to_vec(),
                );
            }

            let data = <[u8; 32]>::try_from(&buffer[..32]).map_err(|_| Vec::new())?;
            CompressedRistretto(data)
                .decompress()
                .map(|pt| (WrappedRistretto(pt), &buffer[32..]))
                .ok_or(Vec::new())
        },
        |point| point.0.compress().as_bytes().to_vec(),
    )
}
#[cfg(not(feature = "ristretto25519"))]
#[inline]
fn parse_ristretto25519(
    _id: &[u8],
    _cxt: &[u8],
    _root_keys_len: usize,
    _data: &[u8],
) -> Result<Vec<u8>, Vec<u8>> {
    Err(format!("ristretto25519 feature not enabled")
        .as_bytes()
        .to_vec())
}

#[cfg(feature = "jubjub")]
fn parse_jubjub(
    id: &[u8],
    cxt: &[u8],
    root_keys_len: usize,
    data: &[u8],
) -> Result<Vec<u8>, Vec<u8>> {
    use hd_keys_curves_wasm::jubjub::{group::GroupEncoding, SubgroupPoint};

    parse_point(
        id,
        cxt,
        root_keys_len,
        data,
        |buffer| {
            if buffer.len() < 32 {
                return Err(
                    format!("Expected to read 32 bytes but only found {}", buffer.len())
                        .as_bytes()
                        .to_vec(),
                );
            }

            let mut repr = <SubgroupPoint as GroupEncoding>::Repr::default();
            repr.as_mut().copy_from_slice(&buffer[..32]);
            Option::<SubgroupPoint>::from(SubgroupPoint::from_bytes(&repr))
                .ok_or(Vec::new())
                .map(|pt| (pt, &buffer[32..]))
        },
        |point| point.to_bytes().as_ref().to_vec(),
    )
}
#[cfg(not(feature = "jubjub"))]
#[inline]
fn parse_jubjub(
    _id: &[u8],
    _cxt: &[u8],
    _root_keys_len: usize,
    _data: &[u8],
) -> Result<Vec<u8>, Vec<u8>> {
    Err(format!("jubjub feature not enabled").as_bytes().to_vec())
}

#[cfg(feature = "decaf377")]
fn parse_decaf377(
    id: &[u8],
    cxt: &[u8],
    root_keys_len: usize,
    data: &[u8],
) -> Result<Vec<u8>, Vec<u8>> {
    use hd_keys_curves_wasm::{decaf377::Element, elliptic_curve::group::GroupEncoding};

    parse_point(
        id,
        cxt,
        root_keys_len,
        data,
        |buffer| {
            if buffer.len() < 32 {
                return Err(
                    format!("Expected to read 32 bytes but only found {}", buffer.len())
                        .as_bytes()
                        .to_vec(),
                );
            }

            let mut repr = <Element as GroupEncoding>::Repr::default();
            repr.as_mut().copy_from_slice(&buffer[..32]);
            Option::<Element>::from(Element::from_bytes(&repr))
                .ok_or(Vec::new())
                .map(|pt| (pt, &buffer[32..]))
        },
        |point| point.to_bytes().as_ref().to_vec(),
    )
}
#[cfg(not(feature = "decaf377"))]
#[inline]
fn parse_decaf377(
    _id: &[u8],
    _cxt: &[u8],
    _root_keys_len: usize,
    _data: &[u8],
) -> Result<Vec<u8>, Vec<u8>> {
    Err(format!("decaf377 feature not enabled").as_bytes().to_vec())
}

#[cfg(feature = "ed448")]
fn parse_ed448(
    id: &[u8],
    cxt: &[u8],
    root_keys_len: usize,
    data: &[u8],
) -> Result<Vec<u8>, Vec<u8>> {
    use hd_keys_curves_wasm::{
        ed448_goldilocks_plus::{
            EdwardsPoint, ScalarBytes
        }, elliptic_curve::group::GroupEncoding,
    };

    parse_point(
        id,
        cxt,
        root_keys_len,
        data,
        |buffer| {
            if buffer.len() < 57 {
                return Err(
                    format!("Expected to read 57 bytes but only found {}", buffer.len())
                        .as_bytes()
                        .to_vec(),
                );
            }

            let mut repr: ScalarBytes  = <EdwardsPoint as GroupEncoding>::Repr::default();
            <ScalarBytes as AsMut<[u8]>>::as_mut(&mut repr).copy_from_slice(&buffer[..57]);
            Option::<EdwardsPoint>::from(EdwardsPoint::from_bytes(&repr))
                .ok_or(Vec::new())
                .map(|pt| (pt, &buffer[57..]))
        },
        |point| <ScalarBytes as AsRef<[u8]>>::as_ref(&point.to_bytes()).as_ref().to_vec(),
    )
}
#[cfg(not(feature = "ed448"))]
#[inline]
fn parse_ed448(
    _id: &[u8],
    _cxt: &[u8],
    _root_keys_len: usize,
    _data: &[u8],
) -> Result<Vec<u8>, Vec<u8>> {
    Err(format!("ed448 feature not enabled").as_bytes().to_vec())
}

#[cfg(any(
    feature = "k256",
    feature = "p256",
    feature = "ed25519",
    feature = "ristretto25519",
    feature = "bls",
    feature = "p384",
    feature = "jubjub",
    feature = "decaf377",
    feature = "ed448",
))]
fn parse_point<D, H, F, E>(
    id: &[u8],
    cxt: &[u8],
    root_keys_len: usize,
    data: &[u8],
    mut parser: F,
    encoder: E,
) -> Result<Vec<u8>, Vec<u8>>
where
    D: HDDeriver,
    H: HDDerivable<Scalar = D>,
    F: FnMut(&[u8]) -> Result<(H, &[u8]), Vec<u8>>,
    E: Fn(H) -> Vec<u8>,
{
    let mut hd_root_keys = vec![H::identity(); root_keys_len];
    let mut data = data;

    for hd_i in hd_root_keys.iter_mut() {
        (*hd_i, data) = parser(data)?;
    }
    let deriver = D::create(id, cxt);
    let key = deriver.hd_derive_public_key(&hd_root_keys);

    Ok(encoder(key))
}

fn try_read_u32(data: &[u8]) -> Result<(usize, &[u8]), Vec<u8>> {
    if data.len() < 4 {
        return Err(Vec::new());
    }

    let res = <[u8; 4]>::try_from(&data[..4])
        .map_err(|_| Vec::new())
        .map(u32::from_be_bytes)?;
    Ok((res as usize, &data[4..]))
}

#[cfg(test)]
mod test {
    use hex::decode_to_slice;

    use super::*;

    #[cfg(feature = "k256")]
    #[test]
    fn test_hd_key_derive() {
        let mut b = [0u8; 418];
        decode_to_slice("0100000020fdb545b1b3d125d517148099c3403c7b1dd3f4cf3b012522afb7d12d07ba0b130000002b4c49545f48445f4b45595f49445f4b3235365f584d443a5348412d3235365f535357555f524f5f4e554c5f0000000a028506cbedca1d12788d6bc74627d99263c93204d2e9565d861b7c1270736b007102a89cb5090c0aaee9c5831df939abbeab2e0f62b5d54ceae6e816a9fe87c8ca32033e0c9d93b41414c3a8d287bb40ab024fbf176cb45c6616a3bf74e97bb68b516503a0c18f5d9db21fec597edef52f7a26449cdd90357532704a1ede6c27981a31b802794db35a0b6a6968ba4ed059630d788d591f083778dac9a45935549ca5f75ea603b398a663086dc7f1b5948d2195b176a7705fe71b0ad07110f57975254e6015980215f2cddeb89428f74132a84acf7e1a344f2ed9a39768f7006c9b8843e513dc550297d2a91f5a52e98873b7a4946c47d7736d6661cebace9c160d955999be97149203d2ee101c65ca0d60b5bc27ca1859c968984b1096d742874649bdc4fac6e9498a02bb0deb45aefb171e7117390991c2a230218fda04d9bb3cfd343f56ab61c3e390", &mut b).expect("Failed to decode hex");
        let result = hd_key_derive(b.to_vec());
        assert!(result.is_ok());
    }
}
