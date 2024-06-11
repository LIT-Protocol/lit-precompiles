pub(crate) fn read_4_byte_be(data: &[u8], offset: &mut usize) -> Result<u32, Vec<u8>> {
    let value = u32::from_be_bytes(
        data[*offset..*offset + 4]
            .try_into()
            .map_err(|_| Vec::new())?,
    );
    *offset += 4;
    Ok(value)
}
