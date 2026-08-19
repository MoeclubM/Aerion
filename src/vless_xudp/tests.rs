use super::*;

#[tokio::test]
async fn reads_xudp_new_packet() -> Result<()> {
    let target = ProxyTarget::Domain("example.com".to_string(), 53);
    let mut bytes = Vec::new();
    write_client_packet(&mut bytes, &target, b"abc", true, &[0u8; 8]).await?;
    let packet = read_packet(&mut bytes.as_slice(), &mut None)
        .await?
        .context("packet")?;
    assert_eq!(packet.destination, target);
    assert_eq!(packet.payload, b"abc");
    Ok(())
}

#[test]
fn decodes_in_memory_xudp_packet_chunk() -> Result<()> {
    let target = ProxyTarget::Domain("example.com".to_string(), 53);
    let bytes = encode_client_packet(&target, b"abc", true, &[0u8; 8])?;
    let metadata_len = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
    assert_eq!(metadata_len, 28);
    assert_eq!(&bytes[2..4], &[0, 0]);
    assert_eq!(bytes[4], STATUS_NEW);
    assert_eq!(bytes[5], 0x01);
    assert_eq!(bytes[6], NETWORK_UDP);
    let (destination, payload) = decode_packet_chunk(&bytes, &mut None)?.context("packet")?;
    assert_eq!(destination, target);
    assert_eq!(payload, b"abc");
    Ok(())
}

#[test]
fn xudp_end_status_is_0x03() {
    assert_eq!(STATUS_END, 0x03);
    assert_eq!(STATUS_KEEPALIVE, 0x04);
}

#[test]
fn keep_frame_includes_address_without_global_id() -> Result<()> {
    let target = ProxyTarget::Domain("example.com".to_string(), 53);
    let bytes = encode_client_packet(&target, b"abc", false, &[1u8; 8])?;
    let metadata_len = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
    assert_eq!(bytes[4], STATUS_KEEP);
    assert_eq!(metadata_len, 20);
    let (destination, payload) = decode_packet_chunk(&bytes, &mut None)?.context("packet")?;
    assert_eq!(destination, target);
    assert_eq!(payload, b"abc");
    Ok(())
}
