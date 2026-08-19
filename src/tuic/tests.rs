use super::*;

#[test]
fn packet_fragments_roundtrip() -> Result<()> {
    let target = ProxyTarget::Domain("example.com".to_string(), 53);
    let payload = (0u8..90).collect::<Vec<_>>();
    let frames = encode_packet_fragments(7, 42, &target, &payload, 48)?;
    assert!(frames.len() > 1);

    let mut fragments = HashMap::new();
    let mut complete = None;
    for frame in frames {
        let packet = parse_packet_command(&frame)?;
        if packet.frag_id > 0 {
            assert!(packet.target.is_none());
        }
        complete = push_fragment(&mut fragments, packet)?;
    }

    let packet = complete.context("fragmented packet did not complete")?;
    assert_eq!(packet.assoc_id, 7);
    assert_eq!(packet.target, target);
    assert_eq!(packet.payload, payload);
    assert!(fragments.is_empty());
    Ok(())
}

#[test]
fn packet_parser_rejects_non_first_fragment_address() -> Result<()> {
    let target = ProxyTarget::Domain("example.com".to_string(), 53);
    let frame = encode_packet_command(7, 42, 2, 1, Some(&target), b"payload")?;
    let error = parse_packet_command(&frame).expect_err("non-first fragment must use none addr");
    assert!(error.to_string().contains("non-first packet fragment"));
    Ok(())
}

#[test]
fn fragment_buffer_rejects_duplicate_fragment() -> Result<()> {
    let target = ProxyTarget::Domain("example.com".to_string(), 53);
    let frame = encode_packet_command(7, 42, 2, 0, Some(&target), b"payload")?;
    let packet = parse_packet_command(&frame)?;
    let mut fragments = HashMap::new();
    assert!(push_fragment(&mut fragments, packet.clone())?.is_none());
    let error = push_fragment(&mut fragments, packet).expect_err("duplicate fragment must fail");
    assert!(error.to_string().contains("duplicate packet fragment"));
    Ok(())
}

#[test]
fn heartbeat_zero_disables_interval() {
    assert!(heartbeat_interval(0).is_none());
    assert_eq!(heartbeat_interval(10), Some(Duration::from_secs(10)));
}

#[test]
fn fragment_map_is_capped() -> Result<()> {
    let target = ProxyTarget::Domain("example.com".to_string(), 53);
    let mut fragments = HashMap::new();
    for packet_id in 0..=MAX_UDP_FRAGMENTS as u16 {
        let frame = encode_packet_command(7, packet_id, 2, 0, Some(&target), b"p")?;
        let packet = parse_packet_command(&frame)?;
        if packet_id < MAX_UDP_FRAGMENTS as u16 {
            assert!(push_fragment(&mut fragments, packet)?.is_none());
        } else {
            let error =
                push_fragment(&mut fragments, packet).expect_err("fragment map must be capped");
            assert!(error.to_string().contains("fragment map exceeded"));
        }
    }
    Ok(())
}
