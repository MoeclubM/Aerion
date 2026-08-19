use super::*;

#[tokio::test]
async fn mux_frame_roundtrip() -> Result<()> {
    let target = ProxyTarget::Domain("example.com".to_string(), 443);
    let bytes = encode_frame(
        7,
        STATUS_NEW,
        Some(&FrameTarget {
            network: TargetNetwork::Tcp,
            destination: target.clone(),
        }),
        b"abc",
        false,
    )?;
    let frame = read_frame(&mut bytes.as_slice()).await?.context("frame")?;
    assert_eq!(frame.session_id, 7);
    assert_eq!(frame.status, STATUS_NEW);
    assert_eq!(frame.payload, b"abc");
    assert_eq!(frame.target.expect("target").destination, target);
    Ok(())
}
