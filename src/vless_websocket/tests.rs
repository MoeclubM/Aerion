use super::*;

#[tokio::test]
async fn websocket_frame_roundtrip() -> Result<()> {
    let frame = build_frame(OPCODE_BINARY, b"hello", true)?;
    let decoded = read_frame(&mut frame.as_slice()).await?.context("frame")?;
    assert_eq!(decoded.opcode, OPCODE_BINARY);
    assert_eq!(decoded.payload, b"hello");
    Ok(())
}
