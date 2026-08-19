use super::*;

#[tokio::test]
async fn grpc_frame_roundtrip() -> Result<()> {
    let encoded = encode_grpc_frame(b"hello");
    let decoded = read_grpc_frame(&mut encoded.as_ref())
        .await?
        .context("frame")?;
    assert_eq!(decoded, b"hello");
    Ok(())
}
