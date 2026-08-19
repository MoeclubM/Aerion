use super::*;

#[tokio::test]
async fn chunk_roundtrip() -> Result<()> {
    let mut encoded = Vec::new();
    append_chunk(&mut encoded, b"hello");
    encoded.extend_from_slice(b"0\r\n\r\n");
    let mut slice = encoded.as_slice();
    let decoded = read_chunk(&mut slice).await?.context("chunk")?;
    assert_eq!(decoded, b"hello");
    assert!(read_chunk(&mut slice).await?.is_none());
    Ok(())
}

#[test]
fn request_path_preserves_existing_query() {
    assert_eq!(
        request_path_with_padding("/x?a=b"),
        format!("/x?a=b&x_padding={}", "X".repeat(X_PADDING_LEN))
    );
}
