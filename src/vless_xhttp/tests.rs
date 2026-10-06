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

#[tokio::test]
async fn backpressure_sends_each_chunk_once() -> Result<()> {
    for role in [XhttpRole::Client, XhttpRole::Server] {
        let (stream, mut peer) = tokio::io::duplex(32);
        let mut stream = XhttpStream::new(stream, role, false);
        let payload = (0..65536).map(|i| i as u8).collect::<Vec<_>>();
        let send = async {
            stream.write_all(&payload).await?;
            stream.write_all(b"next-chunk").await?;
            stream.shutdown().await?;
            Ok::<(), anyhow::Error>(())
        };
        let receive = async {
            if matches!(role, XhttpRole::Server) {
                vless_http::read_http_head(&mut peer).await?;
            }
            assert_eq!(
                read_chunk(&mut peer).await?.context("first chunk")?,
                payload
            );
            assert_eq!(
                read_chunk(&mut peer).await?.context("second chunk")?,
                b"next-chunk"
            );
            assert!(read_chunk(&mut peer).await?.is_none());
            Ok::<(), anyhow::Error>(())
        };
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            tokio::try_join!(send, receive)
        })
        .await??;
    }
    Ok(())
}

#[tokio::test]
async fn dropping_idle_transport_releases_the_underlying_stream() -> Result<()> {
    let (stream, mut peer) = tokio::io::duplex(32);
    let stream = XhttpStream::new(stream, XhttpRole::Server, false);
    tokio::task::yield_now().await;
    drop(stream);
    assert_eq!(
        tokio::time::timeout(std::time::Duration::from_secs(2), peer.read(&mut [0; 1])).await??,
        0
    );
    Ok(())
}
