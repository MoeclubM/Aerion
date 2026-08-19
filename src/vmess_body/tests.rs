use super::*;
use tokio::io::duplex;

#[test]
fn chacha_key_matches_reference() {
    let key = generate_chacha20_poly1305_key(b"0123456789abcdef");
    assert_eq!(
        hex::encode(key),
        "4032af8d61035123906e58e067140cc567304ba676a616064c4340059e1b6370"
    );
}

#[test]
fn shake128_matches_known_vector_prefix() {
    let mut shake = Shake128::default();
    shake.finalize();
    let mut out = [0u8; 16];
    shake.squeeze(&mut out);
    assert_eq!(hex::encode(out), "7f9c2ba4e88f827d616045507605853e");
}

#[tokio::test]
async fn packet_chunk_roundtrip_none() -> Result<()> {
    let mut options = RequestOptions::new(0);
    options.enable_chunk_stream();
    let config = BodyConfig::new_request(SecurityType::None, options, [0x11; 16], [0x22; 16])?;
    let (client, server) = duplex(4096);
    let write = tokio::spawn(async move {
        let mut writer = BodyWriter::new(client, config);
        writer.write_packet_plain(b"one").await?;
        writer.write_packet_plain(b"two").await?;
        writer.finish().await
    });
    let mut reader = BodyReader::new(server, config);
    assert_eq!(reader.read_packet().await?, Some(b"one".to_vec()));
    assert_eq!(reader.read_packet().await?, Some(b"two".to_vec()));
    assert_eq!(reader.read_packet().await?, None);
    write.await??;
    Ok(())
}

#[tokio::test]
async fn stream_chunk_roundtrip_aes_gcm() -> Result<()> {
    let mut options = RequestOptions::new(0);
    options.enable_chunk_stream();
    let config = BodyConfig::new_request(SecurityType::Aes128Gcm, options, [0x11; 16], [0x22; 16])?;
    let (client, server) = duplex(4096);
    let write = tokio::spawn(async move {
        let mut writer = BodyWriter::new(client, config);
        writer.write_all_plain(b"encrypted-body").await?;
        writer.finish().await
    });
    let mut reader = BodyReader::new(server, config);
    let mut output = Vec::new();
    let mut buffer = [0u8; 16];
    loop {
        let read = reader.read_plain(&mut buffer).await?;
        if read == 0 {
            break;
        }
        output.extend_from_slice(&buffer[..read]);
    }
    write.await??;
    assert_eq!(output, b"encrypted-body");
    Ok(())
}
