use super::*;
use tokio::io::duplex;

include!("../../tests/performance/vmess.rs");

#[tokio::test]
async fn vectored_plaintext_chunks_survive_one_byte_partial_writes() -> Result<()> {
    let options = RequestOptions::new(
        REQUEST_OPTION_CHUNK_STREAM | REQUEST_OPTION_CHUNK_MASKING | REQUEST_OPTION_GLOBAL_PADDING,
    );
    let config = BodyConfig::new_request(SecurityType::None, options, [0x11; 16], [0x22; 16])?;
    let (client, server) = duplex(1);
    let write = tokio::spawn(async move {
        let mut writer = BodyWriter::new(client, config);
        for size in [1, 64, 513] {
            writer.write_packet_plain(&vec![size as u8; size]).await?;
        }
        writer.finish().await
    });
    let mut reader = BodyReader::new(server, config);
    for size in [1, 64, 513] {
        assert_eq!(reader.read_packet().await?, Some(vec![size as u8; size]));
    }
    assert!(reader.read_packet().await?.is_none());
    write.await??;
    Ok(())
}

#[tokio::test]
async fn coalesced_chunks_match_reference_wire_and_fragmented_reads() -> Result<()> {
    for security in [
        SecurityType::None,
        SecurityType::Aes128Gcm,
        SecurityType::ChaCha20Poly1305,
    ] {
        for authenticated in [false, true] {
            if authenticated && security == SecurityType::None {
                continue;
            }
            let options = RequestOptions::new(
                REQUEST_OPTION_CHUNK_STREAM
                    | REQUEST_OPTION_CHUNK_MASKING
                    | REQUEST_OPTION_GLOBAL_PADDING
                    | if authenticated {
                        REQUEST_OPTION_AUTHENTICATED_LENGTH
                    } else {
                        0
                    },
            );
            let config = BodyConfig::new_request(security, options, [0x11; 16], [0x22; 16])?;
            let mut writer = BodyWriter::new(Vec::new(), config);
            let mut reference = ChunkState::new(config);
            let mut expected = Vec::new();
            for size in [1, 64, MAX_CHUNK_PLAIN_LEN, 13, 1024] {
                let plain = vec![size as u8; size];
                expected.extend_from_slice(&plain);
                let start = writer.inner.len();
                writer.write_all_plain(&plain).await?;
                let padding = reference.next_padding_len();
                let nonce = generate_chunk_nonce(&config.payload_iv, reference.payload_counter);
                reference.payload_counter = reference.payload_counter.wrapping_add(1);
                let payload = reference.payload_cipher.encrypt(&nonce, &plain)?;
                let total = (payload.len() + padding) as u16;
                let header = if authenticated {
                    let nonce = generate_chunk_nonce(&config.length_iv, reference.size_counter);
                    reference.size_counter = reference.size_counter.wrapping_add(1);
                    reference
                        .length_cipher
                        .as_ref()
                        .unwrap()
                        .encrypt(&nonce, &(total - AEAD_TAG_LEN as u16).to_be_bytes())?
                } else {
                    (reference.size_shake.as_mut().unwrap().next_u16() ^ total)
                        .to_be_bytes()
                        .to_vec()
                };
                let wire = &writer.inner[start..];
                assert_eq!(&wire[..header.len()], header);
                assert_eq!(&wire[header.len()..header.len() + payload.len()], payload);
                assert_eq!(wire.len(), header.len() + total as usize);
            }
            let capacity = writer.frame.capacity();
            writer.finish().await?;
            assert_eq!(writer.frame.capacity(), capacity);
            let mut reader = BodyReader::new(writer.inner.as_slice(), config);
            let mut actual = Vec::new();
            let mut fragment = [0; 37];
            loop {
                let n = reader.read_plain(&mut fragment).await?;
                if n == 0 {
                    break;
                }
                actual.extend_from_slice(&fragment[..n]);
            }
            assert_eq!(actual, expected);
            assert!(reader.pending.capacity() >= MAX_CHUNK_PLAIN_LEN);
        }
    }
    Ok(())
}

#[tokio::test]
async fn modified_payload_and_authenticated_length_are_rejected() -> Result<()> {
    for security in [SecurityType::Aes128Gcm, SecurityType::ChaCha20Poly1305] {
        let options =
            RequestOptions::new(REQUEST_OPTION_CHUNK_STREAM | REQUEST_OPTION_AUTHENTICATED_LENGTH);
        let config = BodyConfig::new_request(security, options, [0x11; 16], [0x22; 16])?;
        let mut writer = BodyWriter::new(Vec::new(), config);
        writer.write_packet_plain(b"authenticated").await?;
        for offset in [0, 2 + AEAD_TAG_LEN] {
            let mut wire = writer.inner.clone();
            wire[offset] ^= 1;
            let mut reader = BodyReader::new(wire.as_slice(), config);
            assert!(reader.read_packet().await.is_err());
            assert!(reader.pending.is_empty());
            assert!(reader.read_plain(&mut [0; 64]).await.is_err());
        }
        let truncated = &writer.inner[..writer.inner.len() - 1];
        let mut reader = BodyReader::new(truncated, config);
        assert!(reader.read_plain(&mut [0; 64]).await.is_err());
        assert!(reader.pending.is_empty());
        assert!(reader.read_plain(&mut [0; 64]).await.is_err());
    }
    Ok(())
}

#[tokio::test]
async fn cached_ciphers_preserve_authenticated_lengths_padding_and_responses() -> Result<()> {
    for security in [SecurityType::Aes128Gcm, SecurityType::ChaCha20Poly1305] {
        let options = RequestOptions::new(
            REQUEST_OPTION_CHUNK_STREAM
                | REQUEST_OPTION_CHUNK_MASKING
                | REQUEST_OPTION_GLOBAL_PADDING
                | REQUEST_OPTION_AUTHENTICATED_LENGTH,
        );
        for config in [
            BodyConfig::new_request(security, options, [0x11; 16], [0x22; 16])?,
            BodyConfig::new_response(security, options, [0x11; 16], [0x22; 16])?,
        ] {
            let (client, server) = duplex(4096);
            let write = tokio::spawn(async move {
                let mut writer = BodyWriter::new(client, config);
                for index in 0..64u8 {
                    writer.write_packet_plain(&vec![index; 1024]).await?;
                }
                writer.finish().await
            });
            let mut reader = BodyReader::new(server, config);
            for index in 0..64u8 {
                assert_eq!(reader.read_packet().await?, Some(vec![index; 1024]));
            }
            assert!(reader.read_packet().await?.is_none());
            write.await??;
        }
    }
    Ok(())
}

#[test]
#[ignore = "microbenchmark; run explicitly in CI release mode"]
fn cipher_cache_microbenchmark() {
    use std::hint::black_box;
    use std::time::Instant;
    for security in [SecurityType::Aes128Gcm, SecurityType::ChaCha20Poly1305] {
        let options =
            RequestOptions::new(REQUEST_OPTION_CHUNK_STREAM | REQUEST_OPTION_AUTHENTICATED_LENGTH);
        let config = BodyConfig::new_request(security, options, [0x11; 16], [0x22; 16]).unwrap();
        let nonce = generate_chunk_nonce(&config.length_iv, 0);
        let start = Instant::now();
        for _ in 0..4096 {
            let key = kdf16(
                black_box(&config.length_key),
                AUTHENTICATED_LENGTH_SALT,
                &[],
            );
            black_box(
                BodyCipher::new(security, &key)
                    .encrypt(&nonce, black_box(&[0, 32]))
                    .unwrap(),
            );
        }
        let uncached = start.elapsed();
        let cipher = ChunkState::new(config);
        let start = Instant::now();
        for _ in 0..4096 {
            black_box(
                cipher
                    .length_cipher
                    .as_ref()
                    .unwrap()
                    .encrypt(&nonce, black_box(&[0, 32]))
                    .unwrap(),
            );
        }
        println!(
            "VMess {security}: uncached length crypto {uncached:?}, cached {:?}",
            start.elapsed()
        );
    }
}

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
