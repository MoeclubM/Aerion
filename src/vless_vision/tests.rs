use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn decodes_vision_frame_and_raw_tail() {
    let user = [7u8; 16];
    let mut bytes = encode_end_frame(&user, b"hello").expect("encode vision frame");
    bytes.extend_from_slice(b" world");

    let mut reader = VisionReader::new(bytes.as_slice(), user);
    let mut decoded = Vec::new();
    reader
        .read_to_end(&mut decoded)
        .await
        .expect("decode vision body");

    assert_eq!(decoded, b"hello world");
}

#[tokio::test]
async fn passes_plain_body_without_vision_prefix() {
    let user = [7u8; 16];
    let mut reader = VisionReader::new(b"plain".as_slice(), user);
    let mut decoded = Vec::new();
    reader
        .read_to_end(&mut decoded)
        .await
        .expect("plain body should pass through");

    assert_eq!(decoded, b"plain");
}

#[tokio::test]
async fn continue_frames_use_nonzero_padding() {
    let user = [7u8; 16];
    let encoded = encode_continue_frame(&user, true, b"hello").expect("encode continue");
    let padding_len = u16::from_be_bytes([encoded[19], encoded[20]]);
    assert!(padding_len > 0);
    let mut reader = VisionReader::new(encoded.as_slice(), user);
    let mut decoded = Vec::new();
    reader
        .read_to_end(&mut decoded)
        .await
        .expect("decode continue");
    assert_eq!(decoded, b"hello");
}

#[tokio::test]
async fn drains_cached_padding_and_frames_without_another_network_read() {
    let user = [7; 16];
    let mut bytes = encode_continue_frame(&user, true, b"first").unwrap();
    bytes.extend(encode_vision_frame(&user, false, COMMAND_PADDING_END, b"second").unwrap());
    let (mut writer, reader) = tokio::io::duplex(bytes.len());
    writer.write_all(&bytes).await.unwrap();
    // Keep the peer open and idle: waiting for another read must time out.
    let mut reader = VisionReader::new(reader, user);
    let mut output = [0; 11];
    tokio::time::timeout(
        std::time::Duration::from_secs(1),
        reader.read_exact(&mut output),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(&output, b"firstsecond");
}

fn tls13_server_hello(cipher: u16) -> Vec<u8> {
    let mut hello = vec![3, 3];
    hello.extend([0; 32]);
    hello.push(0);
    hello.extend(cipher.to_be_bytes());
    hello.extend([0, 0, 6, 0, 43, 0, 2, 3, 4]);
    let mut record = vec![22, 3, 3];
    record.extend(((hello.len() + 4) as u16).to_be_bytes());
    record.extend([2, 0, 0, hello.len() as u8]);
    record.extend(hello);
    record
}

#[test]
fn direct_requires_a_valid_fragmented_tls13_server_hello() {
    let user = [7; 16];
    let application = [23, 3, 3, 0, 2, 1, 2];
    for (cipher, expected) in [(0x1301, true), (0x1303, true), (0x1305, false)] {
        let control = Arc::new(VisionControl::default());
        for part in tls13_server_hello(cipher).chunks(3) {
            control.observe(part, true);
        }
        let mut encoder = VisionEncoder::with_control(user, control);
        let encoded = encoder.encode(&application).unwrap();
        assert_eq!(encoder.direct(), expected);
        assert_eq!(
            encoded[16],
            if expected {
                COMMAND_PADDING_DIRECT
            } else {
                COMMAND_PADDING_END
            }
        );
    }
    let mut encoder = VisionEncoder::new(user);
    let encoded = encoder.encode(&application).unwrap();
    assert_eq!(encoded[16], COMMAND_PADDING_CONTINUE);
    assert!(!encoder.direct());
}

#[tokio::test]
async fn direct_switches_after_all_cached_padding() {
    let user = [7; 16];
    let control = Arc::new(VisionControl::default());
    let bytes = encode_direct_frame(&user, true, b"hello").unwrap();
    let (mut writer, reader) = tokio::io::duplex(bytes.len());
    writer.write_all(&bytes).await.unwrap();
    let mut reader = VisionReader::with_control(reader, user, control.clone());
    let mut payload = [0; 5];
    reader.read_exact(&mut payload).await.unwrap();
    assert_eq!(&payload, b"hello");
    assert!(!control.read_direct());
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(20),
            reader.read(&mut payload)
        )
        .await
        .is_err()
    );
    assert!(control.read_direct());
}
