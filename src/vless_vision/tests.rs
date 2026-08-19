use super::*;
use tokio::io::AsyncReadExt;

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
