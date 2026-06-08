use crate::reality::{RealityClientConfig, build_reality_client_hello_with_alpn};
use crate::utls::UtlsFingerprint;
use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use anyhow::{Context, Result, bail, ensure};
use chacha20poly1305::ChaCha20Poly1305;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha384, Sha512};
use std::pin::Pin;
use std::task::{Context as TaskContext, Poll};
use tokio::io::{
    AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf, duplex,
};
use tokio::net::TcpStream;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};
use tokio::task::JoinHandle;
use x25519_dalek::{PublicKey, StaticSecret};

const TLS_RECORD_HEADER_LEN: usize = 5;
const TLS_MAX_PLAINTEXT_LEN: usize = 16 * 1024;
const TLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC: u8 = 20;
const TLS_CONTENT_TYPE_ALERT: u8 = 21;
const TLS_CONTENT_TYPE_HANDSHAKE: u8 = 22;
const TLS_CONTENT_TYPE_APPLICATION_DATA: u8 = 23;
const TLS_HANDSHAKE_TYPE_NEW_SESSION_TICKET: u8 = 4;
const TLS_HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS: u8 = 8;
const TLS_HANDSHAKE_TYPE_CERTIFICATE: u8 = 11;
const TLS_HANDSHAKE_TYPE_CERTIFICATE_VERIFY: u8 = 15;
const TLS_HANDSHAKE_TYPE_FINISHED: u8 = 20;
const TLS_HANDSHAKE_TYPE_KEY_UPDATE: u8 = 24;
const TLS_ALERT_WARNING: u8 = 1;
const TLS_ALERT_CLOSE_NOTIFY: u8 = 0;
const TLS_GROUP_X25519: u16 = 29;
const TLS_SIGNATURE_SCHEME_ED25519: u16 = 0x0807;
const TLS13_LABEL_PREFIX: &[u8] = b"tls13 ";
const TLS13_SERVER_CERT_VERIFY_CONTEXT: &[u8] = b"TLS 1.3, server CertificateVerify";
const REALITY_PIPE_CAPACITY: usize = 64 * 1024;

type HmacSha512 = Hmac<Sha512>;

pub struct RealityTlsClientStream {
    reader: DuplexStream,
    writer: DuplexStream,
    read_task: JoinHandle<Result<()>>,
    write_task: JoinHandle<Result<()>>,
}

impl Drop for RealityTlsClientStream {
    fn drop(&mut self) {
        self.read_task.abort();
        self.write_task.abort();
    }
}

impl AsyncRead for RealityTlsClientStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.reader).poll_read(cx, buf)
    }
}

impl AsyncWrite for RealityTlsClientStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.writer).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.writer).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.writer).poll_shutdown(cx)
    }
}

pub async fn connect(
    mut stream: TcpStream,
    config: &RealityClientConfig,
    server_name: &str,
    fingerprint: UtlsFingerprint,
    alpn_protocols: Option<Vec<Vec<u8>>>,
) -> Result<RealityTlsClientStream> {
    let built =
        build_reality_client_hello_with_alpn(config, server_name, fingerprint, alpn_protocols)
            .context("build REALITY ClientHello")?;
    stream
        .write_all(&built.client_hello.record)
        .await
        .context("write REALITY ClientHello")?;
    stream.flush().await.context("flush REALITY ClientHello")?;

    let server_hello = read_server_hello(&mut stream)
        .await
        .context("read REALITY ServerHello")?;
    let parsed_server = parse_server_hello(&server_hello)?;
    let suite = CipherSuite::from_id(parsed_server.cipher_suite)?;

    let shared_secret = StaticSecret::from(built.client_hello.private_key)
        .diffie_hellman(&PublicKey::from(parsed_server.x25519_public_key))
        .to_bytes();
    let mut transcript = TranscriptHash::new(suite.hash_kind());
    transcript.update(&built.client_hello.handshake);
    transcript.update(&server_hello);

    let mut key_schedule = Tls13KeySchedule::new(suite.hash_kind());
    key_schedule.input_secret(&shared_secret);
    let server_hello_hash = transcript.finish();
    let client_handshake_secret = key_schedule
        .derive_secret(b"c hs traffic", &server_hello_hash)
        .context("derive REALITY client handshake traffic secret")?;
    let server_handshake_secret = key_schedule
        .derive_secret(b"s hs traffic", &server_hello_hash)
        .context("derive REALITY server handshake traffic secret")?;
    let mut handshake_reader = RecordCipher::new(suite, &server_handshake_secret)
        .context("create REALITY handshake reader")?;
    let mut handshake_writer = RecordCipher::new(suite, &client_handshake_secret)
        .context("create REALITY handshake writer")?;

    read_server_handshake_messages(
        &mut stream,
        &mut handshake_reader,
        suite,
        &built.auth_key,
        &mut transcript,
        &server_handshake_secret,
    )
    .await?;
    let after_server_finished_hash = transcript.finish();

    let client_finished = build_finished(
        suite.hash_kind(),
        &client_handshake_secret,
        &after_server_finished_hash,
    )
    .context("build REALITY client Finished")?;
    let client_finished_record = handshake_writer
        .encrypt_record(TLS_CONTENT_TYPE_HANDSHAKE, &client_finished)
        .context("encrypt REALITY client Finished")?;
    stream
        .write_all(&client_finished_record)
        .await
        .context("write REALITY client Finished")?;
    stream
        .flush()
        .await
        .context("flush REALITY client Finished")?;

    key_schedule.input_empty();
    let client_application_secret = key_schedule
        .derive_secret(b"c ap traffic", &after_server_finished_hash)
        .context("derive REALITY client application traffic secret")?;
    let server_application_secret = key_schedule
        .derive_secret(b"s ap traffic", &after_server_finished_hash)
        .context("derive REALITY server application traffic secret")?;
    let reader_cipher = RecordCipher::new(suite, &server_application_secret)
        .context("create REALITY application reader")?;
    let writer_cipher = RecordCipher::new(suite, &client_application_secret)
        .context("create REALITY application writer")?;
    Ok(spawn_reality_stream(stream, reader_cipher, writer_cipher))
}

fn spawn_reality_stream(
    stream: TcpStream,
    reader_cipher: RecordCipher,
    writer_cipher: RecordCipher,
) -> RealityTlsClientStream {
    let (inbound_sink, reader) = duplex(REALITY_PIPE_CAPACITY);
    let (writer, outbound_source) = duplex(REALITY_PIPE_CAPACITY);
    let (stream_reader, stream_writer) = stream.into_split();
    let (control_tx, control_rx) = unbounded_channel();
    let read_task = tokio::spawn(async move {
        pump_inbound(stream_reader, inbound_sink, reader_cipher, control_tx).await
    });
    let write_task = tokio::spawn(async move {
        pump_outbound(stream_writer, outbound_source, writer_cipher, control_rx).await
    });
    RealityTlsClientStream {
        reader,
        writer,
        read_task,
        write_task,
    }
}

async fn pump_inbound(
    mut stream: tokio::net::tcp::OwnedReadHalf,
    mut sink: DuplexStream,
    mut cipher: RecordCipher,
    control: UnboundedSender<OutboundControl>,
) -> Result<()> {
    loop {
        let Some(mut record) = read_tls_record(&mut stream).await? else {
            let _ = control.send(OutboundControl::CloseNotify);
            sink.shutdown().await.ok();
            return Ok(());
        };
        match record.content_type {
            TLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC => {
                ensure!(
                    record.payload == [1],
                    "invalid REALITY ChangeCipherSpec payload"
                );
            }
            TLS_CONTENT_TYPE_ALERT => {
                if record.payload.len() == 2 && record.payload[1] == TLS_ALERT_CLOSE_NOTIFY {
                    let _ = control.send(OutboundControl::CloseNotify);
                    sink.shutdown().await.ok();
                    return Ok(());
                }
                bail!("REALITY peer sent alert {:?}", record.payload);
            }
            TLS_CONTENT_TYPE_APPLICATION_DATA => {
                let content_type = cipher
                    .decrypt_record_in_place(record.content_type, &mut record.payload)
                    .context("decrypt REALITY application record")?;
                match content_type {
                    TLS_CONTENT_TYPE_APPLICATION_DATA => {
                        sink.write_all(&record.payload)
                            .await
                            .context("write REALITY plaintext into pipe")?;
                    }
                    TLS_CONTENT_TYPE_ALERT => {
                        if record.payload.len() == 2 && record.payload[1] == TLS_ALERT_CLOSE_NOTIFY
                        {
                            let _ = control.send(OutboundControl::CloseNotify);
                            sink.shutdown().await.ok();
                            return Ok(());
                        }
                        bail!("REALITY peer sent encrypted alert {:?}", record.payload);
                    }
                    TLS_CONTENT_TYPE_HANDSHAKE => {
                        let mut messages = record.payload.as_slice();
                        while !messages.is_empty() {
                            let consumed =
                                handle_post_handshake_message(&mut cipher, messages, &control)?;
                            messages = &messages[consumed..];
                        }
                    }
                    other => bail!("unexpected REALITY inner content type {other}"),
                }
            }
            other => bail!("unexpected REALITY record type {other}"),
        }
    }
}

async fn pump_outbound(
    mut stream: tokio::net::tcp::OwnedWriteHalf,
    mut source: DuplexStream,
    mut cipher: RecordCipher,
    mut control: UnboundedReceiver<OutboundControl>,
) -> Result<()> {
    let mut buffer = vec![0u8; TLS_MAX_PLAINTEXT_LEN];
    let mut control_closed = false;
    loop {
        tokio::select! {
            biased;
            command = control.recv(), if !control_closed => {
                match command {
                    Some(OutboundControl::KeyUpdate) => send_key_update(&mut stream, &mut cipher).await?,
                    Some(OutboundControl::CloseNotify) => {
                        send_close_notify(&mut stream, &mut cipher).await.ok();
                        stream.shutdown().await.ok();
                        return Ok(());
                    }
                    None => control_closed = true,
                }
            }
            read = source.read(&mut buffer) => {
                let read = read.context("read REALITY plaintext from pipe")?;
                if read == 0 {
                    send_close_notify(&mut stream, &mut cipher).await.ok();
                    stream.shutdown().await.ok();
                    return Ok(());
                }
                let record = cipher
                    .encrypt_record(TLS_CONTENT_TYPE_APPLICATION_DATA, &buffer[..read])
                    .context("encrypt REALITY application record")?;
                stream
                    .write_all(&record)
                    .await
                    .context("write REALITY application record")?;
            }
        }
    }
}

fn handle_post_handshake_message(
    cipher: &mut RecordCipher,
    bytes: &[u8],
    control: &UnboundedSender<OutboundControl>,
) -> Result<usize> {
    ensure!(
        bytes.len() >= 4,
        "truncated REALITY post-handshake message header"
    );
    let message_len = read_u24_at(bytes, 1, "REALITY post-handshake message length")? as usize;
    let total_len = 4 + message_len;
    ensure!(
        bytes.len() >= total_len,
        "truncated REALITY post-handshake message body"
    );
    match bytes[0] {
        TLS_HANDSHAKE_TYPE_NEW_SESSION_TICKET => {}
        TLS_HANDSHAKE_TYPE_KEY_UPDATE => {
            ensure!(message_len == 1, "REALITY KeyUpdate payload must be 1 byte");
            let request_update = bytes[4];
            ensure!(
                request_update <= 1,
                "REALITY KeyUpdate request_update must be 0 or 1"
            );
            cipher
                .update_key()
                .context("update REALITY application traffic key")?;
            if request_update == 1 {
                let _ = control.send(OutboundControl::KeyUpdate);
            }
        }
        other => bail!("unsupported REALITY post-handshake message type {other}"),
    }
    Ok(total_len)
}

async fn send_close_notify(
    stream: &mut tokio::net::tcp::OwnedWriteHalf,
    cipher: &mut RecordCipher,
) -> Result<()> {
    let record = cipher
        .encrypt_record(
            TLS_CONTENT_TYPE_ALERT,
            &[TLS_ALERT_WARNING, TLS_ALERT_CLOSE_NOTIFY],
        )
        .context("encrypt REALITY close_notify")?;
    stream
        .write_all(&record)
        .await
        .context("write REALITY close_notify")?;
    stream.flush().await.context("flush REALITY close_notify")
}

async fn send_key_update(
    stream: &mut tokio::net::tcp::OwnedWriteHalf,
    cipher: &mut RecordCipher,
) -> Result<()> {
    let message = build_handshake_message(TLS_HANDSHAKE_TYPE_KEY_UPDATE, &[0])
        .context("build REALITY KeyUpdate")?;
    let record = cipher
        .encrypt_record(TLS_CONTENT_TYPE_HANDSHAKE, &message)
        .context("encrypt REALITY KeyUpdate")?;
    stream
        .write_all(&record)
        .await
        .context("write REALITY KeyUpdate")?;
    stream.flush().await.context("flush REALITY KeyUpdate")?;
    cipher.update_key().context("update REALITY send key")
}

async fn read_server_hello(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut handshake = Vec::new();
    let mut expected = None;
    loop {
        let Some(record) = read_tls_record(stream).await? else {
            bail!("unexpected EOF before REALITY ServerHello");
        };
        match record.content_type {
            TLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC => {
                ensure!(
                    record.payload == [1],
                    "invalid REALITY ChangeCipherSpec payload before ServerHello"
                );
            }
            TLS_CONTENT_TYPE_HANDSHAKE => {
                handshake.extend_from_slice(&record.payload);
                if handshake.len() >= 4 && expected.is_none() {
                    ensure!(
                        handshake[0] == 2,
                        "REALITY expected ServerHello handshake message"
                    );
                    expected = Some(
                        4 + read_u24_at(&handshake, 1, "REALITY ServerHello length")? as usize,
                    );
                }
                if let Some(expected) = expected {
                    if handshake.len() >= expected {
                        ensure!(
                            handshake.len() == expected,
                            "REALITY ServerHello contained trailing plaintext handshake bytes"
                        );
                        return Ok(handshake);
                    }
                }
            }
            TLS_CONTENT_TYPE_ALERT => bail!("REALITY peer sent plaintext alert before ServerHello"),
            other => bail!("unexpected REALITY record type {other} before ServerHello"),
        }
    }
}

async fn read_server_handshake_messages(
    stream: &mut TcpStream,
    handshake_reader: &mut RecordCipher,
    suite: CipherSuite,
    auth_key: &[u8; 32],
    transcript: &mut TranscriptHash,
    server_handshake_secret: &[u8],
) -> Result<()> {
    let mut buffer = Vec::new();
    let mut certificate_public_key = None;
    loop {
        let Some(mut record) = read_tls_record(stream).await? else {
            bail!("unexpected EOF before REALITY server Finished");
        };
        match record.content_type {
            TLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC => {
                ensure!(
                    record.payload == [1],
                    "invalid REALITY ChangeCipherSpec payload"
                );
            }
            TLS_CONTENT_TYPE_ALERT => bail!("REALITY peer sent plaintext alert during handshake"),
            TLS_CONTENT_TYPE_APPLICATION_DATA => {
                let content_type = handshake_reader
                    .decrypt_record_in_place(record.content_type, &mut record.payload)
                    .context("decrypt REALITY server handshake record")?;
                ensure!(
                    content_type == TLS_CONTENT_TYPE_HANDSHAKE,
                    "REALITY expected encrypted handshake record"
                );
                buffer.extend_from_slice(&record.payload);
                while let Some(message) = take_handshake_message(&mut buffer)? {
                    match message[0] {
                        TLS_HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS => {
                            // Parsed for validation; the negotiated ALPN is not consumed.
                            parse_encrypted_extensions(&message)
                                .context("parse REALITY EncryptedExtensions")?;
                            transcript.update(&message);
                        }
                        TLS_HANDSHAKE_TYPE_CERTIFICATE => {
                            let certificate = parse_certificate_message(&message)
                                .context("parse REALITY Certificate")?;
                            let public_key = verify_reality_certificate(&certificate, auth_key)
                                .context("verify REALITY certificate")?;
                            certificate_public_key = Some(public_key);
                            transcript.update(&message);
                        }
                        TLS_HANDSHAKE_TYPE_CERTIFICATE_VERIFY => {
                            let public_key = certificate_public_key
                                .context("REALITY CertificateVerify arrived before Certificate")?;
                            verify_certificate_verify(
                                suite.hash_kind(),
                                &public_key,
                                &transcript.finish(),
                                &message,
                            )
                            .context("verify REALITY CertificateVerify")?;
                            transcript.update(&message);
                        }
                        TLS_HANDSHAKE_TYPE_FINISHED => {
                            verify_finished(
                                suite.hash_kind(),
                                server_handshake_secret,
                                &transcript.finish(),
                                &message,
                            )
                            .context("verify REALITY server Finished")?;
                            transcript.update(&message);
                            return Ok(());
                        }
                        other => bail!("unexpected REALITY server handshake message type {other}"),
                    }
                }
            }
            other => bail!("unexpected REALITY record type {other} during handshake"),
        }
    }
}

fn take_handshake_message(buffer: &mut Vec<u8>) -> Result<Option<Vec<u8>>> {
    if buffer.len() < 4 {
        return Ok(None);
    }
    let message_len = read_u24_at(buffer, 1, "REALITY handshake message length")? as usize;
    let total_len = 4 + message_len;
    if buffer.len() < total_len {
        return Ok(None);
    }
    Ok(Some(buffer.drain(..total_len).collect()))
}

struct ParsedServerHello {
    cipher_suite: u16,
    x25519_public_key: [u8; 32],
}

fn parse_server_hello(raw: &[u8]) -> Result<ParsedServerHello> {
    ensure!(raw.len() >= 4 + 2 + 32 + 1, "truncated REALITY ServerHello");
    ensure!(raw[0] == 2, "REALITY expected ServerHello");
    let declared_len = read_u24_at(raw, 1, "REALITY ServerHello length")? as usize;
    ensure!(
        declared_len + 4 == raw.len(),
        "REALITY ServerHello length mismatch"
    );
    let mut offset = 4;
    ensure!(
        read_u16_at(raw, offset, "REALITY ServerHello legacy_version")? == 0x0303,
        "REALITY ServerHello legacy_version must be TLS 1.2"
    );
    offset += 2;
    ensure!(
        offset + 32 <= raw.len(),
        "truncated REALITY ServerHello random"
    );
    let random = &raw[offset..offset + 32];
    ensure!(
        random
            != [
                0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65,
                0xb8, 0x91, 0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2,
                0xc8, 0xa8, 0x33, 0x9c,
            ],
        "REALITY HelloRetryRequest is not supported"
    );
    offset += 32;
    ensure!(
        offset < raw.len(),
        "truncated REALITY ServerHello session id length"
    );
    let session_id_len = raw[offset] as usize;
    offset += 1 + session_id_len;
    ensure!(
        offset + 3 <= raw.len(),
        "truncated REALITY ServerHello selected cipher"
    );
    let cipher_suite = read_u16_at(raw, offset, "REALITY ServerHello cipher suite")?;
    offset += 2;
    ensure!(
        raw[offset] == 0,
        "REALITY ServerHello compression must be null"
    );
    offset += 1;

    let extensions_len =
        read_u16_at(raw, offset, "REALITY ServerHello extensions length")? as usize;
    offset += 2;
    let extensions_end = offset + extensions_len;
    ensure!(
        extensions_end == raw.len(),
        "REALITY ServerHello extensions length mismatch"
    );
    let mut tls13 = false;
    let mut x25519_public_key = None;
    while offset < extensions_end {
        let extension_type = read_u16_at(raw, offset, "REALITY ServerHello extension type")?;
        let extension_len =
            read_u16_at(raw, offset + 2, "REALITY ServerHello extension length")? as usize;
        let data_start = offset + 4;
        let data_end = data_start + extension_len;
        ensure!(
            data_end <= extensions_end,
            "truncated REALITY ServerHello extension"
        );
        let data = &raw[data_start..data_end];
        match extension_type {
            43 => {
                ensure!(
                    data == [0x03, 0x04],
                    "REALITY ServerHello must negotiate TLS 1.3"
                );
                tls13 = true;
            }
            51 => {
                ensure!(data.len() >= 4, "truncated REALITY ServerHello key_share");
                let group = read_u16_at(data, 0, "REALITY ServerHello key_share group")?;
                let key_len =
                    read_u16_at(data, 2, "REALITY ServerHello key_share length")? as usize;
                ensure!(
                    4 + key_len == data.len(),
                    "REALITY ServerHello key_share length mismatch"
                );
                ensure!(
                    group == TLS_GROUP_X25519,
                    "REALITY only supports X25519 server key_share for outbound"
                );
                ensure!(
                    key_len == 32,
                    "REALITY X25519 server key_share must be 32 bytes"
                );
                let mut key = [0u8; 32];
                key.copy_from_slice(&data[4..]);
                x25519_public_key = Some(key);
            }
            _ => {}
        }
        offset = data_end;
    }
    ensure!(tls13, "REALITY ServerHello missing supported_versions");
    Ok(ParsedServerHello {
        cipher_suite,
        x25519_public_key: x25519_public_key.context("REALITY ServerHello missing key_share")?,
    })
}

fn parse_encrypted_extensions(message: &[u8]) -> Result<Option<Vec<u8>>> {
    ensure!(
        message.len() >= 6 && message[0] == TLS_HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS,
        "invalid REALITY EncryptedExtensions"
    );
    ensure!(
        read_u24_at(message, 1, "REALITY EncryptedExtensions length")? as usize + 4
            == message.len(),
        "REALITY EncryptedExtensions length mismatch"
    );
    let mut offset = 4;
    let extensions_len = read_u16_at(
        message,
        offset,
        "REALITY EncryptedExtensions extensions length",
    )? as usize;
    offset += 2;
    let extensions_end = offset + extensions_len;
    ensure!(
        extensions_end == message.len(),
        "REALITY EncryptedExtensions extensions length mismatch"
    );
    let mut selected_alpn = None;
    while offset < extensions_end {
        let extension_type = read_u16_at(
            message,
            offset,
            "REALITY EncryptedExtensions extension type",
        )?;
        let extension_len = read_u16_at(
            message,
            offset + 2,
            "REALITY EncryptedExtensions extension length",
        )? as usize;
        let data_start = offset + 4;
        let data_end = data_start + extension_len;
        ensure!(
            data_end <= extensions_end,
            "truncated REALITY EncryptedExtensions extension"
        );
        if extension_type == 16 {
            selected_alpn = Some(parse_selected_alpn(&message[data_start..data_end])?);
        }
        offset = data_end;
    }
    Ok(selected_alpn)
}

fn parse_selected_alpn(bytes: &[u8]) -> Result<Vec<u8>> {
    let list_len = read_u16_at(bytes, 0, "REALITY selected ALPN list length")? as usize;
    ensure!(
        list_len + 2 == bytes.len(),
        "REALITY selected ALPN list length mismatch"
    );
    ensure!(list_len >= 1, "REALITY selected ALPN is empty");
    let protocol_len = bytes[2] as usize;
    ensure!(
        protocol_len + 3 == bytes.len(),
        "REALITY selected ALPN payload length mismatch"
    );
    Ok(bytes[3..].to_vec())
}

fn parse_certificate_message(message: &[u8]) -> Result<Vec<u8>> {
    ensure!(
        message.len() >= 8 && message[0] == TLS_HANDSHAKE_TYPE_CERTIFICATE,
        "invalid REALITY Certificate message"
    );
    ensure!(
        read_u24_at(message, 1, "REALITY Certificate length")? as usize + 4 == message.len(),
        "REALITY Certificate length mismatch"
    );
    let mut offset = 4;
    let request_context_len = message[offset] as usize;
    offset += 1 + request_context_len;
    ensure!(
        offset + 3 <= message.len(),
        "truncated REALITY Certificate list length"
    );
    let list_len = read_u24_at(message, offset, "REALITY Certificate list length")? as usize;
    offset += 3;
    let list_end = offset + list_len;
    ensure!(
        list_end == message.len(),
        "REALITY Certificate list length mismatch"
    );
    let cert_len = read_u24_at(message, offset, "REALITY Certificate entry length")? as usize;
    offset += 3;
    ensure!(
        offset + cert_len + 2 <= list_end,
        "truncated REALITY Certificate entry"
    );
    Ok(message[offset..offset + cert_len].to_vec())
}

fn verify_reality_certificate(certificate: &[u8], auth_key: &[u8; 32]) -> Result<[u8; 32]> {
    let (public_key, signature) = certificate_public_key_and_signature(certificate)?;
    let mut hmac = <HmacSha512 as Mac>::new_from_slice(auth_key)
        .context("initialize REALITY certificate HMAC")?;
    hmac.update(&public_key);
    let expected = hmac.finalize().into_bytes();
    ensure!(
        signature == expected.as_slice(),
        "REALITY certificate HMAC signature mismatch"
    );
    Ok(public_key)
}

fn certificate_public_key_and_signature(certificate: &[u8]) -> Result<([u8; 32], Vec<u8>)> {
    let root = read_der_element(certificate, 0)?;
    ensure!(root.tag == 0x30, "REALITY certificate root is not SEQUENCE");
    ensure!(
        root.end == certificate.len(),
        "REALITY certificate has trailing data"
    );
    let tbs = read_der_element(certificate, root.content_start)?;
    ensure!(tbs.tag == 0x30, "REALITY certificate TBS is not SEQUENCE");
    let signature_algorithm = read_der_element(certificate, tbs.end)?;
    ensure!(
        signature_algorithm.tag == 0x30,
        "REALITY certificate signature algorithm is not SEQUENCE"
    );
    let signature = read_der_element(certificate, signature_algorithm.end)?;
    ensure!(
        signature.tag == 0x03,
        "REALITY certificate signature is not BIT STRING"
    );
    ensure!(
        signature.content_end == root.content_end,
        "REALITY certificate signature is not final element"
    );
    ensure!(
        certificate[signature.content_start] == 0,
        "REALITY certificate signature has unused bits"
    );
    let signature_bytes = certificate[signature.content_start + 1..signature.content_end].to_vec();
    ensure!(
        signature_bytes.len() == 64,
        "REALITY certificate signature must be 64 bytes"
    );

    let spki = certificate_tbs_spki(certificate, &tbs)?;
    let algorithm = read_der_element(certificate, spki.content_start)?;
    ensure!(
        algorithm.tag == 0x30,
        "REALITY certificate SPKI algorithm is not SEQUENCE"
    );
    let oid = read_der_element(certificate, algorithm.content_start)?;
    ensure!(
        oid.tag == 0x06 && certificate[oid.content_start..oid.content_end] == [0x2b, 0x65, 0x70],
        "REALITY certificate public key is not Ed25519"
    );
    let bit_string = read_der_element(certificate, algorithm.end)?;
    ensure!(
        bit_string.tag == 0x03,
        "REALITY certificate public key is not BIT STRING"
    );
    ensure!(
        bit_string.content_end == spki.content_end,
        "REALITY certificate SPKI has trailing data"
    );
    ensure!(
        certificate[bit_string.content_start] == 0
            && bit_string.content_end == bit_string.content_start + 33,
        "REALITY certificate Ed25519 public key length mismatch"
    );
    let mut public_key = [0u8; 32];
    public_key.copy_from_slice(&certificate[bit_string.content_start + 1..bit_string.content_end]);
    Ok((public_key, signature_bytes))
}

fn certificate_tbs_spki<'a>(certificate: &'a [u8], tbs: &DerElement) -> Result<DerElement> {
    let mut offset = tbs.content_start;
    if certificate[offset] == 0xa0 {
        offset = read_der_element(certificate, offset)?.end;
    }
    for _ in 0..5 {
        offset = read_der_element(certificate, offset)?.end;
    }
    let spki = read_der_element(certificate, offset)?;
    ensure!(
        spki.tag == 0x30,
        "REALITY certificate subjectPublicKeyInfo is not SEQUENCE"
    );
    Ok(spki)
}

fn verify_certificate_verify(
    hash_kind: HashKind,
    public_key: &[u8; 32],
    transcript_hash: &[u8],
    message: &[u8],
) -> Result<()> {
    ensure!(
        message.len() >= 8 && message[0] == TLS_HANDSHAKE_TYPE_CERTIFICATE_VERIFY,
        "invalid REALITY CertificateVerify"
    );
    ensure!(
        read_u24_at(message, 1, "REALITY CertificateVerify length")? as usize + 4 == message.len(),
        "REALITY CertificateVerify length mismatch"
    );
    let scheme = read_u16_at(message, 4, "REALITY CertificateVerify scheme")?;
    ensure!(
        scheme == TLS_SIGNATURE_SCHEME_ED25519,
        "REALITY CertificateVerify must use Ed25519"
    );
    let signature_len =
        read_u16_at(message, 6, "REALITY CertificateVerify signature length")? as usize;
    ensure!(
        signature_len + 8 == message.len(),
        "REALITY CertificateVerify signature length mismatch"
    );
    let mut signed = vec![0x20; 64];
    signed.extend_from_slice(TLS13_SERVER_CERT_VERIFY_CONTEXT);
    signed.push(0);
    signed.extend_from_slice(transcript_hash);
    let key = VerifyingKey::from_bytes(public_key).context("load REALITY Ed25519 public key")?;
    let signature =
        Signature::try_from(&message[8..]).context("load REALITY CertificateVerify signature")?;
    key.verify(&signed, &signature)
        .context("REALITY CertificateVerify signature mismatch")?;
    let _ = hash_kind;
    Ok(())
}

fn verify_finished(
    hash_kind: HashKind,
    base_key: &[u8],
    transcript_hash: &[u8],
    finished: &[u8],
) -> Result<()> {
    ensure!(
        finished.len() >= 4 && finished[0] == TLS_HANDSHAKE_TYPE_FINISHED,
        "REALITY Finished is malformed"
    );
    let declared_len = read_u24_at(finished, 1, "REALITY Finished length")? as usize;
    ensure!(
        finished.len() == 4 + declared_len,
        "REALITY Finished length mismatch"
    );
    let expected = finished_verify_data(hash_kind, base_key, transcript_hash)?;
    ensure!(
        finished[4..] == expected,
        "REALITY Finished verify_data mismatch"
    );
    Ok(())
}

fn build_finished(hash_kind: HashKind, base_key: &[u8], transcript_hash: &[u8]) -> Result<Vec<u8>> {
    let verify_data = finished_verify_data(hash_kind, base_key, transcript_hash)?;
    build_handshake_message(TLS_HANDSHAKE_TYPE_FINISHED, &verify_data)
}

fn finished_verify_data(
    hash_kind: HashKind,
    base_key: &[u8],
    transcript_hash: &[u8],
) -> Result<Vec<u8>> {
    let finished_key = hkdf_expand_label(
        hash_kind,
        base_key,
        b"finished",
        &[],
        hash_kind.output_len(),
    )?;
    Ok(hash_kind.hmac(&finished_key, transcript_hash))
}

fn build_handshake_message(handshake_type: u8, body: &[u8]) -> Result<Vec<u8>> {
    let mut message = Vec::with_capacity(4 + body.len());
    message.push(handshake_type);
    message.extend_from_slice(&encode_u24(body.len())?);
    message.extend_from_slice(body);
    Ok(message)
}

async fn read_tls_record<R>(reader: &mut R) -> Result<Option<TlsRecord>>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0u8; TLS_RECORD_HEADER_LEN];
    let Some(()) = read_exact_or_eof(reader, &mut header).await? else {
        return Ok(None);
    };
    let payload_len = u16::from_be_bytes([header[3], header[4]]) as usize;
    let mut payload = vec![0u8; payload_len];
    reader
        .read_exact(&mut payload)
        .await
        .context("read REALITY TLS record payload")?;
    Ok(Some(TlsRecord {
        content_type: header[0],
        payload,
    }))
}

async fn read_exact_or_eof<R>(reader: &mut R, buffer: &mut [u8]) -> Result<Option<()>>
where
    R: AsyncRead + Unpin,
{
    let mut offset = 0;
    while offset < buffer.len() {
        let read = reader
            .read(&mut buffer[offset..])
            .await
            .context("read REALITY TLS record header")?;
        if read == 0 {
            ensure!(offset == 0, "unexpected EOF in REALITY TLS record header");
            return Ok(None);
        }
        offset += read;
    }
    Ok(Some(()))
}

struct TlsRecord {
    content_type: u8,
    payload: Vec<u8>,
}

struct RecordCipher {
    suite: CipherSuite,
    traffic_secret: Vec<u8>,
    cipher: AeadCipher,
    iv: [u8; 12],
    sequence: u64,
}

enum AeadCipher {
    Aes128(Aes128Gcm),
    Aes256(Aes256Gcm),
    Chacha(ChaCha20Poly1305),
}

enum OutboundControl {
    KeyUpdate,
    CloseNotify,
}

impl RecordCipher {
    fn new(suite: CipherSuite, secret: &[u8]) -> Result<Self> {
        let key = hkdf_expand_label(suite.hash_kind(), secret, b"key", &[], suite.key_len())?;
        let iv = hkdf_expand_label(suite.hash_kind(), secret, b"iv", &[], 12)?;
        let mut nonce_iv = [0u8; 12];
        nonce_iv.copy_from_slice(&iv);
        Ok(Self {
            suite,
            traffic_secret: secret.to_vec(),
            cipher: AeadCipher::new(suite, &key)?,
            iv: nonce_iv,
            sequence: 0,
        })
    }

    fn encrypt_record(&mut self, inner_content_type: u8, plaintext: &[u8]) -> Result<Vec<u8>> {
        ensure!(
            plaintext.len() <= TLS_MAX_PLAINTEXT_LEN,
            "REALITY plaintext chunk exceeds TLS record limit"
        );
        let mut payload = plaintext.to_vec();
        payload.push(inner_content_type);
        let header = build_encrypted_record_header(payload.len() + self.suite.tag_len())?;
        let nonce = build_nonce(self.iv, self.sequence);
        let tag = self
            .cipher
            .encrypt_in_place_detached(&nonce, &header, &mut payload)
            .context("seal REALITY TLS record")?;
        self.sequence += 1;

        let mut record = Vec::with_capacity(TLS_RECORD_HEADER_LEN + payload.len() + tag.len());
        record.extend_from_slice(&header);
        record.extend_from_slice(&payload);
        record.extend_from_slice(&tag);
        Ok(record)
    }

    fn decrypt_record_in_place(&mut self, record_type: u8, payload: &mut Vec<u8>) -> Result<u8> {
        ensure!(
            record_type == TLS_CONTENT_TYPE_APPLICATION_DATA,
            "REALITY expected encrypted application_data record"
        );
        ensure!(
            payload.len() >= self.suite.tag_len(),
            "REALITY encrypted record is too short"
        );
        let header = build_encrypted_record_header(payload.len())?;
        let nonce = build_nonce(self.iv, self.sequence);
        let ciphertext_len = payload.len() - self.suite.tag_len();
        let tag = payload[ciphertext_len..].to_vec();
        payload.truncate(ciphertext_len);
        self.cipher
            .decrypt_in_place_detached(&nonce, &header, payload, &tag)
            .context("open REALITY TLS record")?;
        self.sequence += 1;

        let content_type_offset = payload
            .iter()
            .rposition(|byte| *byte != 0)
            .context("REALITY decrypted record is missing content type")?;
        let content_type = payload[content_type_offset];
        payload.truncate(content_type_offset);
        Ok(content_type)
    }

    fn update_key(&mut self) -> Result<()> {
        let next_secret = hkdf_expand_label(
            self.suite.hash_kind(),
            &self.traffic_secret,
            b"traffic upd",
            &[],
            self.suite.hash_kind().output_len(),
        )?;
        *self = Self::new(self.suite, &next_secret)?;
        Ok(())
    }
}

impl AeadCipher {
    fn new(suite: CipherSuite, key: &[u8]) -> Result<Self> {
        Ok(match suite.id {
            0x1301 => Self::Aes128(
                Aes128Gcm::new_from_slice(key).context("create REALITY AES-128-GCM cipher")?,
            ),
            0x1302 => Self::Aes256(
                Aes256Gcm::new_from_slice(key).context("create REALITY AES-256-GCM cipher")?,
            ),
            0x1303 => Self::Chacha(
                ChaCha20Poly1305::new_from_slice(key)
                    .context("create REALITY ChaCha20-Poly1305 cipher")?,
            ),
            _ => unreachable!(),
        })
    }

    fn encrypt_in_place_detached(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        payload: &mut Vec<u8>,
    ) -> Result<Vec<u8>> {
        match self {
            Self::Aes128(cipher) => cipher
                .encrypt_in_place_detached(aes_gcm::Nonce::from_slice(nonce), aad, payload)
                .map(|tag| tag.to_vec()),
            Self::Aes256(cipher) => cipher
                .encrypt_in_place_detached(aes_gcm::Nonce::from_slice(nonce), aad, payload)
                .map(|tag| tag.to_vec()),
            Self::Chacha(cipher) => cipher
                .encrypt_in_place_detached(chacha20poly1305::Nonce::from_slice(nonce), aad, payload)
                .map(|tag| tag.to_vec()),
        }
        .map_err(|_| anyhow::anyhow!("REALITY AEAD encrypt failed"))
    }

    fn decrypt_in_place_detached(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        payload: &mut Vec<u8>,
        tag: &[u8],
    ) -> Result<()> {
        match self {
            Self::Aes128(cipher) => cipher.decrypt_in_place_detached(
                aes_gcm::Nonce::from_slice(nonce),
                aad,
                payload,
                aes_gcm::Tag::from_slice(tag),
            ),
            Self::Aes256(cipher) => cipher.decrypt_in_place_detached(
                aes_gcm::Nonce::from_slice(nonce),
                aad,
                payload,
                aes_gcm::Tag::from_slice(tag),
            ),
            Self::Chacha(cipher) => cipher.decrypt_in_place_detached(
                chacha20poly1305::Nonce::from_slice(nonce),
                aad,
                payload,
                chacha20poly1305::Tag::from_slice(tag),
            ),
        }
        .map_err(|_| anyhow::anyhow!("REALITY AEAD decrypt failed"))
    }
}

fn build_encrypted_record_header(payload_len: usize) -> Result<[u8; TLS_RECORD_HEADER_LEN]> {
    ensure!(
        payload_len <= u16::MAX as usize,
        "REALITY encrypted record is too large"
    );
    Ok([
        TLS_CONTENT_TYPE_APPLICATION_DATA,
        0x03,
        0x03,
        ((payload_len >> 8) & 0xff) as u8,
        (payload_len & 0xff) as u8,
    ])
}

fn build_nonce(iv: [u8; 12], sequence: u64) -> [u8; 12] {
    let mut nonce = iv;
    let sequence = sequence.to_be_bytes();
    for (index, byte) in sequence.iter().enumerate() {
        nonce[4 + index] ^= *byte;
    }
    nonce
}

#[derive(Clone, Copy)]
struct CipherSuite {
    id: u16,
}

impl CipherSuite {
    fn from_id(id: u16) -> Result<Self> {
        ensure!(
            matches!(id, 0x1301 | 0x1302 | 0x1303),
            "unsupported REALITY cipher suite 0x{id:04x}"
        );
        Ok(Self { id })
    }

    fn hash_kind(self) -> HashKind {
        match self.id {
            0x1302 => HashKind::Sha384,
            _ => HashKind::Sha256,
        }
    }

    fn key_len(self) -> usize {
        match self.id {
            0x1301 => 16,
            0x1302 | 0x1303 => 32,
            _ => unreachable!(),
        }
    }

    fn tag_len(self) -> usize {
        16
    }
}

#[derive(Clone, Copy)]
enum HashKind {
    Sha256,
    Sha384,
}

impl HashKind {
    fn output_len(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha384 => 48,
        }
    }

    fn empty_hash(self) -> Vec<u8> {
        match self {
            Self::Sha256 => Sha256::digest([]).to_vec(),
            Self::Sha384 => Sha384::digest([]).to_vec(),
        }
    }

    fn zero_secret(self) -> Vec<u8> {
        vec![0u8; self.output_len()]
    }

    fn hkdf_extract(self, salt: Option<&[u8]>, ikm: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha256 => hkdf_extract_sha256(salt, ikm),
            Self::Sha384 => hkdf_extract_sha384(salt, ikm),
        }
    }

    fn hkdf_expand(self, prk: &[u8], info: &[u8], len: usize) -> Result<Vec<u8>> {
        match self {
            Self::Sha256 => hkdf_expand_sha256(prk, info, len),
            Self::Sha384 => hkdf_expand_sha384(prk, info, len),
        }
    }

    fn hmac(self, key: &[u8], data: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha256 => hmac_sha256(key, data),
            Self::Sha384 => hmac_sha384(key, data),
        }
    }
}

#[derive(Clone)]
enum TranscriptHash {
    Sha256(Sha256),
    Sha384(Sha384),
}

impl TranscriptHash {
    fn new(kind: HashKind) -> Self {
        match kind {
            HashKind::Sha256 => Self::Sha256(Sha256::new()),
            HashKind::Sha384 => Self::Sha384(Sha384::new()),
        }
    }

    fn update(&mut self, bytes: &[u8]) {
        match self {
            Self::Sha256(hash) => hash.update(bytes),
            Self::Sha384(hash) => hash.update(bytes),
        }
    }

    fn finish(&self) -> Vec<u8> {
        match self {
            Self::Sha256(hash) => hash.clone().finalize().to_vec(),
            Self::Sha384(hash) => hash.clone().finalize().to_vec(),
        }
    }
}

struct Tls13KeySchedule {
    hash_kind: HashKind,
    current_secret: Vec<u8>,
}

impl Tls13KeySchedule {
    fn new(hash_kind: HashKind) -> Self {
        Self {
            hash_kind,
            current_secret: hash_kind.hkdf_extract(None, &hash_kind.zero_secret()),
        }
    }

    fn input_secret(&mut self, secret: &[u8]) {
        let salt = self
            .derive_secret_for_empty_hash(b"derived")
            .expect("derive REALITY empty hash secret");
        self.current_secret = self.hash_kind.hkdf_extract(Some(&salt), secret);
    }

    fn input_empty(&mut self) {
        let salt = self
            .derive_secret_for_empty_hash(b"derived")
            .expect("derive REALITY empty hash secret");
        self.current_secret = self
            .hash_kind
            .hkdf_extract(Some(&salt), &self.hash_kind.zero_secret());
    }

    fn derive_secret(&self, label: &[u8], transcript_hash: &[u8]) -> Result<Vec<u8>> {
        hkdf_expand_label(
            self.hash_kind,
            &self.current_secret,
            label,
            transcript_hash,
            self.hash_kind.output_len(),
        )
    }

    fn derive_secret_for_empty_hash(&self, label: &[u8]) -> Result<Vec<u8>> {
        self.derive_secret(label, &self.hash_kind.empty_hash())
    }
}

fn hkdf_expand_label(
    hash_kind: HashKind,
    secret: &[u8],
    label: &[u8],
    context: &[u8],
    len: usize,
) -> Result<Vec<u8>> {
    ensure!(len <= u16::MAX as usize, "REALITY HKDF output too large");
    ensure!(
        TLS13_LABEL_PREFIX.len() + label.len() <= u8::MAX as usize,
        "REALITY HKDF label too long"
    );
    ensure!(
        context.len() <= u8::MAX as usize,
        "REALITY HKDF context too long"
    );
    let mut info = Vec::with_capacity(4 + TLS13_LABEL_PREFIX.len() + label.len() + context.len());
    info.extend_from_slice(&(len as u16).to_be_bytes());
    info.push((TLS13_LABEL_PREFIX.len() + label.len()) as u8);
    info.extend_from_slice(TLS13_LABEL_PREFIX);
    info.extend_from_slice(label);
    info.push(context.len() as u8);
    info.extend_from_slice(context);
    hash_kind.hkdf_expand(secret, &info, len)
}

fn hkdf_extract_sha256(salt: Option<&[u8]>, ikm: &[u8]) -> Vec<u8> {
    let zero_salt = [0u8; 32];
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(salt.unwrap_or(&zero_salt))
        .expect("initialize HKDF extract HMAC-SHA256");
    mac.update(ikm);
    mac.finalize().into_bytes().to_vec()
}

fn hkdf_extract_sha384(salt: Option<&[u8]>, ikm: &[u8]) -> Vec<u8> {
    let zero_salt = [0u8; 48];
    let mut mac = <Hmac<Sha384> as Mac>::new_from_slice(salt.unwrap_or(&zero_salt))
        .expect("initialize HKDF extract HMAC-SHA384");
    mac.update(ikm);
    mac.finalize().into_bytes().to_vec()
}

fn hkdf_expand_sha256(prk: &[u8], info: &[u8], len: usize) -> Result<Vec<u8>> {
    let hash_len = 32;
    let blocks = len.div_ceil(hash_len);
    ensure!(blocks <= 255, "REALITY HKDF output exceeds RFC 5869 limit");
    let mut okm = Vec::with_capacity(blocks * hash_len);
    let mut previous = Vec::new();
    for counter in 1..=blocks {
        let mut mac =
            <Hmac<Sha256> as Mac>::new_from_slice(prk).expect("initialize HKDF expand HMAC-SHA256");
        mac.update(&previous);
        mac.update(info);
        mac.update(&[counter as u8]);
        previous = mac.finalize().into_bytes().to_vec();
        okm.extend_from_slice(&previous);
    }
    okm.truncate(len);
    Ok(okm)
}

fn hkdf_expand_sha384(prk: &[u8], info: &[u8], len: usize) -> Result<Vec<u8>> {
    let hash_len = 48;
    let blocks = len.div_ceil(hash_len);
    ensure!(blocks <= 255, "REALITY HKDF output exceeds RFC 5869 limit");
    let mut okm = Vec::with_capacity(blocks * hash_len);
    let mut previous = Vec::new();
    for counter in 1..=blocks {
        let mut mac =
            <Hmac<Sha384> as Mac>::new_from_slice(prk).expect("initialize HKDF expand HMAC-SHA384");
        mac.update(&previous);
        mac.update(info);
        mac.update(&[counter as u8]);
        previous = mac.finalize().into_bytes().to_vec();
        okm.extend_from_slice(&previous);
    }
    okm.truncate(len);
    Ok(okm)
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("initialize HMAC-SHA256");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn hmac_sha384(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = <Hmac<Sha384> as Mac>::new_from_slice(key).expect("initialize HMAC-SHA384");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

#[derive(Clone, Copy)]
struct DerElement {
    tag: u8,
    content_start: usize,
    content_end: usize,
    end: usize,
}

fn read_der_element(bytes: &[u8], offset: usize) -> Result<DerElement> {
    ensure!(offset + 2 <= bytes.len(), "truncated DER element");
    let tag = bytes[offset];
    let first_len = bytes[offset + 1];
    let (len, content_start) = if first_len & 0x80 == 0 {
        (first_len as usize, offset + 2)
    } else {
        let len_len = (first_len & 0x7f) as usize;
        ensure!(len_len > 0, "indefinite DER length is not supported");
        ensure!(len_len <= 4, "DER length field is too large");
        ensure!(offset + 2 + len_len <= bytes.len(), "truncated DER length");
        let mut len = 0usize;
        for &byte in &bytes[offset + 2..offset + 2 + len_len] {
            len = (len << 8) | byte as usize;
        }
        (len, offset + 2 + len_len)
    };
    let content_end = content_start + len;
    ensure!(content_end <= bytes.len(), "truncated DER content");
    Ok(DerElement {
        tag,
        content_start,
        content_end,
        end: content_end,
    })
}

fn read_u16_at(bytes: &[u8], offset: usize, label: &str) -> Result<u16> {
    ensure!(offset + 2 <= bytes.len(), "truncated {label}");
    Ok(u16::from_be_bytes([bytes[offset], bytes[offset + 1]]))
}

fn read_u24_at(bytes: &[u8], offset: usize, label: &str) -> Result<u32> {
    ensure!(offset + 3 <= bytes.len(), "truncated {label}");
    Ok(((bytes[offset] as u32) << 16)
        | ((bytes[offset + 1] as u32) << 8)
        | bytes[offset + 2] as u32)
}

fn encode_u24(value: usize) -> Result<[u8; 3]> {
    ensure!(value <= 0x00ff_ffff, "REALITY u24 value is too large");
    Ok([
        ((value >> 16) & 0xff) as u8,
        ((value >> 8) & 0xff) as u8,
        (value & 0xff) as u8,
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypts_and_decrypts_tls13_application_record() -> Result<()> {
        let suite = CipherSuite::from_id(0x1301)?;
        let secret = vec![0x11; 32];
        let mut writer = RecordCipher::new(suite, &secret)?;
        let mut reader = RecordCipher::new(suite, &secret)?;
        let record = writer.encrypt_record(TLS_CONTENT_TYPE_APPLICATION_DATA, b"hello")?;
        let mut payload = record[TLS_RECORD_HEADER_LEN..].to_vec();
        let content_type = reader.decrypt_record_in_place(record[0], &mut payload)?;
        assert_eq!(content_type, TLS_CONTENT_TYPE_APPLICATION_DATA);
        assert_eq!(payload, b"hello");
        Ok(())
    }

    #[test]
    fn tls13_key_schedule_uses_hash_len_zero_secret_for_empty_input() {
        let schedule = Tls13KeySchedule::new(HashKind::Sha256);
        assert_eq!(
            schedule.current_secret,
            HashKind::Sha256.hkdf_extract(None, &vec![0u8; HashKind::Sha256.output_len()])
        );
        assert_ne!(
            schedule.current_secret,
            HashKind::Sha256.hkdf_extract(None, &[])
        );
    }
}
