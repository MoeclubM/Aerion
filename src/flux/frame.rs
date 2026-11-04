use crate::protocol::{ProxyTarget, decode_target, encode_target};
use anyhow::{Context, Result, bail, ensure};
use bytes::{BufMut, Bytes, BytesMut};
use std::collections::VecDeque;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const FLUX_WIRE_VERSION: u8 = 2;
pub const MAX_FLUX_FRAME_LEN: usize = 128 * 1024;
pub const MAX_FLUX_CHUNK_LEN: usize = 32 * 1024;
pub const DEFAULT_STREAM_WINDOW_BYTES: usize = 256 * 1024;

const FRAME_SESSION_HELLO: u8 = 0x01;
const FRAME_SESSION_OK: u8 = 0x02;
const FRAME_PING: u8 = 0x03;
const FRAME_PONG: u8 = 0x04;
const FRAME_STREAM_OPEN: u8 = 0x10;
const FRAME_STREAM_DATA: u8 = 0x11;
const FRAME_STREAM_ACK: u8 = 0x12;
const FRAME_STREAM_MIGRATE: u8 = 0x13;
const FRAME_STREAM_FIN: u8 = 0x14;
const FRAME_STREAM_RST: u8 = 0x15;
const FRAME_UDP_DATAGRAM: u8 = 0x20;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FluxFrame {
    SessionHello {
        session_id: [u8; 16],
        client_ephemeral_pub: [u8; 32],
        timestamp_secs: u64,
        channel_id: String,
        blinded_credential: [u8; 32],
        client_proof: [u8; 32],
    },
    SessionOk {
        status: u8,
        server_proof: [u8; 32],
        udp_enabled: bool,
    },
    Ping {
        seq: u64,
        sent_micros: u64,
        padding: Bytes,
    },
    Pong {
        seq: u64,
        echo_micros: u64,
        padding: Bytes,
    },
    StreamOpen {
        stream_id: u32,
        epoch: u32,
        target: ProxyTarget,
        initial_payload: Bytes,
    },
    StreamData {
        stream_id: u32,
        epoch: u32,
        offset: u64,
        payload: Bytes,
    },
    StreamAck {
        stream_id: u32,
        ack_offset: u64,
    },
    StreamMigrate {
        stream_id: u32,
        epoch: u32,
        resume_offset: u64,
        target: ProxyTarget,
    },
    StreamFin {
        stream_id: u32,
        epoch: u32,
        final_offset: u64,
    },
    StreamRst {
        stream_id: u32,
        code: u8,
    },
    UdpDatagram {
        assoc_id: u32,
        packet_id: u32,
        frag_index: u8,
        frag_total: u8,
        target: ProxyTarget,
        payload: Bytes,
    },
}

pub fn encode_frame_body(frame: &FluxFrame) -> Result<Bytes> {
    let mut buf = BytesMut::with_capacity(128);
    match frame {
        FluxFrame::SessionHello {
            session_id,
            client_ephemeral_pub,
            timestamp_secs,
            channel_id,
            blinded_credential,
            client_proof,
        } => {
            let id_bytes = channel_id.as_bytes();
            ensure!(
                id_bytes.len() <= u8::MAX as usize,
                "Flux channel_id too long"
            );
            buf.put_u8(FRAME_SESSION_HELLO);
            buf.put_u8(FLUX_WIRE_VERSION);
            buf.put_slice(session_id);
            buf.put_slice(client_ephemeral_pub);
            buf.put_u64(*timestamp_secs);
            buf.put_u8(id_bytes.len() as u8);
            buf.put_slice(id_bytes);
            buf.put_slice(blinded_credential);
            buf.put_slice(client_proof);
        }
        FluxFrame::SessionOk {
            status,
            server_proof,
            udp_enabled,
        } => {
            buf.put_u8(FRAME_SESSION_OK);
            buf.put_u8(*status);
            buf.put_slice(server_proof);
            buf.put_u8(u8::from(*udp_enabled));
        }
        FluxFrame::Ping {
            seq,
            sent_micros,
            padding,
        } => {
            ensure!(padding.len() <= 4096, "Flux ping padding too large");
            buf.put_u8(FRAME_PING);
            buf.put_u64(*seq);
            buf.put_u64(*sent_micros);
            buf.put_u16(padding.len() as u16);
            buf.put_slice(padding);
        }
        FluxFrame::Pong {
            seq,
            echo_micros,
            padding,
        } => {
            ensure!(padding.len() <= 4096, "Flux pong padding too large");
            buf.put_u8(FRAME_PONG);
            buf.put_u64(*seq);
            buf.put_u64(*echo_micros);
            buf.put_u16(padding.len() as u16);
            buf.put_slice(padding);
        }
        FluxFrame::StreamOpen {
            stream_id,
            epoch,
            target,
            initial_payload,
        } => {
            ensure!(
                initial_payload.len() <= u16::MAX as usize,
                "Flux initial payload too large"
            );
            let target_bytes = encode_target(target)?;
            buf.put_u8(FRAME_STREAM_OPEN);
            buf.put_u32(*stream_id);
            buf.put_u32(*epoch);
            buf.put_slice(&target_bytes);
            buf.put_u16(initial_payload.len() as u16);
            buf.put_slice(initial_payload);
        }
        FluxFrame::StreamData {
            stream_id,
            epoch,
            offset,
            payload,
        } => {
            ensure!(
                payload.len() <= u16::MAX as usize,
                "Flux stream data chunk too large"
            );
            buf.put_u8(FRAME_STREAM_DATA);
            buf.put_u32(*stream_id);
            buf.put_u32(*epoch);
            buf.put_u64(*offset);
            buf.put_u16(payload.len() as u16);
            buf.put_slice(payload);
        }
        FluxFrame::StreamAck {
            stream_id,
            ack_offset,
        } => {
            buf.put_u8(FRAME_STREAM_ACK);
            buf.put_u32(*stream_id);
            buf.put_u64(*ack_offset);
        }
        FluxFrame::StreamMigrate {
            stream_id,
            epoch,
            resume_offset,
            target,
        } => {
            let target_bytes = encode_target(target)?;
            buf.put_u8(FRAME_STREAM_MIGRATE);
            buf.put_u32(*stream_id);
            buf.put_u32(*epoch);
            buf.put_u64(*resume_offset);
            buf.put_slice(&target_bytes);
        }
        FluxFrame::StreamFin {
            stream_id,
            epoch,
            final_offset,
        } => {
            buf.put_u8(FRAME_STREAM_FIN);
            buf.put_u32(*stream_id);
            buf.put_u32(*epoch);
            buf.put_u64(*final_offset);
        }
        FluxFrame::StreamRst { stream_id, code } => {
            buf.put_u8(FRAME_STREAM_RST);
            buf.put_u32(*stream_id);
            buf.put_u8(*code);
        }
        FluxFrame::UdpDatagram {
            assoc_id,
            packet_id,
            frag_index,
            frag_total,
            target,
            payload,
        } => {
            ensure!(
                payload.len() <= u16::MAX as usize,
                "Flux UDP datagram fragment too large"
            );
            let target_bytes = encode_target(target)?;
            buf.put_u8(FRAME_UDP_DATAGRAM);
            buf.put_u32(*assoc_id);
            buf.put_u32(*packet_id);
            buf.put_u8(*frag_index);
            buf.put_u8(*frag_total);
            buf.put_slice(&target_bytes);
            buf.put_u16(payload.len() as u16);
            buf.put_slice(payload);
        }
    }
    ensure!(buf.len() <= MAX_FLUX_FRAME_LEN, "Flux frame exceeds limit");
    Ok(buf.freeze())
}

pub fn decode_frame_body(body: &[u8]) -> Result<FluxFrame> {
    ensure!(!body.is_empty(), "empty Flux frame");
    let kind = body[0];
    let rest = &body[1..];
    match kind {
        FRAME_SESSION_HELLO => {
            ensure!(
                rest.len() >= 1 + 16 + 32 + 8 + 1 + 32,
                "short Flux SessionHello"
            );
            ensure!(
                rest[0] == FLUX_WIRE_VERSION,
                "unsupported Flux wire version {}",
                rest[0]
            );
            let mut session_id = [0u8; 16];
            session_id.copy_from_slice(&rest[1..17]);
            let mut client_ephemeral_pub = [0u8; 32];
            client_ephemeral_pub.copy_from_slice(&rest[17..49]);
            let timestamp_secs = u64::from_be_bytes(rest[49..57].try_into().unwrap());
            let id_len = usize::from(rest[57]);
            ensure!(
                rest.len() == 58 + id_len + 64,
                "invalid Flux SessionHello length"
            );
            let channel_id = std::str::from_utf8(&rest[58..58 + id_len])
                .context("decode Flux channel_id")?
                .to_string();
            let mut blinded_credential = [0u8; 32];
            blinded_credential.copy_from_slice(&rest[58 + id_len..90 + id_len]);
            let mut client_proof = [0u8; 32];
            client_proof.copy_from_slice(&rest[90 + id_len..]);
            Ok(FluxFrame::SessionHello {
                session_id,
                client_ephemeral_pub,
                timestamp_secs,
                channel_id,
                blinded_credential,
                client_proof,
            })
        }
        FRAME_SESSION_OK => {
            ensure!(rest.len() == 34, "invalid Flux SessionOk length");
            let status = rest[0];
            let mut server_proof = [0u8; 32];
            server_proof.copy_from_slice(&rest[1..33]);
            let udp_enabled = rest[33] != 0;
            Ok(FluxFrame::SessionOk {
                status,
                server_proof,
                udp_enabled,
            })
        }
        FRAME_PING | FRAME_PONG => {
            ensure!(rest.len() >= 18, "short Flux Ping/Pong");
            let seq = u64::from_be_bytes(rest[..8].try_into().unwrap());
            let ts = u64::from_be_bytes(rest[8..16].try_into().unwrap());
            let pad_len = usize::from(u16::from_be_bytes([rest[16], rest[17]]));
            ensure!(rest.len() == 18 + pad_len, "invalid Flux Ping/Pong padding");
            let padding = Bytes::copy_from_slice(&rest[18..]);
            if kind == FRAME_PING {
                Ok(FluxFrame::Ping {
                    seq,
                    sent_micros: ts,
                    padding,
                })
            } else {
                Ok(FluxFrame::Pong {
                    seq,
                    echo_micros: ts,
                    padding,
                })
            }
        }
        FRAME_STREAM_OPEN => {
            ensure!(rest.len() >= 10, "short Flux StreamOpen");
            let stream_id = u32::from_be_bytes(rest[..4].try_into().unwrap());
            let epoch = u32::from_be_bytes(rest[4..8].try_into().unwrap());
            let (target, tail) = decode_target(&rest[8..])?;
            ensure!(tail.len() >= 2, "short Flux StreamOpen initial length");
            let init_len = usize::from(u16::from_be_bytes([tail[0], tail[1]]));
            ensure!(
                tail.len() == 2 + init_len,
                "invalid Flux StreamOpen payload"
            );
            Ok(FluxFrame::StreamOpen {
                stream_id,
                epoch,
                target,
                initial_payload: Bytes::copy_from_slice(&tail[2..]),
            })
        }
        FRAME_STREAM_DATA => {
            ensure!(rest.len() >= 18, "short Flux StreamData");
            let stream_id = u32::from_be_bytes(rest[..4].try_into().unwrap());
            let epoch = u32::from_be_bytes(rest[4..8].try_into().unwrap());
            let offset = u64::from_be_bytes(rest[8..16].try_into().unwrap());
            let len = usize::from(u16::from_be_bytes([rest[16], rest[17]]));
            ensure!(rest.len() == 18 + len, "invalid Flux StreamData length");
            Ok(FluxFrame::StreamData {
                stream_id,
                epoch,
                offset,
                payload: Bytes::copy_from_slice(&rest[18..]),
            })
        }
        FRAME_STREAM_ACK => {
            ensure!(rest.len() == 12, "invalid Flux StreamAck length");
            Ok(FluxFrame::StreamAck {
                stream_id: u32::from_be_bytes(rest[..4].try_into().unwrap()),
                ack_offset: u64::from_be_bytes(rest[4..12].try_into().unwrap()),
            })
        }
        FRAME_STREAM_MIGRATE => {
            ensure!(rest.len() > 16, "short Flux StreamMigrate");
            let stream_id = u32::from_be_bytes(rest[..4].try_into().unwrap());
            let epoch = u32::from_be_bytes(rest[4..8].try_into().unwrap());
            let resume_offset = u64::from_be_bytes(rest[8..16].try_into().unwrap());
            let (target, tail) = decode_target(&rest[16..])?;
            ensure!(tail.is_empty(), "trailing bytes in Flux StreamMigrate");
            Ok(FluxFrame::StreamMigrate {
                stream_id,
                epoch,
                resume_offset,
                target,
            })
        }
        FRAME_STREAM_FIN => {
            ensure!(rest.len() == 16, "invalid Flux StreamFin length");
            Ok(FluxFrame::StreamFin {
                stream_id: u32::from_be_bytes(rest[..4].try_into().unwrap()),
                epoch: u32::from_be_bytes(rest[4..8].try_into().unwrap()),
                final_offset: u64::from_be_bytes(rest[8..16].try_into().unwrap()),
            })
        }
        FRAME_STREAM_RST => {
            ensure!(rest.len() == 5, "invalid Flux StreamRst length");
            Ok(FluxFrame::StreamRst {
                stream_id: u32::from_be_bytes(rest[..4].try_into().unwrap()),
                code: rest[4],
            })
        }
        FRAME_UDP_DATAGRAM => {
            ensure!(rest.len() >= 12, "short Flux UdpDatagram");
            let assoc_id = u32::from_be_bytes(rest[..4].try_into().unwrap());
            let packet_id = u32::from_be_bytes(rest[4..8].try_into().unwrap());
            let frag_index = rest[8];
            let frag_total = rest[9];
            let (target, tail) = decode_target(&rest[10..])?;
            ensure!(tail.len() >= 2, "short Flux UdpDatagram length");
            let len = usize::from(u16::from_be_bytes([tail[0], tail[1]]));
            ensure!(tail.len() == 2 + len, "invalid Flux UdpDatagram payload");
            Ok(FluxFrame::UdpDatagram {
                assoc_id,
                packet_id,
                frag_index,
                frag_total,
                target,
                payload: Bytes::copy_from_slice(&tail[2..]),
            })
        }
        other => bail!("unknown Flux frame type {other:#x}"),
    }
}

pub async fn write_length_prefixed_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    frame: &FluxFrame,
) -> Result<()> {
    let body = encode_frame_body(frame)?;
    let len = body.len() as u32;
    writer
        .write_all(&len.to_be_bytes())
        .await
        .context("write Flux frame length")?;
    writer
        .write_all(&body)
        .await
        .context("write Flux frame body")?;
    Ok(())
}

pub async fn read_length_prefixed_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<Option<FluxFrame>> {
    let mut len_buf = [0u8; 4];
    match reader.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(err) => return Err(err).context("read Flux frame length"),
    }
    let len = u32::from_be_bytes(len_buf) as usize;
    ensure!(
        (1..=MAX_FLUX_FRAME_LEN).contains(&len),
        "invalid Flux frame length {len}"
    );
    let mut body = vec![0u8; len];
    reader
        .read_exact(&mut body)
        .await
        .context("read Flux frame body")?;
    Ok(Some(decode_frame_body(&body)?))
}

#[derive(Debug)]
pub struct SendWindowBuffer {
    acked_offset: u64,
    next_offset: u64,
    buffered_bytes: usize,
    max_bytes: usize,
    chunks: VecDeque<(u64, Bytes)>,
}

impl SendWindowBuffer {
    pub fn new(max_bytes: usize) -> Self {
        Self {
            acked_offset: 0,
            next_offset: 0,
            buffered_bytes: 0,
            max_bytes,
            chunks: VecDeque::new(),
        }
    }

    pub fn available_window(&self) -> usize {
        self.max_bytes.saturating_sub(self.buffered_bytes)
    }

    pub fn next_offset(&self) -> u64 {
        self.next_offset
    }

    pub fn acked_offset(&self) -> u64 {
        self.acked_offset
    }

    pub fn has_unacked(&self) -> bool {
        self.buffered_bytes > 0
    }

    pub fn push(&mut self, data: Bytes) -> u64 {
        let offset = self.next_offset;
        if !data.is_empty() {
            self.next_offset += data.len() as u64;
            self.buffered_bytes += data.len();
            self.chunks.push_back((offset, data));
        }
        offset
    }

    pub fn ack(&mut self, ack_offset: u64) -> usize {
        if ack_offset <= self.acked_offset {
            return 0;
        }
        if self.buffered_bytes >= self.max_bytes / 2 {
            self.max_bytes = self.max_bytes.saturating_mul(2).min(8 * 1024 * 1024);
        }
        let target = ack_offset.min(self.next_offset);
        let mut freed = 0usize;
        while let Some((chunk_offset, chunk)) = self.chunks.front() {
            let end = *chunk_offset + chunk.len() as u64;
            if end <= target {
                freed += chunk.len();
                self.buffered_bytes -= chunk.len();
                self.chunks.pop_front();
            } else if *chunk_offset < target {
                let trim = (target - *chunk_offset) as usize;
                let (_, old) = self.chunks.pop_front().unwrap();
                freed += trim;
                self.buffered_bytes -= trim;
                self.chunks.push_front((target, old.slice(trim..)));
                break;
            } else {
                break;
            }
        }
        self.acked_offset = target;
        freed
    }

    pub fn unacked_from(&self, resume_offset: u64) -> Vec<(u64, Bytes)> {
        let mut out = Vec::new();
        for (offset, chunk) in &self.chunks {
            let end = *offset + chunk.len() as u64;
            if end <= resume_offset {
                continue;
            }
            if *offset < resume_offset {
                let skip = (resume_offset - *offset) as usize;
                out.push((resume_offset, chunk.slice(skip..)));
            } else {
                out.push((*offset, chunk.clone()));
            }
        }
        out
    }
}

#[derive(Debug, Default)]
pub struct RecvOffsetAssembler {
    active_epoch: u32,
    next_offset: u64,
    fin_offset: Option<u64>,
}

impl RecvOffsetAssembler {
    pub fn next_offset(&self) -> u64 {
        self.next_offset
    }

    pub fn active_epoch(&self) -> u32 {
        self.active_epoch
    }

    pub fn accept_migrate(&mut self, epoch: u32) -> bool {
        if epoch < self.active_epoch {
            return false;
        }
        self.active_epoch = epoch;
        true
    }

    pub fn accept_data(
        &mut self,
        epoch: u32,
        offset: u64,
        payload: Bytes,
    ) -> Result<Option<Bytes>> {
        if epoch < self.active_epoch {
            return Ok(None);
        }
        self.active_epoch = epoch;
        if payload.is_empty() {
            return Ok(None);
        }
        let end = offset
            .checked_add(payload.len() as u64)
            .context("Flux stream offset overflow")?;
        if end <= self.next_offset {
            return Ok(None);
        }
        ensure!(
            offset <= self.next_offset,
            "Flux stream gap: expected offset {}, got {offset}",
            self.next_offset
        );
        let skip = (self.next_offset - offset) as usize;
        let fresh = payload.slice(skip..);
        self.next_offset += fresh.len() as u64;
        Ok(Some(fresh))
    }

    pub fn accept_fin(&mut self, epoch: u32, final_offset: u64) -> bool {
        if epoch < self.active_epoch {
            return false;
        }
        self.active_epoch = epoch;
        self.fin_offset = Some(final_offset);
        self.is_complete()
    }

    pub fn is_complete(&self) -> bool {
        self.fin_offset
            .is_some_and(|fin_offset| self.next_offset >= fin_offset)
    }
}
