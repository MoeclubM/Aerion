use super::crypto::{MieruCipher, check_user_from_hint, mieru_keys_for_password};
use super::pattern::{MieruTrafficPattern, random_padding};
use super::{MieruUserSecret, NONCE_LEN};
use anyhow::{Context, Result, bail, ensure};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncReadExt};

const METADATA_LEN: usize = 32;
const AEAD_OVERHEAD: usize = 16;
const PACKET_METADATA_LEN: usize = NONCE_LEN + METADATA_LEN + AEAD_OVERHEAD;

pub(super) const MAX_PDU: usize = 32 * 1024;
pub(super) const MAX_SESSION_OPEN_PAYLOAD: usize = 1024;
pub(super) const PACKET_OVERHEAD: usize = PACKET_METADATA_LEN + AEAD_OVERHEAD;
pub(super) const ACK_WINDOW_SIZE: u16 = 4096;
pub(super) const PACKET_RETRANSMIT_INTERVAL_MS: u64 = 250;

pub(super) const CLOSE_CONN_REQUEST: u8 = 0;
pub(super) const CLOSE_CONN_RESPONSE: u8 = 1;
pub(super) const OPEN_SESSION_REQUEST: u8 = 2;
pub(super) const OPEN_SESSION_RESPONSE: u8 = 3;
pub(super) const CLOSE_SESSION_REQUEST: u8 = 4;
pub(super) const CLOSE_SESSION_RESPONSE: u8 = 5;
pub(super) const DATA_CLIENT_TO_SERVER: u8 = 6;
pub(super) const DATA_SERVER_TO_CLIENT: u8 = 7;
pub(super) const ACK_CLIENT_TO_SERVER: u8 = 8;
pub(super) const ACK_SERVER_TO_CLIENT: u8 = 9;
pub(super) const STATUS_OK: u8 = 0;

#[derive(Clone, Debug)]
pub(super) struct MieruSegment {
    pub(super) metadata: MieruMetadata,
    pub(super) payload: Vec<u8>,
}

#[derive(Clone, Debug)]
pub(super) enum MieruMetadata {
    Session(MieruSessionMetadata),
    DataAck(MieruDataAckMetadata),
}

#[derive(Clone, Debug)]
pub(super) struct MieruSessionMetadata {
    pub(super) protocol: u8,
    pub(super) session_id: u32,
    pub(super) seq: u32,
    pub(super) status_code: u8,
    pub(super) payload_len: u16,
    pub(super) suffix_len: u8,
}

#[derive(Clone, Debug)]
pub(super) struct MieruDataAckMetadata {
    pub(super) protocol: u8,
    pub(super) session_id: u32,
    pub(super) seq: u32,
    pub(super) un_ack_seq: u32,
    pub(super) window_size: u16,
    pub(super) fragment: u8,
    pub(super) prefix_len: u8,
    pub(super) payload_len: u16,
    pub(super) suffix_len: u8,
}

impl MieruMetadata {
    pub(super) fn protocol(&self) -> u8 {
        match self {
            Self::Session(metadata) => metadata.protocol,
            Self::DataAck(metadata) => metadata.protocol,
        }
    }

    pub(super) fn session_id(&self) -> u32 {
        match self {
            Self::Session(metadata) => metadata.session_id,
            Self::DataAck(metadata) => metadata.session_id,
        }
    }

    pub(super) fn seq(&self) -> u32 {
        match self {
            Self::Session(metadata) => metadata.seq,
            Self::DataAck(metadata) => metadata.seq,
        }
    }

    pub(super) fn un_ack_seq(&self) -> Option<u32> {
        match self {
            Self::DataAck(metadata) => Some(metadata.un_ack_seq),
            Self::Session(_) => None,
        }
    }

    pub(super) fn marshal(&self) -> Result<[u8; METADATA_LEN]> {
        let mut bytes = [0u8; METADATA_LEN];
        let timestamp = unix_minutes()?;
        match self {
            Self::Session(metadata) => {
                bytes[0] = metadata.protocol;
                bytes[2..6].copy_from_slice(&timestamp.to_be_bytes());
                bytes[6..10].copy_from_slice(&metadata.session_id.to_be_bytes());
                bytes[10..14].copy_from_slice(&metadata.seq.to_be_bytes());
                bytes[14] = metadata.status_code;
                bytes[15..17].copy_from_slice(&metadata.payload_len.to_be_bytes());
                bytes[17] = metadata.suffix_len;
            }
            Self::DataAck(metadata) => {
                bytes[0] = metadata.protocol;
                bytes[2..6].copy_from_slice(&timestamp.to_be_bytes());
                bytes[6..10].copy_from_slice(&metadata.session_id.to_be_bytes());
                bytes[10..14].copy_from_slice(&metadata.seq.to_be_bytes());
                bytes[14..18].copy_from_slice(&metadata.un_ack_seq.to_be_bytes());
                bytes[18..20].copy_from_slice(&metadata.window_size.to_be_bytes());
                bytes[20] = metadata.fragment;
                bytes[21] = metadata.prefix_len;
                bytes[22..24].copy_from_slice(&metadata.payload_len.to_be_bytes());
                bytes[24] = metadata.suffix_len;
            }
        }
        Ok(bytes)
    }

    pub(super) fn parse(bytes: &[u8]) -> Result<Self> {
        ensure!(bytes.len() == METADATA_LEN, "invalid Mieru metadata length");
        let timestamp = u32::from_be_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]);
        let now = unix_minutes()?;
        ensure!(
            now.abs_diff(timestamp) <= 1,
            "Mieru metadata timestamp is outside accepted window"
        );
        match bytes[0] {
            OPEN_SESSION_REQUEST
            | OPEN_SESSION_RESPONSE
            | CLOSE_SESSION_REQUEST
            | CLOSE_SESSION_RESPONSE
            | CLOSE_CONN_REQUEST
            | CLOSE_CONN_RESPONSE => {
                let payload_len = u16::from_be_bytes([bytes[15], bytes[16]]);
                ensure!(
                    payload_len as usize <= MAX_SESSION_OPEN_PAYLOAD
                        || bytes[0] != OPEN_SESSION_REQUEST,
                    "Mieru open-session payload is too large"
                );
                Ok(Self::Session(MieruSessionMetadata {
                    protocol: bytes[0],
                    session_id: u32::from_be_bytes([bytes[6], bytes[7], bytes[8], bytes[9]]),
                    seq: u32::from_be_bytes([bytes[10], bytes[11], bytes[12], bytes[13]]),
                    status_code: bytes[14],
                    payload_len,
                    suffix_len: bytes[17],
                }))
            }
            DATA_CLIENT_TO_SERVER
            | DATA_SERVER_TO_CLIENT
            | ACK_CLIENT_TO_SERVER
            | ACK_SERVER_TO_CLIENT => Ok(Self::DataAck(MieruDataAckMetadata {
                protocol: bytes[0],
                session_id: u32::from_be_bytes([bytes[6], bytes[7], bytes[8], bytes[9]]),
                seq: u32::from_be_bytes([bytes[10], bytes[11], bytes[12], bytes[13]]),
                un_ack_seq: u32::from_be_bytes([bytes[14], bytes[15], bytes[16], bytes[17]]),
                window_size: u16::from_be_bytes([bytes[18], bytes[19]]),
                fragment: bytes[20],
                prefix_len: bytes[21],
                payload_len: u16::from_be_bytes([bytes[22], bytes[23]]),
                suffix_len: bytes[24],
            })),
            other => bail!("unsupported Mieru metadata protocol {other}"),
        }
    }
}

pub(super) async fn read_first_server_segment<R>(
    reader: &mut R,
    users: &[MieruUserSecret],
    user_hint_mandatory: bool,
    traffic_pattern: Option<&MieruTrafficPattern>,
) -> Result<(MieruCipher, MieruUserSecret, MieruSegment)>
where
    R: AsyncRead + Unpin,
{
    let mut encrypted_metadata = vec![0u8; NONCE_LEN + METADATA_LEN + AEAD_OVERHEAD];
    reader
        .read_exact(&mut encrypted_metadata)
        .await
        .context("read first Mieru metadata")?;
    let nonce = &encrypted_metadata[..NONCE_LEN];
    let mut candidates = Vec::new();
    for user in users {
        if check_user_from_hint(user.username.as_bytes(), nonce) {
            candidates.push(user.clone());
        }
    }
    if candidates.is_empty() && user_hint_mandatory {
        bail!("Mieru user hint did not match any configured user");
    }
    if !user_hint_mandatory {
        for user in users {
            if !candidates
                .iter()
                .any(|candidate| candidate.username == user.username)
            {
                candidates.push(user.clone());
            }
        }
    }
    for user in candidates {
        for key in mieru_keys_for_password(&user.hashed_password)? {
            let mut stateless =
                MieruCipher::new(key, false, user.username.clone(), traffic_pattern);
            if stateless.decrypt(&encrypted_metadata).is_err() {
                continue;
            }
            let mut stateful = MieruCipher::new(key, true, user.username.clone(), traffic_pattern);
            let plain = stateful.decrypt(&encrypted_metadata)?;
            let metadata = MieruMetadata::parse(&plain)?;
            let payload = read_mieru_payload(reader, &metadata, &mut stateful).await?;
            return Ok((stateful, user, MieruSegment { metadata, payload }));
        }
    }
    bail!("Mieru authentication failed")
}

pub(super) async fn read_mieru_segment<R>(
    reader: &mut R,
    cipher: &mut MieruCipher,
    first_read: bool,
) -> Result<MieruSegment>
where
    R: AsyncRead + Unpin,
{
    let read_len = METADATA_LEN + AEAD_OVERHEAD + if first_read { NONCE_LEN } else { 0 };
    let mut encrypted_metadata = vec![0u8; read_len];
    reader
        .read_exact(&mut encrypted_metadata)
        .await
        .context("read Mieru encrypted metadata")?;
    let plain = cipher.decrypt(&encrypted_metadata)?;
    let metadata = MieruMetadata::parse(&plain)?;
    let payload = read_mieru_payload(reader, &metadata, cipher).await?;
    Ok(MieruSegment { metadata, payload })
}

async fn read_mieru_payload<R>(
    reader: &mut R,
    metadata: &MieruMetadata,
    cipher: &mut MieruCipher,
) -> Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    match metadata {
        MieruMetadata::Session(metadata) => {
            let mut payload = Vec::new();
            if metadata.payload_len > 0 {
                let mut encrypted_payload =
                    vec![0u8; metadata.payload_len as usize + AEAD_OVERHEAD];
                reader
                    .read_exact(&mut encrypted_payload)
                    .await
                    .context("read Mieru session payload")?;
                payload = cipher.decrypt(&encrypted_payload)?;
            }
            if metadata.suffix_len > 0 {
                let mut padding = vec![0u8; metadata.suffix_len as usize];
                reader
                    .read_exact(&mut padding)
                    .await
                    .context("read Mieru session suffix padding")?;
            }
            Ok(payload)
        }
        MieruMetadata::DataAck(metadata) => {
            if metadata.prefix_len > 0 {
                let mut padding = vec![0u8; metadata.prefix_len as usize];
                reader
                    .read_exact(&mut padding)
                    .await
                    .context("read Mieru data prefix padding")?;
            }
            let mut payload = Vec::new();
            if metadata.payload_len > 0 {
                let mut encrypted_payload =
                    vec![0u8; metadata.payload_len as usize + AEAD_OVERHEAD];
                reader
                    .read_exact(&mut encrypted_payload)
                    .await
                    .context("read Mieru data payload")?;
                payload = cipher.decrypt(&encrypted_payload)?;
            }
            if metadata.suffix_len > 0 {
                let mut padding = vec![0u8; metadata.suffix_len as usize];
                reader
                    .read_exact(&mut padding)
                    .await
                    .context("read Mieru data suffix padding")?;
            }
            Ok(payload)
        }
    }
}

pub(super) fn encode_mieru_packet_segment(
    cipher: &mut MieruCipher,
    mut segment: MieruSegment,
    mtu: usize,
    traffic_pattern: Option<&MieruTrafficPattern>,
) -> Result<Vec<u8>> {
    let payload_wire_len = if segment.payload.is_empty() {
        0
    } else {
        segment.payload.len() + AEAD_OVERHEAD
    };
    ensure!(
        PACKET_METADATA_LEN + payload_wire_len <= mtu,
        "Mieru UDP packet payload exceeds MTU {mtu}"
    );
    let padding = traffic_pattern.and_then(|pattern| pattern.padding.as_ref());
    let max_middle_padding_len = padding
        .and_then(|padding| padding.max_middle_padding_len)
        .unwrap_or(255)
        .clamp(0, 255) as usize;
    let max_end_padding_len = padding
        .and_then(|padding| padding.max_end_padding_len)
        .unwrap_or(255)
        .clamp(0, 255) as usize;
    let available_padding = mtu - PACKET_METADATA_LEN - payload_wire_len;
    let prefix_padding;
    let suffix_padding;
    match &mut segment.metadata {
        MieruMetadata::Session(metadata) => {
            ensure!(
                segment.payload.len() <= u16::MAX as usize,
                "Mieru session payload is too large"
            );
            prefix_padding = Vec::new();
            suffix_padding = random_padding(max_end_padding_len.min(available_padding))?;
            metadata.payload_len = segment.payload.len() as u16;
            metadata.suffix_len = suffix_padding.len() as u8;
        }
        MieruMetadata::DataAck(metadata) => {
            ensure!(
                segment.payload.len() <= u16::MAX as usize,
                "Mieru data payload is too large"
            );
            prefix_padding = random_padding(max_middle_padding_len.min(available_padding))?;
            suffix_padding =
                random_padding(max_end_padding_len.min(available_padding - prefix_padding.len()))?;
            metadata.payload_len = segment.payload.len() as u16;
            metadata.prefix_len = prefix_padding.len() as u8;
            metadata.suffix_len = suffix_padding.len() as u8;
        }
    }
    let encrypted_metadata = cipher.encrypt(&segment.metadata.marshal()?)?;
    ensure!(
        encrypted_metadata.len() == PACKET_METADATA_LEN,
        "invalid Mieru encrypted packet metadata length"
    );
    let nonce = encrypted_metadata[..NONCE_LEN].to_vec();
    let mut packet = encrypted_metadata;
    packet.extend_from_slice(&prefix_padding);
    if !segment.payload.is_empty() {
        let encrypted_payload = cipher.encrypt_with_nonce(&segment.payload, &nonce)?;
        packet.extend_from_slice(&encrypted_payload);
    }
    packet.extend_from_slice(&suffix_padding);
    ensure!(
        packet.len() <= mtu,
        "Mieru UDP packet length {} exceeds MTU {}",
        packet.len(),
        mtu
    );
    Ok(packet)
}

pub(super) fn decode_mieru_packet_segment(
    cipher: &mut MieruCipher,
    packet: &[u8],
) -> Result<MieruSegment> {
    ensure!(
        packet.len() >= PACKET_METADATA_LEN,
        "Mieru UDP packet is shorter than encrypted metadata"
    );
    let encrypted_metadata = &packet[..PACKET_METADATA_LEN];
    let nonce = &encrypted_metadata[..NONCE_LEN];
    let plain = cipher.decrypt(encrypted_metadata)?;
    let metadata = MieruMetadata::parse(&plain)?;
    let payload =
        decode_mieru_packet_payload(cipher, &metadata, nonce, &packet[PACKET_METADATA_LEN..])?;
    Ok(MieruSegment { metadata, payload })
}

pub(super) fn decode_mieru_packet_segment_for_server(
    packet: &[u8],
    users: &[MieruUserSecret],
    user_hint_mandatory: bool,
    traffic_pattern: Option<&MieruTrafficPattern>,
) -> Result<(MieruSegment, MieruUserSecret, MieruCipher)> {
    ensure!(
        packet.len() >= PACKET_METADATA_LEN,
        "Mieru UDP packet is shorter than encrypted metadata"
    );
    let nonce = &packet[..NONCE_LEN];
    let mut candidates = Vec::new();
    for user in users {
        if check_user_from_hint(user.username.as_bytes(), nonce) {
            candidates.push(user.clone());
        }
    }
    if candidates.is_empty() && user_hint_mandatory {
        bail!("Mieru UDP user hint did not match any configured user");
    }
    if !user_hint_mandatory {
        for user in users {
            if !candidates
                .iter()
                .any(|candidate| candidate.username == user.username)
            {
                candidates.push(user.clone());
            }
        }
    }
    for user in candidates {
        for key in mieru_keys_for_password(&user.hashed_password)? {
            let mut cipher = MieruCipher::new(key, false, user.username.clone(), traffic_pattern);
            if let Ok(segment) = decode_mieru_packet_segment(&mut cipher, packet) {
                return Ok((segment, user, cipher));
            }
        }
    }
    bail!("Mieru UDP authentication failed")
}

fn decode_mieru_packet_payload(
    cipher: &MieruCipher,
    metadata: &MieruMetadata,
    nonce: &[u8],
    mut remaining: &[u8],
) -> Result<Vec<u8>> {
    match metadata {
        MieruMetadata::Session(metadata) => {
            let mut payload = Vec::new();
            if metadata.payload_len > 0 {
                let encrypted_len = metadata.payload_len as usize + AEAD_OVERHEAD;
                ensure!(
                    remaining.len() >= encrypted_len,
                    "Mieru UDP session payload is incomplete"
                );
                payload = cipher.decrypt_with_nonce(&remaining[..encrypted_len], nonce)?;
                remaining = &remaining[encrypted_len..];
            }
            ensure!(
                remaining.len() == metadata.suffix_len as usize,
                "Mieru UDP session padding size mismatch"
            );
            Ok(payload)
        }
        MieruMetadata::DataAck(metadata) => {
            ensure!(
                remaining.len() >= metadata.prefix_len as usize,
                "Mieru UDP data prefix padding is incomplete"
            );
            remaining = &remaining[metadata.prefix_len as usize..];
            let mut payload = Vec::new();
            if metadata.payload_len > 0 {
                let encrypted_len = metadata.payload_len as usize + AEAD_OVERHEAD;
                ensure!(
                    remaining.len() >= encrypted_len,
                    "Mieru UDP data payload is incomplete"
                );
                payload = cipher.decrypt_with_nonce(&remaining[..encrypted_len], nonce)?;
                remaining = &remaining[encrypted_len..];
            }
            ensure!(
                remaining.len() == metadata.suffix_len as usize,
                "Mieru UDP data padding size mismatch"
            );
            Ok(payload)
        }
    }
}

fn unix_minutes() -> Result<u32> {
    Ok((SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() / 60) as u32)
}
