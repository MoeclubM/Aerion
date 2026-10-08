use std::io::{Error, ErrorKind, Result};
use std::pin::Pin;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, ReadBuf};

pub(crate) mod tls;

#[derive(Default)]
pub(crate) struct VisionControl {
    read_direct: AtomicBool,
    write_direct: AtomicBool,
    filter: Mutex<TlsFilter>,
}

impl VisionControl {
    pub(crate) fn read_direct(&self) -> bool {
        self.read_direct.load(Ordering::Acquire)
    }
    pub(crate) fn write_direct(&self) -> bool {
        self.write_direct.load(Ordering::Acquire)
    }
    pub(crate) fn start_write_direct(&self) {
        self.write_direct.store(true, Ordering::Release);
    }
    fn observe(&self, payload: &[u8], incoming: bool) {
        self.filter
            .lock()
            .expect("Vision TLS filter poisoned")
            .observe(payload, incoming);
    }
}

#[derive(Default)]
struct TlsFilter {
    incoming: TlsProbe,
    outgoing: TlsProbe,
    tls: bool,
    direct: bool,
}

#[derive(Default)]
struct TlsProbe {
    buffer: Vec<u8>,
    handshake: Vec<u8>,
    stopped: bool,
}

impl TlsFilter {
    fn observe(&mut self, payload: &[u8], incoming: bool) {
        let probe = if incoming {
            &mut self.incoming
        } else {
            &mut self.outgoing
        };
        if probe.stopped {
            return;
        }
        probe.buffer.extend_from_slice(payload);
        loop {
            if probe.buffer.len() < 5 {
                return;
            }
            if probe.buffer[0] != 22 || probe.buffer[1] != 3 {
                probe.buffer.clear();
                probe.handshake.clear();
                probe.stopped = true;
                return;
            }
            let len = u16::from_be_bytes([probe.buffer[3], probe.buffer[4]]) as usize;
            if len > 18432 {
                probe.stopped = true;
                probe.buffer.clear();
                return;
            }
            if probe.buffer.len() < 5 + len {
                return;
            }
            probe.handshake.extend_from_slice(&probe.buffer[5..5 + len]);
            probe.buffer.drain(..5 + len);
            while probe.handshake.len() >= 4 {
                let len = (usize::from(probe.handshake[1]) << 16)
                    | (usize::from(probe.handshake[2]) << 8)
                    | usize::from(probe.handshake[3]);
                if len > 65536 {
                    probe.stopped = true;
                    probe.handshake.clear();
                    return;
                }
                if probe.handshake.len() < 4 + len {
                    break;
                }
                if matches!(probe.handshake[0], 1 | 2) {
                    self.tls = true;
                }
                if probe.handshake[0] == 2 {
                    self.direct = server_hello_allows_direct(&probe.handshake[4..4 + len]);
                }
                probe.handshake.drain(..4 + len);
            }
        }
    }
}

fn server_hello_allows_direct(hello: &[u8]) -> bool {
    if hello.len() < 38 || hello[..2] != [3, 3] {
        return false;
    }
    let cipher_offset = 35 + usize::from(hello[34]);
    let Some(suite) = hello.get(cipher_offset..cipher_offset + 2) else {
        return false;
    };
    if !matches!(u16::from_be_bytes([suite[0], suite[1]]), 0x1301..=0x1304) {
        return false;
    }
    let extensions_offset = cipher_offset + 3;
    let Some(size) = hello.get(extensions_offset..extensions_offset + 2) else {
        return false;
    };
    let size = u16::from_be_bytes([size[0], size[1]]) as usize;
    let Some(mut extensions) = hello.get(extensions_offset + 2..extensions_offset + 2 + size)
    else {
        return false;
    };
    while extensions.len() >= 4 {
        let kind = u16::from_be_bytes([extensions[0], extensions[1]]);
        let len = u16::from_be_bytes([extensions[2], extensions[3]]) as usize;
        let Some(value) = extensions.get(4..4 + len) else {
            return false;
        };
        if kind == 43 && value == [3, 4] {
            return true;
        }
        extensions = &extensions[4 + len..];
    }
    false
}

const COMMAND_PADDING_CONTINUE: u8 = 0;
const COMMAND_PADDING_END: u8 = 1;
const COMMAND_PADDING_DIRECT: u8 = 2;
const VISION_HEADER_LEN: usize = 5;
const TLS_CONTENT_TYPE_APPLICATION_DATA: u8 = 0x17;
const TLS_VERSION_12: u16 = 0x0303;

enum ReadState {
    Initial,
    Header,
    Content {
        command: u8,
        remaining_content: usize,
        remaining_padding: usize,
    },
    Padding {
        command: u8,
        remaining_padding: usize,
    },
    Raw,
}

pub struct VisionReader<R> {
    inner: R,
    user: [u8; 16],
    state: ReadState,
    encoded: Vec<u8>,
    decoded: Vec<u8>,
    decoded_offset: usize,
    control: Option<Arc<VisionControl>>,
}

impl<R> VisionReader<R> {
    pub fn new(inner: R, user: [u8; 16]) -> Self {
        Self {
            inner,
            user,
            state: ReadState::Initial,
            encoded: Vec::new(),
            decoded: Vec::new(),
            decoded_offset: 0,
            control: None,
        }
    }

    pub(crate) fn with_control(inner: R, user: [u8; 16], control: Arc<VisionControl>) -> Self {
        let mut reader = Self::new(inner, user);
        reader.control = Some(control);
        reader
    }

    fn poll_decoded(&mut self, buf: &mut ReadBuf<'_>) -> bool {
        if self.decoded_offset >= self.decoded.len() {
            self.decoded.clear();
            self.decoded_offset = 0;
            return false;
        }
        let available = &self.decoded[self.decoded_offset..];
        let take = available.len().min(buf.remaining());
        if let Some(control) = &self.control {
            control.observe(&available[..take], true);
        }
        buf.put_slice(&available[..take]);
        self.decoded_offset += take;
        true
    }

    fn decode_available(&mut self, eof: bool) -> Result<()> {
        loop {
            match self.state {
                ReadState::Initial => {
                    let prefix_len = self.encoded.len().min(self.user.len());
                    if self.encoded[..prefix_len] != self.user[..prefix_len] {
                        self.state = ReadState::Raw;
                        self.decoded.extend_from_slice(&self.encoded);
                        self.encoded.clear();
                        return Ok(());
                    }
                    if self.encoded.len() < self.user.len() + VISION_HEADER_LEN {
                        if eof {
                            self.state = ReadState::Raw;
                            self.decoded.extend_from_slice(&self.encoded);
                            self.encoded.clear();
                        }
                        return Ok(());
                    }
                    self.encoded.drain(..self.user.len());
                    self.state = ReadState::Header;
                }
                ReadState::Header => {
                    if self.encoded.len() < VISION_HEADER_LEN {
                        if eof && !self.encoded.is_empty() {
                            return Err(Error::new(
                                ErrorKind::UnexpectedEof,
                                "truncated VLESS Vision block header",
                            ));
                        }
                        return Ok(());
                    }
                    let command = self.encoded[0];
                    let content_len =
                        u16::from_be_bytes([self.encoded[1], self.encoded[2]]) as usize;
                    let padding_len =
                        u16::from_be_bytes([self.encoded[3], self.encoded[4]]) as usize;
                    self.encoded.drain(..VISION_HEADER_LEN);
                    self.state = ReadState::Content {
                        command,
                        remaining_content: content_len,
                        remaining_padding: padding_len,
                    };
                }
                ReadState::Content {
                    command,
                    remaining_content,
                    remaining_padding,
                } => {
                    if remaining_content == 0 {
                        self.state = ReadState::Padding {
                            command,
                            remaining_padding,
                        };
                        continue;
                    }
                    let take = remaining_content.min(self.encoded.len());
                    if take == 0 {
                        if eof {
                            return Err(Error::new(
                                ErrorKind::UnexpectedEof,
                                "truncated VLESS Vision content",
                            ));
                        }
                        return Ok(());
                    }
                    self.decoded.extend_from_slice(&self.encoded[..take]);
                    self.encoded.drain(..take);
                    self.state = ReadState::Content {
                        command,
                        remaining_content: remaining_content - take,
                        remaining_padding,
                    };
                    if !self.decoded.is_empty() {
                        return Ok(());
                    }
                }
                ReadState::Padding {
                    command,
                    remaining_padding,
                } => {
                    let take = remaining_padding.min(self.encoded.len());
                    if take == 0 && remaining_padding > 0 {
                        if eof {
                            return Err(Error::new(
                                ErrorKind::UnexpectedEof,
                                "truncated VLESS Vision padding",
                            ));
                        }
                        return Ok(());
                    }
                    self.encoded.drain(..take);
                    let remaining_padding = remaining_padding - take;
                    if remaining_padding > 0 {
                        self.state = ReadState::Padding {
                            command,
                            remaining_padding,
                        };
                        return Ok(());
                    }
                    match command {
                        COMMAND_PADDING_CONTINUE => self.state = ReadState::Header,
                        COMMAND_PADDING_END | COMMAND_PADDING_DIRECT => {
                            if command == COMMAND_PADDING_DIRECT {
                                let control = self.control.as_ref().ok_or_else(|| {
                                    Error::new(
                                        ErrorKind::Unsupported,
                                        "Vision DIRECT requires a switchable TLS transport",
                                    )
                                })?;
                                control.read_direct.store(true, Ordering::Release);
                            }
                            self.state = ReadState::Raw;
                            self.decoded.extend_from_slice(&self.encoded);
                            self.encoded.clear();
                            return Ok(());
                        }
                        other => {
                            return Err(Error::new(
                                ErrorKind::InvalidData,
                                format!("unsupported VLESS Vision command {other:#x}"),
                            ));
                        }
                    }
                }
                ReadState::Raw => {
                    if !self.encoded.is_empty() {
                        self.decoded.extend_from_slice(&self.encoded);
                        self.encoded.clear();
                    }
                    return Ok(());
                }
            }
        }
    }
}

impl<R> AsyncRead for VisionReader<R>
where
    R: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<()>> {
        if self.poll_decoded(buf) {
            return Poll::Ready(Ok(()));
        }

        loop {
            // Finish cached content, padding and following blocks before
            // polling the network, including the DIRECT transport transition.
            self.decode_available(false)?;
            if self.poll_decoded(buf) {
                return Poll::Ready(Ok(()));
            }
            if matches!(self.state, ReadState::Raw) && self.encoded.is_empty() {
                return Pin::new(&mut self.inner).poll_read(cx, buf);
            }

            let mut scratch = [0u8; 8192];
            let mut read_buf = ReadBuf::new(&mut scratch);
            match Pin::new(&mut self.inner).poll_read(cx, &mut read_buf) {
                Poll::Ready(Ok(())) => {
                    let read = read_buf.filled().len();
                    if read == 0 {
                        self.decode_available(true)?;
                        if self.poll_decoded(buf) {
                            return Poll::Ready(Ok(()));
                        }
                        return Poll::Ready(Ok(()));
                    }
                    self.encoded.extend_from_slice(read_buf.filled());
                    self.decode_available(false)?;
                    if self.poll_decoded(buf) {
                        return Poll::Ready(Ok(()));
                    }
                }
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

#[cfg(test)]
fn encode_end_frame(user: &[u8; 16], payload: &[u8]) -> Result<Vec<u8>> {
    encode_vision_frame(user, true, COMMAND_PADDING_END, payload)
}

pub fn encode_continue_frame(user: &[u8; 16], write_uuid: bool, payload: &[u8]) -> Result<Vec<u8>> {
    encode_vision_frame(user, write_uuid, COMMAND_PADDING_CONTINUE, payload)
}

#[cfg(test)]
fn encode_direct_frame(user: &[u8; 16], write_uuid: bool, payload: &[u8]) -> Result<Vec<u8>> {
    encode_vision_frame(user, write_uuid, COMMAND_PADDING_DIRECT, payload)
}

pub struct VisionEncoder {
    user: [u8; 16],
    uuid_written: bool,
    direct: bool,
    ended: bool,
    blocks: u8,
    control: Arc<VisionControl>,
}

impl VisionEncoder {
    #[cfg(test)]
    fn new(user: [u8; 16]) -> Self {
        Self::with_control(user, Arc::new(VisionControl::default()))
    }

    pub(crate) fn with_control(user: [u8; 16], control: Arc<VisionControl>) -> Self {
        Self {
            user,
            uuid_written: false,
            direct: false,
            ended: false,
            blocks: 0,
            control,
        }
    }

    pub(crate) fn direct(&self) -> bool {
        self.direct
    }

    pub fn encode(&mut self, payload: &[u8]) -> Result<Vec<u8>> {
        if self.ended {
            return Ok(payload.to_vec());
        }
        self.control.observe(payload, false);
        self.blocks = self.blocks.saturating_add(1);
        let write_uuid = !self.uuid_written;
        self.uuid_written = true;
        let filter = self
            .control
            .filter
            .lock()
            .expect("Vision TLS filter poisoned");
        if filter.tls && looks_like_tls13_application_data(payload) {
            self.ended = true;
            self.direct = filter.direct;
            encode_vision_frame(
                &self.user,
                write_uuid,
                if self.direct {
                    COMMAND_PADDING_DIRECT
                } else {
                    COMMAND_PADDING_END
                },
                payload,
            )
        } else if !filter.tls && self.blocks >= 8 {
            self.ended = true;
            encode_vision_frame(&self.user, write_uuid, COMMAND_PADDING_END, payload)
        } else {
            encode_continue_frame(&self.user, write_uuid, payload)
        }
    }
}

fn looks_like_tls13_application_data(payload: &[u8]) -> bool {
    payload.len() >= 5
        && payload[0] == TLS_CONTENT_TYPE_APPLICATION_DATA
        && u16::from_be_bytes([payload[1], payload[2]]) == TLS_VERSION_12
}

fn encode_vision_frame(
    user: &[u8; 16],
    write_uuid: bool,
    command: u8,
    payload: &[u8],
) -> Result<Vec<u8>> {
    if payload.len() > u16::MAX as usize {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "VLESS Vision payload is too large",
        ));
    }
    let padding_len = vision_padding_len(payload.len())?;
    let mut encoded = Vec::with_capacity(
        usize::from(write_uuid) * user.len() + VISION_HEADER_LEN + payload.len() + padding_len,
    );
    if write_uuid {
        encoded.extend_from_slice(user);
    }
    encoded.push(command);
    encoded.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    encoded.extend_from_slice(&(padding_len as u16).to_be_bytes());
    encoded.extend_from_slice(payload);
    encoded.resize(encoded.len() + padding_len, 0);
    let start = encoded.len() - padding_len;
    getrandom::fill(&mut encoded[start..]).map_err(|error| {
        Error::new(
            ErrorKind::Other,
            format!("generate VLESS Vision padding: {error}"),
        )
    })?;
    Ok(encoded)
}

fn vision_padding_len(content_len: usize) -> Result<usize> {
    let mut bytes = [0u8; 2];
    getrandom::fill(&mut bytes).map_err(|error| {
        Error::new(
            ErrorKind::Other,
            format!("generate VLESS Vision padding length: {error}"),
        )
    })?;
    let random = u16::from_ne_bytes(bytes) as usize;
    let padding = if content_len < 900 {
        (900 + random % 500).saturating_sub(content_len)
    } else {
        (random % 256).max(1)
    };
    Ok(padding.min(u16::MAX as usize))
}

#[cfg(test)]
mod tests;
