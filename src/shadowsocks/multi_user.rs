use super::*;
use bytes::BytesMut;
use shadowsocks::crypto::v2::tcp::TcpCipher;
use shadowsocks::relay::udprelay::crypto_io::{decrypt_client_payload, encrypt_server_payload};
use std::io::Cursor;
use std::sync::Mutex as StdMutex;
use tokio::io::{Chain, Join};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};

type ServerTcpIo = Join<Chain<Cursor<Vec<u8>>, OwnedReadHalf>, OwnedWriteHalf>;

pub(super) fn uses_key_detection(server: &ShadowsocksInnerConfig) -> bool {
    server.method() == CipherKind::AEAD2022_BLAKE3_CHACHA20_POLY1305
        && server.user_manager().is_some()
}

pub(super) async fn tcp_stream(
    mut stream: TcpStream,
    server: &ShadowsocksInnerConfig,
    context: ShadowsocksSharedContext,
) -> Result<(ProxyServerStream<ServerTcpIo>, Option<String>)> {
    let mut prefix = Vec::new();
    let mut selected = None;
    if uses_key_detection(server) {
        let method = server.method();
        let salt_len = method.salt_len();
        prefix.resize(salt_len + 1 + 8 + 2 + method.tag_len(), 0);
        timeout(
            crate::io_util::HANDSHAKE_TIMEOUT,
            stream.read_exact(&mut prefix),
        )
        .await
        .context("read Shadowsocks multi-user handshake timed out")??;
        let (salt, header) = prefix.split_at(salt_len);
        for user in server
            .user_manager()
            .expect("multi-user manager")
            .users_iter()
        {
            let mut header = header.to_vec();
            if TcpCipher::new(method, user.key(), salt).decrypt_packet(&mut header) {
                selected = Some(user);
                break;
            }
        }
        ensure!(selected.is_some(), "Shadowsocks user authentication failed");
    }
    let credential = selected.map(ServerUser::encoded_key);
    let key = selected.map_or_else(|| server.key(), ServerUser::key);
    let users = if selected.is_some() {
        None
    } else {
        server.clone_user_manager()
    };
    let (reader, writer) = stream.into_split();
    let io = tokio::io::join(Cursor::new(prefix).chain(reader), writer);
    Ok((
        ProxyServerStream::from_stream_with_user_manager(context, io, server.method(), key, users),
        credential,
    ))
}

pub(super) struct ServerUdpSocket {
    io: ShadowsocksUdpSocket,
    server: ShadowsocksInnerConfig,
    context: ShadowsocksSharedContext,
    last_users: StdMutex<HashMap<SocketAddr, Arc<ServerUser>>>,
}

impl ServerUdpSocket {
    pub(super) async fn bind(
        listen: SocketAddr,
        context: ShadowsocksSharedContext,
        server: &ShadowsocksInnerConfig,
    ) -> Result<Self> {
        Ok(Self {
            io: ShadowsocksUdpSocket::listen(&listen).await?,
            server: server.clone(),
            context,
            last_users: StdMutex::new(HashMap::new()),
        })
    }

    pub(super) fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.io.local_addr()
    }

    pub(super) async fn recv_from(
        &self,
        buffer: &mut [u8],
    ) -> std::result::Result<
        (
            usize,
            SocketAddr,
            ShadowsocksAddress,
            Option<UdpSocketControlData>,
        ),
        ProxySocketError,
    > {
        let (read, peer) = self.io.recv_from(buffer).await?;
        let method = self.server.method();
        if !uses_key_detection(&self.server) {
            let (read, target, control) = decrypt_client_payload(
                &self.context,
                method,
                self.server.key(),
                &mut buffer[..read],
                self.server.user_manager(),
            )
            .map_err(ProxySocketError::ProtocolError)?;
            return Ok((read, peer, target, control));
        }

        let wire = buffer[..read].to_vec();
        let cached = self
            .last_users
            .lock()
            .expect("Shadowsocks UDP users lock")
            .get(&peer)
            .cloned();
        let manager = self.server.user_manager().expect("multi-user manager");
        let users = cached
            .iter()
            .map(Arc::as_ref)
            .chain(manager.users_iter().filter(|user| {
                cached
                    .as_ref()
                    .is_none_or(|cached| cached.name() != user.name())
            }));
        let mut error = None;
        for user in users {
            buffer[..read].copy_from_slice(&wire);
            match decrypt_client_payload(
                &self.context,
                method,
                user.key(),
                &mut buffer[..read],
                None,
            ) {
                Ok((read, target, Some(mut control))) => {
                    control.user = manager.clone_user_by_hash(user.identity_hash());
                    return Ok((read, peer, target, Some(control)));
                }
                Ok(_) => unreachable!("Shadowsocks 2022 packets contain control data"),
                Err(failure) => error = Some(failure),
            }
        }
        Err(ProxySocketError::ProtocolError(
            error.expect("multi-user keys are present"),
        ))
    }

    pub(super) fn remember_user(&self, peer: SocketAddr, control: Option<&UdpSocketControlData>) {
        if uses_key_detection(&self.server)
            && let Some(user) = control.and_then(|control| control.user.as_ref())
        {
            self.last_users
                .lock()
                .expect("Shadowsocks UDP users lock")
                .insert(peer, user.clone());
        }
    }

    pub(super) fn forget_user(&self, peer: SocketAddr, user_id: &str) {
        let mut users = self.last_users.lock().expect("Shadowsocks UDP users lock");
        if users.get(&peer).is_some_and(|user| user.name() == user_id) {
            users.remove(&peer);
        }
    }

    pub(super) async fn send_to_with_ctrl(
        &self,
        peer: SocketAddr,
        target: &ShadowsocksAddress,
        control: &UdpSocketControlData,
        payload: &[u8],
    ) -> std::result::Result<usize, ProxySocketError> {
        let key = control
            .user
            .as_ref()
            .map_or_else(|| self.server.key(), |user| user.key());
        let mut wire = BytesMut::new();
        encrypt_server_payload(
            &self.context,
            self.server.method(),
            key,
            target,
            control,
            payload,
            &mut wire,
        );
        Ok(self.io.send_to(&wire, peer).await?)
    }

    pub(super) async fn send_to(
        &self,
        peer: SocketAddr,
        target: &ShadowsocksAddress,
        payload: &[u8],
    ) -> std::result::Result<usize, ProxySocketError> {
        self.send_to_with_ctrl(peer, target, &UdpSocketControlData::default(), payload)
            .await
    }
}
