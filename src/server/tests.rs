use super::*;

fn test_acceptor() -> Result<ServerTlsAcceptor> {
    tls::init_crypto();
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    tls::build_server_tls_acceptor(&ServerTlsMaterial {
        cert_path: None,
        key_path: None,
        certificates: vec![cert.cert.pem()],
        key: Some(cert.key_pair.serialize_pem()),
        label: "authentication deadline test".into(),
        alpn_protocols: Vec::new(),
        early_data: false,
        ech: None,
    })
}

async fn idle_handshake(is_tls: bool) -> Result<()> {
    let acceptor = test_acceptor()?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let peer = TcpStream::connect(listener.local_addr()?).await?;
    let (stream, addr) = listener.accept().await?;
    let core = ProxyCore::from_credentials("secret", &[]);
    let padding = PaddingScheme::from_lines(PaddingScheme::default_lines())?;
    let task = tokio::spawn(handle_client(stream, acceptor, padding, core, 5, addr));
    let mut peer: Box<dyn crate::vless_transport::TransportStream> = if is_tls {
        Box::new(
            tokio_rustls::TlsConnector::from(tls::client_config(true))
                .connect(rustls::pki_types::ServerName::try_from("localhost")?, peer)
                .await?,
        )
    } else {
        Box::new(peer)
    };
    let error = tokio::time::timeout(
        crate::io_util::HANDSHAKE_TIMEOUT + Duration::from_secs(3),
        task,
    )
    .await??
    .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("AnyTLS authentication timed out")
    );
    let mut byte = [0];
    // A TLS connection may signal unexpected EOF instead of a close_notify.
    let read = tokio::time::timeout(Duration::from_secs(1), peer.read(&mut byte)).await?;
    assert!(read.is_err() || read? == 0);
    Ok(())
}

#[tokio::test]
async fn silent_tls_handshake_has_a_deadline() -> Result<()> {
    idle_handshake(false).await
}

#[tokio::test]
async fn silent_authentication_preface_has_a_deadline() -> Result<()> {
    idle_handshake(true).await
}

#[tokio::test]
async fn queued_dial_does_not_block_mux_parser_and_fin_cancels_it() -> Result<()> {
    let acceptor = test_acceptor()?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let peer = TcpStream::connect(listener.local_addr()?).await?;
    let (stream, _) = listener.accept().await?;
    let connector = tokio_rustls::TlsConnector::from(tls::client_config(true));
    let (stream, peer) = tokio::join!(
        acceptor.accept(stream),
        connector.connect(rustls::pki_types::ServerName::try_from("localhost")?, peer)
    );
    let stream = stream?;
    let mut peer = peer?;
    let (_reader, writer) = split(EarlyDataTlsStream::new(stream, Vec::new()));
    let writer = Arc::new(Mutex::new(writer));
    let core = ProxyCore::from_credentials("secret", &[]);
    let session = core.authenticate("secret").await?;
    let connection_abort = Arc::new(TaskAbort::new());
    let budget = Arc::new(Semaphore::new(1));
    let held = budget.clone().acquire_owned().await?;
    let target = TcpListener::bind("127.0.0.1:0").await?;
    let mut payload = encode_target(&ProxyTarget::Ip(target.local_addr()?))?;
    payload.extend_from_slice(b"hello");
    let (_, control) = tokio::time::timeout(
        Duration::from_secs(1),
        open_stream(
            Frame {
                cmd: CMD_PSH,
                stream_id: 1,
                payload: payload.clone(),
            },
            writer.clone(),
            session.clone(),
            connection_abort.clone(),
            budget.clone(),
        ),
    )
    .await??;
    tokio::task::yield_now().await;
    drop(control);
    drop(held);
    let (_, control) = open_stream(
        Frame {
            cmd: CMD_PSH,
            stream_id: 2,
            payload,
        },
        writer,
        session,
        connection_abort.clone(),
        budget,
    )
    .await?;
    let (mut remote, _) = tokio::time::timeout(Duration::from_secs(1), target.accept()).await??;
    let frame = tokio::time::timeout(Duration::from_secs(1), read_frame(&mut peer)).await??;
    assert_eq!((frame.cmd, frame.stream_id), (CMD_SYNACK, 2));
    let mut hello = [0; 5];
    remote.read_exact(&mut hello).await?;
    assert_eq!(&hello, b"hello");
    remote.write_all(b"reply").await?;
    let frame = tokio::time::timeout(Duration::from_secs(1), read_frame(&mut peer)).await??;
    assert_eq!((frame.cmd, frame.stream_id), (CMD_PSH, 2));
    assert_eq!(frame.payload, b"reply");
    drop(control);
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), remote.read(&mut hello)).await??,
        0
    );
    connection_abort.trigger();
    Ok(())
}
