use super::*;

async fn idle_handshake(is_tls: bool) -> Result<()> {
    tls::init_crypto();
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let acceptor = tls::build_server_tls_acceptor(&ServerTlsMaterial {
        cert_path: None,
        key_path: None,
        certificates: vec![cert.cert.pem()],
        key: Some(cert.key_pair.serialize_pem()),
        label: "authentication deadline test".into(),
        alpn_protocols: Vec::new(),
        early_data: false,
        ech: None,
    })?;
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
