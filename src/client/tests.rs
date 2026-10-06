use super::*;
use crate::server::{ServerConfig, run_server_listener};
use tokio::time::timeout;

#[tokio::test]
async fn reused_sessions_reclaim_streams_and_cancelled_open_cannot_be_reused() -> Result<()> {
    tls::init_crypto();
    let temp = tempfile::tempdir()?;
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let cert_path = temp.path().join("server.crt");
    let key_path = temp.path().join("server.key");
    std::fs::write(&cert_path, cert.cert.pem())?;
    std::fs::write(&key_path, cert.key_pair.serialize_pem())?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let server = tokio::spawn(run_server_listener(
        listener,
        ServerConfig {
            listen: addr,
            password: "secret".into(),
            users: vec![],
            cert_path,
            key_path,
            certificates: vec![],
            key: None,
            padding_scheme: PaddingScheme::default_lines(),
            heartbeat_interval_secs: 1,
            ech: None,
        },
    ));
    let target = TcpListener::bind("127.0.0.1:0").await?;
    let target_addr = target.local_addr()?;
    let target_task = tokio::spawn(async move {
        let mut connections = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                accepted = target.accept() => {
                    let (mut stream, _) = accepted?;
                    connections.spawn(async move {
                        let mut bytes = Vec::new();
                        stream.read_to_end(&mut bytes).await
                    });
                }
                _ = connections.join_next(), if !connections.is_empty() => {}
            }
        }
        #[allow(unreachable_code)]
        Ok::<(), std::io::Error>(())
    });
    let config = ClientConfig {
        listen: addr,
        server_host: "127.0.0.1".into(),
        server_port: addr.port(),
        password: "secret".into(),
        sni: "localhost".into(),
        insecure: true,
        client_fingerprint: None,
        ca_cert_paths: vec![],
        ca_certificates: vec![],
        disable_system_roots: false,
        pinned_cert_sha256: vec![],
        padding_scheme: PaddingScheme::default_lines(),
        heartbeat_interval_secs: 1,
    };
    let result = timeout(Duration::from_secs(10), async {
        let padding = PaddingScheme::from_lines(config.padding_scheme.clone())?;
        let shared = Arc::new(Mutex::new(padding.clone()));
        let session = ClientSession::connect(
            &config,
            tls::client_config(true),
            padding.clone(),
            shared.clone(),
        )
        .await?;
        for _ in 0..32 {
            let mut stream = session
                .open_stream(ProxyTarget::Ip(target_addr), vec![])
                .await?;
            stream.registration.finish().await;
            drop(stream);
            assert!(session.streams.lock().unwrap().is_empty());
            assert!(session.is_alive());
        }
        session.next_stream_id.store(u32::MAX - 1, Ordering::SeqCst);
        let mut stream = session
            .open_stream(ProxyTarget::Ip(target_addr), vec![])
            .await?;
        assert_eq!(stream.stream_id, u32::MAX - 1);
        stream.registration.finish().await;
        drop(stream);
        assert!(
            session
                .open_stream(ProxyTarget::Ip(target_addr), vec![])
                .await
                .is_err()
        );
        assert_eq!(session.next_stream_id.load(Ordering::SeqCst), u32::MAX);
        assert!(!session.is_alive());

        let session =
            ClientSession::connect(&config, tls::client_config(true), padding, shared).await?;
        let writer = session.writer.lock().await;
        assert!(
            timeout(
                Duration::from_millis(20),
                session.open_stream(ProxyTarget::Ip(target_addr), vec![])
            )
            .await
            .is_err()
        );
        assert!(session.streams.lock().unwrap().is_empty());
        assert!(!session.is_alive());
        drop(writer);
        session.close("test completed").await;
        Ok::<(), anyhow::Error>(())
    })
    .await
    .context("AnyTLS stream lifecycle test timed out")
    .and_then(|result| result);
    server.abort();
    target_task.abort();
    result
}
