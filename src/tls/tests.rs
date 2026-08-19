use super::*;
use anyhow::{Context, Result};
use std::io::Read;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};

#[tokio::test]
async fn accepts_tls13_early_data_after_ticket_resumption() -> Result<()> {
    init_crypto();

    let temp = tempfile::tempdir()?;
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;
    let cert_path = temp.path().join("early.crt");
    let key_path = temp.path().join("early.key");
    std::fs::write(&cert_path, certified.cert.pem())?;
    std::fs::write(&key_path, certified.key_pair.serialize_pem())?;

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let acceptor = TlsAcceptor::from(server_config_early_data(&cert_path, &key_path)?);
    let server_task = tokio::spawn(async move {
        for _ in 0..2 {
            let (stream, _) = listener.accept().await?;
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let mut stream = acceptor.accept(stream).await?;
                if let Some(mut early_data) = stream.get_mut().1.early_data() {
                    let mut buf = Vec::new();
                    early_data.read_to_end(&mut buf)?;
                    if !buf.is_empty() {
                        stream.write_all(b"EARLY:").await?;
                        stream.write_all(&buf).await?;
                    }
                }
                stream.write_all(b"LATE:").await?;
                let mut buf = [0u8; 1024];
                loop {
                    let read = stream.read(&mut buf).await?;
                    if read == 0 {
                        stream.shutdown().await?;
                        return Ok::<(), anyhow::Error>(());
                    }
                    stream.write_all(&buf[..read]).await?;
                }
            });
        }
        Ok::<(), anyhow::Error>(())
    });

    let config = client_config_early_data(true);
    let (accepted, body) = early_data_roundtrip(config.clone(), addr, b"hello").await?;
    assert!(!accepted);
    assert_eq!(body, b"LATE:hello");

    let (accepted, body) = early_data_roundtrip(config, addr, b"world").await?;
    assert!(accepted);
    assert_eq!(body, b"EARLY:worldLATE:");

    server_task.abort();
    Ok(())
}

#[tokio::test]
async fn accepts_inline_server_certificate_material() -> Result<()> {
    init_crypto();

    let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;
    let cert_pem = certified.cert.pem();
    let key_pem = certified.key_pair.serialize_pem();
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let acceptor = TlsAcceptor::from(server_config_from_material(
        None,
        None,
        std::slice::from_ref(&cert_pem),
        Some(&key_pem),
        "inline TLS test",
    )?);
    let server_task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await?;
        let mut stream = acceptor.accept(stream).await?;
        let mut buf = [0u8; 5];
        stream.read_exact(&mut buf).await?;
        stream.write_all(&buf).await?;
        Ok::<(), anyhow::Error>(())
    });

    let config =
        client_config_with_custom_root_material(false, &[], std::slice::from_ref(&cert_pem))?;
    let tcp = TcpStream::connect(addr).await?;
    let server_name = ServerName::try_from("localhost").context("build server name")?;
    let mut stream = TlsConnector::from(config)
        .connect(server_name, tcp)
        .await
        .context("connect inline TLS server")?;
    stream.write_all(b"hello").await?;
    let mut echoed = [0u8; 5];
    stream.read_exact(&mut echoed).await?;
    assert_eq!(&echoed, b"hello");
    server_task.await??;
    Ok(())
}

async fn early_data_roundtrip(
    config: Arc<ClientConfig>,
    addr: std::net::SocketAddr,
    payload: &[u8],
) -> Result<(bool, Vec<u8>)> {
    let tcp = TcpStream::connect(addr).await?;
    let server_name = ServerName::try_from("localhost").context("build server name")?;
    let mut stream = TlsConnector::from(config)
        .early_data(true)
        .connect(server_name, tcp)
        .await
        .context("connect with early data")?;
    stream.write_all(payload).await?;
    stream.flush().await?;
    stream.shutdown().await?;
    let mut body = Vec::new();
    stream.read_to_end(&mut body).await?;
    let accepted = stream.get_ref().1.is_early_data_accepted();
    Ok((accepted, body))
}
