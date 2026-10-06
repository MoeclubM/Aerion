use super::helpers::*;
use aerion::{NaiveClientConfig, NaiveServerConfig, run_naive_server};

// macOS defaults net.inet.udp.maxdgram to 9,216 bytes, including SOCKS headers.
const UDP_TEST_PAYLOAD: usize = 8 * 1024;

#[tokio::test]
async fn socks_client_reaches_tcp_target_through_naive_custom_roots() -> Result<()> {
    naive_tcp_accounting_and_idle_revocation(false).await
}

#[tokio::test]
async fn naive_http3_records_traffic_and_revokes_idle_tcp() -> Result<()> {
    naive_tcp_accounting_and_idle_revocation(true).await
}

async fn naive_tcp_accounting_and_idle_revocation(quic: bool) -> Result<()> {
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter("aerion=debug")
        .with_test_writer()
        .finish();
    let _logging = tracing::subscriber::set_default(subscriber);
    tls::init_crypto();

    let echo_listener = TcpListener::bind("127.0.0.1:0").await?;
    let echo_addr = echo_listener.local_addr()?;
    let echo_task = tokio::spawn(async move {
        let (mut stream, _) = echo_listener.accept().await?;
        let mut buffer = [0u8; 64];
        let read = stream.read(&mut buffer).await?;
        stream.write_all(&buffer[..read]).await?;
        Ok::<(), std::io::Error>(())
    });

    let temp = tempfile::tempdir()?;
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;
    let cert_path = temp.path().join("naive.crt");
    let key_path = temp.path().join("naive.key");
    std::fs::write(&cert_path, certified.cert.pem())?;
    std::fs::write(&key_path, certified.key_pair.serialize_pem())?;
    let ca_cert_path = cert_path.clone();

    let server_addr = unused_tcp_addr()?;
    let server_task = tokio::spawn(run_naive_server(NaiveServerConfig {
        listen: server_addr,
        username: "user".to_string(),
        password: "test-password".to_string(),
        users: Vec::new(),
        cert_path,
        key_path,
        certificates: Vec::new(),
        key: None,
        udp_over_tcp: true,
        tcp: true,
        quic,
        quic_congestion_control: "bbr".to_string(),
    }));

    let client_listener = TcpListener::bind("127.0.0.1:0").await?;
    let client_addr = client_listener.local_addr()?;
    let core = aerion::ProxyCore::from_credentials("user:test-password", &[]);
    let client_task = tokio::spawn(aerion::naive::run_naive_client_listener_with_core(
        client_listener,
        NaiveClientConfig {
            listen: client_addr,
            server_host: "127.0.0.1".to_string(),
            server_port: server_addr.port(),
            username: "user".to_string(),
            password: "test-password".to_string(),
            sni: "localhost".to_string(),
            insecure: false,
            ca_cert_paths: vec![ca_cert_path],
            ca_certificates: Vec::new(),
            disable_system_roots: false,
            pinned_cert_sha256: Vec::new(),
            extra_headers: Vec::new(),
            udp_over_tcp: true,
            quic,
            quic_congestion_control: "bbr".to_string(),
        },
        Some(core.clone()),
    ));

    let result = timeout(Duration::from_secs(10), async {
        let payload = b"hello naive custom roots";
        socks_echo(client_addr, echo_addr, payload)
            .await
            .context("Naive TCP echo")?;
        let stats = core.snapshot().await;
        anyhow::ensure!(
            stats[0].upload_bytes == payload.len() as u64
                && stats[0].download_bytes == payload.len() as u64,
            "Naive client did not record payload bytes"
        );
        let mut refused = TcpStream::connect(client_addr).await?;
        refused.write_all(&[5, 1, 0]).await?;
        let mut greeting = [0; 2];
        refused.read_exact(&mut greeting).await?;
        write_socks_connect(&mut refused, unused_tcp_addr()?).await?;
        let mut reply = [0; 10];
        refused
            .read_exact(&mut reply)
            .await
            .context("read rejected Naive CONNECT reply")?;
        anyhow::ensure!(
            reply[1] != 0,
            "Naive reported success before connecting the TCP target"
        );
        let idle_listener = TcpListener::bind("127.0.0.1:0").await?;
        let mut socks = TcpStream::connect(client_addr).await?;
        socks.write_all(&[5, 1, 0]).await?;
        socks.read_exact(&mut greeting).await?;
        write_socks_connect(&mut socks, idle_listener.local_addr()?).await?;
        read_socks_reply_addr(&mut socks)
            .await
            .context("open idle Naive TCP tunnel")?;
        let (mut target, _) = idle_listener.accept().await?;
        core.cancel_all_sessions();
        anyhow::ensure!(
            socks.read(&mut [0; 1]).await? == 0,
            "revoked idle SOCKS connection remained open"
        );
        anyhow::ensure!(
            target.read(&mut [0; 1]).await? == 0,
            "revoked Naive tunnel retained target writer"
        );
        let echo = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
        let echo_addr = echo.local_addr()?;
        let mut control = TcpStream::connect(client_addr).await?;
        control.write_all(&[5, 1, 0]).await?;
        control.read_exact(&mut greeting).await?;
        write_socks_udp_associate(&mut control).await?;
        let bind = read_socks_reply_addr(&mut control)
            .await
            .context("open Naive UOT tunnel")?;
        let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
        let send = async {
            for index in 0..4u8 {
                udp.send_to(
                    &socks_udp_packet(echo_addr, &vec![index; UDP_TEST_PAYLOAD])?,
                    bind,
                )
                .await?;
            }
            Ok::<(), anyhow::Error>(())
        };
        let responses = async {
            let mut buffer = vec![0; 65536];
            let mut seen = [false; 4];
            for _ in 0..4 {
                let (read, _) = udp.recv_from(&mut buffer).await?;
                let bytes = socks_udp_payload(&buffer[..read])?;
                anyhow::ensure!(
                    bytes.len() == UDP_TEST_PAYLOAD
                        && bytes[0] < 4
                        && bytes.iter().all(|byte| *byte == bytes[0]),
                    "Naive framed UDP payload was corrupted"
                );
                anyhow::ensure!(!seen[bytes[0] as usize], "duplicate UDP response");
                seen[bytes[0] as usize] = true;
            }
            Ok::<(), anyhow::Error>(())
        };
        let echo = async {
            let mut buffer = vec![0; 65536];
            for _ in 0..4 {
                let (read, peer) = echo.recv_from(&mut buffer).await?;
                echo.send_to(&buffer[..read], peer).await?;
            }
            Ok::<(), anyhow::Error>(())
        };
        tokio::try_join!(send, responses, echo)?;
        let stats = core.snapshot().await;
        anyhow::ensure!(
            stats[0].upload_bytes == payload.len() as u64 + 4 * UDP_TEST_PAYLOAD as u64
                && stats[0].download_bytes == stats[0].upload_bytes,
            "Naive UDP accounting mismatch"
        );
        core.cancel_all_sessions();
        anyhow::ensure!(
            control.read(&mut [0; 1]).await? == 0,
            "revoked UDP association remained open"
        );
        Ok::<(), anyhow::Error>(())
    })
    .await
    .context("Naive custom roots end-to-end test timed out")
    .and_then(|inner| inner);

    client_task.abort();
    server_task.abort();
    if result.is_ok() {
        echo_task.await??;
    } else {
        echo_task.abort();
    }
    result
}
