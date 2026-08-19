use super::helpers::*;
use aerion::{
    MieruClientConfig, MieruServerConfig, MieruTransport, run_mieru_client_listener,
    run_mieru_server,
};

#[tokio::test]
async fn socks_client_reaches_tcp_target_through_mieru_server() -> Result<()> {
    let echo_listener = TcpListener::bind("127.0.0.1:0").await?;
    let echo_addr = echo_listener.local_addr()?;
    let echo_task = tokio::spawn(async move {
        let (mut stream, _) = echo_listener.accept().await?;
        let mut buffer = [0u8; 64];
        let read = stream.read(&mut buffer).await?;
        stream.write_all(&buffer[..read]).await?;
        Ok::<(), std::io::Error>(())
    });

    let server_addr = unused_tcp_addr()?;
    let server_task = tokio::spawn(run_mieru_server(MieruServerConfig {
        listen: server_addr,
        username: "default".to_string(),
        password: "test-password".to_string(),
        users: Vec::new(),
        mtu: 1500,
        user_hint_mandatory: false,
        traffic_pattern: None,
        transport: MieruTransport::Tcp,
    }));

    let client_listener = TcpListener::bind("127.0.0.1:0").await?;
    let client_addr = client_listener.local_addr()?;
    let client_task = tokio::spawn(run_mieru_client_listener(
        client_listener,
        MieruClientConfig {
            listen: client_addr,
            server_host: "127.0.0.1".to_string(),
            server_port: server_addr.port(),
            username: "default".to_string(),
            password: "test-password".to_string(),
            hashed_password: None,
            mtu: 1500,
            traffic_pattern: None,
            transport: MieruTransport::Tcp,
        },
    ));

    let result = timeout(
        Duration::from_secs(5),
        socks_echo(client_addr, echo_addr, b"hello mieru"),
    )
    .await
    .context("Mieru TCP end-to-end test timed out")
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

#[tokio::test]
async fn mieru_server_finishes_when_tcp_target_fins() -> Result<()> {
    let target_listener = TcpListener::bind("127.0.0.1:0").await?;
    let target_addr = target_listener.local_addr()?;
    let target_task = tokio::spawn(async move {
        let (mut stream, _) = target_listener.accept().await?;
        let mut buffer = [0u8; 64];
        let read = stream.read(&mut buffer).await?;
        stream.write_all(&buffer[..read]).await?;
        stream.shutdown().await?;
        Ok::<(), std::io::Error>(())
    });

    let server_addr = unused_tcp_addr()?;
    let server_task = tokio::spawn(run_mieru_server(MieruServerConfig {
        listen: server_addr,
        username: "default".to_string(),
        password: "test-password".to_string(),
        users: Vec::new(),
        mtu: 1500,
        user_hint_mandatory: false,
        traffic_pattern: None,
        transport: MieruTransport::Tcp,
    }));

    let client_listener = TcpListener::bind("127.0.0.1:0").await?;
    let client_addr = client_listener.local_addr()?;
    let client_task = tokio::spawn(run_mieru_client_listener(
        client_listener,
        MieruClientConfig {
            listen: client_addr,
            server_host: "127.0.0.1".to_string(),
            server_port: server_addr.port(),
            username: "default".to_string(),
            password: "test-password".to_string(),
            hashed_password: None,
            mtu: 1500,
            traffic_pattern: None,
            transport: MieruTransport::Tcp,
        },
    ));

    let result = timeout(Duration::from_secs(8), async {
        let mut socks = TcpStream::connect(client_addr).await?;
        socks.write_all(&[0x05, 0x01, 0x00]).await?;
        let mut greeting = [0u8; 2];
        socks.read_exact(&mut greeting).await?;
        anyhow::ensure!(greeting == [0x05, 0x00], "unexpected SOCKS greeting reply");
        write_socks_connect(&mut socks, target_addr).await?;
        let mut reply = [0u8; 10];
        socks.read_exact(&mut reply).await?;
        anyhow::ensure!(reply[1] == 0x00, "SOCKS connect failed: {:?}", reply);
        socks.write_all(b"ping").await?;
        let mut echoed = [0u8; 4];
        socks.read_exact(&mut echoed).await?;
        anyhow::ensure!(&echoed == b"ping", "echo payload mismatch");
        let mut tail = [0u8; 1];
        let read = socks.read(&mut tail).await?;
        anyhow::ensure!(read == 0, "expected Mieru session EOF after target FIN");
        Ok::<(), anyhow::Error>(())
    })
    .await
    .context("Mieru target-FIN test timed out")
    .and_then(|inner| inner);

    client_task.abort();
    server_task.abort();
    if result.is_ok() {
        target_task.await??;
    } else {
        target_task.abort();
    }
    result
}

#[tokio::test]
async fn socks_client_reaches_tcp_target_through_mieru_udp_packet_underlay() -> Result<()> {
    let echo_listener = TcpListener::bind("127.0.0.1:0").await?;
    let echo_addr = echo_listener.local_addr()?;
    let echo_task = tokio::spawn(async move {
        let (mut stream, _) = echo_listener.accept().await?;
        let mut buffer = [0u8; 64];
        let read = stream.read(&mut buffer).await?;
        stream.write_all(&buffer[..read]).await?;
        Ok::<(), std::io::Error>(())
    });

    let server_addr = unused_udp_addr()?;
    let server_task = tokio::spawn(run_mieru_server(MieruServerConfig {
        listen: server_addr,
        username: "default".to_string(),
        password: "test-password".to_string(),
        users: Vec::new(),
        mtu: 1500,
        user_hint_mandatory: false,
        traffic_pattern: None,
        transport: MieruTransport::Udp,
    }));

    let client_listener = TcpListener::bind("127.0.0.1:0").await?;
    let client_addr = client_listener.local_addr()?;
    let client_task = tokio::spawn(run_mieru_client_listener(
        client_listener,
        MieruClientConfig {
            listen: client_addr,
            server_host: "127.0.0.1".to_string(),
            server_port: server_addr.port(),
            username: "default".to_string(),
            password: "test-password".to_string(),
            hashed_password: None,
            mtu: 1500,
            traffic_pattern: None,
            transport: MieruTransport::Udp,
        },
    ));

    let result = timeout(
        Duration::from_secs(5),
        socks_echo(client_addr, echo_addr, b"hello mieru udp underlay"),
    )
    .await
    .context("Mieru UDP packet underlay TCP end-to-end test timed out")
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

#[tokio::test]
async fn socks_udp_associate_reaches_udp_target_through_mieru_stream() -> Result<()> {
    let udp_echo = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
    let udp_echo_addr = udp_echo.local_addr()?;
    let udp_echo_task = tokio::spawn(async move {
        let mut buffer = [0u8; 256];
        let (read, peer) = udp_echo.recv_from(&mut buffer).await?;
        udp_echo.send_to(&buffer[..read], peer).await?;
        Ok::<(), std::io::Error>(())
    });

    let server_addr = unused_tcp_addr()?;
    let server_task = tokio::spawn(run_mieru_server(MieruServerConfig {
        listen: server_addr,
        username: "default".to_string(),
        password: "test-password".to_string(),
        users: Vec::new(),
        mtu: 1500,
        user_hint_mandatory: false,
        traffic_pattern: None,
        transport: MieruTransport::Tcp,
    }));

    let client_listener = TcpListener::bind("127.0.0.1:0").await?;
    let client_addr = client_listener.local_addr()?;
    let client_task = tokio::spawn(run_mieru_client_listener(
        client_listener,
        MieruClientConfig {
            listen: client_addr,
            server_host: "127.0.0.1".to_string(),
            server_port: server_addr.port(),
            username: "default".to_string(),
            password: "test-password".to_string(),
            hashed_password: None,
            mtu: 1500,
            traffic_pattern: None,
            transport: MieruTransport::Tcp,
        },
    ));

    let result = timeout(Duration::from_secs(5), async {
        let mut control = TcpStream::connect(client_addr).await?;
        control.write_all(&[0x05, 0x01, 0x00]).await?;
        let mut greeting = [0u8; 2];
        control.read_exact(&mut greeting).await?;
        anyhow::ensure!(greeting == [0x05, 0x00], "unexpected SOCKS greeting reply");

        write_socks_udp_associate(&mut control).await?;
        let udp_bind = read_socks_reply_addr(&mut control).await?;
        let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
        udp.send_to(
            &socks_udp_packet(udp_echo_addr, b"hello mieru udp")?,
            udp_bind,
        )
        .await?;

        let mut response = [0u8; 256];
        let (read, _) = udp.recv_from(&mut response).await?;
        let payload = socks_udp_payload(&response[..read])?;
        anyhow::ensure!(payload == b"hello mieru udp", "Mieru UDP payload mismatch");
        Ok::<(), anyhow::Error>(())
    })
    .await
    .context("Mieru UDP-over-stream end-to-end test timed out")
    .and_then(|inner| inner);

    client_task.abort();
    server_task.abort();
    if result.is_ok() {
        udp_echo_task.await??;
    } else {
        udp_echo_task.abort();
    }
    result
}

#[tokio::test]
async fn socks_udp_associate_reaches_udp_target_through_mieru_packet_underlay() -> Result<()> {
    let udp_echo = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
    let udp_echo_addr = udp_echo.local_addr()?;
    let udp_echo_task = tokio::spawn(async move {
        let mut buffer = [0u8; 256];
        let (read, peer) = udp_echo.recv_from(&mut buffer).await?;
        udp_echo.send_to(&buffer[..read], peer).await?;
        Ok::<(), std::io::Error>(())
    });

    let server_addr = unused_udp_addr()?;
    let server_task = tokio::spawn(run_mieru_server(MieruServerConfig {
        listen: server_addr,
        username: "default".to_string(),
        password: "test-password".to_string(),
        users: Vec::new(),
        mtu: 1500,
        user_hint_mandatory: false,
        traffic_pattern: None,
        transport: MieruTransport::Udp,
    }));

    let client_listener = TcpListener::bind("127.0.0.1:0").await?;
    let client_addr = client_listener.local_addr()?;
    let client_task = tokio::spawn(run_mieru_client_listener(
        client_listener,
        MieruClientConfig {
            listen: client_addr,
            server_host: "127.0.0.1".to_string(),
            server_port: server_addr.port(),
            username: "default".to_string(),
            password: "test-password".to_string(),
            hashed_password: None,
            mtu: 1500,
            traffic_pattern: None,
            transport: MieruTransport::Udp,
        },
    ));

    let result = timeout(Duration::from_secs(5), async {
        let mut control = TcpStream::connect(client_addr).await?;
        control.write_all(&[0x05, 0x01, 0x00]).await?;
        let mut greeting = [0u8; 2];
        control.read_exact(&mut greeting).await?;
        anyhow::ensure!(greeting == [0x05, 0x00], "unexpected SOCKS greeting reply");

        write_socks_udp_associate(&mut control).await?;
        let udp_bind = read_socks_reply_addr(&mut control).await?;
        let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
        udp.send_to(
            &socks_udp_packet(udp_echo_addr, b"hello mieru packet udp")?,
            udp_bind,
        )
        .await?;

        let mut response = [0u8; 256];
        let (read, _) = udp.recv_from(&mut response).await?;
        let payload = socks_udp_payload(&response[..read])?;
        anyhow::ensure!(
            payload == b"hello mieru packet udp",
            "Mieru packet underlay UDP payload mismatch"
        );
        Ok::<(), anyhow::Error>(())
    })
    .await
    .context("Mieru packet underlay UDP ASSOCIATE test timed out")
    .and_then(|inner| inner);

    client_task.abort();
    server_task.abort();
    if result.is_ok() {
        udp_echo_task.await??;
    } else {
        udp_echo_task.abort();
    }
    result
}
