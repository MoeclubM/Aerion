use super::*;
use tokio::net::TcpListener;

#[tokio::test]
async fn rejects_greetings_without_supported_authentication() -> Result<()> {
    for greeting in [vec![5, 1, 2], vec![5, 0]] {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let mut client = TcpStream::connect(listener.local_addr()?).await?;
        let (mut server, _) = listener.accept().await?;
        let task = tokio::spawn(async move { read_request(&mut server).await });
        client.write_all(&greeting).await?;
        let mut reply = [0; 2];
        client.read_exact(&mut reply).await?;
        assert_eq!(reply, [5, 0xff]);
        assert!(task.await?.is_err());
    }
    Ok(())
}

#[test]
fn udp_associate_uses_upstream_ip_for_unspecified_bind() -> Result<()> {
    assert_eq!(
        normalize_udp_bind("0.0.0.0:5300".parse()?, "192.0.2.10:1080".parse()?),
        "192.0.2.10:5300".parse::<SocketAddr>()?
    );
    assert_eq!(
        normalize_udp_bind("[::]:5300".parse()?, "[2001:db8::1]:1080".parse()?),
        "[2001:db8::1]:5300".parse::<SocketAddr>()?
    );
    assert_eq!(
        normalize_udp_bind("198.51.100.5:5300".parse()?, "192.0.2.10:1080".parse()?),
        "198.51.100.5:5300".parse::<SocketAddr>()?
    );
    Ok(())
}

#[test]
fn maps_io_and_proxy_errors_to_rfc1928_reply_codes() {
    let refused = anyhow::Error::new(std::io::Error::new(
        std::io::ErrorKind::ConnectionRefused,
        "refused",
    ));
    assert_eq!(reply_code_for_error(&refused), REPLY_CONNECTION_REFUSED);
    assert_eq!(reply_code_for_proxy_error(&refused), REPLY_GENERAL_FAILURE);

    let unreachable_host = anyhow::Error::new(std::io::Error::new(
        std::io::ErrorKind::HostUnreachable,
        "nxdomain",
    ));
    assert_eq!(
        reply_code_for_error(&unreachable_host),
        REPLY_HOST_UNREACHABLE
    );

    let timeout = anyhow::Error::new(std::io::Error::new(std::io::ErrorKind::TimedOut, "timeout"));
    assert_eq!(reply_code_for_error(&timeout), REPLY_TTL_EXPIRED);
    assert_eq!(reply_code_for_proxy_error(&timeout), REPLY_TTL_EXPIRED);

    let socks_err = anyhow::Error::new(SocksConnectError {
        code: REPLY_HOST_UNREACHABLE,
        upstream: "127.0.0.1:1080".parse().expect("valid addr"),
    });
    assert_eq!(
        reply_code_for_proxy_error(&socks_err),
        REPLY_HOST_UNREACHABLE
    );

    assert_eq!(
        reply_code_for_http_connect_failure(403, None),
        REPLY_NOT_ALLOWED
    );
    assert_eq!(
        reply_code_for_http_connect_failure(504, None),
        REPLY_TTL_EXPIRED
    );
    assert_eq!(
        reply_code_for_http_connect_failure(502, Some("aerion; error=dns_error")),
        REPLY_HOST_UNREACHABLE
    );
    assert_eq!(
        reply_code_for_http_connect_failure(502, Some("aerion; error=connection_refused")),
        REPLY_CONNECTION_REFUSED
    );
}

#[tokio::test]
async fn connect_tcp_preserves_upstream_socks_reply_code() -> Result<()> {
    for code in [
        REPLY_NOT_ALLOWED,
        REPLY_NETWORK_UNREACHABLE,
        REPLY_HOST_UNREACHABLE,
        REPLY_CONNECTION_REFUSED,
        REPLY_TTL_EXPIRED,
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let upstream = listener.local_addr()?;
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            let _ = read_request(&mut stream).await?;
            write_reply(&mut stream, code).await?;
            anyhow::Ok(())
        });
        let err = connect_tcp(upstream, &ProxyTarget::Domain("example.com".into(), 443))
            .await
            .expect_err("SOCKS error reply must fail connect_tcp");
        let typed = err
            .downcast_ref::<SocksConnectError>()
            .expect("error must preserve SocksConnectError");
        assert_eq!(typed.code, code);
        assert_eq!(typed.upstream, upstream);
        server.await??;
    }
    Ok(())
}
