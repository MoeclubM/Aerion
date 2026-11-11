use super::*;

#[test]
fn parses_http_connect_authority() -> Result<()> {
    assert_eq!(
        parse_connect_authority("example.com:443")?,
        ProxyTarget::Domain("example.com".to_string(), 443)
    );
    assert_eq!(
        parse_connect_authority("127.0.0.1:8080")?,
        ProxyTarget::Ip("127.0.0.1:8080".parse()?)
    );
    assert_eq!(
        parse_connect_authority("[::1]:8443")?,
        ProxyTarget::Ip("[::1]:8443".parse()?)
    );
    Ok(())
}

#[tokio::test]
async fn listener_stops_on_token() -> Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let stop = ListenerStopToken::new();
    let task_stop = stop.clone();
    let task = tokio::spawn(async move {
        run_http_connect_listener_until(
            listener,
            HttpConnectInboundConfig {
                upstream_socks: "127.0.0.1:9".parse().expect("valid socket addr"),
            },
            task_stop,
        )
        .await
    });
    stop.stop();
    task.await.context("join HTTP CONNECT listener")??;
    Ok(())
}

#[tokio::test]
async fn http_connect_maps_socks_errors_to_status_and_proxy_status() -> Result<()> {
    for (socks_code, expected_status, expected_tag) in [
        (
            socks::REPLY_NOT_ALLOWED,
            "403 Forbidden",
            "error=connection_refused",
        ),
        (
            socks::REPLY_TTL_EXPIRED,
            "504 Gateway Timeout",
            "error=connection_timeout",
        ),
        (
            socks::REPLY_HOST_UNREACHABLE,
            "502 Bad Gateway",
            "error=dns_error",
        ),
        (
            socks::REPLY_CONNECTION_REFUSED,
            "502 Bad Gateway",
            "error=connection_refused",
        ),
    ] {
        let socks_listener = TcpListener::bind("127.0.0.1:0").await?;
        let socks_addr = socks_listener.local_addr()?;
        let socks_task = tokio::spawn(async move {
            let (mut stream, _) = socks_listener.accept().await?;
            let _ = socks::read_request(&mut stream).await?;
            socks::write_reply(&mut stream, socks_code).await?;
            anyhow::Ok(())
        });

        let http_listener = TcpListener::bind("127.0.0.1:0").await?;
        let http_addr = http_listener.local_addr()?;
        let http_task = tokio::spawn(async move {
            let (stream, _) = http_listener.accept().await?;
            let _ = handle_http_connect(stream, socks_addr).await;
        });

        let mut client = TcpStream::connect(http_addr).await?;
        client
            .write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
            .await?;
        let mut buf = Vec::new();
        client.read_to_end(&mut buf).await?;
        let text = String::from_utf8_lossy(&buf);
        assert!(
            text.starts_with(&format!("HTTP/1.1 {expected_status}\r\n")),
            "unexpected status line: {text}"
        );
        assert!(
            text.contains(expected_tag),
            "missing {expected_tag} in response: {text}"
        );

        http_task.await?;
        socks_task.await??;
    }
    Ok(())
}
