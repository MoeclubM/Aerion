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
