use super::*;
use crate::routing::{DomainMatcher, RouteRule};

#[test]
fn route_proxy_state_hot_updates_routes_and_upstreams() {
    let target = ProxyTarget::Domain("example.com".to_string(), 443);
    let state = RouteProxyState::new(RouteTable::default(), BTreeMap::new(), None);
    assert_eq!(
        state.decide(&target, RouteNetwork::Tcp),
        RouteDecision::Direct
    );

    state.replace_routes(RouteTable {
        rules: vec![RouteRule::new(RouteDecision::Proxy("node-a".to_string()))],
        default: RouteDecision::Block,
        ..RouteTable::default()
    });
    assert_eq!(
        state.decide(&target, RouteNetwork::Tcp),
        RouteDecision::Proxy("node-a".to_string())
    );

    let first = "127.0.0.1:10001".parse().expect("valid socket addr");
    let second = "127.0.0.1:10002".parse().expect("valid socket addr");
    state.set_upstream("node-a", first);
    assert_eq!(state.upstream("node-a"), Some(first));
    state.set_upstream("node-a", second);
    assert_eq!(state.upstream("node-a"), Some(second));
    assert_eq!(state.remove_upstream("node-a"), Some(second));
    assert_eq!(state.upstream("node-a"), None);
}

#[tokio::test]
async fn route_proxy_surfaces_real_connect_errors() -> Result<()> {
    let mock_upstream = TcpListener::bind("127.0.0.1:0").await?;
    let mock_upstream_addr = mock_upstream.local_addr()?;
    let upstream_task = tokio::spawn(async move {
        let (mut stream, _) = mock_upstream.accept().await?;
        let _ = socks::read_request(&mut stream).await?;
        socks::write_reply(&mut stream, socks::REPLY_HOST_UNREACHABLE).await?;
        anyhow::Ok(())
    });

    let closed_probe = TcpListener::bind("127.0.0.1:0").await?;
    let closed_addr = closed_probe.local_addr()?;
    drop(closed_probe);

    let mut blocked_rule = RouteRule::new(RouteDecision::Block);
    blocked_rule
        .domains
        .push(DomainMatcher::Exact("blocked.example".to_string()));
    let mut proxy_rule = RouteRule::new(RouteDecision::Proxy("up".to_string()));
    proxy_rule
        .domains
        .push(DomainMatcher::Exact("nx.example".to_string()));

    let mut upstreams = BTreeMap::new();
    upstreams.insert("up".to_string(), mock_upstream_addr);
    let state = RouteProxyState::new(
        RouteTable {
            rules: vec![blocked_rule, proxy_rule],
            default: RouteDecision::Direct,
            ..RouteTable::default()
        },
        upstreams,
        None,
    );

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let route_addr = listener.local_addr()?;
    let stop = ListenerStopToken::new();
    let server_stop = stop.clone();
    let route_task = tokio::spawn(async move {
        run_route_proxy_with_state_until(listener, state, server_stop).await
    });

    let direct_err = socks::connect_tcp(route_addr, &ProxyTarget::Ip(closed_addr))
        .await
        .expect_err("closed local port must fail");
    assert_eq!(
        direct_err
            .downcast_ref::<socks::SocksConnectError>()
            .map(|err| err.code),
        Some(socks::REPLY_CONNECTION_REFUSED)
    );

    let block_err = socks::connect_tcp(
        route_addr,
        &ProxyTarget::Domain("blocked.example".into(), 443),
    )
    .await
    .expect_err("blocked domain must fail");
    assert_eq!(
        block_err
            .downcast_ref::<socks::SocksConnectError>()
            .map(|err| err.code),
        Some(socks::REPLY_NOT_ALLOWED)
    );

    let proxy_err = socks::connect_tcp(route_addr, &ProxyTarget::Domain("nx.example".into(), 443))
        .await
        .expect_err("upstream host unreachable must fail");
    assert_eq!(
        proxy_err
            .downcast_ref::<socks::SocksConnectError>()
            .map(|err| err.code),
        Some(socks::REPLY_HOST_UNREACHABLE)
    );

    stop.stop();
    route_task.await??;
    upstream_task.await??;
    Ok(())
}
