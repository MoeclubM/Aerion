use super::*;
use crate::routing::RouteRule;

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
