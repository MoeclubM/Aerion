use super::*;

#[test]
fn grpc_service_name_maps_to_tun_path() {
    let transport = VlessTransportConfig::grpc(Some("TunService".to_string()), None, vec![]);
    assert_eq!(transport.path, "/TunService/Tun");
}

#[test]
fn grpc_xray_style_path_uses_stream_before_pipe() {
    let transport =
        VlessTransportConfig::grpc(Some("/my/service/Tun|TunMulti".to_string()), None, vec![]);
    assert_eq!(transport.path, "/my/service/Tun");
}

#[test]
fn xhttp_accepts_auto_as_stream_one() -> Result<()> {
    let transport = VlessTransportConfig::xhttp(
        Some("x".to_string()),
        None,
        vec![],
        Some("auto".to_string()),
    )?;
    assert_eq!(transport.kind, VlessTransportKind::Xhttp);
    assert_eq!(transport.path, "/x");
    assert_eq!(transport.mode, "stream-one");
    Ok(())
}

#[test]
fn xhttp_rejects_split_modes_until_wired() {
    let error = VlessTransportConfig::xhttp(
        Some("/x".to_string()),
        None,
        vec![],
        Some("packet-up".to_string()),
    )
    .expect_err("packet-up is not stream-one");
    assert!(error.to_string().contains("stream-one"));
}

#[test]
fn splithttp_is_stream_one_xhttp_alias() -> Result<()> {
    let transport =
        VlessTransportConfig::from_network("splithttp", Some("/split".to_string()), None, vec![])?;
    assert_eq!(transport.kind, VlessTransportKind::Xhttp);
    assert_eq!(transport.path, "/split");
    assert_eq!(transport.mode, "stream-one");
    Ok(())
}
