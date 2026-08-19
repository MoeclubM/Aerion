use super::*;

#[test]
fn maps_ip_packets_to_packet_flow_protocols() -> Result<()> {
    let ipv4 = vec![0x45, 0, 0, 20];
    let ipv6 = vec![0x60, 0, 0, 0];
    let packets = packet_flow_packets_from_ip_packets([ipv4.clone(), ipv6.clone()])?;

    assert_eq!(
        packet_flow_address_families(&packets),
        vec![IOS_PACKET_FLOW_IPV4_PROTOCOL, IOS_PACKET_FLOW_IPV6_PROTOCOL]
    );
    assert_eq!(
        packet_flow_payloads(&packets),
        vec![ipv4.as_slice(), ipv6.as_slice()]
    );
    Ok(())
}

#[test]
fn validates_packet_flow_protocol_matches_payload() -> Result<()> {
    let packet = IosPacketFlowPacket::from_parts(
        IosPacketFlowProtocol::from_address_family(IOS_PACKET_FLOW_IPV4_PROTOCOL)?,
        vec![0x45, 0],
    )?;
    assert_eq!(packet.protocol, IosPacketFlowProtocol::Ipv4);

    let error = IosPacketFlowPacket::from_parts(IosPacketFlowProtocol::Ipv4, vec![0x60, 0])
        .expect_err("mismatched PacketFlow protocol must fail");
    assert!(error.to_string().contains("does not match"));
    Ok(())
}
