use anyhow::{Result, bail, ensure};

pub const IOS_PACKET_FLOW_IPV4_PROTOCOL: u32 = 2;
pub const IOS_PACKET_FLOW_IPV6_PROTOCOL: u32 = 30;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IosPacketFlowProtocol {
    Ipv4,
    Ipv6,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IosPacketFlowPacket {
    pub protocol: IosPacketFlowProtocol,
    pub packet: Vec<u8>,
}

impl IosPacketFlowProtocol {
    pub fn address_family(self) -> u32 {
        match self {
            Self::Ipv4 => IOS_PACKET_FLOW_IPV4_PROTOCOL,
            Self::Ipv6 => IOS_PACKET_FLOW_IPV6_PROTOCOL,
        }
    }

    pub fn from_address_family(value: u32) -> Result<Self> {
        match value {
            IOS_PACKET_FLOW_IPV4_PROTOCOL => Ok(Self::Ipv4),
            IOS_PACKET_FLOW_IPV6_PROTOCOL => Ok(Self::Ipv6),
            other => bail!("unsupported iOS PacketFlow protocol {other}"),
        }
    }

    pub fn from_ip_packet(packet: &[u8]) -> Result<Self> {
        ensure!(!packet.is_empty(), "iOS PacketFlow packet is empty");
        match packet[0] >> 4 {
            4 => Ok(Self::Ipv4),
            6 => Ok(Self::Ipv6),
            other => bail!("unsupported iOS PacketFlow IP version {other}"),
        }
    }

    pub fn validate_ip_packet(self, packet: &[u8]) -> Result<()> {
        let actual = Self::from_ip_packet(packet)?;
        ensure!(
            actual == self,
            "iOS PacketFlow protocol {:?} does not match packet {:?}",
            self,
            actual
        );
        Ok(())
    }
}

impl IosPacketFlowPacket {
    pub fn from_ip_packet(packet: impl Into<Vec<u8>>) -> Result<Self> {
        let packet = packet.into();
        let protocol = IosPacketFlowProtocol::from_ip_packet(&packet)?;
        Ok(Self { protocol, packet })
    }

    pub fn from_parts(protocol: IosPacketFlowProtocol, packet: impl Into<Vec<u8>>) -> Result<Self> {
        let packet = packet.into();
        protocol.validate_ip_packet(&packet)?;
        Ok(Self { protocol, packet })
    }

    pub fn address_family(&self) -> u32 {
        self.protocol.address_family()
    }
}

pub fn packet_flow_packets_from_ip_packets<I, P>(packets: I) -> Result<Vec<IosPacketFlowPacket>>
where
    I: IntoIterator<Item = P>,
    P: Into<Vec<u8>>,
{
    packets
        .into_iter()
        .map(IosPacketFlowPacket::from_ip_packet)
        .collect()
}

pub fn packet_flow_packets_from_parts<I, P>(packets: I) -> Result<Vec<IosPacketFlowPacket>>
where
    I: IntoIterator<Item = (u32, P)>,
    P: Into<Vec<u8>>,
{
    packets
        .into_iter()
        .map(|(protocol, packet)| {
            IosPacketFlowPacket::from_parts(
                IosPacketFlowProtocol::from_address_family(protocol)?,
                packet,
            )
        })
        .collect()
}

pub fn packet_flow_address_families(packets: &[IosPacketFlowPacket]) -> Vec<u32> {
    packets
        .iter()
        .map(IosPacketFlowPacket::address_family)
        .collect()
}

pub fn packet_flow_payloads(packets: &[IosPacketFlowPacket]) -> Vec<&[u8]> {
    packets
        .iter()
        .map(|packet| packet.packet.as_slice())
        .collect()
}

#[cfg(test)]
mod tests {
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
}
