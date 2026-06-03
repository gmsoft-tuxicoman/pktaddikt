use crate::base::{Parser, ParseErr, UniqueId};
use crate::proto::{ProtoPktProcessor, ProtoInfo};
use crate::packet::{Packet, PktInfoStack};
use crate::proto::ethernet::EthernetMac;
use crate::event::{EventStr, Event, EventPayload, EventKind};
use crate::messagebus::MessageBus;

use std::net::Ipv4Addr;
use serde::Serialize;


#[derive(Debug, Serialize)]
pub struct NetDhcpMessage {

    pub conn_id: UniqueId,
    pub r#type: ProtoDhcpMessageType,
    pub xid: u32,
    pub secs: u16,
    pub ciaddr: Ipv4Addr,
    pub yiaddr: Ipv4Addr,
    pub siaddr: Ipv4Addr,
    pub giaddr: Ipv4Addr,
    pub chaddr: EthernetMac,
    pub sname: Option<EventStr>,
    pub file: Option<EventStr>,
    pub subnet: Option<Ipv4Addr>,

}

#[derive(Debug, PartialEq)]
pub struct ProtoDhcpInfo {
    
    pub msg_type: ProtoDhcpMessageType,
    pub client_hw: EthernetMac,
    pub client_ip: Ipv4Addr,

}

pub struct ProtoDhcp {}

#[derive(Debug, PartialEq, Serialize, Copy, Clone)]
pub enum ProtoDhcpMessageType {
    DHCPDISCOVER,
    DHCPOFFER,
    DHCPREQUEST,
    DHCPDECLINE,
    DHCPACK,
    DHCPNAK,
    DHCPRELEASE,
    DHCPINFORM,

    BOOTREQUEST,
    BOOTREPLY,
}

impl ProtoPktProcessor for ProtoDhcp {

    fn new() -> Self {
        Self {}
    }

    fn process(&mut self, pkt: &mut Packet, infos: &mut PktInfoStack) -> Result<(), ParseErr> {


        let op = pkt.read_u8()?;

        let mut msg_type = match op {
            1 => ProtoDhcpMessageType::BOOTREQUEST,
            2 => ProtoDhcpMessageType::BOOTREPLY,
            _ => return Err(ParseErr::Invalid("Invalid DHCP op")),
        };

        let htype = pkt.read_u8()?;

        if htype != 1 {
            return Err(ParseErr::Invalid("Hardware type is not ethernet"));
        }

        let hlen = pkt.read_u8()?;
        if hlen != 6 {
            return Err(ParseErr::Invalid("Hardware length not 6 for ethernet"));
        }

        let hops = pkt.read_u8()?;
        let xid = pkt.read_u32_be()?;
        let secs = pkt.read_u16_be()?;
        let flags = pkt.read_u16_be()?;
        let ciaddr = pkt.read_ipv4()?;
        let yiaddr = pkt.read_ipv4()?;
        let siaddr = pkt.read_ipv4()?;
        let giaddr = pkt.read_ipv4()?;
        let chaddr = EthernetMac(pkt.read_fixed::<6>()?);
        pkt.skip(10)?; // Hardware address padding


        let sname_raw = pkt.read_fixed::<64>()?;

        let sname: Option<EventStr> = (sname_raw.first() != Some(&0)).then(|| {
                EventStr::from(&sname_raw[.. sname_raw.iter().position(|&b| b == 0).unwrap_or(sname_raw.len()) ])
        });

        let file_raw = pkt.read_fixed::<128>()?;

        let file: Option<EventStr> = (file_raw.first() != Some(&0)).then(|| {
                EventStr::from(&file_raw[.. file_raw.iter().position(|&b| b == 0).unwrap_or(file_raw.len()) ])
        });

        if pkt.remaining_len() > 0 {
            if pkt.read_fixed::<4>()? != [ 0x63, 0x82, 0x53, 0x63 ] {
                return Err(ParseErr::Invalid("Invalid DHCP Magic Cookie"));
            }
        }

        let mut subnet: Option<Ipv4Addr> = None;

        while pkt.remaining_len() > 0 {
            
            let opt = pkt.read_u8()?;
        
            match opt {
                0 => continue, // Pad option
                255 => break, // End
                _ => (),
            }

            let opt_len = pkt.read_u8()?;
            match opt {
                1 => { // Subnet Mask
                    if opt_len !=4 { return Err(ParseErr::Invalid("Invalid DHCP subnet mask option length")); };
                    subnet = Some(pkt.read_ipv4()?);

                },
                53 => { // DHCP Message type
                    if opt_len != 1 { return Err(ParseErr::Invalid("Invalid DHCP message type option length")); };
                    msg_type = match pkt.read_u8()? {
                        1 => ProtoDhcpMessageType::DHCPDISCOVER,
                        2 => ProtoDhcpMessageType::DHCPOFFER,
                        3 => ProtoDhcpMessageType::DHCPREQUEST,
                        4 => ProtoDhcpMessageType::DHCPDECLINE,
                        5 => ProtoDhcpMessageType::DHCPACK,
                        6 => ProtoDhcpMessageType::DHCPNAK,
                        7 => ProtoDhcpMessageType::DHCPRELEASE,
                        8 => ProtoDhcpMessageType::DHCPINFORM,
                        _ => return Err(ParseErr::Invalid("Invalid DHCP message type option value")),
                    }
                },
                _ => pkt.skip(opt_len as u32)?,
            }
        }

        let mut proto_info = ProtoDhcpInfo {
            msg_type,
            client_hw: chaddr,
            client_ip: yiaddr,
        };

        let info = infos.proto_last_mut();
        info.proto_info = Some(ProtoInfo::Dhcp(proto_info));

        if MessageBus::event_has_subscribers(EventKind::NetDhcpMessage) {
            let evt_pload = NetDhcpMessage {

                conn_id: infos.get_conn_id().unwrap().clone(),
                r#type: msg_type,
                xid,
                secs,
                ciaddr,
                yiaddr,
                siaddr,
                giaddr,
                chaddr,
                sname,
                file,
                subnet,
            };

            let evt = Event::new(pkt.timestamp(), EventPayload::NetDhcpMessage(evt_pload));
            MessageBus::publish_event(evt);
        }

        Ok(())
    }
}
