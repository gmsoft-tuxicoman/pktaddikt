use crate::base::{Parser, ParseErr, UniqueId};
use crate::proto::{ProtoPktProcessor, ProtoInfo};
use crate::packet::{Packet, PktInfoStack, PktTime};
use crate::proto::ethernet::EthernetMac;
use crate::event::{EventStr, Event, EventPayload, EventKind};
use crate::messagebus::MessageBus;
use crate::timer::{TimerManager, TimerCb, TimerId};
use crate::config::Config;

use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::time::Duration;
use serde::{Serialize, Deserialize};

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DhcpConfig {
    pub dora_timeout: u64,
}

impl Default for DhcpConfig {
    fn default() -> Self {
        Self {
            dora_timeout: 70,
        }
    }
}

#[derive(Debug, Serialize)]
pub enum NetDhcpOptions {

    Subnet(Ipv4Addr),
    Hostname(EventStr),
    RequestedIP(Ipv4Addr),
    LeaseTime(u32),
    DomainName(EventStr),
    ServerIdentifier(Ipv4Addr),
}

#[derive(Debug, Serialize)]
pub struct NetDhcpMessage {

    pub conn_id: UniqueId,
    pub client_ip: Ipv4Addr,
    pub client_port: u16,
    pub server_ip: Ipv4Addr,
    pub server_port: u16,
    pub r#type: ProtoDhcpMessageType,
    pub hops: u8,
    pub xid: u32,
    pub secs: u16,
    pub ciaddr: Ipv4Addr,
    pub yiaddr: Ipv4Addr,
    pub siaddr: Ipv4Addr,
    pub giaddr: Ipv4Addr,
    pub chaddr: EthernetMac,
    pub sname: Option<EventStr>,
    pub file: Option<EventStr>,
    pub options: Vec<NetDhcpOptions>,
}

#[derive(Debug, Serialize)]
pub struct NetDhcpDora {

    pub conns_id: Vec<UniqueId>,
    pub msgs: Vec<ProtoDhcpMessageType>,
    pub client_mac: EthernetMac,
    pub client_ip: Option<Ipv4Addr>,
    pub client_port: u16,
    pub server_ip: Option<Ipv4Addr>,
    pub server_port: u16,
    pub assigned_ip: Option<Ipv4Addr>,
    pub requested_ip: Option<Ipv4Addr>,
    pub subnet: Option<Ipv4Addr>,
    pub hostname: Option<EventStr>,
    pub lease_time: Option<u32>,
    pub domain_name: Option<EventStr>,
    pub duration: Duration,
}

#[derive(Debug, PartialEq)]
pub struct ProtoDhcpInfo {
    
    pub msg_type: ProtoDhcpMessageType,
    pub client_hw: EthernetMac,
    pub assigned_ip: Ipv4Addr,

}

struct ProtoDhcpConvo {

    evt: NetDhcpDora,
    first_seen: PktTime,
    last_seen: PktTime,
    timer: TimerId,
}

pub struct ProtoDhcp {

    convo: Arc<Mutex<HashMap<EthernetMac, ProtoDhcpConvo>>>,

}

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
        Self {
            convo: Arc::new(Mutex::new(HashMap::new())),
        }
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
        pkt.skip_u16()?; // Flags
        let ciaddr = pkt.read_ipv4()?;
        let yiaddr = pkt.read_ipv4()?;
        let siaddr = pkt.read_ipv4()?;
        let giaddr = pkt.read_ipv4()?;
        let chaddr = EthernetMac(pkt.read_fixed::<6>()?);
        pkt.skip(10)?; // Hardware address padding

        if ! MessageBus::event_has_subscribers(EventKind::NetDhcpMessage) && ! MessageBus::event_has_subscribers(EventKind::NetDhcpDora) {
            // No need to parse more if events aren't being listened to
            return Ok(());
        }


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
        let mut hostname: Option<EventStr> = None;
        let mut requested_ip: Option<Ipv4Addr> = None;
        let mut lease_time: Option<u32> = None;
        let mut domain_name: Option<EventStr> = None;
        let mut server_identifier: Option<Ipv4Addr> = None;

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
                12 => { // Hostname
                    hostname = Some(EventStr::from(pkt.read(opt_len as u32)?));
                },
                15 => { // Domain name
                    domain_name = Some(EventStr::from(pkt.read(opt_len as u32)?));
                },
                50 => { // Requested IP
                    if opt_len !=4 { return Err(ParseErr::Invalid("Invalid requested IP option length")); };
                    requested_ip = Some(pkt.read_ipv4()?);
                },
                51 => { // Lease time
                    if opt_len !=4 { return Err(ParseErr::Invalid("Invalid lease time option length")); };
                    lease_time = Some(pkt.read_u32_be()?);
                }
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
                54 => { // Server Identifier
                    if opt_len !=4 { return Err(ParseErr::Invalid("Invalid server identifier option length")); };
                    server_identifier = Some(pkt.read_ipv4()?);
                },
                _ => pkt.skip(opt_len as u32)?,
            }
        }


        let conn_info = infos.get_conn_info();
        let (IpAddr::V4(server_ip), server_port, IpAddr::V4(client_ip), client_port) = (match msg_type {
            ProtoDhcpMessageType::BOOTREQUEST |
            ProtoDhcpMessageType::DHCPDISCOVER |
            ProtoDhcpMessageType::DHCPREQUEST |
            ProtoDhcpMessageType::DHCPDECLINE |
            ProtoDhcpMessageType::DHCPRELEASE |
            ProtoDhcpMessageType::DHCPINFORM =>  {
                // Client request
                (conn_info.dst_host.unwrap(), conn_info.dst_port.unwrap(), conn_info.src_host.unwrap(), conn_info.src_port.unwrap())
            },
            _ => {
                // Server request
                (conn_info.src_host.unwrap(), conn_info.src_port.unwrap(), conn_info.dst_host.unwrap(), conn_info.dst_port.unwrap())
            }

        }) else {
            return Err(ParseErr::Invalid("Unexpected IP type"));
        };

        let proto_info = ProtoDhcpInfo {
            msg_type,
            client_hw: chaddr,
            assigned_ip: yiaddr,
        };

        let info = infos.proto_last_mut();
        info.proto_info = Some(ProtoInfo::Dhcp(proto_info));

        if MessageBus::event_has_subscribers(EventKind::NetDhcpMessage) {
            let mut evt_pload = NetDhcpMessage {

                conn_id: infos.get_conn_id().unwrap().clone(),
                client_ip: client_ip.clone(),
                client_port,
                server_ip: server_ip.clone(),
                server_port,
                r#type: msg_type,
                hops,
                xid,
                secs,
                ciaddr,
                yiaddr,
                siaddr,
                giaddr,
                chaddr,
                sname,
                file,
                options: Vec::new(),
            };

            if let Some(s) = subnet {
                evt_pload.options.push(NetDhcpOptions::Subnet(s));
            }

            if let Some(ref h) = hostname {
                evt_pload.options.push(NetDhcpOptions::Hostname(h.clone()));
            }

            if let Some(r) = requested_ip {
                evt_pload.options.push(NetDhcpOptions::RequestedIP(r));
            }

            if let Some(l) = lease_time {
                evt_pload.options.push(NetDhcpOptions::LeaseTime(l));
            }

            if let Some(ref d) = domain_name {
                evt_pload.options.push(NetDhcpOptions::DomainName(d.clone()));
            }

            if let Some(s) = server_identifier {
                evt_pload.options.push(NetDhcpOptions::ServerIdentifier(s));
            }

            let evt = Event::new(pkt.timestamp(), EventPayload::NetDhcpMessage(evt_pload));
            MessageBus::publish_event(evt);
        }

        if MessageBus::event_has_subscribers(EventKind::NetDhcpDora) {

            let mut convo_locked = self.convo.lock().unwrap();

            let cfg = Config::get();

            let dora = match convo_locked.entry(chaddr) {
                Entry::Vacant(e) => {
                    let evt = NetDhcpDora {

                        conns_id: vec![infos.get_conn_id().unwrap().clone()],
                        msgs: vec![msg_type],
                        client_mac: chaddr,
                        client_ip: None,
                        client_port,
                        server_ip: None,
                        server_port,
                        hostname: None,
                        assigned_ip: None,
                        lease_time: None,
                        requested_ip: None,
                        subnet: None,
                        domain_name: None,
                        duration: Duration::ZERO,
                    };

                    let convo_clone = self.convo.clone();
                    let cleanup: TimerCb = Arc::new(move || {
                        if let Some(mut entry) = convo_clone.lock().unwrap().remove(&chaddr) {
                            entry.evt.duration = (entry.last_seen - entry.first_seen).into();
                            let evt = Event::new(entry.last_seen, EventPayload::NetDhcpDora(entry.evt));
                            MessageBus::publish_event(evt);
                        }
                    });

                    let timer = TimerManager::queue_new(Duration::from_secs(cfg.proto.dhcp.dora_timeout), pkt.timestamp(), cleanup);

                    e.insert(ProtoDhcpConvo {
                        evt,
                        first_seen: pkt.timestamp(),
                        last_seen: pkt.timestamp(),
                        timer
                    })
                },
                Entry::Occupied(e) => {
                    let dora = e.into_mut();
                    TimerManager::requeue(dora.timer, Duration::from_secs(cfg.proto.dhcp.dora_timeout), pkt.timestamp());

                    // Add the conn_id if it's not in there already
                    let conn_id = infos.get_conn_id().unwrap();
                    if ! dora.evt.conns_id.contains(conn_id) {
                        dora.evt.conns_id.push(conn_id.clone());
                    }
                    // Add the message if it's not in there already
                    if ! dora.evt.msgs.contains(&msg_type) {
                        dora.evt.msgs.push(msg_type);
                    }


                    // Update last seen
                    dora.last_seen = pkt.timestamp();

                    dora
                },
            };

            let evt_pload = &mut dora.evt;
            if evt_pload.client_ip.is_none() && client_ip != Ipv4Addr::UNSPECIFIED {
                evt_pload.client_ip = Some(client_ip.clone());
            }

            if evt_pload.assigned_ip.is_none() && yiaddr != Ipv4Addr::UNSPECIFIED {
                evt_pload.assigned_ip = Some(yiaddr.clone());
            }

            if evt_pload.server_ip.is_none() && server_ip != Ipv4Addr::BROADCAST {
                evt_pload.server_ip = Some(server_ip.clone());
            }

            evt_pload.subnet =  evt_pload.subnet.or(subnet);
            evt_pload.requested_ip = evt_pload.requested_ip.or(requested_ip);
            evt_pload.lease_time = evt_pload.lease_time.or(lease_time);

            if evt_pload.hostname.is_none() {
                evt_pload.hostname = hostname;
            }

            if evt_pload.domain_name.is_none() {
                evt_pload.domain_name = domain_name;
            }
        }

        Ok(())
    }
}
