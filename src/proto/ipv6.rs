use crate::base::{Parser, ParseErr};
use crate::proto::{ProtoPktProcessor, Protocols, ProtoInfo};
use crate::conntrack::{ConntrackTable, ConntrackKeyBidir};
use crate::packet::{Packet, PktInfoStack};
use crate::config::ConfigRef;

use std::net::Ipv6Addr;
use std::time::Duration;
use serde::Deserialize;

#[derive(Debug, PartialEq)]
pub struct ProtoIpv6Info {
    pub src: Ipv6Addr,
    pub dst: Ipv6Addr,
    pub hop_limit: u8,
    pub proto: u8,
}

pub struct ProtoIpv6 {
    cfg: ConfigRef,
    ct: ConntrackTable<ConntrackKeyIpv6>,
}


type ConntrackKeyIpv6 = ConntrackKeyBidir<u64>;


#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Ipv6Config {
    pub conntrack_size: usize,
    pub conntrack_timeout: u64,
}

impl Default for Ipv6Config {
    fn default() -> Self {
        Self {
            conntrack_size: 65535,
            conntrack_timeout: 7200,
        }
    }
}

impl ProtoIpv6 {
    pub fn new(cfg: ConfigRef) -> Self {
        Self {
            cfg: cfg.clone(),
            ct: ConntrackTable::new(cfg.proto.ipv6.conntrack_size),
        }
    }
}

impl ProtoPktProcessor for ProtoIpv6 {

    fn process(&mut self, pkt: &mut Packet, infos: &mut PktInfoStack) -> Result<(), ParseErr> {

        let ver_tc_flow = pkt.read_u32_be()?;
        if ver_tc_flow >> 28 != 6 { // not IP version 6
            return Err(ParseErr::Invalid("IP version is not 6"));
        }

        let tot_len = pkt.read_u32_be()?;
        let mut nhdr = pkt.read_u8()?;
        let hop_limit = pkt.read_u8()?;
        let src = pkt.read_ipv6()?;
        let dst = pkt.read_ipv6()?;




        loop {
            nhdr = match nhdr {
                0  |  // HOPOPTS
                43 |  // ROUTING
                44 |  // FRAGMENT (TODO)
                60 => { // DSTOPTS
                    // Read header length
                    let nhdr_len = pkt.read_u8()?;
                    // Skip header
                    pkt.skip(nhdr_len as usize)?;
                    pkt.read_u8()?
                }

                _ => {
                    break;
                }
            }
        }

        let info = infos.proto_last_mut();

        let proto_info = ProtoIpv6Info {
            src,
            dst,
            hop_limit,
            proto: nhdr,
        };

        info.proto_info = Some(ProtoInfo::Ipv6(proto_info));
        info.tot_len = tot_len as usize;

        let a = src.to_bits();
        let b = dst.to_bits();

        let next_proto = match nhdr {
            4 => Protocols::Ipv4,
            6 => Protocols::Tcp,
            17 => Protocols::Udp,
            41 => Protocols::Ipv6,
            _ => Protocols::None

        };

        if next_proto == Protocols::None {
            // Cut short processing if we don't know what the next proto is
            infos.proto_push(next_proto, None);
            return Ok(());
        }

        let ct_key = ConntrackKeyIpv6 { a: ((a >> 8) as u64) ^ (a as u64) , b: ((b >> 8) as u64) ^ (b as u64) };
        let (ce, ce_dir) = self.ct.get(ct_key, info.parent_ce());

        infos.proto_push(next_proto, Some((ce.clone(), ce_dir)));
        let mut ce_locked = ce.lock().unwrap();

        match ce_locked.has_children() {
            true => ce_locked.set_timeout(Duration::ZERO, pkt.timestamp()),
            false => ce_locked.set_timeout(Duration::from_secs(self.cfg.proto.ipv6.conntrack_timeout), pkt.timestamp())
        }

        Ok(())

    }

}

