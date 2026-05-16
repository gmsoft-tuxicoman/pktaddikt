use crate::base::{Parser, ParseErr};
use crate::proto::{ProtoPktProcessor, Protocols, ProtoInfo};
use crate::conntrack::{ConntrackTable, ConntrackKeyBidir};
use crate::packet::{Packet, PktInfoStack};
use crate::config::Config;

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

impl ProtoPktProcessor for ProtoIpv6 {

    fn new() -> Self {
        let cfg = Config::get();
        Self {
            ct: ConntrackTable::new(cfg.proto.ipv6.conntrack_size),
        }
    }

    fn process(&mut self, pkt: &mut Packet, infos: &mut PktInfoStack) -> Result<(), ParseErr> {

        let ver_tc_flow = pkt.read_u32_be()?;
        if ver_tc_flow >> 28 != 6 { // not IP version 6
            return Err(ParseErr::Invalid("IP version is not 6"));
        }

        let tot_len = pkt.read_u16_be()?;
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
            false => {
                let cfg = Config::get();
                ce_locked.set_timeout(Duration::from_secs(cfg.proto.ipv6.conntrack_timeout), pkt.timestamp())
            }
        }

        Ok(())

    }

}


#[cfg(test)]
mod tests {

    use super::*;
    use crate::packet::PktTime;

    #[test]
    fn ipv6_parse_basic() {
        let data = vec![ 0x60, 0x00, 0x00, 0x00, 0x00, 0x01, 0x11, 0x2A, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0xFF ];
        let mut pkt = Packet::from_slice(PktTime::from_micros(0), &data);
        let mut infos = PktInfoStack::new(Protocols::Ipv6);

        let ret = ProtoIpv6::new().process(&mut pkt, &mut infos);
        assert_eq!(ret, Ok(()));

        let info = infos.iter().next().unwrap();

        let expected = ProtoInfo::Ipv6(ProtoIpv6Info {
            src: Ipv6Addr::new(0x0102, 0x0304, 0x0506, 0x0708, 0x090A, 0x0B0C, 0x0D0E, 0x0F10),
            dst: Ipv6Addr::new(0x1112, 0x1314, 0x1516, 0x1718, 0x191A, 0x1B1C, 0x1D1E, 0x1F20),
            hop_limit: 42,
            proto: 17,
        });

        assert_eq!(info.proto_info, Some(expected));
    }

}
