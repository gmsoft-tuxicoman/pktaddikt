use crate::base::{Parser, ParseErr};
use crate::proto::{ProtoPktProcessor, Protocols, ProtoInfo};
use crate::conntrack::{ConntrackTable, ConntrackKeyBidir, ConntrackData, ConntrackTimer, ConntrackRef};
use crate::packet::{Packet, PacketMultipart, PktInfoStack};
use crate::config::Config;

use std::sync::Arc;
use std::net::Ipv4Addr;
use std::collections::HashMap;
use std::time::Duration;
use serde::Deserialize;
use tracing::{debug, trace};

const IP_DONT_FRAG: u16 = 0x4000;
const IP_MORE_FRAG: u16 = 0x2000;
const IP_OFFSET_MASK: u16 = 0x1FFF;


#[derive(Debug, PartialEq)]
pub struct ProtoIpv4Info {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub id: u16,
    pub hdr_len: u16,
    pub ttl: u8,
    pub proto: u8,
}

pub struct ProtoIpv4 {
    ct: ConntrackTable<ConntrackKeyIpv4>,
}

type ConntrackKeyIpv4 = ConntrackKeyBidir<u32>;

struct Ipv4Fragment {
    pkt: Option<PacketMultipart>,
    timer: ConntrackTimer
}

struct ConntrackIpv4 {
    fragments: HashMap<u16, Ipv4Fragment>
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Ipv4Config {

    pub conntrack_size: usize,
    pub conntrack_timeout: u64,
    pub fragment_timeout: u64,
}

impl Default for Ipv4Config {
    fn default() -> Self {
        Self {
            conntrack_size: 65535,
            conntrack_timeout: 7200,
            fragment_timeout: 30,
        }
    }
}

impl ProtoIpv4 {

    fn frag_cleanup(ce: ConntrackRef, frag_id: u16) {
        let mut ce_locked = ce.lock().unwrap();

        let cd = ce_locked.get_or_insert_with(|| Box::new(ConntrackIpv4 { fragments: HashMap::new() }) as ConntrackData)
                    .downcast_mut::<ConntrackIpv4>()
                    .unwrap();
        trace!("Fragment cleaned up with conntrack {:p} and id {}", Arc::as_ptr(&ce), frag_id);
        cd.fragments.remove(&frag_id);
    }
}

impl ProtoPktProcessor for ProtoIpv4 {

    fn new() -> Self {
        let cfg = Config::get();
        Self {
            ct: ConntrackTable::new(cfg.proto.ipv4.conntrack_size),
        }
    }

    fn process(&mut self, pkt: &mut Packet, infos: &mut PktInfoStack) -> Result<(), ParseErr> {

        let ver_len = pkt.read_u8()?;
        let ip_version = ver_len >> 4;
        if ip_version != 4 { // not IP version 4
            debug!("Invalid protocol version : {} in packet {:p}", ip_version, pkt);
            return Err(ParseErr::Invalid("IP version is not 4"));
        }
        pkt.skip_u8()?; // TOS

        let hdr_len = (ver_len & 0xf) as u16 * 4;

        let tot_len = pkt.read_u16_be()?;
        let id = pkt.read_u16_be()?;
        let frag_off = pkt.read_u16_be()?;
        let ttl = pkt.read_u8()?;
        let proto = pkt.read_u8()?;
        pkt.skip_u16()?; // Checksum
        let src = pkt.read_ipv4()?;
        let dst = pkt.read_ipv4()?;

        if hdr_len < 20 { // header length smaller than minimum IP header
            debug!("Header length too small for packet {:p}", pkt);
            return Err(ParseErr::Invalid("Header length too small"));
        }

        if tot_len <= hdr_len { // Total length <= header length
            debug!("Total length shorter than header size in packet {:p}", pkt);
            return Err(ParseErr::Invalid("Total length shorter than header size"));
        }

        // Check that the packet isn't truncated
        pkt.has_len((tot_len - 20) as u32)?;

        // Skip IP options
        pkt.skip((hdr_len as u32) - 20)?;

        // Shrink payload to the right size
        let data_len = (tot_len - hdr_len) as u32;
        if data_len < pkt.remaining_len() {
            pkt.shrink(data_len);
        }


        let info = infos.proto_last_mut();

        let proto_info = ProtoIpv4Info {
            src,
            dst,
            id,
            hdr_len,
            ttl,
            proto,
        };

        info.proto_info = Some(ProtoInfo::Ipv4(proto_info));
        info.tot_len = tot_len as u32;
        info.data_len = data_len;


        let next_proto = match proto {
            1 => Protocols::Icmp,
            4 => Protocols::Ipv4,
            6 => Protocols::Tcp,
            17 => Protocols::Udp,
            41 => Protocols::Ipv6,
            255 => Protocols::Test,
            _ => Protocols::None
        };

        if next_proto == Protocols::None {
            // Cut short processing if we don't know what the next proto is
            infos.proto_push(next_proto, None);
            return Ok(());
        }

        let ct_key = ConntrackKeyIpv4 { a: src.to_bits(), b: dst.to_bits()};
        let (ce, ce_dir) = self.ct.get(ct_key, info.parent_ce());


        infos.proto_push(next_proto, Some((ce.clone(), ce_dir)));
        let mut ce_locked = ce.lock().unwrap();
        let cfg = Config::get();

        match ce_locked.has_children() {
            true => ce_locked.set_timeout(Duration::ZERO, pkt.timestamp()),
            false => ce_locked.set_timeout(Duration::from_secs(cfg.proto.ipv4.conntrack_timeout), pkt.timestamp())
        }

        // Check if the packet is fragmented and needs more handling

        // Full packet (offset is 0 and no more packets)
        if (frag_off & IP_MORE_FRAG) == 0 && (frag_off & IP_OFFSET_MASK) == 0 {
            return Ok(());
        }

        // Packet cannot be fragmented
        if (frag_off & IP_DONT_FRAG) != 0 {
            return Ok(());
        }

        if ((frag_off & IP_MORE_FRAG) != 0) && ((data_len % 8) != 0) {
            // Fragment parts must be multiple of 8 bytes
            return Err(ParseErr::Invalid("IP fragment not multiple of 8 bytes"));
        }

        let offset = ((frag_off & IP_OFFSET_MASK) << 3) as u32;

        let cd = ce_locked.get_or_insert_with(|| Box::new(ConntrackIpv4 { fragments: HashMap::new() }) as ConntrackData)
                    .downcast_mut::<ConntrackIpv4>()
                    .unwrap();

        let frags_entry = cd.fragments.entry(id);

        let frags = frags_entry
            .and_modify(|v| {
                trace!("Fragment data with conntrack {:p} and id {}", Arc::as_ptr(&ce), id);
                ConntrackTimer::requeue(&v.timer, Duration::from_secs(cfg.proto.ipv4.fragment_timeout), pkt.timestamp());
            })
            .or_insert_with( || {
                    trace!("Fragment created with conntrack {:p} and id {}", Arc::as_ptr(&ce), id);
                    Ipv4Fragment {
                        pkt: Some(PacketMultipart::new(1500)),
                        timer: ConntrackTimer::new(&ce, Duration::from_secs(cfg.proto.ipv4.fragment_timeout), pkt.timestamp(), Arc::new(move |x| ProtoIpv4::frag_cleanup(x, id))),
                    }
                }
            );

        if frags.pkt.is_none() {
            // The fragment has been processed
            return Err(ParseErr::Stop);
        }

        let frags_pkt = frags.pkt.as_mut().unwrap();
        frags_pkt.add(offset, pkt.remaining_data());

        if (frag_off & IP_MORE_FRAG) == 0 {
            // Last fragment
            frags_pkt.set_expected_len(offset + data_len);
        }

        if frags_pkt.is_complete() {
            // Process the reassembled packet
            let complete_pkt = frags.pkt.take().unwrap();

            let new_pkt = Packet::from_vec(pkt.timestamp(), Arc::new(complete_pkt.take_data()));

            return Err(ParseErr::New(new_pkt));

        }

        return Err(ParseErr::Stop);
    }

}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::packet::PktTime;
    use tracing_test::traced_test;

    fn ipv4_parse_test(proto: &mut ProtoIpv4, data: &[u8], ts: PktTime) -> Result<(), ParseErr> {
        let mut pkt = Packet::from_slice(ts, data);
        let mut infos = PktInfoStack::new(Protocols::Ipv4);

        proto.process(&mut pkt, &mut infos)
    }

    #[test]
    fn ipv4_parse_basic() {
        let data = vec![ 0x45, 0x00, 0x00, 0x16, 0xbe, 0xef, 0x00, 0x00, 0x40, 0x11, 0xff, 0xff, 0x01, 0x02, 0x03, 0x04, 0x10, 0x20, 0x30, 0x40, 0xde, 0xad ];
        let mut pkt = Packet::from_slice(PktTime::from_micros(0), &data);
        let mut infos = PktInfoStack::new(Protocols::Ipv4);

        let ret = ProtoIpv4::new().process(&mut pkt, &mut infos);
        assert_eq!(ret, Ok(()));

        let info = infos.iter().next().unwrap();

        let expected = ProtoInfo::Ipv4(ProtoIpv4Info {
            src: Ipv4Addr::new(0x01, 0x02, 0x03, 0x04),
            dst: Ipv4Addr::new(0x10, 0x20, 0x30, 0x40),
            id: 48879,
            hdr_len: 20,
            ttl: 64,
            proto: 17,
        });

        assert_eq!(info.proto_info, Some(expected));
    }

    #[test]
    #[traced_test]
    fn ipv4_packet_too_short() {
        let data = vec![ 0x45, 0x00, 0x05, 0xdc, 0xbe, 0xef, 0x00, 0x00, 0x40, 0x11, 0xff, 0xff, 0x01, 0x01, 0x01, 0x01, 0x02, 0x02, 0x02 ];
        let ret = ipv4_parse_test(&mut ProtoIpv4::new(), &data, PktTime::from_micros(0));
        assert_eq!(ret, Err(ParseErr::Truncated));
    }

    #[test]
    #[traced_test]
    fn ipv4_invalid_version() {
        let data = vec![ 0x55, 0x00, 0x05, 0xdc, 0xbe, 0xef, 0x00, 0x00, 0x40, 0x11, 0xff, 0xff, 0x01, 0x01, 0x01, 0x01, 0x02, 0x02, 0x02, 0x02 ];
        let ret = ipv4_parse_test(&mut ProtoIpv4::new(), &data, PktTime::from_micros(0));
        assert_eq!(ret, Err(ParseErr::Invalid("")));
        assert!(logs_contain("Invalid protocol version : 5"));
    }

    #[test]
    #[traced_test]
    fn ipv4_hlen_too_short() {
        let data = vec![ 0x44, 0x00, 0x05, 0xdc, 0xbe, 0xef, 0x00, 0x00, 0x40, 0x11, 0xff, 0xff, 0x01, 0x01, 0x01, 0x01, 0x02, 0x02, 0x02, 0x02 ];
        let ret = ipv4_parse_test(&mut ProtoIpv4::new(), &data, PktTime::from_micros(0));
        assert_eq!(ret, Err(ParseErr::Invalid("")));
        assert!(logs_contain("Header length too small"));
    }

    #[test]
    #[traced_test]
    fn ipv4_totlen_too_short() {
        let data = vec![ 0x45, 0x00, 0x00, 0x14, 0xbe, 0xef, 0x00, 0x00, 0x40, 0x11, 0xff, 0xff, 0x01, 0x01, 0x01, 0x01, 0x02, 0x02, 0x02, 0x02 ];
        let ret = ipv4_parse_test(&mut ProtoIpv4::new(), &data, PktTime::from_micros(0));
        assert_eq!(ret, Err(ParseErr::Invalid("")));
        assert!(logs_contain("Total length shorter than header size"));
    }

    #[test]
    #[traced_test]
    fn ipv4_truncated_pkt() {
        let data = vec![ 0x45, 0x00, 0x00, 0xff, 0xbe, 0xef, 0x00, 0x00, 0x40, 0x11, 0xff, 0xff, 0x01, 0x01, 0x01, 0x01, 0x02, 0x02, 0x02, 0x02 ];
        let ret = ipv4_parse_test(&mut ProtoIpv4::new(), &data, PktTime::from_micros(0));
        assert_eq!(ret, Err(ParseErr::Truncated));
    }

    #[test]
    fn ipv4_pkt_shrink() {
        let data = vec![ 0x45, 0x00, 0x00, 0x15, 0xbe, 0xef, 0x00, 0x00, 0x40, 0x11, 0xff, 0xff, 0x01, 0x01, 0x01, 0x01, 0x02, 0x02, 0x02, 0x02, 0xff, 0xff ];
        let mut pkt = Packet::from_slice(PktTime::from_micros(0), &data);
        let mut infos = PktInfoStack::new(Protocols::Ipv4);

        let ret = ProtoIpv4::new().process(&mut pkt, &mut infos);

        assert_eq!(ret, Ok(()));
        assert_eq!(pkt.remaining_len(), 1);

    }

    #[test]
    #[traced_test]
    fn ipv4_frag() {
        // Frag 1 (MORE FRAG set)
        let data1 = vec![ 0x45, 0x00, 0x00, 0x1c, 0x05, 0x39, 0x20, 0x00, 0x40, 0xff, 0xff, 0xff, 0x01, 0x01, 0x01, 0x01, 0x02, 0x02, 0x02, 0x02, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a ];
        // Frag 2 continued data with 0xb data
        let data2 = vec![ 0x45, 0x00, 0x00, 0x1c, 0x05, 0x39, 0x20, 0x01, 0x40, 0xff, 0xff, 0xff, 0x01, 0x01, 0x01, 0x01, 0x02, 0x02, 0x02, 0x02, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b ];
        // Frag 3 final data with 0xc data
        let data3 = vec![ 0x45, 0x00, 0x00, 0x15, 0x05, 0x39, 0x00, 0x02, 0x40, 0xff, 0xff, 0xff, 0x01, 0x01, 0x01, 0x01, 0x02, 0x02, 0x02, 0x02, 0x0c ];

        let expect_data = vec![ 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0c];

        let mut ipv4 = ProtoIpv4::new();

        let ret1 = ipv4_parse_test(&mut ipv4, &data1, PktTime::from_micros(0));
        assert_eq!(ret1, Err(ParseErr::Stop));
        let ret2 = ipv4_parse_test(&mut ipv4, &data2, PktTime::from_micros(1));
        assert_eq!(ret2, Err(ParseErr::Stop));
        let mut ret3 = ipv4_parse_test(&mut ipv4, &data3, PktTime::from_micros(2));

        let pkt = match ret3 {
            Err(ParseErr::New(ref mut p)) => p,
            _ => panic!("Reassembled fragment not found"),
        };

        assert_eq!(pkt.remaining_data(), expect_data);

    }

    #[test]
    fn ipv4_frag_not_8byte_multiple() {
        // Frag 2 continued data with 0xb data
        let data = vec![ 0x45, 0x00, 0x00, 0x1b, 0x05, 0x39, 0x20, 0x01, 0x40, 0x11, 0xff, 0xff, 0x01, 0x01, 0x01, 0x01, 0x02, 0x02, 0x02, 0x02, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b ];
        let ret = ipv4_parse_test(&mut ProtoIpv4::new(), &data, PktTime::from_micros(0));
        assert_eq!(ret, Err(ParseErr::Invalid("")));
    }
}
