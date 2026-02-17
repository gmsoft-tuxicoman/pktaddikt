use crate::proto::{ProtoProcessor, ProtoParseResult, Protocols};
use crate::param::{Param, ParamValue};
use crate::conntrack::{ConntrackTable, ConntrackKeyBidir};
use crate::packet::Packet;

use std::sync::OnceLock;
use std::net::Ipv6Addr;
use std::time::Duration;

pub struct ProtoIpv6 {}


type ConntrackKeyIpv6 = ConntrackKeyBidir<u64>;



static CT_IPV6_SIZE :usize = 65535;
static CT_IPV6: OnceLock<ConntrackTable<ConntrackKeyIpv6>> = OnceLock::new();

const IPV6_TIMEOUT :u64 = 7200;

impl ProtoProcessor for ProtoIpv6 {

    fn process(pkt: &mut Packet) -> ProtoParseResult {

        let plen = pkt.remaining_len();
        if plen < 40 {
            return ProtoParseResult::Invalid;
        }

        let hdr = pkt.read_bytes(40).unwrap();

        if hdr[0] >> 4 != 6 { // not IP version 6
            return ProtoParseResult::Invalid;
        }

        let src = Ipv6Addr::new((hdr[8] as u16) << 8 | (hdr[9] as u16),
                                (hdr[10] as u16) << 8 | (hdr[11] as u16),
                                (hdr[12] as u16) << 8 | (hdr[13] as u16),
                                (hdr[14] as u16) << 8 | (hdr[15] as u16),
                                (hdr[16] as u16) << 8 | (hdr[17] as u16),
                                (hdr[18] as u16) << 8 | (hdr[19] as u16),
                                (hdr[20] as u16) << 8 | (hdr[21] as u16),
                                (hdr[22] as u16) << 8 | (hdr[23] as u16));
        let dst = Ipv6Addr::new((hdr[24] as u16) << 8 | (hdr[25] as u16),
                                (hdr[26] as u16) << 8 | (hdr[27] as u16),
                                (hdr[28] as u16) << 8 | (hdr[29] as u16),
                                (hdr[30] as u16) << 8 | (hdr[31] as u16),
                                (hdr[32] as u16) << 8 | (hdr[33] as u16),
                                (hdr[34] as u16) << 8 | (hdr[35] as u16),
                                (hdr[36] as u16) << 8 | (hdr[37] as u16),
                                (hdr[38] as u16) << 8 | (hdr[39] as u16));

        let hop_limit = hdr[7];


        let mut nhdr_type: u8 = hdr[6];

        loop {
            nhdr_type = match nhdr_type {
                0  |  // HOPOPTS
                43 |  // ROUTING
                44 |  // FRAGMENT (TODO)
                60 => { // DSTOPTS
                    // Read header length
                    let nhdr_len = pkt.read_u8();
                    if nhdr_len == None {
                        return ProtoParseResult::Invalid;
                    }
                    // Skip header
                    if pkt.skip_bytes(nhdr_len.unwrap() as usize) == Err(()) {
                        return ProtoParseResult::Invalid;
                    }
                    // Read next header value
                    let nhdr_type_opt = pkt.read_u8();
                    if nhdr_type_opt == None {
                        return ProtoParseResult::Invalid;
                    }
                    nhdr_type_opt.unwrap()
                }

                _ => {
                    break;
                }
            }
        }

        let info = pkt.stack_last_mut();
        info.field_push(Param { name: "src", value: Some(ParamValue::Ipv6(src)) });
        info.field_push(Param { name: "dst", value: Some(ParamValue::Ipv6(dst)) });
        info.field_push(Param { name: "hop_limit", value: Some(ParamValue::U8(hop_limit)) });

        let a = src.to_bits();
        let b = dst.to_bits();

        let ct_key = ConntrackKeyIpv6 { a: ((a >> 8) as u64) ^ (a as u64) , b: ((b >> 8) as u64) ^ (b as u64) };
        let ce = CT_IPV6.get_or_init(|| ConntrackTable::new(CT_IPV6_SIZE)).get(ct_key, info.parent_ce(), Some((Duration::from_secs(IPV6_TIMEOUT), pkt.ts)));

        let next_proto = match nhdr_type {
            17 => Protocols::Udp,
            _ => Protocols::None

        };

        pkt.stack_push(next_proto, Some(ce));

        ProtoParseResult::Ok

    }

    fn purge() {
        if let Some(ct) = CT_IPV6.get() {
            ct.purge();
        }
    }
}
