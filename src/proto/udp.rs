use crate::proto::{ProtoProcessor, ProtoParseResult, Protocols};
use crate::param::{Param, ParamValue};
use crate::conntrack::{ConntrackTable, ConntrackKeyBidir};
use crate::packet::Packet;

use std::sync::OnceLock;
use std::time::Duration;


type ConntrackKeyUdp = ConntrackKeyBidir<u16>;

static UDP_TIMEOUT :u64 = 120;

static CT_UDP_SIZE :usize = 32768;
static CT_UDP: OnceLock<ConntrackTable<ConntrackKeyUdp>> = OnceLock::new();

pub struct ProtoUdp {}


impl ProtoProcessor for ProtoUdp {

    fn process(pkt: &mut Packet) -> ProtoParseResult {

        let plen = pkt.remaining_len();
        if plen < 9 { // length smaller than UDP header and 1 byte of data
            return ProtoParseResult::Invalid;
        }

        let hdr = pkt.read_bytes(8).unwrap();

        let sport : u16 = (hdr[0] as u16) << 8 | (hdr[1] as u16);
        let dport : u16 = (hdr[2] as u16) << 8 | (hdr[3] as u16);
        let len : u16 = (hdr[4] as u16) << 8 | (hdr[5] as u16);


        let plen = (len as usize) - 8;
        if plen > pkt.remaining_len() {
            // Stop processing if payload is not complete
            return ProtoParseResult::Stop;
        } else if plen < pkt.remaining_len() {
            // Shrink remaining payload to advertised size
            pkt.shrink_remaining(plen);
        }

        let info = pkt.stack_last_mut();
        info.field_push(Param { name: "sport", value: Some(ParamValue::U16(sport)) });
        info.field_push(Param { name: "dport", value: Some(ParamValue::U16(dport)) });


        let ct_key = ConntrackKeyUdp { a: sport, b: dport };
        let ce = CT_UDP.get_or_init(|| ConntrackTable::new(CT_UDP_SIZE)).get(ct_key, info.parent_ce(), Some((Duration::from_secs(UDP_TIMEOUT), pkt.ts)));

        pkt.stack_push(Protocols::None, Some(ce));


        ProtoParseResult::Ok

    }

    fn purge() {
        if let Some(ct) = CT_UDP.get() {
           ct.purge();
        }
    }

}
