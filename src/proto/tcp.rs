use crate::proto::{ProtoProcessor, ProtoParseResult, Protocols};
use crate::param::{Param, ParamValue};
use crate::conntrack::{ConntrackTable, ConntrackKeyBidir};
use crate::packet::Packet;

use std::sync::OnceLock;
use std::time::Duration;


type ConntrackKeyTcp = ConntrackKeyBidir<u16>;

static TCP_TIMEOUT :u64 = 120;

static CT_TCP_SIZE :usize = 32768;
static CT_TCP: OnceLock<ConntrackTable<ConntrackKeyTcp>> = OnceLock::new();


const TCP_TH_FIN: u8 = 0x1;
const TCP_TH_SYN: u8 = 0x2;
const TCP_TH_RST: u8 = 0x4;
const TCP_TH_ACK: u8 = 0x10;

pub struct ProtoTcp {}


impl ProtoProcessor for ProtoTcp {

    fn process(pkt: &mut Packet) -> ProtoParseResult {

        let plen = pkt.remaining_len();
        if plen < 20 { // length smaller than TCP header
            return ProtoParseResult::Invalid;
        }

        let hdr = pkt.read_bytes(20).unwrap();

        let sport: u16 = (hdr[0] as u16) << 8 | (hdr[1] as u16);
        let dport: u16 = (hdr[2] as u16) << 8 | (hdr[3] as u16);
        let seq: u32 = (hdr[4] as u32) << 24 | (hdr[5] as u32) << 16 | (hdr[6] as u32) << 8 | (hdr[7] as u32);
        let seq_ack: u32 = (hdr[8] as u32) << 24 | (hdr[9] as u32) << 16 | (hdr[10] as u32) << 8 | (hdr[11] as u32);
        let window: u16 = (hdr[16] as u16) << 8 | (hdr[17] as u16);
        let flags: u8 = hdr[14];

        let hdr_len = ((hdr[12] & 0xf0) >> 2) as usize;

        if hdr_len < 20 {
            // Header length too small
            return ProtoParseResult::Invalid;
        }

        if hdr_len > plen {
            // Header length bigger than payload size
            return ProtoParseResult::Invalid;
        }

        if hdr_len > 20 {
            // Skip options and padding
            if pkt.skip_bytes((hdr_len - 20).into()) == Err(()) {
                return ProtoParseResult::Invalid;
            }
        }

        let mut data_len = plen - hdr_len;
        if ((flags & TCP_TH_SYN) != 0) && data_len > 0 {
            // No payload allowed in SYN packets
            return ProtoParseResult::Invalid;
        }

        if ((flags & TCP_TH_RST) != 0) && data_len > 0 {
            // RFC 1122 4.2.2.12 : RST may contain the data that caused the packet to be sent,
            // discard it
            if pkt.skip_bytes(data_len) == Err(()) {
                return ProtoParseResult::Invalid;
            }
            data_len = 0;
        }



        let info = pkt.stack_last_mut();
        info.field_push(Param { name: "sport", value: Some(ParamValue::U16(sport)) });
        info.field_push(Param { name: "dport", value: Some(ParamValue::U16(dport)) });
        info.field_push(Param { name: "seq", value: Some(ParamValue::U32(seq)) });
        info.field_push(Param { name: "seq_ack", value: Some(ParamValue::U32(seq_ack)) });
        info.field_push(Param { name: "win", value: Some(ParamValue::U16(window)) });


        let ct_key = ConntrackKeyTcp { a: sport, b: dport };
        let ce = CT_TCP.get_or_init(|| ConntrackTable::new(CT_TCP_SIZE)).get(ct_key, info.parent_ce(), Some((Duration::from_secs(TCP_TIMEOUT), pkt.ts)));

        pkt.stack_push(Protocols::None, Some(ce));


        ProtoParseResult::Ok

    }

    fn purge() {
        if let Some(ct) = CT_TCP.get() {
           ct.purge();
        }
    }

}
