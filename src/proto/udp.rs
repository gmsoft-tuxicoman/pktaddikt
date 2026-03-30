use crate::proto::{ProtoPktProcessor, ProtoParseResult, Protocols};
use crate::param::{Param, ParamValue};
use crate::conntrack::{ConntrackTable, ConntrackKeyBidir};
use crate::packet::{Packet, PktInfoStack};

use std::sync::OnceLock;
use std::time::Duration;


type ConntrackKeyUdp = ConntrackKeyBidir<u16>;

static UDP_TIMEOUT :u64 = 120;

static CT_UDP_SIZE :usize = 32768;
static CT_UDP: OnceLock<ConntrackTable<ConntrackKeyUdp>> = OnceLock::new();

pub struct ProtoUdp {}


impl ProtoUdp {

    pub fn new() -> Self {
        Self {}
    }
}

impl ProtoPktProcessor for ProtoUdp {

    fn process(&mut self, pkt: &mut Packet, infos: &mut PktInfoStack) -> ProtoParseResult {

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

        let info = infos.proto_last_mut();
        info.field_push(Param { name: "sport", value: Some(ParamValue::U16(sport)) });
        info.field_push(Param { name: "dport", value: Some(ParamValue::U16(dport)) });


        let ct_key = ConntrackKeyUdp { a: sport, b: dport };
        let (ce, _) = CT_UDP.get_or_init(|| ConntrackTable::new(CT_UDP_SIZE)).get(ct_key, info.parent_ce());

        // WIP
        infos.proto_push(Protocols::None, None);

        let mut ce_locked = ce.lock().unwrap();

        match ce_locked.has_children() {
            true => ce_locked.set_timeout(Duration::ZERO, pkt.ts),
            false => ce_locked.set_timeout(Duration::from_secs(UDP_TIMEOUT), pkt.ts)
        }


        ProtoParseResult::Ok

    }
}

impl Drop for ProtoUdp {
    fn drop(&mut self) {
        if let Some(ct) = CT_UDP.get() {
           ct.purge();
        }
    }

}
