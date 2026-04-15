use crate::proto::{ProtoPktProcessor, ProtoParseResult, ProtoInfo};
use crate::packet::{Packet, PktInfoStack, PktTime};
use crate::event::{Event, EventId, EventStr, EventPayload, EventBus, EventKind};
use crate::stream::{PktStreamProcessor, PktStreamParser, StreamParseResult};
use crate::conntrack::ConntrackDirection;

use serde::Serialize;
use std::net::{Ipv4Addr, Ipv6Addr, IpAddr};
use smallvec::SmallVec;
use tracing::trace;

#[repr(u8)]
#[derive(Debug, Serialize)]
pub enum NetDnsResponseCode {
    OK,
    FormatError,
    ServerFailure,
    NameError,
    NotImplemented,
    Refused,
    Reserved,
}

#[derive(Debug, Serialize)]
pub enum NetDnsRecordType {
    A,
    NS,
    CNAME,
    SOA,
    PTR,
    MX,
    TXT,
    AAAA,
    Other(u16),

}

#[derive(Debug, Serialize)]
pub enum NetDnsRecordClass {
    IN,
    CS,
    CH,
    HS,
    Other(u16),
}

#[derive(Debug, Serialize)]
pub enum NetDnsRecordData {
    A(Ipv4Addr),
    AAAA(Ipv6Addr),
    CNAME(EventStr),
    PTR(EventStr),
    MX((u16, EventStr)),
    TXT(EventStr),
    Other(Vec<u8>),
}

#[derive(Debug, Serialize)]
pub struct NetDnsRecord {
    pub name: EventStr,
    pub r#type: u16,
    pub class: u16,
    pub ttl: u32,

}

#[derive(Debug, Serialize)]
pub struct NetDnsMessage {
    pub conn_id: EventId,
    pub proto: &'static str,
    pub src_host: Option<IpAddr>,
    pub dst_host: Option<IpAddr>,
    pub src_port: u16,
    pub dst_port: u16,
    pub direction: ConntrackDirection,
    pub id: u16,
    pub response_code: NetDnsResponseCode,
    pub is_response: bool,
    pub question_count: u16,
    pub answer_count: u16,
    pub authority_count: u16,
    pub additional_count: u16,
    pub qname: EventStr,
    pub qtype: NetDnsRecordType,
    pub qclass: NetDnsRecordClass,
}

#[derive(Debug)]
pub struct ProtoDns {
    tcp_bytes: Option<usize>,
    conn_id: Option<EventId>,
    src_host: Option<IpAddr>,
    dst_host: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    proto: &'static str,
}

impl ProtoDns {

    pub fn new() -> Self {
        Self {
            tcp_bytes: None,
            conn_id: None,
            src_host: None,
            dst_host: None,
            src_port: 0,
            dst_port: 0,
            proto: "udp",

        }
    }

    fn rr_type_to_enum(rr_type: u16) -> NetDnsRecordType {
        match rr_type {
            1 => NetDnsRecordType::A,
            2 => NetDnsRecordType::NS,
            5 => NetDnsRecordType::CNAME,
            6 => NetDnsRecordType::SOA,
            12 => NetDnsRecordType::PTR,
            15 => NetDnsRecordType::MX,
            16 => NetDnsRecordType::TXT,
            28 => NetDnsRecordType::AAAA,
            t => NetDnsRecordType::Other(t),
        }
    }

    fn rr_class_to_enum(rr_class: u16) -> NetDnsRecordClass {
        match rr_class {
            1 => NetDnsRecordClass::IN,
            2 => NetDnsRecordClass::CS,
            3 => NetDnsRecordClass::CH,
            4 => NetDnsRecordClass::HS,
            c => NetDnsRecordClass::Other(c),
        }
    }

    fn rcode_to_enum(rcode: u8) -> NetDnsResponseCode {
        match rcode {
            0 => NetDnsResponseCode::OK,
            1 => NetDnsResponseCode::FormatError,
            2 => NetDnsResponseCode::ServerFailure,
            3 => NetDnsResponseCode::NameError,
            4 => NetDnsResponseCode::NotImplemented,
            5 => NetDnsResponseCode::Refused,
            _ => NetDnsResponseCode::Reserved,
        }
    }

    fn parse_message(&mut self, data: &[u8], ts: PktTime, dir: ConntrackDirection) -> ProtoParseResult {

        // Parse DNS headers
        let id = ((data[0] as u16) << 8) + data[1] as u16;
        let rcode = data[3] & 0xF;
        let is_response = data[2] & 0x80 == 0x80;
        let question_count = ((data[4] as u16) << 8) + data[5] as u16;
        let answer_count = ((data[6] as u16) << 8) + data[7] as u16;
        let authority_count = ((data[8] as u16) << 8) + data[9] as u16;
        let additional_count = ((data[10] as u16) << 8) + data[11] as u16;

        if question_count != 1 {
            // DNS queries in practice only have one question
            return ProtoParseResult::Invalid;
        }

        // Parse query section
        let Some((qname, mut offset)) = ProtoDns::parse_name(data, 12) else {
            trace!("Unable to parse QNAME");
            return ProtoParseResult::Invalid;
        };

        if data.len() < offset + 4 {
            trace!("Query header truncated");
            return ProtoParseResult::Invalid;
        }

        trace!("QNAME : {}", String::from_utf8_lossy(&qname));

        let qtype = ((data[offset] as u16) << 8) + (data[offset + 1] as u16);
        offset += 2;
        let qclass = ((data[offset] as u16) << 8) + (data[offset + 1] as u16);
        offset += 2;


        let evt_pload = NetDnsMessage {
            conn_id: self.conn_id.clone().unwrap(),
            proto: self.proto,
            src_host: self.src_host,
            dst_host: self.dst_host,
            src_port: self.src_port,
            dst_port: self.dst_port,
            direction: dir,
            id,
            response_code: ProtoDns::rcode_to_enum(rcode),
            is_response,
            question_count,
            answer_count,
            authority_count,
            additional_count,
            qname: qname.to_vec().into(),
            qtype: ProtoDns::rr_type_to_enum(qtype),
            qclass: ProtoDns::rr_class_to_enum(qclass),
        };

        let evt = Event::new(ts, EventPayload::NetDnsMessage(evt_pload));
        evt.send();
        ProtoParseResult::Ok
    }

    fn parse_name(msg: &[u8], name_offset: usize) -> Option<(SmallVec<[u8;128]>, usize)> {

        let mut name: SmallVec<[u8; 128]> = SmallVec::new();

        if name_offset > msg.len() {
            return None;
        }

        // Current pointer to the label being parsed
        let mut off = name_offset;

        // Number of bytes to skip in the message
        let mut data_offset = 0;

        let mut label_len = msg[off];

        while label_len > 0 {
            if label_len > 63 {
                if name.len() == 0 {
                    // Pointer not allowed as first label
                    trace!("Pointer found in first label of DNS name");
                    return None;
                }

                if (label_len & 0xC0) != 0xC0 {
                    // Pointers must start with 11XXXXXX
                    trace!("Invalid label pointer start");
                    return None;
                }

                if off + 1 > msg.len() {
                    trace!("Pointer goes after end of msg");
                    return None;
                }

                // Return parsing the header after the pointer
                if data_offset == 0 {
                    data_offset = off + 1;
                }

                // Pointer seems valid
                off = (((msg[off] & 0x3F) as usize) << 8) + (msg[off + 1] as usize);

                if off > msg.len() {
                    trace!("Pointer points after the message");
                    return None;
                }

                label_len = msg[off];

            }

            if label_len as usize + 1 + off > msg.len() {
                trace!("Label lenght overflow message size");
                return None;
            }

            name.extend_from_slice(&msg[off + 1..off + 1 + label_len as usize]);
            off += label_len as usize + 1;
            label_len = msg[off];
            if label_len > 0 {
                name.push(b'.');
            }

        }

        if data_offset == 0 {
            data_offset = off + 1;
        }

        trace!("Parsed DNS name (off: {}) : {}", data_offset, String::from_utf8_lossy(&name));
        Some((name, data_offset))

    }

}

impl ProtoPktProcessor for ProtoDns {

    // DNS over UDP
    fn process(&mut self, pkt: &mut Packet, infos: &mut PktInfoStack) -> ProtoParseResult {

        if ! (EventBus::has_subscribers(EventKind::NetDnsMessage)) {
            return ProtoParseResult::Ok;
        }

        let info = infos.proto_from_last(1).unwrap();
        if self.conn_id.is_none() {
            self.conn_id = Some(infos.get_conn_id().unwrap().clone());

            let ip_info = infos.proto_from_last(2).map(|p| p.proto_info.as_ref().unwrap());
            let (src_host, dst_host) = match ip_info {
                Some(ProtoInfo::Ipv4(v4)) => (Some(IpAddr::V4(v4.src)), Some(IpAddr::V4(v4.dst))),
                Some(ProtoInfo::Ipv6(v6)) => (Some(IpAddr::V6(v6.src)), Some(IpAddr::V6(v6.dst))),
                _ => (None, None),
            };

            let ProtoInfo::Udp(udp_info) = info.proto_info.as_ref().unwrap() else {
                unreachable!();
            };
    

            self.src_host = src_host;
            self.dst_host = dst_host;
            self.src_port = udp_info.sport;
            self.dst_port = udp_info.dport;
        }

        let plen = pkt.remaining_len();
        if plen < 12 {
            // Length smaller than DNS header
            return ProtoParseResult::Invalid;
        }
        let ts = pkt.ts;
        let dir = info.ce_dir().unwrap();
        self.parse_message(pkt.remaining_data(), ts, dir)
    }

}

impl PktStreamProcessor for ProtoDns {

    fn new(infos: &PktInfoStack) -> Self {

        let ip_info = infos.proto_from_last(2).map(|p| p.proto_info.as_ref().unwrap());
        let (src_host, dst_host) = match ip_info {
            Some(ProtoInfo::Ipv4(v4)) => (Some(IpAddr::V4(v4.src)), Some(IpAddr::V4(v4.dst))),
            Some(ProtoInfo::Ipv6(v6)) => (Some(IpAddr::V6(v6.src)), Some(IpAddr::V6(v6.dst))),
            _ => (None, None),
        };

        let ProtoInfo::Tcp(tcp_info) = infos.proto_from_last(1).map(|p| p.proto_info.as_ref().unwrap()).unwrap() else {
            unreachable!();
        };

        Self {
            tcp_bytes: None,
            conn_id: Some(infos.get_conn_id().unwrap().clone()),
            src_host,
            dst_host,
            src_port: tcp_info.sport,
            dst_port: tcp_info.dport,
            proto: "tcp",

        }
    }

    // DNS over TCP
    fn process(&mut self, dir: ConntrackDirection, mut parser: PktStreamParser) -> StreamParseResult {

        if ! (EventBus::has_subscribers(EventKind::NetDnsMessage)) {
            return StreamParseResult::Done;
        }

        if let Some(msg_size) = self.tcp_bytes {
            let ts = parser.timestamp();
            let Some(data) = parser.read(msg_size) else {
                return StreamParseResult::NeedData;
            };
            let ret = self.parse_message(&data, ts, dir);
            if ret == ProtoParseResult::Invalid {
                return StreamParseResult::Invalid;
            }
            self.tcp_bytes = None;
        } else {
            let Some(size_raw) = parser.read(2) else {
                return StreamParseResult::NeedData;
            };
            let size = ((size_raw[0] as u16) << 8) + size_raw[1] as u16;
            self.tcp_bytes = Some(size.into());
        }
        StreamParseResult::Ok
    }
}


#[cfg(test)]
mod test {
    use super::*;
    use tracing_test::traced_test;

    #[test]
    #[traced_test]
    fn dns_name_parse_rfc_example() {
        let msg = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            1, b'F', 3, b'I', b'S', b'I', 4, b'A', b'R', b'P',
            b'A', 0, 0, 0, 0, 0, 0, 0, 0, 0,
            3, b'F', b'O', b'O', 0xC0, 20, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0xC0, 26, 0, 0, 0, 0 ];

        let (name, off) = ProtoDns::parse_name(&msg, 20).unwrap();
        assert!(name.eq_ignore_ascii_case(b"F.ISI.ARPA"));

        let (name, off) = ProtoDns::parse_name(&msg, 40).unwrap();
        assert!(name.eq_ignore_ascii_case(b"FOO.F.ISI.ARPA"));

    }

}
