use crate::base::{Parser, ParseErr};
use crate::proto::ProtoPktProcessor;
use crate::packet::{Packet, PktInfoStack};
use crate::event::{Event, EventStr, EventPayload, EventKind};
use crate::messagebus::MessageBus;
use crate::base::UniqueId;
use crate::stream::{PktStreamProcessor, PktStreamParser};
use crate::conntrack::{ConntrackDirection, ConntrackTableUnique};

use serde::Serialize;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use smallvec::SmallVec;
use tracing::{debug, trace};

#[derive(Debug, Serialize)]
pub struct NetDnsRecordDataSoa {
    pub mname: EventStr,
    pub rname: EventStr,
    pub serial: u32,
    pub refresh: u32,
    pub retry: u32,
    pub expire: u32,
    pub minimum: u32,

}

#[derive(Debug, Serialize)]
pub struct NetDnsRecordDataMx {
    pub pref: u16,
    pub mx: EventStr,
}

#[derive(Debug, Serialize)]
pub struct NetDnsRecordDataSrv {
    pub priority: u16,
    pub weight: u16,
    pub port: u16,
    pub target: EventStr,
}

#[derive(Debug, Serialize)]
pub struct NetDnsRecord {
    pub name: EventStr,
    pub r#type: NetDnsRecordType,
    pub class: NetDnsRecordClass,
    pub ttl: u32,
    pub data: NetDnsRecordData,
}

#[repr(u8)]
#[derive(Copy, Clone, Debug, Serialize)]
pub enum NetDnsResponseCode {
    OK,
    FormatError,
    ServerFailure,
    NameError,
    NotImplemented,
    Refused,
    Reserved,
}

#[repr(u16)]
#[derive(Copy, Clone, Debug, Serialize)]
pub enum NetDnsRecordType {
    A          = 1,
    NS         = 2,
    CNAME      = 5,
    SOA        = 6,
    WKS        = 11,
    PTR        = 12,
    HINFO      = 13,
    MX         = 15,
    TXT        = 16,
    RP         = 17,
    AFSDB      = 18,
    SIG        = 24,
    KEY        = 25,
    AAAA       = 28,
    LOC        = 29,
    NBS        = 32,
    SRV        = 33,
    NAPTR      = 35,
    KX         = 36,
    CERT       = 37,
    DNAME      = 39,
    OPT        = 41,
    APL        = 42,
    DS         = 43,
    SSHFP      = 44,
    IPSECKEY   = 45,
    RRSIG      = 46,
    NSEC       = 47,
    DNSKEY     = 48,
    DHCID      = 49,
    NSEC3      = 50,
    NSEC3PARAM = 51,
    TLSA       = 52,
    SMIMEA     = 53,
    HIP        = 55,
    CDS        = 59,
    CDNSKEY    = 60,
    OPENPGPKEY = 61,
    CSYNC      = 62,
    ZONEMD     = 63,
    SVCB       = 64,
    HTTPS      = 65,
    SPF        = 99,
    TKEY       = 249,
    TSIG       = 250,
    IXFR       = 251,
    AXFR       = 252,
    MAILB      = 253,
    MAILA      = 254,
    ANY        = 255,
    URI        = 256,
    CAA        = 257,
    DLV        = 32769,
}

#[repr(u16)]
#[derive(Copy, Clone, Debug, Serialize)]
pub enum NetDnsRecordClass {
    IN = 1,
    CS = 2,
    CH = 3,
    HS = 4,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum NetDnsRecordData {
    None,
    A(Ipv4Addr),
    AAAA(Ipv6Addr),
    NS(EventStr),
    CNAME(EventStr),
    SOA(NetDnsRecordDataSoa),
    PTR(EventStr),
    MX(NetDnsRecordDataMx),
    SRV(NetDnsRecordDataSrv),
    TXT(EventStr),
    Other(Vec<u8>),
}

#[derive(Debug, Serialize)]
pub struct NetDnsMessage {
    pub conn_id: UniqueId,
    pub proto: &'static str,
    pub client_addr: IpAddr,
    pub client_port: u16,
    pub server_addr: IpAddr,
    pub server_port: u16,
    pub direction: ConntrackDirection,
    pub id: u16,
    pub response_code: NetDnsResponseCode,
    pub is_response: bool,
    pub opcode: u8,
    pub aa: bool,
    pub tc: bool,
    pub rd: bool,
    pub ra: bool,
    pub ad: bool,
    pub cd: bool,
    pub z: bool,
    pub question_count: u16,
    pub answer_count: u16,
    pub authority_count: u16,
    pub additional_count: u16,
    pub qname: EventStr,
    pub qtype: NetDnsRecordType,
    pub qclass: NetDnsRecordClass,
    pub answers: Option<Vec<NetDnsRecord>>,
    pub authorities: Option<Vec<NetDnsRecord>>,
    pub additionals: Option<Vec<NetDnsRecord>>,
}

#[derive(Debug)]
pub struct ProtoDns {
    conn_id: UniqueId,
    client_addr: IpAddr,
    client_port: u16,
    server_addr: IpAddr,
    server_port: u16,
    proto: &'static str,
}

impl ProtoDns {

    pub fn new(infos: &PktInfoStack, proto: &'static str) -> Self {
        let conn_info = infos.get_conn_info();
        Self {
            conn_id: infos.get_conn_id().unwrap().clone(),
            client_addr: conn_info.src_host.unwrap(),
            client_port: conn_info.src_port.unwrap(),
            server_addr: conn_info.dst_host.unwrap(),
            server_port: conn_info.dst_port.unwrap(),
            proto,
        }
    }

    fn rr_type_to_enum(rr_type: u16) -> Result<NetDnsRecordType, ParseErr> {
        match rr_type {
            1   => Ok(NetDnsRecordType::A),
            2   => Ok(NetDnsRecordType::NS),
            5   => Ok(NetDnsRecordType::CNAME),
            6   => Ok(NetDnsRecordType::SOA),
            11  => Ok(NetDnsRecordType::WKS),
            12  => Ok(NetDnsRecordType::PTR),
            13  => Ok(NetDnsRecordType::HINFO),
            15  => Ok(NetDnsRecordType::MX),
            16  => Ok(NetDnsRecordType::TXT),
            17  => Ok(NetDnsRecordType::RP),
            18  => Ok(NetDnsRecordType::AFSDB),
            24  => Ok(NetDnsRecordType::SIG),
            25  => Ok(NetDnsRecordType::KEY),
            28  => Ok(NetDnsRecordType::AAAA),
            29  => Ok(NetDnsRecordType::LOC),
            32  => Ok(NetDnsRecordType::NBS),
            33  => Ok(NetDnsRecordType::SRV),
            35  => Ok(NetDnsRecordType::NAPTR),
            36  => Ok(NetDnsRecordType::KX),
            37  => Ok(NetDnsRecordType::CERT),
            39  => Ok(NetDnsRecordType::DNAME),
            41  => Ok(NetDnsRecordType::OPT),
            42  => Ok(NetDnsRecordType::APL),
            43  => Ok(NetDnsRecordType::DS),
            44  => Ok(NetDnsRecordType::SSHFP),
            45  => Ok(NetDnsRecordType::IPSECKEY),
            46  => Ok(NetDnsRecordType::RRSIG),
            47  => Ok(NetDnsRecordType::NSEC),
            48  => Ok(NetDnsRecordType::DNSKEY),
            49  => Ok(NetDnsRecordType::DHCID),
            50  => Ok(NetDnsRecordType::NSEC3),
            51  => Ok(NetDnsRecordType::NSEC3PARAM),
            52  => Ok(NetDnsRecordType::TLSA),
            53  => Ok(NetDnsRecordType::SMIMEA),
            55  => Ok(NetDnsRecordType::HIP),
            59  => Ok(NetDnsRecordType::CDS),
            60  => Ok(NetDnsRecordType::CDNSKEY),
            61  => Ok(NetDnsRecordType::OPENPGPKEY),
            62  => Ok(NetDnsRecordType::CSYNC),
            63  => Ok(NetDnsRecordType::ZONEMD),
            64  => Ok(NetDnsRecordType::SVCB),
            65  => Ok(NetDnsRecordType::HTTPS),
            99  => Ok(NetDnsRecordType::SPF),
            249 => Ok(NetDnsRecordType::TKEY),
            250 => Ok(NetDnsRecordType::TSIG),
            251 => Ok(NetDnsRecordType::IXFR),
            252 => Ok(NetDnsRecordType::AXFR),
            253 => Ok(NetDnsRecordType::MAILB),
            254 => Ok(NetDnsRecordType::MAILA),
            255 => Ok(NetDnsRecordType::ANY),
            256 => Ok(NetDnsRecordType::URI),
            257 => Ok(NetDnsRecordType::CAA),
            32769 => Ok(NetDnsRecordType::DLV),
            _     => Err(ParseErr::Invalid("Invalid DNS type")),
        }
    }

    fn rr_class_to_enum(rr_class: u16) -> Result<NetDnsRecordClass, ParseErr> {
        match rr_class {
            1 => Ok(NetDnsRecordClass::IN),
            2 => Ok(NetDnsRecordClass::CS),
            3 => Ok(NetDnsRecordClass::CH),
            4 => Ok(NetDnsRecordClass::HS),
            _ => Err(ParseErr::Invalid("Invalid DNS class")),
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

    fn parse_rr(data: &[u8], offset: usize) -> Result<(NetDnsRecord, usize), ParseErr> {
        let (name, mut offset) = ProtoDns::parse_name(data, offset)?;

        if data.len() < offset + 10 {
            debug!("Record truncated");
            return Err(ParseErr::Truncated);
        }

        let qtype = u16::from_be_bytes(data[offset .. offset + 2].try_into().unwrap());
        offset += 2;
        let qclass = u16::from_be_bytes(data[offset .. offset + 2].try_into().unwrap());
        offset += 2;
        let ttl = u32::from_be_bytes(data[offset .. offset + 4].try_into().unwrap());
        offset += 4;
        let rlen = u16::from_be_bytes(data[offset .. offset + 2].try_into().unwrap());
        offset += 2;

        if data.len() < offset + rlen as usize {
            debug!("Rdata truncated");
            return Err(ParseErr::Truncated);
        }

        let data = match qtype {
            1 => {
                if rlen < 4 {
                    return Err(ParseErr::Invalid("A record rdata too short"));
                }
                NetDnsRecordData::A(Ipv4Addr::new(data[offset], data[offset + 1], data[offset + 2], data[offset + 3]))
            }
            2 => {
                let (ns, _) = ProtoDns::parse_name(data, offset)?;
                NetDnsRecordData::NS(ns.to_vec().into())
            }
            5 => {
                let (cname, _) = ProtoDns::parse_name(data, offset)?;
                NetDnsRecordData::CNAME(cname.to_vec().into())
            }
            6 => {
                let (mname, new_offset) = ProtoDns::parse_name(data, offset)?;
                offset = new_offset;
                let (rname, new_offset) = ProtoDns::parse_name(data, offset)?;
                offset = new_offset;
                if data.len() < offset + 20 {
                    return Err(ParseErr::Invalid("SOA record rdata too short"));
                }
                let serial = u32::from_be_bytes(data[offset .. offset + 4].try_into().unwrap());
                offset += 4;
                let refresh = u32::from_be_bytes(data[offset .. offset + 4].try_into().unwrap());
                offset += 4;
                let retry = u32::from_be_bytes(data[offset .. offset + 4].try_into().unwrap());
                offset += 4;
                let expire = u32::from_be_bytes(data[offset .. offset + 4].try_into().unwrap());
                offset += 4;
                let minimum = u32::from_be_bytes(data[offset .. offset + 4].try_into().unwrap());

                NetDnsRecordData::SOA(NetDnsRecordDataSoa {
                    mname: mname.to_vec().into(),
                    rname: rname.to_vec().into(),
                    serial,
                    refresh,
                    retry,
                    expire,
                    minimum,
                })
            }
            12 => {
                let (ptr, _) = ProtoDns::parse_name(data, offset)?;
                NetDnsRecordData::PTR(ptr.to_vec().into())
            }
            15 => {
                if rlen < 2 {
                    return Err(ParseErr::Invalid("MX record rdata too short"));
                }
                let pref = ((data[offset] as u16) << 8) + (data[offset + 1] as u16);
                let (mx, _) = ProtoDns::parse_name(data, offset + 2)?;
                NetDnsRecordData::MX( NetDnsRecordDataMx {
                    pref,
                    mx: mx.to_vec().into()
                })
            },
            16 => {
                let txt = &data[offset..offset + rlen as usize];
                let mut value = Vec::new();
                let mut pos = 0;
                while pos < txt.len() {
                    let len = txt[pos] as usize;
                    if pos + 1 + len > txt.len() {
                        return Err(ParseErr::Invalid("TXT record segment overflows rdata"));
                    }
                    let cstring = &txt[pos + 1..pos + 1 + len];
                    value.extend_from_slice(cstring);
                    pos += len + 1;
                }
                NetDnsRecordData::TXT(value.into())
            }
            28 => {
                if rlen < 16 {
                    return Err(ParseErr::Invalid("AAAA record rdata too short"));
                }
                let ipv6 = Ipv6Addr::from(<[u8; 16]>::try_from(&data[offset .. offset + 16]).unwrap());
                NetDnsRecordData::AAAA(ipv6)
            }
            33 => {
                if rlen < 6 {
                    return Err(ParseErr::Invalid("SRV record rdata too short"));
                }
                let priority = u16::from_be_bytes(data[offset     .. offset + 2].try_into().unwrap());
                let weight   = u16::from_be_bytes(data[offset + 2 .. offset + 4].try_into().unwrap());
                let port     = u16::from_be_bytes(data[offset + 4 .. offset + 6].try_into().unwrap());
                let (target, _) = ProtoDns::parse_name(data, offset + 6)?;
                NetDnsRecordData::SRV(NetDnsRecordDataSrv { priority, weight, port, target: target.to_vec().into() })
            }
            _ => NetDnsRecordData::Other(data[offset..offset + rlen as usize].to_vec())
        };

        let rr = NetDnsRecord {
            name: name.to_vec().into(),
            r#type: ProtoDns::rr_type_to_enum(qtype)?,
            class: ProtoDns::rr_class_to_enum(qclass)?,
            ttl,
            data,
        };


        Ok((rr, offset + rlen as usize))

    }

    fn parse_message(&mut self, parser: &mut Packet, dir: ConntrackDirection) -> Result<(), ParseErr> {

        let data = parser.remaining_data();

        if data.len() < 12  {
            return Err(ParseErr::Truncated);
        }

        // Parse DNS headers
        let id = u16::from_be_bytes(data[0..2].try_into().unwrap());
        let rcode = data[2] & 0xF;
        let is_response = data[3] & 0x80 == 0x80;
        let opcode = (data[2] >> 3) & 0x0F;
        let aa = data[2] & 0x04 != 0;
        let tc = data[2] & 0x02 != 0;
        let rd = data[2] & 0x01 != 0;
        let ra = data[3] & 0x80 != 0;
        let ad = data[3] & 0x20 != 0;
        let cd = data[3] & 0x10 != 0;
        let z  = data[3] & 0x40 != 0;
        let question_count = u16::from_be_bytes(data[4..6].try_into().unwrap());
        let answer_count = u16::from_be_bytes(data[6..8].try_into().unwrap());
        let authority_count = u16::from_be_bytes(data[8..10].try_into().unwrap());
        let additional_count = u16::from_be_bytes(data[10..12].try_into().unwrap());

        if question_count != 1 {
            // DNS queries in practice only have one question
            return Err(ParseErr::Invalid("More than one question"));
        }

        // Parse query section
        let (qname, mut offset) = ProtoDns::parse_name(data, 12)?;

        if data.len() < offset + 4 {
            return Err(ParseErr::Invalid("Query header truncated"));
        }

        trace!("QNAME : {}", String::from_utf8_lossy(&qname));

        let qtype = u16::from_be_bytes(data[offset .. offset + 2].try_into().unwrap());
        offset += 2;
        let qclass = u16::from_be_bytes(data[offset .. offset + 2].try_into().unwrap());
        offset += 2;


        let mut evt_pload = NetDnsMessage {
            conn_id: self.conn_id.clone(),
            proto: self.proto,
            client_addr: self.client_addr,
            client_port: self.client_port,
            server_addr: self.server_addr,
            server_port: self.server_port,
            direction: dir,
            id,
            response_code: ProtoDns::rcode_to_enum(rcode),
            is_response,
            opcode,
            aa,
            tc,
            rd,
            ra,
            ad,
            cd,
            z,
            question_count,
            answer_count,
            authority_count,
            additional_count,
            qname: qname.to_vec().into(),
            qtype: ProtoDns::rr_type_to_enum(qtype)?,
            qclass: ProtoDns::rr_class_to_enum(qclass)?,
            answers: None,
            authorities: None,
            additionals: None,
        };

        if answer_count > 0 {
            let mut answers = Vec::with_capacity(answer_count as usize);
            for _i in 0..answer_count {
                let (rr, new_offset) = ProtoDns::parse_rr(data, offset)?;
                offset = new_offset;
                answers.push(rr);
            }
            evt_pload.answers = Some(answers);
        }

        if authority_count > 0 {
            let mut authorities = Vec::with_capacity(authority_count as usize);
            for _i in 0..authority_count {
                let (rr, new_offset) = ProtoDns::parse_rr(data, offset)?;
                offset = new_offset;
                authorities.push(rr);
            }
            evt_pload.authorities= Some(authorities);
        }

        if additional_count > 0 {
            let mut additionals = Vec::with_capacity(additional_count as usize);
            for _i in 0..additional_count {
                let (rr, new_offset) = ProtoDns::parse_rr(data, offset)?;
                offset = new_offset;
                additionals.push(rr);
            }
            evt_pload.additionals = Some(additionals);
        }
        let evt = Event::new(parser.timestamp(), EventPayload::NetDnsMessage(evt_pload));
        MessageBus::publish_event(evt);
        Ok(())
    }

    fn parse_name(msg: &[u8], name_offset: usize) -> Result<(SmallVec<[u8;128]>, usize), ParseErr> {

        let mut name: SmallVec<[u8; 128]> = SmallVec::new();

        if name_offset >= msg.len() {
            return Err(ParseErr::Invalid("Offset points outside the message"));
        }

        // Current pointer to the label being parsed
        let mut off = name_offset;

        // Number of bytes to skip in the message
        let mut data_offset = 0;

        let mut label_len = msg[off];

        while label_len > 0 {
            if label_len > 63 {

                if (label_len & 0xC0) != 0xC0 {
                    // Pointers must start with 11XXXXXX
                    return Err(ParseErr::Invalid("Invalid pointer"));
                }

                if off + 2 > msg.len() {
                    return Err(ParseErr::Invalid("Pointer truncated"));
                }

                // Return parsing the header after the pointer
                if data_offset == 0 {
                    data_offset = off + 2;
                }

                // Pointer seems valid
                off = (u16::from_be_bytes(msg[off .. off + 2].try_into().unwrap()) & 0x3FFF) as usize;

                if off >= msg.len() {
                    return Err(ParseErr::Invalid("Pointer points after the message"));
                }

                label_len = msg[off];

            }

            if label_len as usize + 1 + off > msg.len() {
                return Err(ParseErr::Invalid("Label length overflow message size"));
            }

            name.extend_from_slice(&msg[off + 1..off + 1 + label_len as usize]);
            off += label_len as usize + 1;
            if off >= msg.len() {
                return Err(ParseErr::Truncated);
            }
            label_len = msg[off];
            if label_len > 0 {
                name.push(b'.');
            }

        }

        if data_offset == 0 {
            data_offset = off + 1;
        }

        trace!("Parsed DNS name (off: {}) : {}", data_offset, String::from_utf8_lossy(&name));
        Ok((name, data_offset))

    }

}

pub struct ProtoDnsUdp {
    ct: ConntrackTableUnique,
}

impl ProtoPktProcessor for ProtoDnsUdp {

    fn new() -> Self {
        Self {
            ct: ConntrackTableUnique::new(),
        }
    }

    // DNS over UDP
    fn process(&mut self, pkt: &mut Packet, infos: &mut PktInfoStack) -> Result<(), ParseErr> {

        if ! (MessageBus::event_has_subscribers(EventKind::NetDnsMessage)) {
            return Ok(());
        }

        let info = infos.proto_last();
        let (ce, ce_dir) = self.ct.get(info.parent_ce().unwrap());

        let mut ce_locked = ce.lock().unwrap();
        let dns = ce_locked.get_or_insert_with(|| Box::new(ProtoDns::new(infos, "udp"))).downcast_mut::<ProtoDns>().unwrap();

        dns.parse_message(pkt, ce_dir)
    }

}

pub struct ProtoDnsTcp {
    tcp_bytes: Option<u32>,
    dns: ProtoDns
}

impl PktStreamProcessor for ProtoDnsTcp {

    fn new(infos: &PktInfoStack) -> Self {


        Self {
            tcp_bytes: None,
            dns: ProtoDns::new(infos, "tcp"),

        }
    }

    // DNS over TCP
    fn process(&mut self, dir: ConntrackDirection, mut parser: PktStreamParser) -> Result<(), ParseErr> {

        if ! (MessageBus::event_has_subscribers(EventKind::NetDnsMessage)) {
            return Err(ParseErr::Stop);
        }

        if let Some(msg_size) = self.tcp_bytes {
            let mut data = parser.sub_packet(msg_size)?;
            if self.dns.parse_message(&mut data, dir) == Err(ParseErr::Truncated) {
                return Err(ParseErr::Invalid("DNS over TCP message incomplete"));
            }
            self.tcp_bytes = None;
        } else {
            let size = parser.read_u16_be()?;
            self.tcp_bytes = Some(size.into());
        }
        Ok(())
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

        let (name, _off) = ProtoDns::parse_name(&msg, 20).unwrap();
        assert!(name.eq_ignore_ascii_case(b"F.ISI.ARPA"));

        let (name, _off) = ProtoDns::parse_name(&msg, 40).unwrap();
        assert!(name.eq_ignore_ascii_case(b"FOO.F.ISI.ARPA"));

    }

}
