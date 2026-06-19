use crate::output::{Output, OutputConfig};
use crate::event::{EventRef, EventKind, EventPayload, EventStr};
use crate::proto::dns::{NetDnsMessage, NetDnsRecordClass, NetDnsRecordData, NetDnsResponseCode};
use crate::messagebus::{MessageBus, MessageTxChannel, MessageRxChannel, Message};
use crate::base::UniqueId;
use crate::packet::PktTime;
use crate::config::Config;

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use serde::{Deserialize, Serialize};
use serde_json::to_writer;
use std::net::IpAddr;
use tracing::error;
use std::path::PathBuf;

#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct LogZeekConfig {

    pub path: String,
    pub conn_log: bool,
    pub dns_log: bool,
    pub dns_auth_addl: bool,

}

impl Default for LogZeekConfig {

    fn default() -> Self {
        Self {
            path: "".to_string(),
            conn_log: true,
            dns_log: true,
            dns_auth_addl: false,
        }
    }

}

pub struct OutputLogZeek {
    conn_log: Option<BufWriter<File>>,
    dns_log: Option<BufWriter<File>>,
    dns_auth_addl: bool,
    pending_dns_queries: HashMap<(UniqueId, u16), EventRef>,
}


#[derive(Debug, Serialize)]
struct ZeekConnLog {

    ts: PktTime,
    uid: UniqueId,
    #[serde(rename = "id.orig_h")]
    orig_h: IpAddr,
    #[serde(rename = "id.orig_p")]
    orig_p: u16,
    #[serde(rename = "id.resp_h")]
    resp_h: IpAddr,
    #[serde(rename = "id.resp_p")]
    resp_p: u16,
    proto: &'static str,
    //service: &'static str,
    duration: PktTime,
    orig_bytes: u64,
    resp_bytes: u64,
    //conn_state
    missed_bytes: u64,
    //history
    orig_pkts: u64,
    orig_ip_bytes: u64,
    resp_pkts: u64,
    resp_ip_bytes: u64,
    ip_proto: u16,
}

#[derive(Debug, Serialize)]
#[allow(non_snake_case)]
struct ZeekDnsLog {

    ts: PktTime,
    uid: UniqueId,
    #[serde(rename = "id.orig_h")]
    orig_h: IpAddr,
    #[serde(rename = "id.orig_p")]
    orig_p: u16,
    #[serde(rename = "id.resp_h")]
    resp_h: IpAddr,
    #[serde(rename = "id.resp_p")]
    resp_p: u16,
    proto: &'static str,
    trans_id: u16,
    opcode: u8,
    opcode_name: &'static str,
    query: EventStr,
    rcode: u8,
    rcode_name: &'static str,
    qclass: u16,
    qclass_name: &'static str,
    qtype: u16,
    qtype_name: String,
    answers: Vec<String>,
    TTLs: Vec<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    auth: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    addl: Option<Vec<String>>,
    AA: bool,
    TC: bool,
    RD: bool,
    RA: bool,
    Z: u8,
}


impl OutputLogZeek {

    pub fn new(name: &str, msg_bus: &mut MessageBus, tx: &MessageTxChannel) -> Box<dyn Output> {

        let main_cfg = Config::get();
        let OutputConfig::LogZeek(cfg) = main_cfg.outputs.get(name).unwrap() else {
            panic!("Config is not logzeek");
        };

        let path = PathBuf::from(cfg.path.clone());

        let mut conn_log: Option<BufWriter<File>> = None;
        if cfg.conn_log {
            let conn_path = path.clone().join("conn.log");
            let file = OpenOptions::new().create(true).write(true).append(true).open(&conn_path).expect(&format!("Unable to open {} for output logzeek", conn_path.display()));
            conn_log = Some(BufWriter::new(file));
        }

        let mut dns_log: Option<BufWriter<File>> = None;
        if cfg.dns_log {
            let dns_path = path.clone().join("dns.log");
            let file = OpenOptions::new().create(true).write(true).append(true).open(&dns_path).expect(&format!("Unable to open {} for output logzeek", dns_path.display()));
            dns_log = Some(BufWriter::new(file));
            msg_bus.event_subscribe_kind(EventKind::NetDnsMessage, tx);
        }

        // Connection-end events are needed for conn.log and to flush unanswered DNS queries
        if cfg.conn_log || cfg.dns_log {
            msg_bus.event_subscribe_kind(EventKind::NetTcpConnectionEnd, tx);
            msg_bus.event_subscribe_kind(EventKind::NetUdpConnectionEnd, tx);
        }

        Box::new( Self {
            conn_log,
            dns_log,
            dns_auth_addl: cfg.dns_auth_addl,
            pending_dns_queries: HashMap::new(),
        })

    }

    fn build_dns_log(&self, ts: PktTime, p: &NetDnsMessage) -> ZeekDnsLog {
        ZeekDnsLog {
            ts,
            uid: p.conn_id.clone(),
            orig_h: p.client_addr,
            orig_p: p.client_port,
            resp_h: p.server_addr,
            resp_p: p.server_port,
            proto: p.proto,
            trans_id: p.id,
            opcode: p.opcode,
            opcode_name: match p.opcode {
                0 => "QUERY",
                1 => "IQUERY",
                2 => "STATUS",
                4 => "NOTIFY",
                5 => "UPDATE",
                6 => "DSO",
                _ => "unknown",
            },
            query: p.qname.clone(),
            rcode: p.response_code as u8,
            rcode_name: match p.response_code {
                NetDnsResponseCode::OK             => "NOERROR",
                NetDnsResponseCode::FormatError    => "FORMERR",
                NetDnsResponseCode::ServerFailure  => "SERVFAIL",
                NetDnsResponseCode::NameError      => "NXDOMAIN",
                NetDnsResponseCode::NotImplemented => "NOTIMP",
                NetDnsResponseCode::Refused        => "REFUSED",
                NetDnsResponseCode::Reserved       => "unknown",
            },
            qclass: p.qclass as u16,
            qclass_name: match p.qclass {
                NetDnsRecordClass::IN => "C_INTERNET",
                NetDnsRecordClass::CS => "C_CSNET",
                NetDnsRecordClass::CH => "C_CHAOS",
                NetDnsRecordClass::HS => "C_HESIOD",
            },
            qtype: p.qtype as u16,
            qtype_name: format!("{:?}", p.qtype),
            answers: p.answers.as_ref().map_or(vec![], |rrs| rrs.iter().map(|rr| match &rr.data {
                NetDnsRecordData::A(ip)    => ip.to_string(),
                NetDnsRecordData::AAAA(ip) => ip.to_string(),
                NetDnsRecordData::NS(s) | NetDnsRecordData::CNAME(s) | NetDnsRecordData::PTR(s) | NetDnsRecordData::TXT(s) => {
                    String::from_utf8_lossy(s).into_owned()
                },
                NetDnsRecordData::MX(mx)   => String::from_utf8_lossy(&mx.mx).into_owned(),
                NetDnsRecordData::SRV(srv) => format!("{} {} {} {}", srv.priority, srv.weight, srv.port, String::from_utf8_lossy(&srv.target)),
                NetDnsRecordData::SOA(soa) => String::from_utf8_lossy(&soa.mname).into_owned(),
                _                          => "-".to_string(),
            }).collect()),
            TTLs:    p.answers.as_ref().map_or(vec![], |rrs| rrs.iter().map(|rr| rr.ttl).collect()),
            auth: if self.dns_auth_addl { Some(p.authorities.as_ref().map_or(vec![], |rrs| rrs.iter().map(|rr| match &rr.data {
                NetDnsRecordData::NS(s)    => String::from_utf8_lossy(s).into_owned(),
                NetDnsRecordData::SOA(soa) => String::from_utf8_lossy(&soa.mname).into_owned(),
                _                          => "-".to_string(),
            }).collect())) } else { None },
            addl: if self.dns_auth_addl { Some(p.additionals.as_ref().map_or(vec![], |rrs| rrs.iter().map(|rr| match &rr.data {
                NetDnsRecordData::A(ip)    => ip.to_string(),
                NetDnsRecordData::AAAA(ip) => ip.to_string(),
                _                          => "-".to_string(),
            }).collect())) } else { None },
            AA: p.aa,
            TC: p.tc,
            RD: p.rd,
            RA: p.ra,
            Z: (p.z as u8) << 2 | (p.ad as u8) << 1 | (p.cd as u8),
        }
    }

    fn write_dns_log(&mut self, log: ZeekDnsLog) {
        let dns_log = match self.dns_log.as_mut() {
            Some(f) => f,
            None => return,
        };
        if let Err(e) = to_writer(&mut *dns_log, &log) {
            error!("Error serializing the DNS log: {}", e);
            self.dns_log = None;
            return;
        }
        if let Err(e) = writeln!(&mut *dns_log) {
            error!("Error writing to DNS log file: {}", e);
            self.dns_log = None;
        }
    }

    fn flush_pending_dns_queries(&mut self, conn_id: &UniqueId) {
        if self.dns_log.is_none() {
            return;
        }
        let keys: Vec<(UniqueId, u16)> = self.pending_dns_queries.keys()
            .filter(|(cid, _)| cid == conn_id)
            .cloned()
            .collect();
        for key in keys {
            if let Some(qe) = self.pending_dns_queries.remove(&key) {
                if let EventPayload::NetDnsMessage(p) = &qe.payload {
                    let log = self.build_dns_log(qe.ts, p);
                    self.write_dns_log(log);
                }
            }
        }
    }

    fn process_event(&mut self, event: EventRef) {

        match event.kind() {

            EventKind::NetTcpConnectionEnd => self.process_conn_event(event),
            EventKind::NetUdpConnectionEnd => self.process_conn_event(event),
            EventKind::NetDnsMessage => self.process_dns_event(event),
            _ => unreachable!(),

        }

    }

    fn process_conn_event(&mut self, event: EventRef) {

        let conn_id = match &event.payload {
            EventPayload::NetTcpConnectionEnd(p) => p.conn_id.clone(),
            EventPayload::NetUdpConnectionEnd(p) => p.conn_id.clone(),
            _ => panic!("Wrong event received"),
        };

        if self.conn_log.is_some() {
            let log = match &event.payload {
                EventPayload::NetTcpConnectionEnd(p) => {
                    ZeekConnLog {
                        ts: event.ts,
                        uid: p.conn_id.clone(),
                        orig_h: p.client_addr,
                        orig_p: p.client_port,
                        resp_h: p.server_addr,
                        resp_p: p.server_port,
                        proto: "tcp",
                        duration: p.duration,
                        orig_bytes: p.fwd_bytes,
                        resp_bytes: p.rev_bytes,
                        missed_bytes: p.fwd_missed_bytes + p.rev_missed_bytes,
                        orig_pkts: p.fwd_pkts,
                        orig_ip_bytes: p.fwd_ip_bytes,
                        resp_pkts: p.rev_pkts,
                        resp_ip_bytes: p.rev_ip_bytes,
                        ip_proto: 6,
                    }
                },
                EventPayload::NetUdpConnectionEnd(p) => {
                    ZeekConnLog {
                        ts: event.ts,
                        uid: p.conn_id.clone(),
                        orig_h: p.client_addr,
                        orig_p: p.client_port,
                        resp_h: p.server_addr,
                        resp_p: p.server_port,
                        proto: "udp",
                        duration: p.duration,
                        orig_bytes: p.fwd_bytes,
                        resp_bytes: p.rev_bytes,
                        missed_bytes: 0,
                        orig_pkts: p.fwd_pkts,
                        orig_ip_bytes: p.fwd_ip_bytes,
                        resp_pkts: p.rev_pkts,
                        resp_ip_bytes: p.rev_ip_bytes,
                        ip_proto: 17,
                    }
                }
                _ => panic!("Wrong event received")
            };

            let conn_log = self.conn_log.as_mut().unwrap();
            if let Err(e) = to_writer(&mut *conn_log, &log) {
                error!("Error serializing the conn log: {}", e);
                self.conn_log = None;
            } else if let Err(e) = writeln!(&mut *conn_log) {
                error!("Error writing to conn log file: {}", e);
                self.conn_log = None;
            }
        }

        self.flush_pending_dns_queries(&conn_id);
    }

    fn process_dns_event(&mut self, event: EventRef) {

        if self.dns_log.is_none() {
            return;
        }

        let EventPayload::NetDnsMessage(p) = &event.payload else {
            panic!("Wrong event received")
        };

        if !p.is_response {
            self.pending_dns_queries.insert((p.conn_id.clone(), p.id), event);
            return;
        }

        // Use the query's timestamp if we saw the matching query
        let ts = self.pending_dns_queries
            .remove(&(p.conn_id.clone(), p.id))
            .map(|q| q.ts)
            .unwrap_or(event.ts);

        let log = self.build_dns_log(ts, p);
        self.write_dns_log(log);
    }
}

impl Output for OutputLogZeek {

    fn run(mut self: Box<Self>, rx: MessageRxChannel) {
        for msg in rx {

            match msg {
                Message::Shutdown => {
                    // Flush any queries that never received a response
                    if self.dns_log.is_some() {
                        let keys: Vec<_> = self.pending_dns_queries.keys().cloned().collect();
                        for key in keys {
                            if let Some(qe) = self.pending_dns_queries.remove(&key) {
                                if let EventPayload::NetDnsMessage(p) = &qe.payload {
                                    let log = self.build_dns_log(qe.ts, p);
                                    self.write_dns_log(log);
                                }
                            }
                        }
                    }

                    if let Some(ref mut f) = self.conn_log {
                        if let Err(e) = f.flush() {
                            error!("Error flushing the conn log file: {}", e);
                        }
                    }
                    if let Some(ref mut f) = self.dns_log {
                        if let Err(e) = f.flush() {
                            error!("Error flushing the dns log file: {}", e);
                        }
                    }

                    break;
                }
                Message::Event(e) => self.process_event(e),
                _ => panic!("Unknown message type"),
            }
        }
    }


}
