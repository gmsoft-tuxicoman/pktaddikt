use crate::output::{Output, OutputConfig};
use crate::event::{EventRef, EventKind, EventPayload};
use crate::messagebus::{MessageBus, MessageTxChannel, MessageRxChannel, Message};
use crate::base::UniqueId;
use crate::packet::PktTime;
use crate::config::Config;

use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use serde::{Deserialize, Serialize};
use serde_json::to_writer;
use std::net::IpAddr;
use tracing::error;

#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct LogZeekConfig {

    pub path: String,

}

impl Default for LogZeekConfig {
    
    fn default() -> Self {
        Self {
            path: "".to_string(),
        }
    }

}

pub struct OutputLogZeek {
    conn_log: Option<BufWriter<File>>,
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


impl OutputLogZeek {

    pub fn new(name: &str, msg_bus: &mut MessageBus, tx: &MessageTxChannel) -> Box<dyn Output> {

        let main_cfg = Config::get();
        let OutputConfig::LogZeek(cfg) = main_cfg.outputs.get(name).unwrap() else {
            panic!("Config is not logzeek");
        };

        let mut path = cfg.path.clone();
        if path.len() > 0 && ! path.ends_with('/') {
            path.push('/');
        }

        path.push_str("conn.log");

        let file = OpenOptions::new().create(true).write(true).append(true).open(&path).expect(&format!("Unable to open {} for output logzeek", path));
        let writer = BufWriter::new(file);


        msg_bus.event_subscribe_kind(EventKind::NetTcpConnectionEnd, tx);
        msg_bus.event_subscribe_kind(EventKind::NetUdpConnectionEnd, tx);

        Box::new(Self { conn_log: Some(writer) })
    }

    fn process_event(&mut self, event: EventRef) {

        if self.conn_log.is_none() {
            // There was an error writing the logs
            // Keep processing the messages but don't attempt to write
            return;
        }

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
                    //service: &'static str,
                    duration: p.duration,
                    orig_bytes: p.fwd_bytes,
                    resp_bytes: p.rev_bytes,
                    //conn_state
                    missed_bytes: p.fwd_missed_bytes + p.rev_missed_bytes,
                    //history
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
                    //service: &'static str,
                    duration: p.duration,
                    orig_bytes: p.fwd_bytes,
                    resp_bytes: p.rev_bytes,
                    //conn_state
                    missed_bytes: 0,
                    //history
                    orig_pkts: p.fwd_pkts,
                    orig_ip_bytes: p.fwd_ip_bytes,
                    resp_pkts: p.rev_pkts,
                    resp_ip_bytes: p.rev_ip_bytes,
                    ip_proto: 17,
                }
            }
            _ => panic!("Wrong event received")
        };

        let mut conn_log = self.conn_log.as_mut().unwrap();

        if let Err(e) = to_writer(&mut conn_log, &log) {
            error!("Error serializing the logs: {}", e);
            self.conn_log = None;
            return;
        }
        if let Err(e) = writeln!(&mut conn_log) {
            error!("Error writing to the log file: {}", e);
            self.conn_log = None;
            return;
        }
    }

}

impl Output for OutputLogZeek {

    fn run(mut self: Box<Self>, rx: MessageRxChannel) {
        for msg in rx {

            match msg {
                Message::Shutdown => {
                    if self.conn_log.is_none() {
                        break;
                    }
                    if let Err(e) = self.conn_log.as_mut().unwrap().flush() {
                        error!("Error flushing the log file: {}", e);
                    }
                    break;
                }
                Message::Event(e) => self.process_event(e),
                _ => panic!("Unknown message type"),
            }
        }
    }


}
