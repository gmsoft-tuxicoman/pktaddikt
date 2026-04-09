use crate::config::ConfigRef;
use crate::output::Output;
use crate::event::{EventTxChannel, EventRxChannel, EventBus, EventKind, EventId, EventPayload};
use crate::param::ParamValue;
use crate::packet::PktTime;

use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::time::Duration;
use serde::{Deserialize, Serialize};
use serde_json::to_writer;

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
    conn_log: BufWriter<File>,
}


#[derive(Debug, Serialize)]
struct ZeekConnLog {

    ts: PktTime,
    uid: EventId,
    #[serde(rename = "id.orig_h")]
    orig_h: Option<ParamValue>,
    #[serde(rename = "id.orig_p")]
    orig_p: u16,
    #[serde(rename = "id.resp_h")]
    resp_h: Option<ParamValue>,
    #[serde(rename = "id.resp_p")]
    resp_p: u16,
    proto: &'static str,
    //service: &'static str,
    duration: Duration,
    orig_bytes: usize,
    resp_bytes: usize,
    //conn_state
    missed_bytes: usize,
    //history
    orig_pkts: usize,
    orig_ip_bytes: usize,
    resp_pkts: usize,
    resp_ip_bytes: usize,
    ip_proto: u16,
}


impl OutputLogZeek {

    pub fn new(_cfg: ConfigRef, output_cfg: &LogZeekConfig, evt_bus: &mut EventBus, tx: &EventTxChannel) -> Box<dyn Output> {

        let mut path = output_cfg.path.clone();
        if path.len() > 0 && ! path.ends_with('/') {
            path.push('/');
        }

        path.push_str("conn.log");

        let file = OpenOptions::new().create(true).write(true).append(true).open(&path).expect(&format!("Unable to open {} for output logzeek", path));
        let writer = BufWriter::new(file);


        evt_bus.subscribe_kind(EventKind::NetTcpConnectionEnd, tx);
        evt_bus.subscribe_kind(EventKind::NetUdpConnectionEnd, tx);

        Box::new(Self { conn_log: writer })
    }

}

impl Output for OutputLogZeek {

    fn run(mut self: Box<Self>, rx: EventRxChannel) {
        for event in rx {

            if event.kind() == EventKind::SysShutdown {
                break;
            }

            let log = match &event.payload {
                EventPayload::NetTcpConnectionEnd(p) => {
                    ZeekConnLog {
                        ts: event.ts,
                        uid: p.conn_id.clone(),
                        orig_h: p.src_host,
                        orig_p: p.src_port,
                        resp_h: p.dst_host,
                        resp_p: p.dst_port,
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
                        orig_h: p.src_host,
                        orig_p: p.src_port,
                        resp_h: p.dst_host,
                        resp_p: p.dst_port,
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


            to_writer(&mut self.conn_log, &log).unwrap(); // FIXME clean the unwrap
            if writeln!(&mut self.conn_log).is_err() {
                panic!("Error while writing into file."); // FIXME clean this up
            }
        }
    }


}
