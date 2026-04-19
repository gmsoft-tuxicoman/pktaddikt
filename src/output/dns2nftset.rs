use crate::output::Output;
use crate::event::{EventTxChannel, EventRxChannel, EventBus, EventKind};
use crate::output::EventPayload::NetDnsMessage;
use crate::proto::dns::NetDnsRecordData;

use serde::Deserialize;
use tracing::{warn, trace};
use std::net::IpAddr;
use nftables::{batch::Batch, helper, schema, types, expr};
use smallvec::SmallVec;
use std::borrow::Cow;
use std::collections::HashSet;

#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct Dns2NftSetConfig {
    pub matches: Vec<String>,
    pub table: String,
    pub set: String,
}


impl Default for Dns2NftSetConfig {

    fn default() -> Self {
        Self {
            matches: Vec::new(),
            table: "filter".to_string(),
            set: "pktaddikt".to_string(),
        }
    }

}

pub struct OutputDns2NftSet {

    table: String,
    matches: Vec<String>,
    set_v4: String,
    set_v6: String,
}

impl OutputDns2NftSet {

    pub fn new(output_cfg: &Dns2NftSetConfig, evt_bus: &mut EventBus, tx: &EventTxChannel) -> Box<dyn Output> {

        evt_bus.subscribe_kind(EventKind::NetDnsMessage, tx);

        if output_cfg.matches.len() == 0 {
            warn!("No match configured, the output will not match anything !");
        }

        let set_v4 = output_cfg.set.clone() + "_v4";
        let set_v6 = output_cfg.set.clone() + "_v6";
        
        let mut batch = Batch::new();
        batch.add(schema::NfListObject::Table(schema::Table {
            family: types::NfFamily::INet,
            name: output_cfg.table.clone().into(),
            ..Default::default()
        }));

        let mut timeout_flag = HashSet::new();
        timeout_flag.insert(schema::SetFlag::Timeout);

        batch.add(schema::NfListObject::Set(Box::new(schema::Set {
            family: types::NfFamily::INet,
            flags: Some(timeout_flag.clone()),
            name: set_v4.clone().into(),
            ..Default::default()
        })));

        batch.add(schema::NfListObject::Set(Box::new(schema::Set {
            family: types::NfFamily::INet,
            set_type: schema::SetTypeValue::Single(schema::SetType::Ipv6Addr),
            flags: Some(timeout_flag.clone()),
            name: set_v6.clone().into(),
            ..Default::default()
        })));

        helper::apply_ruleset(&batch.to_nftables()).unwrap();

        Box::new(Self {
            table: output_cfg.table.clone(),
            matches: output_cfg.matches.clone(),
            set_v4,
            set_v6,
        })
    }
}

impl Output for OutputDns2NftSet {

    fn run(self: Box<Self>, rx: EventRxChannel) {

        for event in rx {
            if event.kind() == EventKind::SysShutdown {
                break;
            }

            let NetDnsMessage(msg) = &event.payload else {
                panic!("Wrong event kind received");
            };

            // We need answers !
            if ! msg.is_response || msg.answer_count == 0 {
                continue;
            }

            let mut ips: SmallVec<[(IpAddr, u32); 10]> = SmallVec::new();

            for a in msg.answers.as_ref().unwrap() {

                let ip = match a.data {
                    NetDnsRecordData::A(ipv4) => (IpAddr::V4(ipv4), a.ttl),
                    NetDnsRecordData::AAAA(ipv6) => (IpAddr::V6(ipv6), a.ttl),
                    _ => continue
                };

                let name = String::from_utf8_lossy(&a.name);
            
                for m in &self.matches {
                    if name.contains(m) {
                        trace!("Adding ip from matched hostname: {} -> {} (ttl: {})", name, ip.0, ip.1);
                        ips.push(ip);
                        break;
                    }
                }
            }

            if ips.len() == 0 {
                // No matched ip
                continue;
            }


            let mut batch = Batch::new();
            for ip in &ips {

                let elem = expr::Elem {
                    val: Box::new(expr::Expression::String(Cow::Owned(ip.0.to_string()))),
                    timeout: Some(ip.1),
                    ..Default::default()
                };

                batch.add(schema::NfListObject::Element(schema::Element {
                    family: types::NfFamily::INet,
                    table: Cow::Borrowed(&self.table),
                    name: match ip.0 {
                        IpAddr::V4(_) => Cow::Borrowed(&self.set_v4),
                        IpAddr::V6(_) => Cow::Borrowed(&self.set_v6),
                    },
                    elem: vec![expr::Expression::Named(expr::NamedExpression::Elem(elem))].into(),
                }));

            }

            trace!("Applying batch !");

            helper::apply_ruleset(&batch.to_nftables()).unwrap();
        }


    }

}
