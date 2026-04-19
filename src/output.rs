
use crate::output::logjson::{OutputLogJson, LogJsonConfig};
use crate::output::logzeek::{OutputLogZeek, LogZeekConfig};
#[cfg(feature = "with_nftables")]
use crate::output::dns2nftset::{OutputDns2NftSet, Dns2NftSetConfig};
use crate::config::ConfigRef;
use crate::event::{EventRxChannel, EventTxChannel, EventBus, Event, EventPayload, SysShutdown};
use crate::packet::PktTime;

use serde::Deserialize;
use crossbeam_channel;
use std::sync::Arc;

pub mod logjson;
pub mod logzeek;

#[cfg(feature = "with_nftables")]
pub mod dns2nftset;

#[derive(Debug, Deserialize)]
#[serde(tag = "type" )]
pub enum OutputConfig {
    
    #[serde(rename = "logjson")]
    LogJson(LogJsonConfig),
    #[serde(rename = "logzeek")]
    LogZeek(LogZeekConfig),
    #[serde(rename = "dns2nftset")]
    #[cfg(feature = "with_nftables")]
    Dns2NftSet(Dns2NftSetConfig),
}

pub trait Output: Send + 'static {

    fn run(self: Box<Self>, rx: EventRxChannel);

}

#[derive(Debug)]
pub struct OutputRunner {
    tx: EventTxChannel,
    thread: std::thread::JoinHandle<()>,
}

pub struct OutputBuilder {

    outputs: Vec<OutputRunner>,
}


impl OutputBuilder {

    pub fn build_all(cfg: ConfigRef, evt_bus: &mut EventBus) -> Self {

        let mut outputs: Vec<OutputRunner> = Vec::new();

        for (output_name, _) in &cfg.outputs {

            let (tx, rx) = crossbeam_channel::unbounded();

            let output = OutputBuilder::new(cfg.clone(), output_name, evt_bus, &tx);

            let handle = std::thread::spawn(move || {
                output.run(rx);
            });

            outputs.push(OutputRunner {
                tx,
                thread: handle,
            });

        }

        Self { outputs }

    }

    fn new(cfg: ConfigRef, name: &str, evt_bus: &mut EventBus, tx: &EventTxChannel) -> Box<dyn Output> {

        let output_cfg = match cfg.outputs.get(name) {
            Some(o) => o,
            None => panic!("Invalid output type"),
        };

        println!("Adding output {} ...", name);

        match &output_cfg {
            OutputConfig::LogJson(c) => OutputLogJson::new(c, evt_bus, tx),
            OutputConfig::LogZeek(c) => OutputLogZeek::new(c, evt_bus, tx),
            OutputConfig::Dns2NftSet(c) => OutputDns2NftSet::new(c, evt_bus, tx),
        }

    }

    pub fn join(&mut self) {

        for output in self.outputs.drain(..) {
            output.tx.send(Arc::new(Event::new(PktTime::from_micros(0), EventPayload::SysShutdown(SysShutdown{})))).unwrap();
            output.thread.join().unwrap();
        }

    }

}
