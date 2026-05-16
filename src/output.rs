
use crate::output::logjson::{OutputLogJson, LogJsonConfig};
use crate::output::logzeek::{OutputLogZeek, LogZeekConfig};
#[cfg(feature = "with_nftables")]
use crate::output::dns2nftset::{OutputDns2NftSet, Dns2NftSetConfig};
use crate::config::Config;
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

    pub fn build_all(evt_bus: &mut EventBus) -> Self {

        let mut outputs: Vec<OutputRunner> = Vec::new();

        let cfg = Config::get();

        for (output_name, output_cfg) in &cfg.outputs {

            let (tx, rx) = crossbeam_channel::unbounded();

            let output = OutputBuilder::new(output_name, output_cfg, evt_bus, &tx);

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

    fn new(name: &str, output_cfg: &OutputConfig, evt_bus: &mut EventBus, tx: &EventTxChannel) -> Box<dyn Output> {

        println!("Adding output {} ...", name);

        match &output_cfg {
            OutputConfig::LogJson(_) => OutputLogJson::new(name, evt_bus, tx),
            OutputConfig::LogZeek(_) => OutputLogZeek::new(name, evt_bus, tx),
            OutputConfig::Dns2NftSet(_) => OutputDns2NftSet::new(name, evt_bus, tx),
        }

    }

    pub fn join(&mut self) {

        for output in self.outputs.drain(..) {
            output.tx.send(Arc::new(Event::new(PktTime::from_micros(0), EventPayload::SysShutdown(SysShutdown{})))).unwrap();
            output.thread.join().unwrap();
        }

    }

}
