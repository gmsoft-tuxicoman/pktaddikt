
use crate::output::logjson::{OutputLogJson, LogJsonConfig};
use crate::output::logzeek::{OutputLogZeek, LogZeekConfig};
#[cfg(feature = "with_nftables")]
use crate::output::dns2nftset::{OutputDns2NftSet, Dns2NftSetConfig};
use crate::output::blob2disk::{OutputBlob2Disk, Blob2DiskConfig};
use crate::config::Config;
use crate::event::EventPayload;
use crate::messagebus::{MessageBus, MessageTxChannel, MessageRxChannel, Message};

use serde::Deserialize;
use crossbeam_channel;
use std::sync::Arc;

pub mod logjson;
pub mod logzeek;
#[cfg(feature = "with_nftables")]
pub mod dns2nftset;
pub mod blob2disk;

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
    #[serde(rename = "blob2disk")]
    Blob2Disk(Blob2DiskConfig),
}

pub trait Output: Send + 'static {

    fn run(self: Box<Self>, rx: MessageRxChannel);

}

#[derive(Debug)]
pub struct OutputRunner {
    tx: MessageTxChannel,
    thread: std::thread::JoinHandle<()>,
}

pub struct OutputBuilder {

    outputs: Vec<OutputRunner>,
}


impl OutputBuilder {

    pub fn build_all(msg_bus: &mut MessageBus) -> Self {

        let mut outputs: Vec<OutputRunner> = Vec::new();

        let cfg = Config::get();

        for (output_name, output_cfg) in &cfg.outputs {

            let (tx, rx) = crossbeam_channel::unbounded();

            let output = OutputBuilder::new(output_name, output_cfg, msg_bus, &tx);

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

    fn new(name: &str, output_cfg: &OutputConfig, msg_bus: &mut MessageBus, tx: &MessageTxChannel) -> Box<dyn Output> {

        println!("Adding output {} ...", name);

        match &output_cfg {
            OutputConfig::LogJson(_) => OutputLogJson::new(name, msg_bus, tx),
            OutputConfig::LogZeek(_) => OutputLogZeek::new(name, msg_bus, tx),
            OutputConfig::Dns2NftSet(_) => OutputDns2NftSet::new(name, msg_bus, tx),
            OutputConfig::Blob2Disk(_) => OutputBlob2Disk::new(name, msg_bus, tx),
        }

    }

    pub fn join(&mut self) {

        for output in self.outputs.drain(..) {
            output.tx.send(Arc::new(Message::Shutdown)).unwrap();
            output.thread.join().unwrap();
        }

    }

}
