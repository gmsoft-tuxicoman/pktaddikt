use crate::config::ConfigRef;
use crate::output::Output;
use crate::event::{EventTxChannel, EventRxChannel, EventBus, EventKind};

use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use serde::Deserialize;
use serde_json::to_writer;

#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct LogJsonConfig {

    pub file: String,
    pub events: Vec<String>,

}

impl Default for LogJsonConfig {
    
    fn default() -> Self {
        Self {
            file: "log.json".to_string(),
            events: Vec::new(),
        }
    }

}

pub struct OutputLogJson {
    writer: BufWriter<File>,
}


impl OutputLogJson {

    pub fn new(_cfg: ConfigRef, output_cfg: &LogJsonConfig, evt_bus: &mut EventBus, tx: &EventTxChannel) -> Box<dyn Output> {
        let file = OpenOptions::new().create(true).write(true).append(true).open(&output_cfg.file).expect("Unable to open file {} for output logjson", &output_cfg.file);
        let writer = BufWriter::new(file);


        for evt_name in &output_cfg.events {
            evt_bus.subscribe_glob(evt_name, tx);
        }

        Box::new(Self { writer })
    }

}

impl Output for OutputLogJson {

    fn run(mut self: Box<Self>, rx: EventRxChannel) {
        for event in rx {

            if event.kind() == EventKind::SysShutdown {
                break;
            }

            to_writer(&mut self.writer, event.as_ref()).unwrap(); // FIXME clean the unwrap
            if writeln!(&mut self.writer).is_err() {
                panic!("Error while writing into file."); // FIXME clean this up
            }
        }
    }


}
