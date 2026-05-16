use crate::output::{Output, OutputConfig};
use crate::event::{EventTxChannel, EventRxChannel, EventBus, EventKind};
use crate::config::Config;

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

    pub fn new(name: &str, evt_bus: &mut EventBus, tx: &EventTxChannel) -> Box<dyn Output> {
        let main_cfg = Config::get();
        let OutputConfig::LogJson(cfg) = main_cfg.outputs.get(name).unwrap() else {
            panic!("Config is not logjson");
        };
        let file = OpenOptions::new().create(true).write(true).append(true).open(&cfg.file).expect(&format!("Unable to open file {} for output logjson", &cfg.file));
        let writer = BufWriter::new(file);


        for evt_name in &cfg.events {
            evt_bus.subscribe_glob(evt_name, tx).expect(&format!("Event {} does not exists", evt_name));
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
