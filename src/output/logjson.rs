use crate::output::{Output, OutputConfig};
use crate::messagebus::{MessageBus, MessageTxChannel, MessageRxChannel, Message};
use crate::config::Config;

use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use serde::Deserialize;
use serde_json::to_writer;
use tracing::error;

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
    writer: Option<BufWriter<File>>,
}


impl OutputLogJson {

    pub fn new(name: &str, tx: &MessageTxChannel) -> Box<dyn Output> {
        let main_cfg = Config::get();
        let OutputConfig::LogJson(cfg) = main_cfg.outputs.get(name).unwrap() else {
            panic!("Config is not logjson");
        };
        let file = OpenOptions::new().create(true).write(true).append(true).open(&cfg.file).expect(&format!("Unable to open file {} for output logjson", &cfg.file));
        let writer = BufWriter::new(file);

        for evt_name in &cfg.events {
            MessageBus::event_subscribe_glob(evt_name, tx).expect(&format!("Event {} does not exists", evt_name));
        }

        Box::new(Self { writer: Some(writer) })
    }

}

impl Output for OutputLogJson {

    fn run(mut self: Box<Self>, rx: MessageRxChannel) {
        for msg in rx {

            match msg {
                Message::Shutdown => {
                    if self.writer.is_none() {
                        break;
                    }
                    if let Err(e) = self.writer.as_mut().unwrap().flush() {
                        error!("Error flushing the log file: {}", e);
                    }
                    break;
                }
                Message::Event(e) => {

                    let Some(mut writer) = self.writer.as_mut() else {
                        // Writer had some failure
                        // Continue processing the messages but discard the content
                        continue;
                    };
                    if let Err(err) = to_writer(&mut writer, e.as_ref()) {
                        error!("Error serializing logs: {}", err);
                        self.writer = None;
                        continue;
                    }
                    if let Err(err) = writeln!(&mut writer) {
                        error!("Error writing to log file: {}", err);
                        self.writer = None;
                        continue;
                    }
                },
                _ => panic!("Unknown message type")
            }
        }
    }
}
