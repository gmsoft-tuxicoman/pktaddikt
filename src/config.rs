

use crate::input::InputConfig;
use crate::proto::ProtoConfig;
use crate::output::OutputConfig;

use config::{Config as ConfigLoader, File};
use serde::Deserialize;
use std::sync::Arc;
use std::collections::HashMap;

pub type ConfigRef = Arc<Config>;


#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {

    pub input: InputConfig,
    pub proto: ProtoConfig,
    pub outputs: HashMap<String, OutputConfig>,

}
impl Default for Config {
    fn default() -> Self {
        Self {
            input: InputConfig::default(),
            proto: ProtoConfig::default(),
            outputs: HashMap::new(),
        }
    }
}

impl Config {

    pub fn new() -> ConfigRef {
        Arc::new(Config::default())
    }

    pub fn load(filename: &str) -> Result<Config, config::ConfigError> {

        ConfigLoader::builder()
            .add_source(File::with_name(filename).required(false))
            .build()?
            .try_deserialize()


    }

}
