

use crate::input::InputConfig;
use crate::proto::ProtoConfig;

use config::{Config as ConfigLoader, File};
use serde::Deserialize;
use std::sync::Arc;

pub type ConfigRef = Arc<Config>;


#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {

    pub input: InputConfig,
    pub proto: ProtoConfig,

}
impl Default for Config {
    fn default() -> Self {
        Self {
            input: InputConfig::default(),
            proto: ProtoConfig::default(),
        }
    }
}

impl Config {

    pub fn new() -> ConfigRef {
        Arc::new(Config::default())
    }

    pub fn load(filename: &str) -> Result<Config, config::ConfigError> {

        let settings = ConfigLoader::builder()
            .add_source(File::with_name(filename).required(false))
            .build()?;

        settings.try_deserialize()

    }
}
