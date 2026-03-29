
use config::{Config as ConfigLoader, File};
use crate::input::InputConfig;

use serde::Deserialize;



#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct Config {

    pub input: InputConfig

}
impl Default for Config {
    fn default() -> Self {
        Self {
            input: InputConfig::default()
        }
    }
}

impl Config {

    pub fn load(filename: &str) -> Result<Config, config::ConfigError> {

        let settings = ConfigLoader::builder()
            .add_source(File::with_name(filename).required(false))
            .build()?;

        settings.try_deserialize()

    }
}
