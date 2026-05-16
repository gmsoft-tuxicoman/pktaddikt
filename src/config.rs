

use crate::input::InputConfig;
use crate::proto::ProtoConfig;
use crate::output::OutputConfig;

use config::{Config as ConfigLoader, File};
use serde::Deserialize;
use std::sync::{Arc, OnceLock};
use std::collections::HashMap;
use arc_swap::{ArcSwap, Guard};


static CONFIG: OnceLock<ArcSwap<Config>> = OnceLock::new();


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


    pub fn init(cfg: Config) {
        CONFIG.set(ArcSwap::from_pointee(cfg)).unwrap();
    }

    #[cfg(not(test))]
    pub fn get() -> Guard<Arc<Config>> {
        CONFIG.get().unwrap().load()
    }

    #[cfg(test)]
    pub fn get() -> Guard<Arc<Config>> {
        CONFIG.get_or_init(|| ArcSwap::from_pointee(Config::default())).load()
    }

    pub fn load_file(filename: &str) -> Result<Config, config::ConfigError> {

        ConfigLoader::builder()
            .add_source(File::with_name(filename).required(false))
            .build()?
            .try_deserialize()


    }

}
