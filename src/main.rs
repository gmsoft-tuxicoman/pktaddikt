use crate::config::Config;
use crate::input::{Input, InputConfig};
use crate::input::pcap::{PcapFileConfig, PcapInterfaceConfig};
use clap::Parser;
use tracing_subscriber::{EnvFilter, fmt, prelude::*};
use std::sync::Arc;

pub mod proto;
pub mod conntrack;
pub mod param;
pub mod packet;
pub mod timer;
pub mod stream;
pub mod event;
pub mod config;
pub mod input;


#[derive(Parser, Debug)]
struct CliOpts {

    #[arg(short = 'c', long = "config", default_value = "config.yaml")]
    config: String,

    #[arg(short = 'r', long = "read", conflicts_with = "pcap_interface")]
    pcap_file: Option<String>,

    #[arg(short = 'i', long = "interface", conflicts_with = "pcap_file")]
    pcap_interface: Option<String>,

}


fn main() {

    let cli_cfg = CliOpts::parse();

    let mut cfg = Config::load(&cli_cfg.config).unwrap();

    if cli_cfg.pcap_file.is_some() {
        cfg.input = InputConfig::PcapFile(PcapFileConfig {
            file: cli_cfg.pcap_file.unwrap().clone(),
        });
    } else if cli_cfg.pcap_interface.is_some() {
        match cfg.input {
            InputConfig::PcapFile(_) => {
                cfg.input = InputConfig::PcapInterface(PcapInterfaceConfig {
                    iface: cli_cfg.pcap_interface.unwrap().clone(),
                    buffer_size: 65535,
                    promisc: true,
                    snaplen: 1550
                })
            },
            InputConfig::PcapInterface(ref mut c) => {
                    c.iface = cli_cfg.pcap_interface.unwrap().clone();
            }
        };
    }

    let mut input = Input::new(Arc::new(cfg));

    let subscriber = tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env());

    tracing::subscriber::set_global_default(subscriber)
            .expect("Failed to set global subscriber");

    input.main_loop();
}


