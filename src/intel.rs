
use crate::intel::hostdb::{HostDbRunner, HostDbConfig, HostDbRef};

use serde::Deserialize;
use ipnet::IpNet;

use std::sync::OnceLock;

pub mod hostdb;

static INTEL: OnceLock<Intel> = OnceLock::new();

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct IntelConfig {

    /// Networks to treat as local (CIDR, IPv4 and IPv6).
    /// Defaults to the RFC 1918 private ranges plus the IPv6 unique local range.
    pub local_nets: Vec<IpNet>,
    /// Host DB configuration
    #[serde(default)]
    pub hosts: Option<HostDbConfig>,
}

impl Default for IntelConfig {
    fn default() -> Self {
        Self {
            local_nets: [
                "10.0.0.0/8",
                "172.16.0.0/12",
                "192.168.0.0/16",
                "fd00::/8",
            ]
            .iter()
            .map(|n| n.parse().expect("valid default local_nets CIDR"))
            .collect(),
            hosts: None
        }
    }
}

#[derive(Debug)]
pub struct Intel {
    hostdb: Option<HostDbRunner>
}

impl Intel {

    pub fn new() -> Self {
        Self {
            hostdb: Some(HostDbRunner::new())
        }
    }

    pub fn init() {
        INTEL.set(Self::new()).unwrap();
    }

    /// Shared handle other threads use to mutate the host table.
    pub fn hosts() -> Option<HostDbRef> {
        INTEL.get().and_then(|intel| intel.hostdb.as_ref()).map(|runner| runner.db())
    }

    /// Signal the HostDb worker to stop and join its thread.
    pub fn shutdown() {
        if let Some(intel) = INTEL.get() {
            if let Some(runner) = &intel.hostdb {
                runner.join();
            }
        }
    }

}
