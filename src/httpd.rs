
pub mod mcp;

use crate::config::Config;

use axum::{routing::get, Router};
use serde::Deserialize;
use tokio::runtime::Runtime;


#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HttpdConfig {
    pub bind: String,
    pub mcp: bool,
    /// Hostnames (or host:port) allowed in the MCP Host header.
    /// Overrides the rmcp default (localhost only) when non-empty.
    pub mcp_allowed_hosts: Vec<String>,
}

impl Default for HttpdConfig {
    fn default() -> Self {
        Self {
            bind: "127.0.0.1:8080".to_owned(),
            mcp: true,
            mcp_allowed_hosts: vec![],
        }
    }
}


pub struct Httpd {

    thread: std::thread::JoinHandle<()>,

}

impl Httpd {

    pub fn new() -> Self {

        let thread = std::thread::spawn(|| {
            let rt = Runtime::new().expect("httpd tokio runtime");
            rt.block_on(Self::run())
        });

        Self {
            thread,
        }
    }

    async fn run() {
        let cfg = Config::get();
        let bind_addr = cfg.httpd.bind.clone();
        let enable_mcp = cfg.httpd.mcp;
        let mcp_allowed_hosts = cfg.httpd.mcp_allowed_hosts.clone();
        drop(cfg);

        let mut app = Router::new()
            .route("/", get(|| async { "pktaddikt ok" }));

        if enable_mcp {
            app = app.route_service("/mcp", mcp::mcp_service(mcp_allowed_hosts));
        }

        let listener = tokio::net::TcpListener::bind(&bind_addr).await.unwrap_or_else(|e| panic!("httpd bind {bind_addr}: {e}"));

        axum::serve(listener, app).await.expect("httpd");

    }

}
