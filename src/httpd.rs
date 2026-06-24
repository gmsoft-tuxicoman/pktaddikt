
pub mod mcp;

use axum::{routing::get, Router};
use tokio::runtime::Runtime;


pub struct Httpd {

    thread: std::thread::JoinHandle<()>,

}

impl Httpd {


    pub fn new(bind_addr: &str, enable_mcp: bool) -> Self {

        let bind_addr = bind_addr.to_owned();
        let thread = std::thread::spawn(move || {
            let rt = Runtime::new().expect("httpd tokio runtime");
            rt.block_on(Self::run(bind_addr, enable_mcp))
        });

        Self {
            thread,
        }
    }

    async fn run(bind_addr: String, enable_mcp: bool) {
        let mut app = Router::new()
            .route("/", get(|| async { "pktaddikt ok" }));

        if enable_mcp {
            app = app.route_service("/mcp", mcp::mcp_service());
        }

        let listener = tokio::net::TcpListener::bind(&bind_addr).await.unwrap_or_else(|e| panic!("httpd bind {bind_addr}: {e}"));

        axum::serve(listener, app).await.expect("httpd");

    }

}
