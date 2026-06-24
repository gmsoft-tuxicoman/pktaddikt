use crate::event::EventKind;
use crate::messagebus::{MessageBus, Message};

use std::sync::Arc;
use std::time::{Duration, Instant};
use rmcp::{
    ErrorData, ServerHandler,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{CallToolResult, Content, ServerCapabilities, ServerInfo},
    tool, tool_handler, tool_router,
    transport::streamable_http_server::{
        StreamableHttpService, StreamableHttpServerConfig,
        session::local::LocalSessionManager,
    },
};
use schemars::JsonSchema;
use serde::Deserialize;
use strum::IntoEnumIterator;


#[derive(Deserialize, JsonSchema)]
struct WatchEventsParams {
    /// Event glob pattern (e.g. "net.http.*", "net.dns.message", "*")
    pattern: String,
    /// Maximum number of events to collect (default: 10)
    max_events: Option<u32>,
    /// Seconds to wait for events (default: 5)
    timeout_secs: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct McpServer {
    tool_router: ToolRouter<Self>,
}

#[tool_router(router = tool_router)]
impl McpServer {

    #[tool(description = "List all available event kinds that can be subscribed to")]
    fn list_event_kinds(&self) -> String {
        EventKind::iter()
            .map(|e| e.as_ref().to_string())
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[tool(description = "Watch for events matching a glob pattern. Collects up to max_events events or until timeout_secs elapses.")]
    async fn watch_events(&self, params: Parameters<WatchEventsParams>) -> Result<CallToolResult, ErrorData> {

        let p = params.0;
        let max = p.max_events.unwrap_or(10) as usize;
        let timeout = Duration::from_secs(p.timeout_secs.unwrap_or(5) as u64);

        let (tx, rx) = crossbeam_channel::bounded::<Message>(max + 1);

        MessageBus::event_subscribe_glob(&p.pattern, &tx)
            .map_err(|_| ErrorData::invalid_params(
                format!("no events match pattern '{}'", p.pattern), None
            ))?;

        let events = tokio::task::spawn_blocking(move || {
            let deadline = Instant::now() + timeout;
            let mut events = Vec::<serde_json::Value>::new();

            loop {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() { break; }
                match rx.recv_timeout(remaining) {
                    Ok(Message::Event(evt)) => {
                        if let Ok(v) = serde_json::to_value(&*evt) {
                            events.push(v);
                        }
                        if events.len() >= max { break; }
                    }
                    Ok(Message::Shutdown) | Err(_) => break,
                    Ok(_) => {}
                }
            }
            events
        }).await.map_err(|e| ErrorData::internal_error(e.to_string(), None))?;

        MessageBus::unsubscribe_all(&tx);

        let text = serde_json::to_string_pretty(&events)
            .unwrap_or_else(|_| "[]".to_string());

        Ok(CallToolResult::success(vec![Content::text(text)]))
    }

}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for McpServer {
    fn get_info(&self) -> ServerInfo {
        let mut info = ServerInfo::new(ServerCapabilities::builder().enable_tools().build());
        info.server_info.name = env!("CARGO_PKG_NAME").to_string();
        info.server_info.version = env!("CARGO_PKG_VERSION").to_string();
        info
    }
}

impl McpServer {
    pub fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }
}

pub fn mcp_service() -> StreamableHttpService<McpServer, LocalSessionManager> {
    StreamableHttpService::new(
        || Ok(McpServer::new()),
        Arc::new(LocalSessionManager::default()),
        StreamableHttpServerConfig::default(),
    )
}
