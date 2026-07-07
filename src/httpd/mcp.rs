use crate::event::EventKind;
use crate::messagebus::{MessageBus, MessageTxChannel, MessageRxChannel, Message};

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
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

/// Default ring-buffer capacity for a subscription, in events.
const DEFAULT_BUFFER_SIZE: usize = 1024;


#[derive(Deserialize, JsonSchema)]
struct SubscribeParams {
    /// Event glob pattern (e.g. "net.http.*", "net.dns.message", "*")
    pattern: String,
    /// Ring-buffer capacity in events; oldest events are dropped once full (default: 1024)
    buffer_size: Option<u32>,
}

#[derive(Deserialize, JsonSchema)]
struct PollEventsParams {
    /// Subscription id returned by `subscribe`
    sub_id: u64,
    /// Maximum number of events to drain from the buffer (default: 100)
    max_events: Option<u32>,
    /// Seconds to wait for at least one event if the buffer is empty (default: 5)
    timeout_secs: Option<u32>,
}

#[derive(Deserialize, JsonSchema)]
struct UnsubscribeParams {
    /// Subscription id returned by `subscribe`
    sub_id: u64,
}

/// Bounded, drop-oldest ring buffer of serialized events, plus a count of how
/// many events were dropped due to overflow since the last drain.
#[derive(Debug)]
struct RingBuffer {
    deque: VecDeque<serde_json::Value>,
    cap: usize,
    dropped: u64,
}

impl RingBuffer {
    fn new(cap: usize) -> Self {
        RingBuffer { deque: VecDeque::new(), cap, dropped: 0 }
    }

    fn push(&mut self, v: serde_json::Value) {
        if self.deque.len() >= self.cap {
            self.deque.pop_front();
            self.dropped += 1;
        }
        self.deque.push_back(v);
    }

    /// Remove and return up to `max` events, together with the number of
    /// overflow drops accumulated since the previous drain (which is reset).
    fn drain(&mut self, max: usize) -> (Vec<serde_json::Value>, u64) {
        let n = max.min(self.deque.len());
        let events = self.deque.drain(..n).collect();
        let dropped = self.dropped;
        self.dropped = 0;
        (events, dropped)
    }
}

/// Shared handle to a subscription's buffer. The `Condvar` lets `poll_events`
/// block until the drainer thread pushes a new event.
type SharedBuffer = Arc<(Mutex<RingBuffer>, Condvar)>;

/// Body of a subscription's background thread: move events off the bus channel
/// into the ring buffer until a `Shutdown` arrives or the channel disconnects.
fn run_drainer(rx: MessageRxChannel, buffer: SharedBuffer) {
    loop {
        match rx.recv() {
            Ok(Message::Event(evt)) => {
                if let Ok(v) = serde_json::to_value(&*evt) {
                    let (lock, cvar) = &*buffer;
                    lock.lock().unwrap().push(v);
                    cvar.notify_all();
                }
            }
            Ok(Message::Shutdown) | Err(_) => break,
            Ok(_) => {}
        }
    }
}

/// Drain up to `max` events, waiting up to `timeout` for at least one event if
/// the buffer is currently empty. Returns the events and the overflow-drop
/// count accumulated since the previous drain.
fn drain_blocking(buffer: SharedBuffer, max: usize, timeout: Duration) -> (Vec<serde_json::Value>, u64) {
    let (lock, cvar) = &*buffer;
    let mut guard = lock.lock().unwrap();
    let deadline = Instant::now() + timeout;
    while guard.deque.is_empty() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() { break; }
        let (g, res) = cvar.wait_timeout(guard, remaining).unwrap();
        guard = g;
        if res.timed_out() { break; }
    }
    guard.drain(max)
}

/// A long-lived subscription whose lifetime is decoupled from any single tool
/// call. A background drainer thread moves events off the bus channel into the
/// ring buffer, so events arriving between polls are retained.
#[derive(Debug)]
struct Subscription {
    tx: MessageTxChannel,
    buffer: SharedBuffer,
    drainer: Option<JoinHandle<()>>,
}

impl Subscription {
    fn shutdown(&mut self) {
        // Stop new events first, then wake the drainer so it can exit. Our `tx`
        // clone keeps the channel connected until the drainer drops `rx`.
        MessageBus::unsubscribe_all(&self.tx);
        let _ = self.tx.send(Message::Shutdown);
        if let Some(handle) = self.drainer.take() {
            let _ = handle.join();
        }
    }
}

/// Per-session subscription registry. Held behind an `Arc` inside `McpServer`
/// so every clone of the server shares it, and every subscription is torn down
/// when the session (and its last server clone) is dropped.
#[derive(Debug)]
struct SessionState {
    subs: Mutex<HashMap<u64, Subscription>>,
    next_id: AtomicU64,
}

impl SessionState {
    fn new() -> Self {
        SessionState {
            subs: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(1),
        }
    }
}

impl Drop for SessionState {
    fn drop(&mut self) {
        if let Ok(mut subs) = self.subs.lock() {
            for (_, mut sub) in subs.drain() {
                sub.shutdown();
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct McpServer {
    tool_router: ToolRouter<Self>,
    state: Arc<SessionState>,
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

    #[tool(description = "Create a persistent subscription for events matching a glob pattern. Events are buffered from the moment of subscription, so nothing is lost between polls. Returns a sub_id to pass to poll_events and unsubscribe.")]
    async fn subscribe(&self, params: Parameters<SubscribeParams>) -> Result<CallToolResult, ErrorData> {

        let p = params.0;
        let cap = p.buffer_size.map(|n| n as usize).unwrap_or(DEFAULT_BUFFER_SIZE).max(1);

        let (tx, rx) = crossbeam_channel::unbounded::<Message>();

        MessageBus::event_subscribe_glob(&p.pattern, &tx)
            .map_err(|_| ErrorData::invalid_params(
                format!("no events match pattern '{}'", p.pattern), None
            ))?;

        let buffer: SharedBuffer = Arc::new((Mutex::new(RingBuffer::new(cap)), Condvar::new()));

        let drain_buffer = buffer.clone();
        let drainer = std::thread::spawn(move || run_drainer(rx, drain_buffer));

        let sub_id = self.state.next_id.fetch_add(1, Ordering::Relaxed);
        self.state.subs.lock().unwrap().insert(sub_id, Subscription {
            tx,
            buffer,
            drainer: Some(drainer),
        });

        let text = serde_json::json!({ "sub_id": sub_id, "pattern": p.pattern, "buffer_size": cap }).to_string();
        Ok(CallToolResult::success(vec![Content::text(text)]))
    }

    #[tool(description = "Drain buffered events from a subscription. Returns up to max_events events plus a `dropped` count of events lost to buffer overflow since the last poll. If the buffer is empty, waits up to timeout_secs for at least one event.")]
    async fn poll_events(&self, params: Parameters<PollEventsParams>) -> Result<CallToolResult, ErrorData> {

        let p = params.0;
        let max = p.max_events.unwrap_or(100) as usize;
        let timeout = Duration::from_secs(p.timeout_secs.unwrap_or(5) as u64);

        let buffer = self.state.subs.lock().unwrap()
            .get(&p.sub_id)
            .map(|s| s.buffer.clone())
            .ok_or_else(|| ErrorData::invalid_params(
                format!("no such subscription: {}", p.sub_id), None
            ))?;

        let (events, dropped) = tokio::task::spawn_blocking(move || {
            drain_blocking(buffer, max, timeout)
        }).await.map_err(|e| ErrorData::internal_error(e.to_string(), None))?;

        let text = serde_json::to_string_pretty(&serde_json::json!({
            "events": events,
            "dropped": dropped,
        })).unwrap_or_else(|_| "{}".to_string());

        Ok(CallToolResult::success(vec![Content::text(text)]))
    }

    #[tool(description = "Cancel a persistent subscription created by subscribe and free its buffer.")]
    async fn unsubscribe(&self, params: Parameters<UnsubscribeParams>) -> Result<CallToolResult, ErrorData> {

        let p = params.0;
        let sub = self.state.subs.lock().unwrap().remove(&p.sub_id);

        match sub {
            Some(mut sub) => {
                sub.shutdown();
                Ok(CallToolResult::success(vec![Content::text(
                    format!("unsubscribed {}", p.sub_id)
                )]))
            }
            None => Err(ErrorData::invalid_params(
                format!("no such subscription: {}", p.sub_id), None
            )),
        }
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
            state: Arc::new(SessionState::new()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{Event, EventPayload};
    use crate::proto::ssh::NetSshSession;
    use crate::packet::PktTime;
    use crate::base::UniqueId;
    use std::net::{IpAddr, Ipv4Addr};

    fn shared(cap: usize) -> SharedBuffer {
        Arc::new((Mutex::new(RingBuffer::new(cap)), Condvar::new()))
    }

    /// A minimal but real, serializable event.
    fn make_event() -> crate::event::EventRef {
        let ts = PktTime::from_secs(1);
        let payload = EventPayload::NetSshSession(NetSshSession {
            conn_id: UniqueId::new(ts),
            server_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            server_port: 22,
            server_version: None,
            client_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            client_port: 4000,
            client_version: None,
            kex_algorithm: None,
            server_host_key_algorithm: None,
            host_key_fingerprint: None,
            encryption_algorithm_client_to_server: None,
            mac_algorithm_client_to_server: None,
            compression_algorithm_client_to_server: None,
            encryption_algorithm_server_to_client: None,
            mac_algorithm_server_to_client: None,
            compression_algorithm_server_to_client: None,
            authentication_failed: 0,
            authentication_succeeded: None,
        });
        Event::new(ts, payload)
    }

    fn wait_len(buffer: &SharedBuffer, want: usize) {
        for _ in 0..200 {
            if buffer.0.lock().unwrap().deque.len() >= want { return; }
            std::thread::sleep(Duration::from_millis(5));
        }
        panic!("timed out waiting for {want} buffered events");
    }

    #[test]
    fn ring_buffer_drops_oldest_and_counts() {
        let mut rb = RingBuffer::new(3);
        for i in 0..5 {
            rb.push(serde_json::json!(i));
        }
        // Capacity 3, pushed 5 -> oldest two (0, 1) dropped.
        let (events, dropped) = rb.drain(10);
        assert_eq!(dropped, 2);
        assert_eq!(events, vec![json_i(2), json_i(3), json_i(4)]);
        // dropped counter resets after a drain.
        let (events, dropped) = rb.drain(10);
        assert!(events.is_empty());
        assert_eq!(dropped, 0);
    }

    fn json_i(i: i64) -> serde_json::Value { serde_json::json!(i) }

    #[test]
    fn drain_respects_max_and_leaves_remainder() {
        let mut rb = RingBuffer::new(10);
        for i in 0..5 { rb.push(json_i(i)); }
        let (events, _) = rb.drain(2);
        assert_eq!(events.len(), 2);
        assert_eq!(rb.deque.len(), 3);
    }

    #[test]
    fn drain_blocking_times_out_when_empty() {
        let buf = shared(10);
        let start = Instant::now();
        let (events, dropped) = drain_blocking(buf, 100, Duration::from_millis(80));
        assert!(events.is_empty());
        assert_eq!(dropped, 0);
        assert!(start.elapsed() >= Duration::from_millis(70));
    }

    /// The core property: events that arrive while no poll is in flight are
    /// retained and returned by the next poll (this is what the old one-shot
    /// watch_events lost).
    #[test]
    fn drainer_buffers_events_between_polls() {
        let buf = shared(1024);
        let (tx, rx) = crossbeam_channel::unbounded::<Message>();
        let drain_buf = buf.clone();
        let handle = std::thread::spawn(move || run_drainer(rx, drain_buf));

        // Batch 1 arrives before the first poll.
        for _ in 0..3 { tx.send(Message::Event(make_event())).unwrap(); }
        wait_len(&buf, 3);
        let (events, dropped) = drain_blocking(buf.clone(), 100, Duration::from_millis(200));
        assert_eq!(events.len(), 3);
        assert_eq!(dropped, 0);

        // Batch 2 arrives *between* polls, with nothing draining.
        for _ in 0..2 { tx.send(Message::Event(make_event())).unwrap(); }
        wait_len(&buf, 2);
        let (events, _) = drain_blocking(buf.clone(), 100, Duration::from_millis(200));
        assert_eq!(events.len(), 2, "events arriving between polls must be retained");

        // Shutdown cleanly.
        tx.send(Message::Shutdown).unwrap();
        handle.join().unwrap();
    }

    #[test]
    fn drainer_exits_on_shutdown() {
        let buf = shared(8);
        let (tx, rx) = crossbeam_channel::unbounded::<Message>();
        let handle = std::thread::spawn(move || run_drainer(rx, buf));
        tx.send(Message::Shutdown).unwrap();
        handle.join().unwrap(); // returns only if the drainer broke out of its loop
    }
}

pub fn mcp_service(allowed_hosts: Vec<String>) -> StreamableHttpService<McpServer, LocalSessionManager> {
    let config = if allowed_hosts.is_empty() {
        StreamableHttpServerConfig::default()
    } else {
        StreamableHttpServerConfig::default().with_allowed_hosts(allowed_hosts)
    };
    StreamableHttpService::new(
        || Ok(McpServer::new()),
        Arc::new(LocalSessionManager::default()),
        config,
    )
}
