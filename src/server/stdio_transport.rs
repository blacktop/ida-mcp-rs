//! Windows stdio transport guard for IDALIB database opens.

use rmcp::model::{ClientRequest, JsonRpcMessage, RequestId};
use rmcp::service::{RxJsonRpcMessage, TxJsonRpcMessage};
use rmcp::transport::{async_rw::AsyncRwTransport, Transport};
use rmcp::RoleServer;
use std::sync::{Arc, Mutex};
use tokio::sync::Notify;

struct OpenReadGate {
    request_id: Mutex<Option<RequestId>>,
    peer_response_id: Mutex<Option<RequestId>>,
    released: Notify,
}

/// Prevent Tokio's next blocking stdin read from overlapping an `open_idb`
/// request. IDA 9.3's official `open_database()` API probes stdin while
/// processing loader options; on Windows, an outstanding Tokio stdin read
/// owns the same handle and deadlocks IDA until the client closes the pipe.
pub struct IdaSafeStdioTransport {
    inner: AsyncRwTransport<RoleServer, tokio::io::Stdin, tokio::io::Stdout>,
    gate: Arc<OpenReadGate>,
}

impl IdaSafeStdioTransport {
    pub fn new() -> Self {
        Self {
            inner: AsyncRwTransport::new_server(tokio::io::stdin(), tokio::io::stdout()),
            gate: Arc::new(OpenReadGate {
                request_id: Mutex::new(None),
                peer_response_id: Mutex::new(None),
                released: Notify::new(),
            }),
        }
    }

    fn open_request_id(message: &RxJsonRpcMessage<RoleServer>) -> Option<RequestId> {
        let JsonRpcMessage::Request(request) = message else {
            return None;
        };
        let ClientRequest::CallToolRequest(call) = &request.request else {
            return None;
        };
        (call.params.name == "open_idb").then(|| request.id.clone())
    }

    fn response_id(message: &TxJsonRpcMessage<RoleServer>) -> Option<RequestId> {
        match message {
            JsonRpcMessage::Response(response) => Some(response.id.clone()),
            JsonRpcMessage::Error(error) => error.id.clone(),
            _ => None,
        }
    }

    fn outbound_request_id(message: &TxJsonRpcMessage<RoleServer>) -> Option<RequestId> {
        match message {
            JsonRpcMessage::Request(request) => Some(request.id.clone()),
            _ => None,
        }
    }

    fn inbound_response_id(message: &RxJsonRpcMessage<RoleServer>) -> Option<RequestId> {
        match message {
            JsonRpcMessage::Response(response) => Some(response.id.clone()),
            JsonRpcMessage::Error(error) => error.id.clone(),
            _ => None,
        }
    }

    async fn wait_until_released(&self) {
        loop {
            let released = self.gate.released.notified();
            let open_pending = self
                .gate
                .request_id
                .lock()
                .expect("stdio open gate poisoned")
                .is_some();
            let peer_response_allowed = self
                .gate
                .peer_response_id
                .lock()
                .expect("stdio peer-response gate poisoned")
                .is_some();
            if !open_pending || peer_response_allowed {
                return;
            }
            released.await;
        }
    }
}

impl Default for IdaSafeStdioTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl Transport<RoleServer> for IdaSafeStdioTransport {
    type Error = std::io::Error;

    fn send(
        &mut self,
        item: TxJsonRpcMessage<RoleServer>,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send + 'static {
        let response_id = Self::response_id(&item);
        let outbound_request_id = Self::outbound_request_id(&item);
        let inner = self.inner.send(item);
        let gate = self.gate.clone();
        async move {
            let result = inner.await;
            if result.is_ok()
                && let Some(outbound_request_id) = outbound_request_id
                && gate
                    .request_id
                    .lock()
                    .expect("stdio open gate poisoned")
                    .is_some()
            {
                *gate
                    .peer_response_id
                    .lock()
                    .expect("stdio peer-response gate poisoned") = Some(outbound_request_id);
                gate.released.notify_waiters();
            }
            if let Some(response_id) = response_id {
                let mut paused = gate.request_id.lock().expect("stdio open gate poisoned");
                if paused.as_ref() == Some(&response_id) {
                    paused.take();
                    gate.peer_response_id
                        .lock()
                        .expect("stdio peer-response gate poisoned")
                        .take();
                    drop(paused);
                    gate.released.notify_waiters();
                }
            }
            result
        }
    }

    async fn receive(&mut self) -> Option<RxJsonRpcMessage<RoleServer>> {
        self.wait_until_released().await;
        let message = self.inner.receive().await?;
        if let Some(response_id) = Self::inbound_response_id(&message) {
            let mut expected = self
                .gate
                .peer_response_id
                .lock()
                .expect("stdio peer-response gate poisoned");
            if expected.as_ref() == Some(&response_id) {
                expected.take();
            }
        }
        if let Some(request_id) = Self::open_request_id(&message) {
            *self
                .gate
                .request_id
                .lock()
                .expect("stdio open gate poisoned") = Some(request_id);
        }
        Some(message)
    }

    async fn close(&mut self) -> Result<(), Self::Error> {
        self.inner.close().await
    }
}

#[cfg(test)]
mod tests {
    use super::IdaSafeStdioTransport;
    use rmcp::model::{
        CallToolRequest, CallToolRequestParams, ClientRequest, JsonRpcMessage, NumberOrString,
    };

    #[test]
    fn only_open_idb_requests_pause_stdin_reads() {
        let open = JsonRpcMessage::request(
            ClientRequest::CallToolRequest(CallToolRequest::new(CallToolRequestParams::new(
                "open_idb",
            ))),
            NumberOrString::Number(1),
        );
        let segments = JsonRpcMessage::request(
            ClientRequest::CallToolRequest(CallToolRequest::new(CallToolRequestParams::new(
                "segments",
            ))),
            NumberOrString::Number(2),
        );

        assert_eq!(
            IdaSafeStdioTransport::open_request_id(&open),
            Some(NumberOrString::Number(1))
        );
        assert_eq!(IdaSafeStdioTransport::open_request_id(&segments), None);
    }
}
