//! The runtime end of a debug session's terminal stream (#1558).
//!
//! For each session it holds, the agent keeps one WebSocket to the relay
//! open. No executor attaches a terminal yet: when an operator attaches, the
//! agent answers [`CloseReason::Unsupported`] and connects again for the
//! next one. An upgrade the server or a proxy in front of it refuses is
//! reported once, so the session shows why it cannot attach, and never
//! retried over another transport.

use std::time::Duration;

use futures_util::{SinkExt as _, StreamExt as _};
use reqwest::StatusCode;
use reqwest::header::{
    CONNECTION, SEC_WEBSOCKET_ACCEPT, SEC_WEBSOCKET_KEY, SEC_WEBSOCKET_PROTOCOL,
    SEC_WEBSOCKET_VERSION, UPGRADE,
};
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::handshake::client::generate_key;
use tokio_tungstenite::tungstenite::handshake::derive_accept_key;
use tokio_tungstenite::tungstenite::protocol::{Role, WebSocketConfig};

use crate::debug_stream::{CloseReason, Control, STREAM_PROTOCOL, UNSUPPORTED_MESSAGE};

/// The wait before connecting again after a stream ended or failed.
const RECONNECT: Duration = Duration::from_secs(2);
/// The largest frame the relay sends.
const MAX_FRAME: usize = 64 * 1024;

/// One held session's stream: where it connects and as whom.
pub(super) struct StreamEnd {
    pub(super) client: reqwest::Client,
    /// `{base}/v1/runtime/environments/{environment}/debug-sessions/{session}`.
    pub(super) session_url: String,
    pub(super) token: String,
    pub(super) instance: String,
}

enum Connected {
    Stream(Box<WebSocketStream<reqwest::Upgraded>>),
    /// The upgrade was answered without a stream, and why.
    Refused(String),
    /// The server no longer gives this instance the session.
    Ended,
}

impl StreamEnd {
    /// Keep the stream until the relay ends the session or the upgrade is
    /// refused. The caller aborts it when the session ends here.
    pub(super) async fn run(self) {
        loop {
            match self.connect().await {
                Ok(Connected::Stream(stream)) => {
                    if let Some(reason) = serve(stream).await
                        && final_reason(reason)
                    {
                        return;
                    }
                }
                Ok(Connected::Refused(reason)) => {
                    if let Err(error) = self.report(&reason).await {
                        eprintln!("reporting a debug stream refusal failed: {error:#}");
                    }
                    return;
                }
                Ok(Connected::Ended) => return,
                Err(error) => eprintln!("debug stream connect failed (retrying): {error:#}"),
            }
            tokio::time::sleep(RECONNECT).await;
        }
    }

    async fn connect(&self) -> anyhow::Result<Connected> {
        let key = generate_key();
        let response = self
            .client
            .get(format!("{}/stream", self.session_url))
            .bearer_auth(&self.token)
            .header("x-tenkai-runtime-instance", &self.instance)
            .header("x-tenkai-runtime-version", env!("CARGO_PKG_VERSION"))
            .header(CONNECTION, "upgrade")
            .header(UPGRADE, "websocket")
            .header(SEC_WEBSOCKET_VERSION, "13")
            .header(SEC_WEBSOCKET_KEY, &key)
            .header(SEC_WEBSOCKET_PROTOCOL, STREAM_PROTOCOL)
            .send()
            .await?;
        match response.status() {
            StatusCode::SWITCHING_PROTOCOLS => {}
            StatusCode::CONFLICT => return Ok(Connected::Ended),
            status => {
                return Ok(Connected::Refused(format!(
                    "the stream upgrade was answered {status}"
                )));
            }
        }
        let headers = response.headers();
        let accepted = headers.get(SEC_WEBSOCKET_ACCEPT).is_some_and(|accept| {
            accept.as_bytes() == derive_accept_key(key.as_bytes()).as_bytes()
        });
        let protocol = headers
            .get(SEC_WEBSOCKET_PROTOCOL)
            .is_some_and(|protocol| protocol.as_bytes() == STREAM_PROTOCOL.as_bytes());
        if !accepted || !protocol {
            return Ok(Connected::Refused(format!(
                "the stream upgrade was not a {STREAM_PROTOCOL} WebSocket"
            )));
        }
        let upgraded = response.upgrade().await?;
        let config = WebSocketConfig::default()
            .max_message_size(Some(MAX_FRAME))
            .max_frame_size(Some(MAX_FRAME));
        Ok(Connected::Stream(Box::new(
            WebSocketStream::from_raw_socket(upgraded, Role::Client, Some(config)).await,
        )))
    }

    async fn report(&self, reason: &str) -> anyhow::Result<()> {
        let response = self
            .client
            .post(format!("{}/stream-error", self.session_url))
            .bearer_auth(&self.token)
            .header("x-tenkai-runtime-instance", &self.instance)
            .header("x-tenkai-runtime-version", env!("CARGO_PKG_VERSION"))
            .json(&crate::runtime_delivery::RuntimeDebugStreamError {
                reason: reason.to_owned(),
            })
            .send()
            .await?;
        anyhow::ensure!(
            response.status().is_success(),
            "the server answered {}",
            response.status()
        );
        Ok(())
    }
}

/// Answer the relay until the stream ends; the close reason the relay sent,
/// if any.
async fn serve(mut stream: Box<WebSocketStream<reqwest::Upgraded>>) -> Option<CloseReason> {
    while let Some(Ok(message)) = stream.next().await {
        let Message::Text(text) = message else {
            if matches!(message, Message::Close(_)) {
                return None;
            }
            continue;
        };
        match serde_json::from_str::<Control>(&text) {
            Ok(Control::Attached) => {
                let unsupported = Control::Close {
                    reason: CloseReason::Unsupported,
                    message: Some(UNSUPPORTED_MESSAGE.into()),
                };
                if let Ok(json) = serde_json::to_string(&unsupported) {
                    let _ = stream.send(Message::text(json)).await;
                }
                let _ = WebSocketStream::close(&mut stream, None).await;
                return None;
            }
            Ok(Control::Close { reason, .. }) => return Some(reason),
            _ => {}
        }
    }
    None
}

/// Whether a relay close ends this session's stream for good. Not
/// `grant_revoked`: it may be the operator's grant that lapsed, and the
/// next upgrade checks this runtime's own.
fn final_reason(reason: CloseReason) -> bool {
    matches!(
        reason,
        CloseReason::BoundReached | CloseReason::SessionClosed | CloseReason::Replaced
    )
}
