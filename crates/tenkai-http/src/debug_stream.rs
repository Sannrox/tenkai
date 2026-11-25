//! The terminal stream relay of debug sessions (ADR 0061 §7, #1558).
//!
//! The operator opens `GET /v1/debug-sessions/{session}/stream` and the
//! owning runtime `GET /v1/runtime/environments/{environment}/debug-sessions/
//! {session}/stream`, each a WebSocket with subprotocol
//! [`STREAM_PROTOCOL`]. Both are authenticated before the upgrade. The relay
//! pairs the two ends of a session in memory and forwards frames between
//! them; it writes no frame anywhere, durable or logged.
//!
//! The pair lives in this replica's memory only, so the deployment routes
//! both paths of one session to one replica (hash on the session id). After
//! a replica dies, both ends reconnect.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use axum::extract::ws::rejection::WebSocketUpgradeRejection;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use tokio::sync::{mpsc, watch};

use tenkai::auth_context::CredentialMaterial;
use tenkai::debug_stream::{CloseReason, Control, STREAM_PROTOCOL};
use tenkai::management_operations::ManagementError;
use tenkai::runtime_delivery::RuntimeDeliveryError;

use super::auth::require_management;
use super::router::AppState;
use super::runtime::{bearer, error_response, management_error, runtime_caller};

/// How often each end's grant and session are checked again.
const RECHECK: Duration = Duration::from_secs(2);
/// Frames queued toward one end before the relay gives up on it.
const QUEUE: usize = 256;
/// The largest frame either end may send.
const MAX_FRAME: usize = 64 * 1024;
/// The longest one write to an end may take. An end that stops reading
/// is ended, so a stalled write never holds off the bound or a recheck.
const WRITE: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Side {
    Operator,
    Runtime,
}

/// One connected end: its frame queue and its end signal.
struct End {
    id: u64,
    frames: mpsc::Sender<Message>,
    ended: watch::Sender<Option<Control>>,
}

impl End {
    fn end(&self, control: Control) {
        self.ended.send_replace(Some(control));
    }
}

#[derive(Default)]
struct Pair {
    operator: Option<End>,
    runtime: Option<End>,
}

impl Pair {
    fn side(&mut self, side: Side) -> &mut Option<End> {
        match side {
            Side::Operator => &mut self.operator,
            Side::Runtime => &mut self.runtime,
        }
    }

    fn other(&mut self, side: Side) -> &mut Option<End> {
        match side {
            Side::Operator => &mut self.runtime,
            Side::Runtime => &mut self.operator,
        }
    }
}

/// The connected ends of every session streaming through this replica.
#[derive(Default)]
pub(super) struct DebugRelay {
    pairs: Mutex<HashMap<String, Pair>>,
    next: AtomicU64,
}

impl DebugRelay {
    fn pairs(&self) -> std::sync::MutexGuard<'_, HashMap<String, Pair>> {
        self.pairs.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Connect `side` of `session`. A previous connection of the same side
    /// ends as replaced; when the other side is present, both are told
    /// [`Control::Attached`].
    fn join(
        &self,
        session: &str,
        side: Side,
    ) -> (
        u64,
        mpsc::Receiver<Message>,
        watch::Receiver<Option<Control>>,
    ) {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        let (frames, frames_rx) = mpsc::channel(QUEUE);
        let (ended, ended_rx) = watch::channel(None);
        let mut pairs = self.pairs();
        let pair = pairs.entry(session.to_owned()).or_default();
        if let Some(old) = pair.side(side).replace(End { id, frames, ended }) {
            old.end(Control::close(CloseReason::Replaced));
        }
        if pair.other(side).is_some() {
            let attached = control_frame(&Control::Attached);
            for end in [&pair.operator, &pair.runtime].into_iter().flatten() {
                if end.frames.try_send(attached.clone()).is_err() {
                    end.end(Control::close(CloseReason::ProtocolError));
                }
            }
        }
        (id, frames_rx, ended_rx)
    }

    /// The frame queue of the end opposite `side`, when connected.
    fn peer(&self, session: &str, side: Side) -> Option<mpsc::Sender<Message>> {
        let mut pairs = self.pairs();
        let pair = pairs.get_mut(session)?;
        pair.other(side).as_ref().map(|end| end.frames.clone())
    }

    /// Connection `id` of `side` left: the pair ends and the other side is
    /// told `notice`. A connection already replaced changes nothing.
    fn leave(&self, session: &str, side: Side, id: u64, notice: Control) {
        let mut pairs = self.pairs();
        let Some(pair) = pairs.get_mut(session) else {
            return;
        };
        if pair.side(side).as_ref().is_none_or(|end| end.id != id) {
            return;
        }
        if let Some(mut pair) = pairs.remove(session)
            && let Some(other) = pair.other(side).take()
        {
            other.end(notice);
        }
    }

    /// End both sides of `session` with `control`.
    pub(super) fn end_all(&self, session: &str, control: Control) {
        if let Some(pair) = self.pairs().remove(session) {
            for end in [pair.operator, pair.runtime].into_iter().flatten() {
                end.end(control.clone());
            }
        }
    }
}

/// What admits one end, checked at the upgrade and again every [`RECHECK`].
enum Grant {
    Operator(CredentialMaterial),
    Runtime {
        environment: String,
        headers: HeaderMap,
        certificate: Option<axum::Extension<crate::tls::ClientCertificate>>,
    },
}

impl Grant {
    /// The session's `not_after` while the grant admits the stream, or the
    /// close that ends it. `first` audits the attach.
    async fn check(&self, state: &AppState, session: &str, first: bool) -> Result<i64, Refusal> {
        match self {
            Self::Operator(credential) => state
                .management
                .authorize_debug_stream(credential, session, first)
                .await
                .map(|session| session.not_after)
                .map_err(Refusal::Management),
            Self::Runtime {
                environment,
                headers,
                certificate,
            } => state
                .runtime_delivery
                .authorize_debug_stream(
                    bearer(headers),
                    runtime_caller(headers, certificate.as_ref()),
                    environment,
                    session,
                    first,
                )
                .await
                .map(|session| session.not_after)
                .map_err(Refusal::Runtime),
        }
    }
}

enum Refusal {
    Management(ManagementError),
    Runtime(RuntimeDeliveryError),
}

impl Refusal {
    /// The close a refusal ends a running stream with. An ended session is
    /// `session_closed`; anything else, including a store that cannot
    /// answer, fails closed as `grant_revoked`.
    fn close(&self) -> Control {
        let ended = matches!(
            self,
            Self::Management(ManagementError::Conflict(_) | ManagementError::NotFound(_))
                | Self::Runtime(RuntimeDeliveryError::Conflict(_))
        );
        if ended {
            Control::close(CloseReason::SessionClosed)
        } else {
            Control::close(CloseReason::GrantRevoked)
        }
    }

    fn response(self) -> Response {
        match self {
            Self::Management(error) => management_error(error),
            Self::Runtime(error) => super::runtime::runtime_delivery_error(error),
        }
    }
}

/// `GET /v1/debug-sessions/{session}/stream`: the operator's end.
pub(super) async fn operator_stream(
    State(state): State<Arc<AppState>>,
    Path(session): Path<String>,
    headers: HeaderMap,
    upgrade: Result<WebSocketUpgrade, WebSocketUpgradeRejection>,
) -> Response {
    let credential = match require_management(&headers) {
        Ok(credential) => credential,
        Err(error) => return *error,
    };
    accept(
        state,
        session,
        Side::Operator,
        Grant::Operator(credential),
        upgrade,
    )
    .await
}

/// `GET /v1/runtime/environments/{environment}/debug-sessions/{session}/stream`:
/// the owning runtime's end.
pub(super) async fn runtime_stream(
    State(state): State<Arc<AppState>>,
    Path((environment, session)): Path<(String, String)>,
    headers: HeaderMap,
    certificate: Option<axum::Extension<crate::tls::ClientCertificate>>,
    upgrade: Result<WebSocketUpgrade, WebSocketUpgradeRejection>,
) -> Response {
    let grant = Grant::Runtime {
        environment,
        headers,
        certificate,
    };
    accept(state, session, Side::Runtime, grant, upgrade).await
}

/// Admit `grant` before anything else, then require a WebSocket upgrade
/// that offers [`STREAM_PROTOCOL`].
async fn accept(
    state: Arc<AppState>,
    session: String,
    side: Side,
    grant: Grant,
    upgrade: Result<WebSocketUpgrade, WebSocketUpgradeRejection>,
) -> Response {
    let upgrade = match upgrade {
        Ok(upgrade) => upgrade.protocols([STREAM_PROTOCOL]),
        Err(rejection) => {
            // Credentials first: a bad one never learns more than that.
            if let Err(refusal) = grant.check(&state, &session, false).await {
                return refusal.response();
            }
            return rejection.into_response();
        }
    };
    if upgrade.selected_protocol().is_none() {
        if let Err(refusal) = grant.check(&state, &session, false).await {
            return refusal.response();
        }
        return error_response(
            StatusCode::BAD_REQUEST,
            format!("the stream requires subprotocol {STREAM_PROTOCOL}"),
        );
    }
    let not_after = match grant.check(&state, &session, true).await {
        Ok(not_after) => not_after,
        Err(refusal) => return refusal.response(),
    };
    upgrade
        .max_message_size(MAX_FRAME)
        .max_frame_size(MAX_FRAME)
        .on_upgrade(move |socket| relay(socket, state, session, side, grant, not_after))
}

/// How one connection ended.
enum Ending {
    /// End both sides with this close.
    Both(Control),
    /// This side was told to end; the relay already let it go.
    Told(Control),
    /// This side left; the other is told this close.
    Left(Control),
}

async fn relay(
    mut socket: WebSocket,
    state: Arc<AppState>,
    session: String,
    side: Side,
    grant: Grant,
    not_after: i64,
) {
    let relay = &state.debug_relay;
    let (id, mut frames, mut ended) = relay.join(&session, side);
    let remaining = u64::try_from(not_after.saturating_sub(tenkai::now_millis())).unwrap_or(0);
    let bound = tokio::time::sleep(Duration::from_millis(remaining));
    tokio::pin!(bound);
    let mut recheck = tokio::time::interval_at(tokio::time::Instant::now() + RECHECK, RECHECK);
    recheck.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let ending = loop {
        tokio::select! {
            () = &mut bound => break Ending::Both(Control::close(CloseReason::BoundReached)),
            _ = recheck.tick() => {
                if let Err(refusal) = grant.check(&state, &session, false).await {
                    break Ending::Both(refusal.close());
                }
            }
            Ok(()) = ended.changed() => {
                if let Some(control) = ended.borrow_and_update().clone() {
                    break Ending::Told(control);
                }
            }
            Some(frame) = frames.recv() => match tokio::time::timeout(WRITE, socket.send(frame)).await {
                Ok(Ok(())) => {}
                Ok(Err(_)) => break Ending::Left(Control::close(CloseReason::PeerClosed)),
                Err(_) => break Ending::Both(Control::close(CloseReason::ProtocolError)),
            },
            incoming = socket.recv() => match incoming {
                Some(Ok(Message::Binary(bytes))) => {
                    if !forward(relay, &session, side, Message::Binary(bytes)) {
                        break Ending::Both(Control::close(CloseReason::ProtocolError));
                    }
                }
                Some(Ok(Message::Text(text))) => match accepted_control(side, &text) {
                    Some(close @ Control::Close { .. }) => break Ending::Left(close),
                    Some(_) => {
                        if !forward(relay, &session, side, Message::Text(text)) {
                            break Ending::Both(Control::close(CloseReason::ProtocolError));
                        }
                    }
                    None => break Ending::Both(Control::close(CloseReason::ProtocolError)),
                },
                Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
                Some(Ok(Message::Close(_)) | Err(_)) | None => {
                    break Ending::Left(Control::close(CloseReason::PeerClosed));
                }
            },
        }
    };
    let own = match ending {
        Ending::Both(control) => {
            relay.end_all(&session, control.clone());
            // `end_all` misses this side when a newer connection replaced it.
            Some(control)
        }
        Ending::Told(control) => Some(control),
        Ending::Left(notice) => {
            relay.leave(&session, side, id, notice);
            None
        }
    };
    // A peer that closed on its own sent its frames before the close: they
    // go out first. A forced end (bound, revocation) drops them.
    let graceful = matches!(
        own,
        Some(Control::Close {
            reason: CloseReason::PeerClosed | CloseReason::Unsupported,
            ..
        })
    );
    let _ = tokio::time::timeout(WRITE, async {
        while graceful && let Ok(frame) = frames.try_recv() {
            socket.send(frame).await?;
        }
        if let Some(control) = own {
            socket.send(control_frame(&control)).await?;
        }
        socket.send(Message::Close(None)).await
    })
    .await;
}

/// Queue `frame` toward the other side. Without one, the frame is dropped;
/// false when the other side's queue is full.
fn forward(relay: &DebugRelay, session: &str, side: Side, frame: Message) -> bool {
    relay
        .peer(session, side)
        .is_none_or(|peer| match peer.try_send(frame) {
            Ok(()) | Err(mpsc::error::TrySendError::Closed(_)) => true,
            Err(mpsc::error::TrySendError::Full(_)) => false,
        })
}

/// The control `text` carries, when `side` may send it. The relay owns
/// `attached` and every close reason but `peer_closed` and the runtime's
/// `unsupported`.
fn accepted_control(side: Side, text: &str) -> Option<Control> {
    let control: Control = serde_json::from_str(text).ok()?;
    let allowed = match (&control, side) {
        (Control::Resize { .. } | Control::Command { .. }, Side::Operator)
        | (Control::Exit { .. }, Side::Runtime) => true,
        (Control::Close { reason, message }, _) => {
            message.as_ref().is_none_or(|message| message.len() <= 256)
                && (*reason == CloseReason::PeerClosed
                    || (*reason == CloseReason::Unsupported && side == Side::Runtime))
        }
        _ => false,
    };
    allowed.then_some(control)
}

fn control_frame(control: &Control) -> Message {
    let json = serde_json::to_string(control)
        .unwrap_or_else(|_| r#"{"type":"close","reason":"protocol_error"}"#.into());
    Message::Text(json.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_side_sends_only_its_controls() {
        let operator = r#"{"type":"resize","cols":80,"rows":24}"#;
        let exit = r#"{"type":"exit","code":0}"#;
        let unsupported = r#"{"type":"close","reason":"unsupported"}"#;
        assert!(accepted_control(Side::Operator, operator).is_some());
        assert!(accepted_control(Side::Runtime, operator).is_none());
        assert!(accepted_control(Side::Runtime, exit).is_some());
        assert!(accepted_control(Side::Operator, exit).is_none());
        assert!(accepted_control(Side::Runtime, unsupported).is_some());
        assert!(accepted_control(Side::Operator, unsupported).is_none());
        assert!(accepted_control(Side::Runtime, r#"{"type":"attached"}"#).is_none());
        assert!(
            accepted_control(Side::Operator, r#"{"type":"close","reason":"replaced"}"#).is_none()
        );
    }
}
