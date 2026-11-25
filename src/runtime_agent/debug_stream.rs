//! The runtime end of a debug session's terminal stream (#1558).
//!
//! For each session it holds, the agent keeps one WebSocket to the relay
//! open. When an operator attaches, a built-in runtime finds the instance's
//! deployed release and its executor and runs the operator's read commands
//! through it (#1559). Each command is recorded before it runs, and one the
//! server does not record never runs. A command the executor does not name
//! as read is refused and recorded as refused. A runtime that cannot read the
//! instance answers [`CloseReason::Unsupported`] with the reason and connects
//! again for the next attach. An upgrade the server or a proxy in front of it
//! refuses is reported once, so the session shows why it cannot attach, and
//! never retried over another transport.

use std::sync::Arc;
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

use crate::debug_command::{DebugAccess, DebugOutput, MAX_LINE, split_command};
use crate::debug_stream::{CloseReason, Control, STREAM_PROTOCOL, UNSUPPORTED_MESSAGE};
use crate::runtime_builtin::{BuiltinConfig, DebugTarget};
use crate::runtime_delivery::{RuntimeDebugCommand, RuntimeDebugCommandOutcome};

/// The wait before connecting again after a stream ended or failed.
const RECONNECT: Duration = Duration::from_secs(2);
/// The largest frame the relay sends.
const MAX_FRAME: usize = 64 * 1024;
/// The largest output frame this end sends.
const OUTPUT_FRAME: usize = 32 * 1024;
/// The exit code of a command this end refused or could not record.
const REFUSED_EXIT: i32 = 126;

/// One held session's stream: where it connects and as whom.
pub(super) struct StreamEnd {
    pub(super) client: reqwest::Client,
    /// `{base}/v1/runtime/environments/{environment}/debug-sessions/{session}`.
    pub(super) session_url: String,
    pub(super) token: String,
    pub(super) instance: String,
    pub(super) environment: String,
    pub(super) session: String,
    /// Each listed session, as of the last pull.
    pub(super) targets: super::DebugTargets,
    /// Present in built-in mode, the only mode that reads an instance.
    pub(super) builtin: Option<Arc<BuiltinConfig>>,
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
                    if let Some(reason) = self.serve(stream).await
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

    /// Answer the relay until the stream ends; the close reason the relay
    /// sent, if any.
    async fn serve(
        &self,
        mut stream: Box<WebSocketStream<reqwest::Upgraded>>,
    ) -> Option<CloseReason> {
        let mut target = None;
        while let Some(Ok(message)) = stream.next().await {
            let Message::Text(text) = message else {
                if matches!(message, Message::Close(_)) {
                    return None;
                }
                continue;
            };
            match serde_json::from_str::<Control>(&text) {
                Ok(Control::Attached) => match self.target() {
                    Ok(attached) => {
                        let usage = format!(
                            "debug session on {}; {}\r\n",
                            attached.request.instance,
                            usage(&attached)
                        );
                        if stream.send(Message::binary(usage)).await.is_err() {
                            return None;
                        }
                        target = Some(attached);
                    }
                    Err(reason) => {
                        let unsupported = Control::Close {
                            reason: CloseReason::Unsupported,
                            message: Some(reason),
                        };
                        if let Ok(json) = serde_json::to_string(&unsupported) {
                            let _ = stream.send(Message::text(json)).await;
                        }
                        let _ = WebSocketStream::close(&mut stream, None).await;
                        return None;
                    }
                },
                Ok(Control::Command { command }) => {
                    let Some(target) = &target else { continue };
                    let (output, code) = self.command(target, &command).await;
                    for chunk in output.chunks(OUTPUT_FRAME) {
                        if stream.send(Message::binary(chunk.to_vec())).await.is_err() {
                            return None;
                        }
                    }
                    let Ok(exit) = serde_json::to_string(&Control::Exit { code }) else {
                        return None;
                    };
                    if stream.send(Message::text(exit)).await.is_err() {
                        return None;
                    }
                }
                Ok(Control::Close { reason, .. }) => return Some(reason),
                _ => {}
            }
        }
        None
    }

    /// Whether the session's last handed-out elevation holds at `now`.
    fn elevated(&self, now: i64) -> bool {
        self.targets
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .get(&self.session)
            .and_then(|session| session.elevated_until)
            .is_some_and(|until| now < until)
    }

    /// The executor and request this session reads, or why it cannot.
    fn target(&self) -> Result<DebugTarget, String> {
        let Some(builtin) = &self.builtin else {
            return Err(UNSUPPORTED_MESSAGE.into());
        };
        let session = self
            .targets
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .get(&self.session)
            .cloned();
        let Some(session) = session else {
            return Err("the session is no longer listed".into());
        };
        let Some(target) = &session.target else {
            return Err("the instance has no deployed release to read".into());
        };
        builtin.debug_target(&self.environment, &session.instance, target)
    }

    /// Run one command line: what to send the operator, and the exit code.
    async fn command(&self, target: &DebugTarget, line: &str) -> (Vec<u8>, i32) {
        let refuse = async |argv: Vec<String>, access, reason: String| {
            let note = match self
                .record(
                    argv,
                    access,
                    RuntimeDebugCommandOutcome::Refused,
                    None,
                    Some(reason.clone()),
                )
                .await
            {
                Ok(()) => String::new(),
                Err(error) => format!(" (recording the refusal failed: {error:#})"),
            };
            let text = format!("refused: {reason}{note}; {}\r\n", usage(target));
            (text.into_bytes(), REFUSED_EXIT)
        };
        let argv = match split_command(line) {
            Ok(argv) if argv.is_empty() => return (Vec::new(), 0),
            Ok(argv) => argv,
            Err(error) => {
                let mut kept = line.to_owned();
                kept.truncate(kept.floor_char_boundary(MAX_LINE));
                return refuse(vec![kept], DebugAccess::Write, format!("{error:#}")).await;
            }
        };
        let access = target.reader.access(&argv);
        if access == DebugAccess::Write {
            // An unknown argv is refused in every session; a known write
            // only while the session's elevation holds on this clock too.
            if !target.reader.is_write(&argv) {
                return refuse(argv, access, "not a debug command".into()).await;
            }
            if !self.elevated(crate::now_millis()) {
                return refuse(
                    argv,
                    access,
                    "the session is not elevated; write commands need an approved elevation".into(),
                )
                .await;
            }
        }
        if let Err(error) = self
            .record(
                argv.clone(),
                access,
                RuntimeDebugCommandOutcome::Started,
                None,
                None,
            )
            .await
        {
            let text =
                format!("not run: the session audit did not record the command: {error:#}\r\n");
            return (text.into_bytes(), REFUSED_EXIT);
        }
        let reader = target.reader.clone();
        let request = target.request.clone();
        let run_argv = argv.clone();
        let ran = tokio::task::spawn_blocking(move || match access {
            DebugAccess::Read => reader.read(&request, &run_argv),
            DebugAccess::Write => reader.write(&request, &run_argv),
        })
        .await;
        let DebugOutput { output, exit_code } = match ran {
            Ok(Ok(output)) => output,
            Ok(Err(error)) => DebugOutput {
                output: format!("tenkai: {error:#}\r\n").into_bytes(),
                exit_code: -1,
            },
            Err(error) => DebugOutput {
                output: format!("tenkai: the command failed: {error}\r\n").into_bytes(),
                exit_code: -1,
            },
        };
        if let Err(error) = self
            .record(
                argv,
                access,
                RuntimeDebugCommandOutcome::Completed,
                Some(exit_code),
                None,
            )
            .await
        {
            eprintln!("recording a debug command's exit failed: {error:#}");
        }
        (output, exit_code)
    }

    /// Record one command in the session's audit.
    async fn record(
        &self,
        argv: Vec<String>,
        access: DebugAccess,
        outcome: RuntimeDebugCommandOutcome,
        exit_code: Option<i32>,
        reason: Option<String>,
    ) -> anyhow::Result<()> {
        let response = self
            .client
            .post(format!("{}/commands", self.session_url))
            .bearer_auth(&self.token)
            .header("x-tenkai-runtime-instance", &self.instance)
            .header("x-tenkai-runtime-version", env!("CARGO_PKG_VERSION"))
            .json(&RuntimeDebugCommand {
                argv,
                access,
                outcome,
                exit_code,
                reason,
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

/// Whether a relay close ends this session's stream for good. Not
/// `grant_revoked`: it may be the operator's grant that lapsed, and the
/// next upgrade checks this runtime's own.
fn final_reason(reason: CloseReason) -> bool {
    matches!(
        reason,
        CloseReason::BoundReached | CloseReason::SessionClosed | CloseReason::Replaced
    )
}

/// The command usage a session prints: its reads, and the writes an
/// approved elevation unlocks.
fn usage(target: &DebugTarget) -> String {
    let mut usage = format!("read commands: {}", target.reader.commands().join(", "));
    let writes = target.reader.write_commands();
    if !writes.is_empty() {
        usage.push_str(&format!("; when elevated: {}", writes.join(", ")));
    }
    usage
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::software_executor::{SoftwareApplyRequest, SoftwareExecutor, SoftwareObserveStatus};

    /// Reads `get` and counts the commands it ran.
    #[derive(Default)]
    struct Counts(AtomicUsize);

    impl SoftwareExecutor for Counts {
        fn apply(&self, _: &SoftwareApplyRequest) -> anyhow::Result<()> {
            unreachable!("a debug session applies nothing")
        }
        fn remove(&self, _: &SoftwareApplyRequest) -> anyhow::Result<()> {
            unreachable!("a debug session removes nothing")
        }
        fn observe(&self, _: &SoftwareApplyRequest) -> anyhow::Result<SoftwareObserveStatus> {
            unreachable!("a debug session observes nothing")
        }
        fn debug_commands(&self) -> &'static [&'static str] {
            &["get"]
        }
        fn debug_access(&self, argv: &[String]) -> DebugAccess {
            if argv == ["get"] {
                DebugAccess::Read
            } else {
                DebugAccess::Write
            }
        }
        fn debug_read(
            &self,
            _: &SoftwareApplyRequest,
            _: &[String],
        ) -> anyhow::Result<DebugOutput> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(DebugOutput {
                output: b"pods\n".to_vec(),
                exit_code: 3,
            })
        }
        fn debug_write_commands(&self) -> &'static [&'static str] {
            &["restart"]
        }
        fn debug_write(
            &self,
            _: &SoftwareApplyRequest,
            _: &[String],
        ) -> anyhow::Result<DebugOutput> {
            self.0.fetch_add(100, Ordering::SeqCst);
            Ok(DebugOutput {
                output: b"restarted\n".to_vec(),
                exit_code: 0,
            })
        }
    }

    /// A read is recorded before it runs and after it exits; a write is
    /// recorded as refused and never runs; a read the server does not
    /// record never runs.
    #[tokio::test]
    async fn a_command_runs_only_after_the_audit_records_it() {
        use axum::response::IntoResponse as _;
        let down = Arc::new(AtomicBool::new(false));
        let records = Arc::new(Mutex::new(Vec::<serde_json::Value>::new()));
        let app = {
            let (down, records) = (down.clone(), records.clone());
            axum::Router::new().route(
                "/v1/runtime/environments/prod/debug-sessions/s1/commands",
                axum::routing::post(move |axum::Json(body): axum::Json<serde_json::Value>| {
                    let (down, records) = (down.clone(), records.clone());
                    async move {
                        if down.load(Ordering::SeqCst) {
                            return StatusCode::SERVICE_UNAVAILABLE.into_response();
                        }
                        records.lock().unwrap().push(body);
                        StatusCode::NO_CONTENT.into_response()
                    }
                }),
            )
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await });
        let end = StreamEnd {
            client: reqwest::Client::new(),
            session_url: format!("http://{address}/v1/runtime/environments/prod/debug-sessions/s1"),
            token: "tkc_bearer".into(),
            instance: "runtime-1".into(),
            environment: "prod".into(),
            session: "s1".into(),
            targets: Default::default(),
            builtin: None,
        };
        let counts = Arc::new(Counts::default());
        let mut request =
            crate::software_executor::request_from_parts("api", "1.0.0", "prod", ".", "r");
        request.instance = "api-a".into();
        let target = DebugTarget {
            reader: crate::debug_command::DebugReader::Executor(counts.clone()),
            request,
        };
        let outcomes = |records: &Mutex<Vec<serde_json::Value>>| {
            let records = records.lock().unwrap();
            records
                .iter()
                .map(|record| record["outcome"].as_str().unwrap().to_owned())
                .collect::<Vec<_>>()
        };

        assert_eq!(end.command(&target, "get").await, (b"pods\n".to_vec(), 3));
        assert_eq!(outcomes(&records), ["started", "completed"]);
        assert_eq!(records.lock().unwrap()[1]["exit_code"], 3);

        let (output, code) = end.command(&target, "delete pod x").await;
        assert_eq!(code, REFUSED_EXIT);
        assert!(String::from_utf8_lossy(&output).starts_with("refused: "));
        let (_, code) = end.command(&target, "'open").await;
        assert_eq!(code, REFUSED_EXIT);
        assert_eq!(
            outcomes(&records),
            ["started", "completed", "refused", "refused"]
        );
        assert_eq!(
            records.lock().unwrap()[2]["argv"],
            serde_json::json!(["delete", "pod", "x"])
        );
        assert_eq!(counts.0.load(Ordering::SeqCst), 1);

        down.store(true, Ordering::SeqCst);
        let (output, code) = end.command(&target, "get").await;
        assert_eq!(code, REFUSED_EXIT);
        assert!(String::from_utf8_lossy(&output).starts_with("not run: "));
        assert_eq!(
            counts.0.load(Ordering::SeqCst),
            1,
            "an unrecorded read never runs"
        );
    }

    /// A known write runs only while the session's handed-out elevation
    /// holds on the runtime's clock; an unknown argv never runs.
    #[tokio::test]
    async fn a_write_runs_only_while_the_session_is_elevated() {
        let records = Arc::new(Mutex::new(Vec::new()));
        let app = {
            let records = records.clone();
            axum::Router::new().route(
                "/v1/runtime/environments/prod/debug-sessions/s1/commands",
                axum::routing::post(move |axum::Json(body): axum::Json<serde_json::Value>| {
                    let records = records.clone();
                    async move {
                        records.lock().unwrap().push(body);
                        axum::http::StatusCode::NO_CONTENT
                    }
                }),
            )
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await });
        let end = StreamEnd {
            client: reqwest::Client::new(),
            session_url: format!("http://{address}/v1/runtime/environments/prod/debug-sessions/s1"),
            token: "tkc_bearer".into(),
            instance: "runtime-1".into(),
            environment: "prod".into(),
            session: "s1".into(),
            targets: Default::default(),
            builtin: None,
        };
        let elevate = |until: Option<i64>| {
            end.targets.lock().unwrap().insert(
                "s1".into(),
                crate::runtime_delivery::RuntimeDebugSession {
                    id: "s1".into(),
                    instance: "api-a".into(),
                    mode: crate::debug_session::DebugSessionMode::Read,
                    not_after: crate::now_millis() + 600_000,
                    target: None,
                    elevated_until: until,
                },
            );
        };
        let counts = Arc::new(Counts::default());
        let target = DebugTarget {
            reader: crate::debug_command::DebugReader::Executor(counts.clone()),
            request: crate::software_executor::request_from_parts("api", "1.0.0", "prod", ".", "r"),
        };
        let reason = |records: &Mutex<Vec<serde_json::Value>>| {
            records.lock().unwrap().last().unwrap()["reason"].clone()
        };

        elevate(None);
        assert_eq!(end.command(&target, "restart").await.1, REFUSED_EXIT);
        assert!(reason(&records).as_str().unwrap().contains("not elevated"));
        elevate(Some(crate::now_millis() + 60_000));
        assert_eq!(end.command(&target, "delete pod x").await.1, REFUSED_EXIT);
        assert_eq!(reason(&records), "not a debug command");
        assert_eq!(
            end.command(&target, "restart").await,
            (b"restarted\n".to_vec(), 0)
        );
        let started = {
            let records = records.lock().unwrap();
            records[records.len() - 2].clone()
        };
        assert_eq!(started["outcome"], "started");
        assert_eq!(started["access"], "write");
        elevate(Some(crate::now_millis() - 1));
        assert_eq!(end.command(&target, "restart").await.1, REFUSED_EXIT);
        assert_eq!(counts.0.load(Ordering::SeqCst), 100, "one write ran");
    }
}
