//! SMTP digest sinks for operational events (#725).
//!
//! Each sink in `TENKAI_SMTP_SINKS` (a JSON list) receives a plain-text
//! digest of the operational events it lists, at most once per window.
//! Announcing a transition enqueues one outbox record per subscribed sink,
//! due at the end of the current window and identified by the sink and the
//! transition, so a repeated announcement is no second line. The digest
//! worker claims due records, sends one message per sink and marks them
//! delivered; a relay that is down only defers them, so it never blocks
//! reconcile, apply or import.
//!
//! STARTTLS is required unless the relay is on loopback, and trusts
//! `TENKAI_CA_BUNDLE` ([`crate::outbound_tls`]). Relay credentials come from
//! secret settings ([`crate::secret_source`]) named by the sink.

use std::sync::OnceLock;
use std::time::Duration;

use anyhow::{Context as _, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tokio::io::{AsyncBufReadExt as _, AsyncRead, AsyncWrite, AsyncWriteExt as _, BufReader};

use crate::deploy_webhook::OperationalEvent;
use crate::operational_events::{HOST_SCOPE, Transition};
use crate::provider_event::{ProviderEventStore, provider_event_record};
use crate::providers::{EvidenceBinding, PROVIDER_CONTRACT_VERSION, ProviderError, ProviderEvent};
use crate::storage::ProviderEventRecord;

pub const SMTP_SINKS_ENV: &str = "TENKAI_SMTP_SINKS";
/// Each sink has its own outbox kind, `operational_digest:<id>`.
pub const DIGEST_KIND_PREFIX: &str = "operational_digest:";
const DIGEST_SCHEMA: &str = "tenkai.operational_digest_line.v1";
const DEFAULT_WINDOW_SECONDS: u64 = 900;
const MIN_WINDOW_SECONDS: u64 = 60;
/// A failed digest is tried again after this long.
const RETRY_MS: i64 = 5 * 60 * 1000;
/// How long a claim outlasts the send, for marking its lines delivered.
const COMPLETION_MS: i64 = 10 * 60 * 1000;
/// Longest SMTP reply line, and most lines in one reply.
const MAX_REPLY_LINE_BYTES: u64 = 1024;
const MAX_REPLY_LINES: usize = 64;
/// Lines one claim takes. The claim is one transaction, so a window is
/// claimed whole by one worker and never split across passes or replicas;
/// only a window past this many lines spills into a second message.
const MAX_CLAIM: usize = 10_000;

/// One SMTP digest sink.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SmtpSink {
    /// Names the sink in delivery status (`smtp:<id>`).
    pub id: String,
    /// `host:port` of the relay.
    pub relay: String,
    pub from: String,
    pub to: Vec<String>,
    /// Operational events the digest carries.
    pub operational: Vec<OperationalEvent>,
    #[serde(default = "default_window")]
    pub window_seconds: u64,
    /// False only for a loopback relay; anything else needs STARTTLS.
    #[serde(default = "default_starttls")]
    pub starttls: bool,
    /// Secret settings holding the relay user and password, if it needs AUTH.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username_secret: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password_secret: Option<String>,
}

fn default_window() -> u64 {
    DEFAULT_WINDOW_SECONDS
}

fn default_starttls() -> bool {
    true
}

impl SmtpSink {
    pub fn validate(&self) -> Result<()> {
        if self.id.is_empty()
            || self.id.len() > 40
            || !self
                .id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        {
            bail!("smtp sink id must be 1-40 letters, digits, '-' or '_'");
        }
        let host = self.relay_host()?;
        if !self.starttls && !matches!(host, "localhost" | "127.0.0.1" | "::1" | "[::1]") {
            bail!(
                "smtp sink {}: STARTTLS may be off only for a loopback relay",
                self.id
            );
        }
        let address_ok = |address: &str| {
            address.contains('@')
                && !address
                    .chars()
                    .any(|c| c.is_whitespace() || c.is_control() || matches!(c, '<' | '>'))
        };
        if !address_ok(&self.from) || self.to.is_empty() || !self.to.iter().all(|to| address_ok(to))
        {
            bail!(
                "smtp sink {}: from and to must be plain mail addresses",
                self.id
            );
        }
        if self.operational.is_empty() {
            bail!(
                "smtp sink {}: list the operational events it carries",
                self.id
            );
        }
        if self.window_seconds < MIN_WINDOW_SECONDS {
            bail!(
                "smtp sink {}: window_seconds must be at least {MIN_WINDOW_SECONDS}",
                self.id
            );
        }
        if self.username_secret.is_some() != self.password_secret.is_some() {
            bail!(
                "smtp sink {}: set both username_secret and password_secret, or neither",
                self.id
            );
        }
        Ok(())
    }

    fn relay_host(&self) -> Result<&str> {
        let (host, port) = self
            .relay
            .rsplit_once(':')
            .with_context(|| format!("smtp sink {}: relay must be host:port", self.id))?;
        if host.is_empty() || port.parse::<u16>().is_err() {
            bail!("smtp sink {}: relay must be host:port", self.id);
        }
        Ok(host)
    }

    /// The end of the window holding `now`: when its lines are due.
    fn window_end(&self, now: i64) -> i64 {
        let window = i64::try_from(self.window_seconds.saturating_mul(1000)).unwrap_or(i64::MAX);
        (now.div_euclid(window) + 1).saturating_mul(window)
    }
}

static SINKS: OnceLock<Vec<SmtpSink>> = OnceLock::new();

/// Sinks from `TENKAI_SMTP_SINKS`, validated.
pub fn sinks_from_env() -> Result<Vec<SmtpSink>> {
    let Some(raw) = std::env::var(SMTP_SINKS_ENV)
        .ok()
        .filter(|raw| !raw.trim().is_empty())
    else {
        return Ok(Vec::new());
    };
    let sinks: Vec<SmtpSink> =
        serde_json::from_str(&raw).with_context(|| format!("{SMTP_SINKS_ENV} is not valid"))?;
    let mut ids = std::collections::BTreeSet::new();
    for sink in &sinks {
        sink.validate()?;
        if !ids.insert(&sink.id) {
            bail!("{SMTP_SINKS_ENV} names smtp sink {} twice", sink.id);
        }
    }
    Ok(sinks)
}

/// Make `sinks` the ones this process announces to. The server calls this
/// once at startup; until then, and in other hosts, no sink is announced to.
pub fn install(sinks: Vec<SmtpSink>) {
    let _ = SINKS.set(sinks);
}

pub(crate) fn installed() -> &'static [SmtpSink] {
    SINKS.get().map(Vec::as_slice).unwrap_or(&[])
}

/// One digest line, as the outbox holds it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct DigestLine {
    schema: String,
    sink: String,
    /// `smtp:<sink>`, so delivery status lists the line like a webhook.
    url: String,
    event: String,
    environment: String,
    resource: String,
    code: String,
}

/// Outbox records putting `transition` on the digest of every sink that
/// lists its event.
pub(crate) fn records(
    sinks: &[SmtpSink],
    transition: &Transition<'_>,
    now: i64,
) -> Vec<ProviderEventRecord> {
    sinks
        .iter()
        .filter(|sink| sink.operational.contains(&transition.event))
        .filter_map(|sink| record(sink, transition, now).ok())
        .collect()
}

fn record(
    sink: &SmtpSink,
    transition: &Transition<'_>,
    now: i64,
) -> Result<ProviderEventRecord, ProviderError> {
    let line = DigestLine {
        schema: DIGEST_SCHEMA.into(),
        sink: sink.id.clone(),
        url: format!("smtp:{}", sink.id),
        event: transition.event.as_str().into(),
        environment: if transition.scope == HOST_SCOPE {
            String::new()
        } else {
            transition.scope.into()
        },
        resource: transition.resource.into(),
        code: transition.code.into(),
    };
    let mut identity = Sha256::new();
    for value in [
        sink.id.as_str(),
        transition.event.as_str(),
        transition.scope,
        transition.resource,
        transition.key,
    ] {
        identity.update((value.len() as u64).to_le_bytes());
        identity.update(value.as_bytes());
    }
    let id = format!("tenkai:operational-digest:v1:{:x}", identity.finalize());
    let binding = EvidenceBinding {
        contract_version: PROVIDER_CONTRACT_VERSION,
        release_digest: format!("sha256:{:x}", Sha256::digest(transition.event.as_str())),
        plan_digest: format!("sha256:{:x}", Sha256::digest(&id)),
        configuration_digest: format!("sha256:{:x}", Sha256::digest(sink.id.as_bytes())),
        environment_id: transition.scope.into(),
    };
    let mut record = provider_event_record(
        &digest_kind(&sink.id),
        &ProviderEvent {
            id,
            binding,
            payload_json: serde_json::to_string(&line)?,
            collected_at_ms: None,
            source_sequence: None,
        },
        now,
    )?;
    // Lines wait for the end of their window, so a sink gets one digest per
    // window however many transitions it saw.
    record.next_attempt_at = sink.window_end(now);
    Ok(record)
}

/// Send the digests that are due: one message per sink. Returns the lines
/// delivered and deferred. A sink that fails is tried again later; it never
/// fails the caller's loop.
/// `clock` is read before each sink's claim, so a slow relay earlier in the
/// pass cannot leave a later sink claiming with an already expired lease.
pub async fn deliver_due<S>(
    store: &S,
    sinks: &[SmtpSink],
    trust: &crate::outbound_tls::OutboundTrust,
    timeout: Duration,
    clock: impl Fn() -> i64,
) -> Result<(usize, usize), ProviderError>
where
    S: ProviderEventStore + ?Sized,
{
    let mut delivered = 0;
    let mut deferred = 0;
    for sink in sinks {
        let (sent, held) = deliver_sink(store, sink, trust, timeout, clock()).await?;
        delivered += sent;
        deferred += held;
    }
    Ok((delivered, deferred))
}

/// One sink's due lines, claimed in one transaction under the sink's own
/// outbox kind, so its window is never split with another sink or replica.
async fn deliver_sink<S>(
    store: &S,
    sink: &SmtpSink,
    trust: &crate::outbound_tls::OutboundTrust,
    timeout: Duration,
    now: i64,
) -> Result<(usize, usize), ProviderError>
where
    S: ProviderEventStore + ?Sized,
{
    let kind = digest_kind(&sink.id);
    let claim_token = format!("digest-worker:{}", uuid::Uuid::new_v4());
    // The claim must outlast the send and marking every line delivered;
    // a worker that dies holding it only delays the retry by this long.
    let claim_until = now.saturating_add(
        i64::try_from(timeout.as_millis())
            .unwrap_or(i64::MAX)
            .saturating_add(COMPLETION_MS),
    );
    let claimed =
        store.claim_provider_events_for_kind(&kind, now, MAX_CLAIM, &claim_token, claim_until)?;
    if claimed.is_empty() {
        return Ok((0, 0));
    }
    let mut lines = Vec::new();
    let mut deferred = 0;
    for record in claimed {
        let line = serde_json::from_str::<ProviderEvent>(&record.payload_json)
            .ok()
            .and_then(|event| serde_json::from_str::<DigestLine>(&event.payload_json).ok())
            .filter(|line| line.schema == DIGEST_SCHEMA && line.sink == sink.id);
        match line {
            Some(line) => lines.push((record, line)),
            None => {
                store.record_provider_failure(
                    &kind,
                    &record.id,
                    &claim_token,
                    now.saturating_add(RETRY_MS),
                    "digest line is unreadable",
                )?;
                deferred += 1;
            }
        }
    }
    if lines.is_empty() {
        return Ok((0, deferred));
    }
    let body = digest_body(sink, &lines);
    let outcome = match tokio::time::timeout(timeout, send(sink, trust, &body)).await {
        Ok(Ok(session)) => {
            // Accepted: say goodbye off the delivery path, so a relay that
            // stalls on QUIT cannot make an accepted digest count as failed.
            tokio::spawn(async move {
                let mut session = session;
                let _ = tokio::time::timeout(Duration::from_secs(5), session.command("QUIT", 221))
                    .await;
            });
            Ok(())
        }
        Ok(Err(error)) => Err(format!("{error:#}")),
        Err(_) => Err(format!("smtp sink {} timed out", sink.id)),
    };
    let mut delivered = 0;
    for (record, _) in &lines {
        match &outcome {
            Ok(()) => {
                store.mark_provider_event_delivered(&kind, &record.id, &claim_token, now)?;
                delivered += 1;
            }
            Err(error) => {
                store.record_provider_failure(
                    &kind,
                    &record.id,
                    &claim_token,
                    now.saturating_add(RETRY_MS),
                    error,
                )?;
                deferred += 1;
            }
        }
    }
    if let Err(error) = &outcome {
        eprintln!(
            "tenkai.operational_digest outcome=deferred sink={} detail={error}",
            sink.id
        );
    }
    Ok((delivered, deferred))
}

/// The outbox kind of `sink_id`'s digest lines.
pub fn digest_kind(sink_id: &str) -> String {
    format!("{DIGEST_KIND_PREFIX}{sink_id}")
}

/// The plain-text message for `lines`, headers included.
fn digest_body(sink: &SmtpSink, lines: &[(ProviderEventRecord, DigestLine)]) -> String {
    let mut text = format!(
        "From: <{}>\r\nTo: {}\r\nSubject: Tenkai operational digest: {} event(s)\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n",
        sink.from,
        sink.to
            .iter()
            .map(|to| format!("<{to}>"))
            .collect::<Vec<_>>()
            .join(", "),
        lines.len()
    );
    for (_, line) in lines {
        let scope = if line.environment.is_empty() {
            "host"
        } else {
            line.environment.as_str()
        };
        text.push_str(&format!(
            "{} {} {} {}\r\n",
            line.event, scope, line.resource, line.code
        ));
    }
    text
}

/// One SMTP transaction for `message`, returning the session once the relay
/// has accepted the message, so the caller can close it.
async fn send(
    sink: &SmtpSink,
    trust: &crate::outbound_tls::OutboundTrust,
    message: &str,
) -> Result<Session> {
    let stream = tokio::net::TcpStream::connect(&sink.relay)
        .await
        .with_context(|| format!("connecting to smtp relay {}", sink.relay))?;
    let mut session = Session::new(Box::new(stream));
    session.expect(220).await?;
    session.command("EHLO tenkai", 250).await?;
    if sink.starttls {
        session.command("STARTTLS", 220).await?;
        let host = sink
            .relay_host()?
            .trim_start_matches('[')
            .trim_end_matches(']');
        let name = rustls::pki_types::ServerName::try_from(host.to_string())
            .context("smtp relay host is not a valid TLS name")?;
        let connector =
            tokio_rustls::TlsConnector::from(std::sync::Arc::new(trust.rustls_client_config()?));
        let plain = session.into_inner();
        let tls = connector
            .connect(name, plain)
            .await
            .context("smtp STARTTLS handshake")?;
        session = Session::new(Box::new(tls));
        session.command("EHLO tenkai", 250).await?;
    }
    if let (Some(user), Some(password)) = (&sink.username_secret, &sink.password_secret) {
        use base64::Engine as _;
        let user = crate::secret_source::require(user)?;
        let password = crate::secret_source::require(password)?;
        let token =
            base64::engine::general_purpose::STANDARD.encode(format!("\0{user}\0{password}"));
        session.command(&format!("AUTH PLAIN {token}"), 235).await?;
    }
    session
        .command(&format!("MAIL FROM:<{}>", sink.from), 250)
        .await?;
    for to in &sink.to {
        // 251: the relay accepts the recipient and forwards the message.
        session
            .command_any(&format!("RCPT TO:<{to}>"), &[250, 251])
            .await?;
    }
    session.command("DATA", 354).await?;
    // Dot-stuff, then end the data with a lone dot.
    let mut data = String::new();
    for line in message.split("\r\n") {
        if line.starts_with('.') {
            data.push('.');
        }
        data.push_str(line);
        data.push_str("\r\n");
    }
    data.push('.');
    session.command(&data, 250).await?;
    Ok(session)
}

trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}

/// A line-oriented SMTP client session.
struct Session {
    stream: BufReader<Box<dyn Stream>>,
}

impl Session {
    fn new(stream: Box<dyn Stream>) -> Self {
        Self {
            stream: BufReader::new(stream),
        }
    }

    fn into_inner(self) -> Box<dyn Stream> {
        self.stream.into_inner()
    }

    async fn command(&mut self, line: &str, expect: u16) -> Result<()> {
        self.command_any(line, &[expect]).await
    }

    /// `command`, accepting any of `codes` as success.
    async fn command_any(&mut self, line: &str, codes: &[u16]) -> Result<()> {
        self.stream
            .get_mut()
            .write_all(format!("{line}\r\n").as_bytes())
            .await
            .context("writing to the smtp relay")?;
        self.stream.get_mut().flush().await?;
        self.expect_any(codes).await
    }

    /// Reads one reply (all its continuation lines) and checks its code.
    /// The relay's text is not echoed into errors, which carry only the code.
    async fn expect(&mut self, code: u16) -> Result<()> {
        self.expect_any(&[code]).await
    }

    async fn expect_any(&mut self, codes: &[u16]) -> Result<()> {
        use tokio::io::AsyncReadExt as _;
        // Replies are bounded before TLS too, so an untrusted relay cannot
        // grow memory without end.
        for _ in 0..MAX_REPLY_LINES {
            let mut line = String::new();
            let read = (&mut self.stream)
                .take(MAX_REPLY_LINE_BYTES)
                .read_line(&mut line)
                .await?;
            if read == 0 {
                bail!("smtp relay closed the connection");
            }
            if !line.ends_with('\n') {
                bail!("smtp relay sent an overlong reply line");
            }
            let reply: u16 = line
                .get(..3)
                .and_then(|digits| digits.parse().ok())
                .context("smtp relay sent a malformed reply")?;
            if line.as_bytes().get(3) == Some(&b'-') {
                continue;
            }
            if !codes.contains(&reply) {
                bail!("smtp relay answered {reply}, expected {codes:?}");
            }
            return Ok(());
        }
        bail!("smtp relay sent an overlong reply")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::SqliteStore;
    use tokio::io::AsyncReadExt as _;

    fn sink(relay: &str) -> SmtpSink {
        SmtpSink {
            id: "oncall".into(),
            relay: relay.into(),
            from: "tenkai@site.test".into(),
            to: vec!["oncall@site.test".into()],
            operational: vec![OperationalEvent::BackupStale, OperationalEvent::ClockDrift],
            window_seconds: 60,
            starttls: false,
            username_secret: None,
            password_secret: None,
        }
    }

    /// A loopback relay that accepts `messages` sessions and returns the
    /// DATA of each.
    async fn relay(messages: usize) -> (String, tokio::task::JoinHandle<Vec<String>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let handle = tokio::spawn(async move {
            let mut received = Vec::new();
            for _ in 0..messages {
                let (socket, _) = listener.accept().await.unwrap();
                let (read, mut write) = socket.into_split();
                let mut read = BufReader::new(read);
                write.write_all(b"220 test\r\n").await.unwrap();
                let mut data = String::new();
                let mut in_data = false;
                loop {
                    let mut line = String::new();
                    if read.read_line(&mut line).await.unwrap() == 0 {
                        break;
                    }
                    if in_data {
                        if line == ".\r\n" {
                            in_data = false;
                            write.write_all(b"250 queued\r\n").await.unwrap();
                        } else {
                            data.push_str(&line);
                        }
                        continue;
                    }
                    let reply: &[u8] = match line.split_whitespace().next().unwrap_or("") {
                        "EHLO" => b"250-test\r\n250 OK\r\n",
                        "DATA" => {
                            in_data = true;
                            b"354 go\r\n"
                        }
                        "QUIT" => {
                            write.write_all(b"221 bye\r\n").await.unwrap();
                            break;
                        }
                        _ => b"250 OK\r\n",
                    };
                    write.write_all(reply).await.unwrap();
                }
                let mut rest = Vec::new();
                let _ = read.read_to_end(&mut rest).await;
                received.push(data);
            }
            received
        });
        (address, handle)
    }

    fn transition<'a>(event: OperationalEvent, code: &'a str, key: &'a str) -> Transition<'a> {
        Transition {
            event,
            scope: HOST_SCOPE,
            resource: event.as_str().split('.').next().unwrap(),
            code,
            key,
        }
    }

    fn enqueue(store: &SqliteStore, sinks: &[SmtpSink], transition: &Transition<'_>, now: i64) {
        for record in records(sinks, transition, now) {
            store.enqueue_provider_event(&record).unwrap();
        }
    }

    fn trust() -> crate::outbound_tls::OutboundTrust {
        crate::outbound_tls::OutboundTrust::new(None, true).unwrap()
    }

    #[tokio::test]
    async fn a_window_of_transitions_is_one_digest_sent_once() {
        let (address, received) = relay(1).await;
        let sinks = [sink(&address)];
        let store = SqliteStore::open_in_memory().unwrap();
        enqueue(
            &store,
            &sinks,
            &transition(OperationalEvent::BackupStale, "stale", "a"),
            1_000,
        );
        enqueue(
            &store,
            &sinks,
            &transition(OperationalEvent::ClockDrift, "warn", "b"),
            2_000,
        );
        // Announcing the same transition again adds no line.
        enqueue(
            &store,
            &sinks,
            &transition(OperationalEvent::ClockDrift, "warn", "b"),
            3_000,
        );
        // Not due before the window ends.
        assert_eq!(
            deliver_due(&store, &sinks, &trust(), Duration::from_secs(5), || 59_000)
                .await
                .unwrap(),
            (0, 0)
        );
        assert_eq!(
            deliver_due(&store, &sinks, &trust(), Duration::from_secs(5), || 60_000)
                .await
                .unwrap(),
            (2, 0)
        );
        assert_eq!(
            deliver_due(&store, &sinks, &trust(), Duration::from_secs(5), || 120_000)
                .await
                .unwrap(),
            (0, 0)
        );
        let messages = received.await.unwrap();
        assert_eq!(messages.len(), 1);
        assert!(messages[0].contains("Subject: Tenkai operational digest: 2 event(s)"));
        assert!(messages[0].contains("backup.stale host backup stale"));
        assert!(messages[0].contains("clock.drift host clock warn"));
    }

    #[tokio::test]
    async fn a_down_relay_defers_the_digest_and_keeps_its_lines() {
        // Nothing listens on this port once the listener is dropped.
        let address = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            listener.local_addr().unwrap().to_string()
        };
        let sinks = [sink(&address)];
        let store = SqliteStore::open_in_memory().unwrap();
        enqueue(
            &store,
            &sinks,
            &transition(OperationalEvent::BackupStale, "stale", "a"),
            1_000,
        );
        assert_eq!(
            deliver_due(&store, &sinks, &trust(), Duration::from_secs(5), || 60_000)
                .await
                .unwrap(),
            (0, 1)
        );
        let pending = store
            .list_provider_events(&digest_kind("oncall"), HOST_SCOPE, 10)
            .unwrap();
        assert_eq!(pending.len(), 1);
        assert!(pending[0].delivered_at.is_none());
        assert!(pending[0].last_error.contains("connecting"));
    }

    #[test]
    fn sinks_refuse_plaintext_to_a_remote_relay_and_unsubscribed_events() {
        let mut remote = sink("mail.site.test:587");
        assert!(
            remote
                .validate()
                .unwrap_err()
                .to_string()
                .contains("STARTTLS")
        );
        remote.starttls = true;
        assert!(remote.validate().is_ok());
        assert!(
            records(
                &[remote],
                &transition(OperationalEvent::PlanHeld, "held", "p"),
                1
            )
            .is_empty()
        );
    }
}
