//! Runtime clock-drift guard (#643).
//!
//! Signatures, leases and approvals all carry times that only mean something
//! when the host clock is right. A server configured with a time source
//! (`TENKAI_TIME_SOURCE`, an SNTP server inside the site, so it works
//! offline) measures its skew on a schedule. Above `warn_ms` health reports
//! `warn`; above `refuse_ms` the server refuses plan approvals, every new
//! environment lease (reconcile and API applies, configuration changes) and
//! runtime lease claims until the clock is back in range. A failed measurement reports `unknown` and does
//! not start refusing (an unreachable time server is not evidence of drift),
//! but it never lifts a refusal: that takes a good reading.

use std::sync::{Arc, OnceLock, RwLock};
use std::time::Duration;

use anyhow::{Result, bail};
use serde::Serialize;

/// Where to measure and how much skew to tolerate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClockPolicy {
    /// `host:port` of an SNTP server.
    pub server: String,
    pub warn_ms: i64,
    pub refuse_ms: i64,
}

/// The last clock reading, as health reports it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, schemars::JsonSchema)]
pub struct ClockHealth {
    /// `ok`, `warn`, `refuse`, or `unknown` (no successful reading yet, or the
    /// last measurement failed).
    pub state: &'static str,
    /// Time-source time minus local time, from the last successful reading.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub skew_ms: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub measured_at_ms: Option<i64>,
    pub warn_ms: i64,
    pub refuse_ms: i64,
}

pub struct ClockGuard {
    policy: ClockPolicy,
    reading: RwLock<ClockHealth>,
}

impl ClockGuard {
    pub fn new(policy: ClockPolicy) -> Result<Self> {
        if policy.warn_ms < 0 || policy.refuse_ms <= policy.warn_ms {
            bail!("clock thresholds need 0 <= warn < refuse");
        }
        let reading = RwLock::new(ClockHealth {
            state: "unknown",
            skew_ms: None,
            measured_at_ms: None,
            warn_ms: policy.warn_ms,
            refuse_ms: policy.refuse_ms,
        });
        Ok(Self { policy, reading })
    }

    /// Measure against the time source now and record the result. Blocking.
    pub fn measure(&self) -> ClockHealth {
        let skew = crate::host_preflight::sntp_skew_ms(&self.policy.server, Duration::from_secs(2));
        if let Err(error) = &skew {
            eprintln!(
                "tenkai.clock state=unknown source={} detail={error:#}",
                self.policy.server
            );
        }
        self.record(skew.ok(), crate::now_millis())
    }

    /// Record one measurement: a skew, or `None` when it failed.
    pub fn record(&self, skew_ms: Option<i64>, now_ms: i64) -> ClockHealth {
        if skew_ms.is_none() && self.health().state == "refuse" {
            return self.health();
        }
        let health = ClockHealth {
            state: match skew_ms.map(i64::abs) {
                None => "unknown",
                Some(skew) if skew > self.policy.refuse_ms => "refuse",
                Some(skew) if skew > self.policy.warn_ms => "warn",
                Some(_) => "ok",
            },
            skew_ms,
            measured_at_ms: skew_ms.map(|_| now_ms),
            warn_ms: self.policy.warn_ms,
            refuse_ms: self.policy.refuse_ms,
        };
        if let Ok(mut reading) = self.reading.write() {
            *reading = health.clone();
        }
        health
    }

    pub fn health(&self) -> ClockHealth {
        self.reading
            .read()
            .map(|reading| reading.clone())
            .unwrap_or_else(|poisoned| poisoned.into_inner().clone())
    }

    /// Refuse `operation` while the last reading is beyond `refuse_ms`.
    pub fn require_trusted(&self, operation: &str) -> Result<()> {
        let health = self.health();
        if health.state == "refuse" {
            bail!(
                "{operation} {REFUSAL_MARKER} {} ms off its time source, more than the {} ms allowed",
                health.skew_ms.unwrap_or_default(),
                health.refuse_ms
            );
        }
        Ok(())
    }
}

const REFUSAL_MARKER: &str = "refused: the host clock is";

/// True for an error message that a clock refusal produced, so callers can
/// report it as a temporary condition (retry later), not a bad request.
pub fn is_clock_refusal(message: &str) -> bool {
    message.contains(REFUSAL_MARKER)
}

static GUARD: OnceLock<Arc<ClockGuard>> = OnceLock::new();

/// Install this process's guard (once, at server start).
pub fn install(guard: Arc<ClockGuard>) {
    let _ = GUARD.set(guard);
}

pub fn installed() -> Option<Arc<ClockGuard>> {
    GUARD.get().cloned()
}

/// Refuse `operation` when an installed guard reads too much drift. Without
/// a guard (no time source configured) nothing is refused.
pub fn require_trusted_time(operation: &str) -> Result<()> {
    match GUARD.get() {
        Some(guard) => guard.require_trusted(operation),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn guard(server: String) -> ClockGuard {
        ClockGuard::new(ClockPolicy {
            server,
            warn_ms: 1_000,
            refuse_ms: 10_000,
        })
        .unwrap()
    }

    #[test]
    fn simulated_drift_warns_then_refuses_and_recovers() {
        let guard = guard("unused".into());
        assert_eq!(guard.health().state, "unknown");
        assert_eq!(guard.record(Some(200), 1).state, "ok");
        assert_eq!(guard.record(Some(-4_000), 2).state, "warn");
        assert!(guard.require_trusted("plan approval").is_ok());
        assert_eq!(guard.record(Some(15_000), 3).state, "refuse");
        let refused = guard
            .require_trusted("plan approval")
            .unwrap_err()
            .to_string();
        assert!(refused.contains("15000 ms off"), "{refused}");
        assert!(is_clock_refusal(&refused));
        // A failed measurement does not lift a refusal; a good reading does.
        assert_eq!(guard.record(None, 4).state, "refuse");
        assert_eq!(guard.record(Some(100), 5).state, "ok");
        // Nor is it evidence of drift on its own.
        assert_eq!(guard.record(None, 6).state, "unknown");
        assert!(guard.require_trusted("plan approval").is_ok());
        assert!(
            ClockGuard::new(ClockPolicy {
                server: "x".into(),
                warn_ms: 5,
                refuse_ms: 5
            })
            .is_err()
        );
    }

    /// A local SNTP server is the only time source needed: no network.
    #[test]
    fn measures_against_a_local_time_source() {
        let ahead = guard(crate::host_preflight::fake_time_server(20_000)).measure();
        assert_eq!(ahead.state, "refuse");
        assert!(ahead.skew_ms.unwrap() > 19_000);
        let close = guard(crate::host_preflight::fake_time_server(0)).measure();
        assert_eq!(close.state, "ok");
    }
}
