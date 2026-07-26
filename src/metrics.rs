//! Optional OpenMetrics (Prometheus text) exposition for control-plane diagnostics (#137).
//!
//! Not a TSDB. No secrets, bearer tokens, or tenant identifiers in labels.
//! Low-cardinality labels only (outcome enum). Default path works without Prometheus.

use crate::reconciler::ReconcileDiagnostics;

/// Metric name prefix for Tenkai hub scrape series.
pub const METRIC_PREFIX: &str = "tenkai_";

/// Render OpenMetrics / Prometheus text exposition for reconcile counters.
///
/// Output is deterministic for a given diagnostics snapshot (stable key order).
pub fn render_reconcile_openmetrics(diag: &ReconcileDiagnostics) -> String {
    let outcome = sanitize_label_value(&diag.last_outcome);
    let mut out = String::with_capacity(512);
    out.push_str("# HELP tenkai_reconcile_ticks_total Total reconcile ticks attempted.\n");
    out.push_str("# TYPE tenkai_reconcile_ticks_total counter\n");
    out.push_str(&format!(
        "tenkai_reconcile_ticks_total {}\n",
        diag.ticks_total
    ));

    out.push_str(
        "# HELP tenkai_reconcile_ticks_failed_total Reconcile ticks with environment failures or tick errors.\n",
    );
    out.push_str("# TYPE tenkai_reconcile_ticks_failed_total counter\n");
    out.push_str(&format!(
        "tenkai_reconcile_ticks_failed_total {}\n",
        diag.ticks_failed
    ));

    out.push_str(
        "# HELP tenkai_reconcile_last_environments Environments considered on the last successful tick structure.\n",
    );
    out.push_str("# TYPE tenkai_reconcile_last_environments gauge\n");
    out.push_str(&format!(
        "tenkai_reconcile_last_environments {}\n",
        diag.last_environments_total
    ));

    out.push_str(
        "# HELP tenkai_reconcile_last_environments_failed Environments failed on the last tick.\n",
    );
    out.push_str("# TYPE tenkai_reconcile_last_environments_failed gauge\n");
    out.push_str(&format!(
        "tenkai_reconcile_last_environments_failed {}\n",
        diag.last_environments_failed
    ));

    out.push_str(
        "# HELP tenkai_reconcile_last_outcome Last tick outcome (ok, degraded, error, or empty).\n",
    );
    out.push_str("# TYPE tenkai_reconcile_last_outcome gauge\n");
    out.push_str(&format!(
        "tenkai_reconcile_last_outcome{{outcome=\"{outcome}\"}} 1\n"
    ));

    out.push_str(
        "# HELP tenkai_reconcile_environments_busy_total Environments skipped as Busy (in-flight or fence).\n",
    );
    out.push_str("# TYPE tenkai_reconcile_environments_busy_total counter\n");
    out.push_str(&format!(
        "tenkai_reconcile_environments_busy_total {}\n",
        diag.environments_busy_total
    ));

    out.push_str("# EOF\n");
    out
}

/// Restrict label values to a safe OpenMetrics character set (no quotes/newlines).
fn sanitize_label_value(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return "none".into();
    }
    trimmed
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .take(32)
        .collect()
}

/// True when a metrics body must not contain known fixture secrets.
pub fn body_leaks_secret(body: &str, secrets: &[&str]) -> bool {
    secrets
        .iter()
        .any(|secret| !secret.is_empty() && body.contains(secret))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn openmetrics_contains_documented_series_without_secrets() {
        let diag = ReconcileDiagnostics {
            ticks_total: 3,
            ticks_failed: 1,
            last_outcome: "degraded".into(),
            last_environments_total: 4,
            last_environments_failed: 1,
            environments_busy_total: 2,
        };
        let body = render_reconcile_openmetrics(&diag);
        assert!(body.contains("tenkai_reconcile_ticks_total 3"));
        assert!(body.contains("tenkai_reconcile_ticks_failed_total 1"));
        assert!(body.contains("tenkai_reconcile_last_environments 4"));
        assert!(body.contains("tenkai_reconcile_last_environments_failed 1"));
        assert!(body.contains("outcome=\"degraded\""));
        assert!(body.contains("tenkai_reconcile_environments_busy_total 2"));
        assert!(body.contains("# EOF"));
        assert!(!body_leaks_secret(
            &body,
            &["management-secret", "Bearer ", "token="]
        ));
        assert!(!body.contains("tenant"));
    }

    #[test]
    fn sanitize_outcome_label() {
        assert_eq!(sanitize_label_value("ok"), "ok");
        assert_eq!(sanitize_label_value("bad\"quote"), "bad_quote");
        assert_eq!(sanitize_label_value(""), "none");
    }
}
