# ADR 0035: Host preflight is signed environment evidence

- Status: Accepted
- Date: 2026-10-18
- Issue: [#632](https://github.com/Sannrox/tenkai/issues/632)
- Owner: Tenkai maintainers
- Related: [ADR 0034](0034-agent-actor-mutations.md)

## Context

Compatibility profiles check software, but nothing checked the host before
the first install: disk, memory, ports, clock drift, certificate validity,
and registry and identity-provider reachability. Isolated sites need these
checks to run offline. Operators also need a failed host to stop plan
execution by policy, not just print a warning.

## Decision

1. **`tenkaictl preflight <env>` runs on the host.** A version 1 TOML file
   names the checks. Each one passes or fails with a reason, and a check
   that cannot run fails. Every check uses local resources or site
   addresses: `statvfs`, `/proc/meminfo`, a bind, one SNTP exchange, a PEM
   file, and TCP connects.
2. **Results are signed evidence on the environment.** The command signs a
   `tenkai.preflight.v1` statement (environment, time, results, overall
   verdict) with an Ed25519 seed. It stores the envelope in the
   environment's `preflight_evidence` property and replaces the previous
   one. A failed run is recorded too.
3. **Signers are trust roots scoped to `preflight`.** They live in the plan
   approval trust roots with explicit environments and only the `preflight`
   provider. Plan approvals naming that provider are refused, so a host key
   cannot approve plans.
4. **The approval policy gates execution.** `require_preflight.max_age_ms`
   on the environment's policy makes `verify_for_execution` refuse a plan
   unless the stored evidence verifies, passed, and is fresh. Every apply,
   approve, and automatic execution path goes through that check.

## Consequences

- A failed or stale preflight blocks human and automatic execution in that
  environment until a passing preflight is recorded.
- Policies without `require_preflight` and environments without a policy are
  unchanged.
- Certificate expiry is read with a minimal DER walk to `notAfter`, so no
  X.509 dependency is added. It reads only the first PEM certificate.

## Alternatives considered

- **Warn without gating.** Rejected: the issue asks for a failed preflight to
  block plan approval by policy.
- **A separate preflight trust file.** Rejected: plan approval trust roots
  already carry environment and provider scopes and are present wherever
  execution is verified.
- **Query a public time service.** Rejected: isolated sites have none. The
  clock check uses an SNTP server inside the site.
