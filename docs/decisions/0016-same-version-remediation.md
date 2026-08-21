# ADR 0016: Bounded same-version remediations

- Status: Accepted
- Date: 2026-08-21
- Issue: [#280](https://github.com/Sannrox/tenkai/issues/280)
- Related: [ADR 0001](0001-standalone-core-and-service-evolution.md),
  [Catalog contract](../catalog-contract.md),
  [Software executor](../software-executor.md)

## Context

Tenkai converges Catalog channel heads onto recorded `deployed.{product}`
facts. Apply-time health can roll a failed upgrade back to the previous pin.
That leaves several operator failures without a Plan: a same-version bounce,
a missing live target while Catalog is `Current`, a recalled release that is
already deployed, a maintenance-blocked Plan after the window reopens, a
product-only upgrade window, and a workload that becomes unhealthy after a
successful apply.

Owning live Kubernetes as an orchestrator, storing cluster secrets, or
restarting healthy installs on a timer would move recovery material off
Tenkai-owned Catalog and Plan facts.

## Decision

Tenkai owns a **bounded** same-version remediation set. It does not become a
live-state reconciler for arbitrary cluster drift.

| Concern | Owner |
| --- | --- |
| Recorded deployed version | Tenkai Catalog / environment properties |
| Live target observation | Executor `observe()` during **reconcile only**; Present/Absent/Mismatched. Unknown is never a Plan |
| Same-version bounce | Plan `Action::Restart` from operator command or reconcile evidence |
| Recalled release | Catalog recall mutation; planning fails closed on recalled heads; roll-off to a non-recalled channel head; rollback onto recalled content only with an audited recovery reason |
| Maintenance eligibility | Intersection of environment and product windows; reconciler may resume a maintenance-blocked Plan when the resolved window is open |
| Post-apply health | Apply records `healthy` / `unhealthy`. Reconcile may Restart from recorded `unhealthy`. Tenkai does not execute `deploy.health` during unapproved planning |
| Config or secret change | Non-secret environment overlays (`tenkaictl env overlay`) can force a same-version Restart. Secrets still require a new immutable release. No secret storage |

Rejected: hygiene restarts, kubelet/node/autoscaler ownership, treating
`observe() == Unknown` as drift, and making `fleet watch` auto-remediate.

## Consequences

- `Action::Restart` is a first-class Plan step. `from` and `to` are the same
  recorded version. Apply still requires approval, fencing, and maintenance
  admission.
- `tenkaictl restart` and `tenkaictl release recall` are operator commands.
- Reconcile may create Restart steps when Helm/Kubernetes `observe()` is
  `Absent` or `Mismatched`, recorded apply health is `unhealthy`, or
  environment overlays are stale. `tenkaictl plan` does not probe live
  targets or execute `deploy.health`, but it does emit Restart when
  Tenkai-owned overlays changed since the last apply.
- Product maintenance windows are unrestricted when unset. A Plan starts only
  when every applicable environment and product window is open (or an audited
  emergency override is present).
- Rollback onto recalled content is denied by default. An operator may admit it
  only with `--allow-recalled-recovery --recovery-reason`; Catalog lookup and
  channel-head planning stay fail-closed.

## Alternatives

1. **Versioned delivery only.** Document the gaps and ship nothing. Rejected:
   operators already have no safe same-version Plan.
2. **Live target as first-class desired state.** Continuous content comparison
   against the cluster. Rejected: Tenkai does not own cluster object identity
   or secret material, and `Current` would stop meaning Catalog agreement.

## Amendment (2026-08-21)

The bounded set now also includes:

- environment-scoped **non-secret overlays** that change `config_digest` and
  emit a Restart when the digest differs from `applied_config`;
- reconcile `observe() == Mismatched` when live Tenkai version/release labels
  disagree with the requested pin (`Unknown` still does not become a Plan);
- recorded apply health (`healthy` / `unhealthy`); reconcile may Restart from
  recorded `unhealthy` and does not execute `deploy.health` during planning;
- audited rollback onto recalled content, recorded on the Plan as
  `recalled_recovery_reason`.

Secret overlays, hygiene timers, and full live-content comparison remain
rejected.
