# Threat model

What Tenkai protects, against whom, and which mechanism does it. Each claim
links to the page or decision that implements it; this page does not repeat
them. The short version, with release verification and reporting, is the
[security overview](security.md).

## Assets

| Asset | Why it matters |
| --- | --- |
| Signed releases | What may run anywhere. A forged or altered release is code execution on every target. |
| Approved plans | Which release runs where, and when. A forged approval is an unreviewed change. |
| Signing, approval, revocation and audit keys | Whoever holds them can produce the two assets above. |
| Sealed secret values | Credentials a product needs at apply. |
| Workload identities and peer grants | Which instance a product believes it is talking to. |
| Operational state | Environments, deployments, leases, receipts and audit. Recovery depends on it. |
| Target hosts and clusters | Where releases run, including root on hosts that run privileged host releases. |
| Tenkai's own binaries | A tampered `tenkaictl`, server or runtime bypasses every check above. |

## Actors

| Actor | Assumed capability |
| --- | --- |
| Operator or approver | Holds a scoped credential and, for approvers, a signing key. Trusted for their grants only. |
| Agent actor | Holds a delegated credential. Trusted to read and propose plans, not to apply or approve them. |
| Tenant | Shares a hub with other tenants. Must not see or touch their records. |
| Compromised server | Full control of `tenkai-server`, its database and its network position. |
| Compromised runtime | Full control of one environment's runtime host and its credential. |
| Compromised approver key | A valid approval signing key in the wrong hands. |
| Compromised CI | Control of a workflow run, its tokens and its build outputs. |
| Network attacker | Can read and change traffic between components. |

## Trust boundaries

1. **Signer to catalog.** A release enters the catalog only with a valid
   signature from a trusted root. Unsigned publish is refused outside the
   `local` environment
   ([publication policy](release-signing.md#publication-policy)).
2. **Approver to plan.** An approval signs one plan digest, for one
   environment and one purpose, until it expires
   ([approval format](plan-approval.md#plan-approval-format)).
3. **Client to server.** Every management and runtime request is
   authenticated, and the tenant is
   derived by the authenticator, never chosen by the caller
   ([principal vs tenant](auth-request-context.md#principal-vs-tenant)).
4. **Server to runtime.** A runtime pulls work with a credential scoped to
   one environment. In built-in mode it verifies the release itself before
   it applies
   ([built-in executors](run-tenkai-server.md#built-in-executors-on-the-runtime),
   [release package](runtime-protocol-v1.md#release-package)).
5. **Server to root.** On a host that runs privileged host releases, the
   server can only start a fixed systemd unit. Everything it hands over is
   untrusted input to the applier
   ([what one step does](host-releases.md#what-one-step-does)).
6. **Tenkai to provider.** Optional provider evidence is bound by digest and
   fails closed when an operation requires it
   ([evidence and required decisions](provider-contracts.md#evidence-and-required-decisions)).
7. **CI to user.** A release binary is trusted only after its checksum and
   build attestation verify
   ([verify and install by hand](release-binaries.md#verify-and-install-by-hand)).

## What each mechanism defends

### Against a compromised server

The server is not trusted with what runs or with secret values.

- **No unsigned content.** A runtime in built-in mode verifies the release
  signature against its own trust roots, with revocation and signer windows,
  and checks every artifact and rebuilt input against the signed digests. A
  server cannot make such a runtime apply content no trusted signer released
  ([ADR 0048 §3](decisions/0048-runtime-runs-built-in-executors.md#3-the-runtime-verifies-the-release-before-it-applies),
  [built-in executors](run-tenkai-server.md#built-in-executors-on-the-runtime)).
- **No unapproved sealed writes.** A runtime that writes sealed values
  verifies the approvals itself, and the values are sealed to keys the
  server never holds
  ([ADR 0045](decisions/0045-sealed-secrets.md#threat-model),
  [§4](decisions/0045-sealed-secrets.md#4-the-runtime-verifies-opens-and-writes-at-apply)).
- **No unapproved root.** The host applier verifies the release, its digests
  and its human approvals, refuses links and special files in the request,
  and runs each step at most once
  ([ADR 0041 §2](decisions/0041-per-release-executor-and-privileged-host-releases.md#2-privileged-host-releases-run-through-a-narrow-systemd-path),
  [approvals](host-releases.md#approvals)).
- **No minted identities.** Identity issuance and peer grants follow approved
  plans, and an environment without a separate runtime refuses plans that
  issue identities
  ([ADR 0046](decisions/0046-workload-identity-and-peer-policy.md#threat-model),
  [§8](decisions/0046-workload-identity-and-peer-policy.md#8-environments-without-a-separate-runtime)).
- **No silent audit edits.** Audit exports are a signed chain; offline
  verification refuses gaps, reordering and edits
  ([verify](audit-export.md#verify)).

### Against a compromised runtime

- **One environment.** A runtime principal maps to exactly one environment,
  and its lease binds scope and instance. Enrollment tokens are single-use,
  short-lived and stored as digests; the credential is revocable
  ([enrolling a runtime](run-tenkai-server.md#enrolling-a-runtime)).
- **Fenced work.** Execution leases are generation-fenced, so a runtime that
  lost its lease cannot complete or overwrite work
  ([execution leases and fencing](run-tenkai-server.md#execution-leases-and-fencing)).

### Against a compromised approver key

- **Bounded approvals.** An approval binds the plan digest, environment,
  purpose and expiry, and a gated approval cannot authorize skipping gates
  ([approval format](plan-approval.md#plan-approval-format)).
- **More than one approver.** A quorum requires signers distinct by key and
  by principal, and automatic approval cannot satisfy it
  ([multi-party approval](plan-approval.md#multi-party-approval)).
- **Revocation.** A signed, monotonic revocation list removes the key from
  every signature check, online or through an offline bundle
  ([revoke a key fleet-wide](key-rollover.md#revoke-a-key-fleet-wide)).
- **Hardware keys in production.** A production profile refuses file and lab
  keys, and the on-site ceremony requires two custodians
  ([production signer](release-signing.md#production-signer),
  [dual control](key-ceremony.md#dual-control)).

### Against a compromised CI

- **Signed tags.** A release starts only from an annotated tag signed by a
  key in the repository's tag fingerprints
  ([who cuts a tag](../RELEASING.md#who-cuts-a-tag)).
- **Attested binaries.** Every attached file, `SHA256SUMS` and the SBOM carry
  build provenance attestations, and the SBOM is validated before it is
  attested ([packaging path](release-binaries.md#packaging-path)).
- **Product releases stay separate.** A CI run that publishes a product
  release still needs a trusted signer, and deploying it still needs an
  approval ([publication policy](release-signing.md#publication-policy)).

### Against agents and other tenants

- **Agents propose, people approve.** An agent actor may read and create
  plans. Apply, approve, publish, promote and recall are refused, and
  rollback or downgrade always needs a human approval
  ([ADR 0034](decisions/0034-agent-actor-mutations.md#decision)).
- **Tenant isolation.** A two-tenant conformance harness and a route guard
  run in CI, and a denial reveals nothing about the other tenant
  ([purpose](tenant-isolation-conformance.md#purpose),
  [error posture](tenant-isolation-conformance.md#non-disclosing-error-posture)).
- **No implicit development permissions.** Development flags work only for
  the `local` environment and are recorded with a reason
  ([unattended approval policy](plan-approval.md#unattended-approval-policy)).

### Against a network attacker

- **TLS off loopback.** The server refuses a plaintext bind on a
  non-loopback address
  ([native TLS](run-tenkai-server.md#native-tls)).
- **Content is signed anyway.** Releases, approvals, revocations, advisory
  feeds and recall notices are verified by signature, not by the channel
  that carried them
  ([advisory feed](offline-bundles.md#advisory-feed),
  [signed recall notices](recall-notices.md#signed-recall-notices)).

## Known limits

Stated plainly; each links to where it is decided.

- **A server chooses what runs among approved work.** Outside sealed steps
  and host releases, a runtime trusts the plan the server hands it and does
  not check approvals itself
  ([ADR 0045](decisions/0045-sealed-secrets.md#threat-model)).
- **Program-mode runtimes trust the release content.** Only a runtime in
  built-in mode verifies release signatures. A runtime that hands steps to an
  operator program applies what the server sends; that program owns any
  check ([built-in executors](run-tenkai-server.md#built-in-executors-on-the-runtime)).
- **Automatic approval lets agent plans run.** In an environment whose
  policy approves forward plans automatically, an agent's plan runs like the
  reconciler's
  ([ADR 0034 consequences](decisions/0034-agent-actor-mutations.md#consequences)).
- **A server can withhold.** A compromised server can delay work, or
  withhold and delete sealed values, though it cannot read or forge them
  ([ADR 0045 consequences](decisions/0045-sealed-secrets.md#consequences)).
- **In-process executors.** An executor that runs inside the server gets no
  protection from the server
  ([ADR 0045 out of scope](decisions/0045-sealed-secrets.md#out-of-scope)).
- **Signer windows do not stop a leaked key.** Revoke it
  ([signer validity windows](release-signing.md#signer-validity-windows)).
- **Revocation on a running server.** A list imported through the CLI takes
  effect on the server at restart, and revocation cannot be undone
  ([ADR 0036 consequences](decisions/0036-offline-key-revocation.md#consequences)).
- **Recalled host releases.** A recalled host release can still run while
  its approval is unexpired; `max_approval_ttl_ms` bounds that window
  ([known limit](host-releases.md#known-limit-recall)).
- **Workload identity.** No revocation lists, mesh or network policy;
  products enforce peer identity themselves
  ([ADR 0046 out of scope](decisions/0046-workload-identity-and-peer-policy.md#out-of-scope)).
- **Audit ranges.** The bounds of a ranged export are not signed; anchor it
  ([verify](audit-export.md#verify)).
- **Binary attestations need a network.** Disconnected sites verify the
  offline bundle signature instead
  ([disconnected sites](release-binaries.md#disconnected-sites)).
- **Attestations name the workflow on main.** The source revision is pinned
  by the signed tag and the manifest commit
  ([start, retry and dry run](../RELEASING.md#start-retry-and-dry-run)).
- **No noisy-neighbor isolation** between tenants on one hub
  ([ADR 0008 non-goals](decisions/0008-production-tenant-operational-store.md#5-explicit-non-goals)).
- **No atomic third-party targets.** Tenkai cannot make shell or external
  targets atomic
  ([unsupported claims](delivery-effect-conformance.md#unsupported-claims)).
- **Host identity** is Linux only
  ([ADR 0047 out of scope](decisions/0047-host-identity.md#out-of-scope)).
- **Reproducible builds** are not yet checked, so a binary is trusted through
  its attestation
  ([packaging path](release-binaries.md#packaging-path)), not by
  rebuilding it.
