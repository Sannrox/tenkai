# ADR 0031: Web console as a separate, pinned client

- Status: Accepted
- Date: 2026-09-30
- Issue: [#458](https://github.com/Sannrox/tenkai/issues/458)
- Owner: Tenkai maintainers
- Related: [ADR 0001](0001-standalone-core-and-service-evolution.md),
  [ADR 0004](0004-authenticated-request-context.md),
  [ADR 0006](0006-federated-identity.md),
  [ADR 0030](0030-remote-management-lifecycle.md),
  [Management lifecycle](../management-lifecycle.md),
  [Release binaries](../release-binaries.md)

## Context

Tenkai is operated through `tenkaictl` and the remote management API only.
Operators cannot see at a glance which release runs where or what blocks a
promotion, and there is no browser surface to request approval or roll back.
[#458](https://github.com/Sannrox/tenkai/issues/458) proposed a delivery web UI
with a promotion matrix home and asked three questions: where the UI lives and
in which stack, which gates are real, and how sign-in works without Tenkai
knowing the host.

Mature Rust servers with a UI mostly keep it in its own repository and ship one
pinned build of it. Two delivery styles exist. Serving a folder from disk works
only where a container image supplies the folder; plain-binary users get a
404. Compiling a checksummed release into the binary behind a Cargo feature
keeps one self-contained artifact and an offline default build. Tenkai ships
plain binaries and targets air-gapped sites, so the second style fits.

## Decision

1. **Separate repository.** The console lives in
   [Sannrox/tenkai-console](https://github.com/Sannrox/tenkai-console)
   (TypeScript, React, Vite). This repository stays Rust-only and needs no
   Node toolchain.
2. **Public API only.** The console is a client of Tenkai's versioned,
   authenticated API. There are no console-private routes and no privileges the
   API lacks; anything the console does, `tenkaictl` and integrators can do
   with the same contract and audit record. API types are generated from
   Tenkai's published contract at a pinned tag. The console checks the server's
   contract version at startup and refuses to half-work against an older one.
3. **Pinned, checksummed, compiled in.** Console releases publish a zip,
   `SHA256SUMS`, and an attestation. This repository pins one release URL and
   SHA-256 in a single place. Under the opt-in `ui` Cargo feature, `build.rs`
   downloads that zip, refuses a checksum mismatch, and embeds it;
   `tenkai-server` serves it at `/ui/` on the API's origin with a strict
   Content-Security-Policy. Default source builds perform no download. The
   release workflow enables `ui` for attached hosts. `--ui-dir` exists only as
   a development override. Updating the console is a one-line pin change.
4. **Only gates with a contract.** Gate state comes from server plan evidence;
   the browser never computes it. Shown today: signed approvals, maintenance
   windows, eval gates, environment constraints (shown for "pinned"), release
   waves, and recorded bypasses. Per-node rollout progress, "migrations
   reversible", and cross-environment health evidence have no general contract
   and are not shown until one is accepted.
5. **Delegated sign-in, server-side authorization.** A deployment's
   identity-aware proxy or OIDC login supplies a short-lived, audience-bound
   assertion checked by the existing verifier (ADR 0004, ADR 0006). The
   community fallback exchanges the management bearer once for a short-lived
   `HttpOnly`, `SameSite=Strict` session, on loopback only, with CSRF
   protection; the bearer never reaches browser storage. Tenkai stores no
   passwords and knows no identity-provider product. The server decides every
   authorization; the console may only hide actions. Signing keys never enter
   the browser, and signed releases and approvals are not weakened.

## Consequences

- Console and server release independently; compatibility is the versioned
  API plus the startup contract check.
- Release binaries grow by the bundle size. Source builds without `ui` are
  unchanged.
- New surfaces to secure: static serving (#463) and browser sessions (#464).
- The console needs read routes that do not exist yet: the promotion matrix
  (#465) and a plan with its gate evidence (#466).
- Console work (scaffold and release, matrix home, plan panel, settings) is
  planned in the console repository, each screen starting from mocks.

## Alternatives

- **UI in this repository, embedded at build time.** Rejected: puts a Node
  build in front of every Rust build and lets the UI reach internals.
- **Serve a folder from disk by default.** Rejected: plain-binary and
  air-gapped operators would get a missing UI.
- **Server-rendered HTML in this repository.** Keeps one language, but the
  matrix and plan panel are interactive enough to strain it, and it couples UI
  iteration to server releases.
- **Rust compiled to WASM.** Rejected: smaller ecosystem and accessibility
  tooling for a thin client whose boundary is a typed contract anyway.

## Follow-ups

- [#463](https://github.com/Sannrox/tenkai/issues/463) serve the pinned bundle under `/ui` behind `ui`
- [#464](https://github.com/Sannrox/tenkai/issues/464) browser sign-in
- [#465](https://github.com/Sannrox/tenkai/issues/465) promotion matrix read API
- [#466](https://github.com/Sannrox/tenkai/issues/466) plan read with gate evidence
- [tenkai-console#1](https://github.com/Sannrox/tenkai-console/issues/1) scaffold and checksummed release
- [tenkai-console#2](https://github.com/Sannrox/tenkai-console/issues/2) promotion matrix home
- [tenkai-console#3](https://github.com/Sannrox/tenkai-console/issues/3) plan panel
- [tenkai-console#4](https://github.com/Sannrox/tenkai-console/issues/4) settings surfaces
