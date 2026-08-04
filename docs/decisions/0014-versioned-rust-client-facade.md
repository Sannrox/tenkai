# ADR 0014: Versioned Rust client facade

- Status: Accepted
- Date: 2026-08-04
- Issue: [#209](https://github.com/Sannrox/tenkai/issues/209)
- Owner: Tenkai maintainers
- Related: [ADR 0001](0001-standalone-core-and-service-evolution.md), [ADR 0012](0012-legacy-graph-action-compatibility-boundary.md), [ADR 0013](0013-evaluation-gate-evidence-projection.md)
- Dependency: [Sekai-Chisei #523](https://github.com/Sannrox/sekai-chisei/issues/523), [PR #531](https://github.com/Sannrox/sekai-chisei/pull/531), [PR #535](https://github.com/Sannrox/sekai-chisei/pull/535)

## Context

Tenkai's remote adapter had its own generated Sekai and Chisei clients,
metadata interceptor, endpoint construction, and retry handling. Sekai-Chisei
now publishes `sekai-client`, a Rust 2024 facade for the canonical
`sekai-proto` surface. Its transport owns connection validation, reserved
identity and credential metadata, deadlines, bounded retries, and sanitized
typed errors while leaving operational authority and recovery to the host.

Tenkai still calls several existing compatibility RPCs that do not yet have
typed helpers in the 0.1 client. Removing those calls or silently replacing
them with a different authority would change behavior and trust boundaries.

## Decision

Tenkai uses `sekai-client` 0.1.2 at the merged Sekai-Chisei revision
`1a3ab137e146c10e36b5ba3ece74c25f16db860a`. The client and its direct
`sekai-proto` dependency are Apache-2.0 licensed, matching the current
Sekai-Chisei workspace license.

The remote `Ctx` owns one `CoreLoopClient<GrpcTransport>` and routes existing
unary Sekai and Chisei calls through the SDK's bounded raw escape hatch. This
keeps auth, principal propagation, endpoint policy, deadlines, error mapping,
and request metadata in the client facade while preserving the existing
application methods and embedded backend.

Only lease-fenced object writes opt into the configured two-attempt retry
policy. They pass the stable lease-precondition request ID to both the SDK
metadata and the protobuf request. Other calls remain single-attempt unless a
future contract explicitly makes them retryable. Deterministic link creation
asks the server for typed `AlreadyExists` behavior so duplicate links remain
idempotent without inspecting provider error text. HTTPS uses the SDK's
bundled WebPKI roots by default; hosts that need the platform store can opt
into its native-roots feature, and custom PEM CAs remain supported.

Tenkai remains the operational authority: the SDK does not own plans,
approvals, receipts, persistence, recovery, or policy decisions. Provider
projections remain optional and retryable unless an operation policy requires
their evidence. The dependency stays pinned to a Git revision until the
published client has a separately reviewed release-distribution path.

## Alternatives considered

### Keep Tenkai's hand-written remote clients

Rejected because it duplicates transport, credential, deadline, retry, and
error-sanitization policy at the integration boundary.

### Wait for typed helpers for every existing RPC

Rejected because the available facade already provides a bounded raw adapter
with the same SDK-owned metadata and error path. Typed helpers can replace
individual raw calls later without changing the Tenkai authority boundary.

### Use the TypeScript or Python client from Rust

Rejected because it adds a second runtime boundary and does not provide a
native Rust dependency for Tenkai's embedded/server-equivalent hosts.

## Consequences

- `Cargo.lock` pins `sekai-client` and its canonical `sekai-proto` dependency
  to the reviewed Sekai-Chisei revision.
- Remote and embedded modes continue to share Tenkai application behavior;
  only the remote transport adapter changes.
- Existing unsupported RPCs remain visible as explicit path-bound raw calls
  until typed SDK helpers are available.
- Non-loopback plaintext remote targets fail closed under the SDK transport
  policy; loopback development targets and HTTPS remain supported.
- The SDK's default HTTPS trust source remains independent of the host CA
  bundle, with an explicit native-roots feature for platform-specific trust
  stores.
- A future SDK release or typed-helper migration needs compatibility tests and
  a follow-up decision if it changes retry, authority, or protocol semantics.

## Evidence and provenance

- Sekai-Chisei PR [#531](https://github.com/Sannrox/sekai-chisei/pull/531)
  merged as `4d61ce1d4590f5ba9ca80cc033218ee9300351f` and published the
  `sekai-client` facade and its design decision.
- Sekai-Chisei commit
  [`fe6e047`](https://github.com/Sannrox/sekai-chisei/commit/fe6e04747cfad75d6655b9b509690637bd256733)
  returned the workspace and public crates to Apache-2.0 and recorded ADR
  0017.
- Sekai-Chisei PR [#535](https://github.com/Sannrox/sekai-chisei/pull/535)
  merged as `1a3ab137e146c10e36b5ba3ece74c25f16db860a` and preserved bundled
  WebPKI roots as the default HTTPS trust source while adding an explicit
  native-roots feature.
- Tenkai's adapter and compatibility tests are implemented in
  [`src/client.rs`](../../src/client.rs).
- The integration dependency is declared in
  [`Cargo.toml`](../../Cargo.toml) and locked in
  [`Cargo.lock`](../../Cargo.lock).
