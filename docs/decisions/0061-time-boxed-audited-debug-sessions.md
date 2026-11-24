# ADR 0061: Time-boxed audited debug sessions

- Status: Accepted
- Date: 2026-11-24
- Issue: [#1097](https://github.com/Sannrox/tenkai/issues/1097)
- Owner: Tenkai maintainers
- Builds on: [ADR 0034](0034-agent-actor-mutations.md),
  [ADR 0037](0037-multi-party-plan-approval.md),
  [ADR 0041](0041-per-release-executor-and-privileged-host-releases.md),
  [ADR 0048](0048-runtime-runs-built-in-executors.md)
- Related: [runtime protocol v1](../runtime-protocol-v1.md),
  Sannrox/tenkai-console#137

## Context

Operators debug a misbehaving instance with out-of-band cluster or host
access. That path is not instance-scoped, not time-boxed, and not in
Tenkai's audit. The management token is fleet-wide break-glass. The
runtime already holds the credentials that can reach the instance (ADR
0048). The protocol is pull-only HTTP; the server never pushes into an
environment.

## Decision

1. **A debug session is a durable record the runtime owns.** The
   management API creates it (environment, instance, subject and actors,
   mode `read` or `elevated`, `not_after`). The runtime that advertised
   `debug_session` pulls it on work, runs the attach with its own
   credentials, and closes it at `not_after` on its clock even if the
   server is unreachable. The server relays operator I/O over that
   runtime-initiated connection. It never stores or uses cluster or host
   credentials.

2. **Grant is a new capability, not Management.** `DeliveryCapability`
   gains `debug`. The fleet management token does not imply it. Stored
   grant rules grant it the same way they grant `read` and `publish`.

3. **Environment policy defaults to forbid.** Optional
   `debug_sessions = "forbid" | "read" | "elevate"` on the approval
   policy. Absent means forbid, including every upgraded environment
   whose stored policy has no field. `read` allows read-only sessions.
   `elevate` allows read-only sessions and write after a collected
   quorum for a new purpose `debug_elevate` (ADR 0037 envelopes, reason
   required). The v1 envelope schema does not change.

4. **Read-only is enforced per executor, on the runtime.** Cluster
   executors (`kubernetes`, `kubernetes-inprocess`, `helm`): get, logs,
   describe, events scoped to the instance's resources; exec into a
   running container is allowed only as a non-mutating attach. Host and
   docker: list and read under the instance's applied target. Any write
   (apply, delete, scale, a writable shell, a writable exec) needs a
   live elevation. A command the executor cannot classify is refused.

5. **Agents never.** Opening or elevating a session is refused for an
   agent actor, the same 403 as ADR 0034 §3. Only human principals
   hold or use `debug`: a service principal whose token matches a grant
   rule naming `debug` is refused the same way. Audit records subject and
   actors. If audit cannot be written, the session is refused. Discrete
   commands are captured where the executor sees an argv; TTY bytes are
   not a command log.

6. **Bound.** Default `not_after` is four hours from open. Policy may
   set a lower maximum. The runtime closes the session at the bound; a
   later server is told it already ended.

7. **Relay transport is WebSocket, opened from both ends toward the
   server.** The server never dials into an environment. After the
   runtime pulls an open session (§1), it upgrades
   `GET /v1/runtime/environments/{environment}/debug-sessions/{session}/stream`
   with the same runner credentials as its other calls (client
   certificate or enrolled bearer, plus `x-tenkai-runtime-instance`). The
   operator attaches through the management API at
   `GET /v1/debug-sessions/{session}/stream`, authenticated like any other
   management call. The server relays frames between the two and stores
   no terminal bytes. Frames are versioned (`tenkai.debug-stream.v1`):
   binary frames carry I/O, and text frames carry JSON control messages
   (resize, command, exit, close with a reason). Any of these ends the
   stream: either side closing, the bound passing (§6), or the grant
   being revoked. Runtime protocol v1 stays add-only: a runtime that does
   not advertise `debug_session` never pulls a session or upgrades. A TLS
   terminator that blocks the upgrade leaves the session unattachable,
   with a visible reason; it never falls back to another transport.

## Consequences

- Operators get instance-scoped, time-boxed, audited access without
  giving the hub cluster credentials.
- Console (Sannrox/tenkai-console#137) is a client of this API; #1097
  is the control plane, delivered in layers #1555 to #1560.
- Adding `debug` to `DeliveryCapability` and `debug_sessions` to the
  approval policy is a public-contract change, marked breaking at
  delivery.

## Alternatives considered

- **kubectl or SSH from the server.** Rejected: the server would hold
  environment credentials, and disconnected sites would not work.
- **Reuse `management`.** Rejected: the management token is fleet-wide
  break-glass; debug is a separate, instance-scoped grant.
- **Agent-opened sessions.** Rejected: ADR 0034; a human opens and
  elevates.
- **A pushed stream or new gRPC service.** Rejected: runtime protocol v1
  stays pull-only HTTP and add-only.
- **Long-poll request and response chunks for I/O.** Rejected
  (maintainer decision, 2026-11-24): a round trip per chunk, higher
  latency, and a re-authenticated request for every keystroke batch.
- **Default-allow on upgrade.** Rejected: absent policy is forbid.
- **Recovery bundle (ADR 0027) as the debug path.** Rejected: that is a
  derived read-only dump, not interactive access.
