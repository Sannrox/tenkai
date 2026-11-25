# Debug sessions

A debug session is time-boxed, audited access to one instance
([ADR 0061](decisions/0061-time-boxed-audited-debug-sessions.md)). This page
covers the session record, its management API, and how the environment's
runtime picks it up. Attaching a terminal arrives with the relay; until then
a runtime holds the session and ends it at its bound.

## Who may open one

All of these must hold, or the open is refused and the refusal is audited:

- the caller holds `debug`: a human acting directly, through a grant rule
  ([server authentication](configure-server-authentication.md)). The
  management token does not hold it, and neither does a call with an agent in
  its actor chain;
- an environment-scoped credential is scoped to the session's environment;
- the environment's approval policy sets `debug_sessions` to `read` or
  `elevate` ([plan approval](plan-approval.md#debug-sessions));
- the requested length is within the environment's `debug_session_max_ms`.

An unknown instance or environment is 404. If the audit record cannot be
written, the session does not open.

## API

| Request | Needs | Result |
| --- | --- | --- |
| `POST /v1/debug-sessions` with `environment`, `instance`, `reason`, optional `duration_ms` | `debug` | 201 and the session, `state` `open` |
| `GET /v1/debug-sessions[?environment=]` | `read` | `{"sessions": [...]}`, newest first |
| `GET /v1/debug-sessions/{session}` | `read` | the session |
| `POST /v1/debug-sessions/{session}/close` with `reason` | `debug` or `management` | the session, `state` `closed` |
| `GET /v1/debug-sessions/{session}/stream`, a WebSocket upgrade | `debug` | the terminal [stream](#stream) |

`duration_ms` defaults to the environment's maximum. A session is stored in
the operational store (SQLite, or the tenant's partition on a Postgres hub),
so it survives a restart and every replica serves it.

## Bound and states

- `open`: the session may be used until `not_after`.
- `closed`: someone closed it; `closed_by` and `close_reason` say who and why.
  Closing a session that already ended returns it unchanged.
- `expired`: `not_after` passed while it was open. The first read after the
  bound records the expiry; `closed_at` is `not_after`.

## Runtime

A runtime that names the `debug_session` capability picks up the open
sessions of its environment with its work; the first runtime instance to do
so owns the session, shown as `runtime.instance` and `runtime.attached_at`.
An older runtime is never handed a session, and `runtime` stays absent. The
runtime ends the session at `not_after` on its own clock, even while the
server is unreachable, and reports the close when it reaches the server
again (`runtime.closed_at`). See
[runtime protocol](runtime-protocol-v1.md#debug-sessions).

## Stream

An operator holding `debug` and the runtime that owns the session each open
a WebSocket with subprotocol `tenkai.debug-stream.v1`: the operator at
`GET /v1/debug-sessions/{session}/stream` with its management credential,
the runtime at
`GET /v1/runtime/environments/{environment}/debug-sessions/{session}/stream`
with its runner credential. The credential is checked before the upgrade,
so a bad one is answered with an HTTP error and no frame; an upgrade that
does not offer the subprotocol is 400, and a session that has ended is 409.

The server relays frames between the two ends and writes none of them to
the store or a log. Binary frames carry terminal I/O. Each text frame is one
JSON control message:

| `type` | From | Fields |
| --- | --- | --- |
| `attached` | server, to both ends | the other end is connected |
| `resize` | operator | `cols`, `rows` |
| `command` | operator | `command` |
| `exit` | runtime | `code` |
| `close` | any | `reason`, optional `message` |

A frame is at most 64 KiB. A control the sending end may not send, a
frame the other end's queue cannot take, or a write to an end that has not
read for five seconds, ends both ends with `protocol_error`. The last frame of a stream is a `close`, whose `reason`
is one of:

- `peer_closed`: the other end closed;
- `bound_reached`: the session reached `not_after`;
- `session_closed`: the session was closed or expired;
- `grant_revoked`: a credential or grant no longer admits the stream. Each
  end is checked again every two seconds, and a check that cannot be
  answered also ends it;
- `replaced`: a newer connection of the same end took over;
- `unsupported`: the runtime cannot attach a terminal to this instance.
  Until command execution lands, every runtime answers this, with message
  `not supported for this executor`, once an operator attaches.

The relay holds both ends of a session in one server's memory. With several
replicas, route both stream paths of a session to the same replica, for
example by hashing on the session id; after a replica dies, both ends
connect again. If a proxy in front of the server refuses the upgrade, the
runtime reports why and the session shows it as `runtime.stream_error`.
There is no fallback transport.

## Audit

| Operation | When |
| --- | --- |
| `debug_session.open.completed` | before the session is stored; the resource names session, environment, instance, bound and reason |
| `debug_session.open.refused` | every refused open, with its reason |
| `debug_session.open.failed` | the session could not be stored after the open was recorded |
| `debug_session.close.completed` | a close, with its reason |
| `debug_session.close.refused` | an agent tried to close |
| `debug_session.expire.completed` | the first read after the bound, under principal `tenkai` |
| `debug_session.attach.completed` | a runtime instance took the session, under principal `runtime:<instance>` |
| `debug_session.runtime_close.completed` | the owning runtime reported closing it |
| `debug_session.stream.attached` | an end's stream upgrade was admitted; the resource names the side |
