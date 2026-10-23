# Host preflight

Compatibility profiles check software. Host preflight checks the machine
before the first install: free disk, available memory, free ports, clock
skew, certificate validity, and whether the registry and identity provider
answer. `tenkaictl preflight` runs the checks on the environment's host,
signs the results, and records them on the environment. An approval policy
can then refuse to execute any plan there until a fresh preflight has
passed. See [ADR 0035](decisions/0035-host-preflight-evidence.md).

Every check uses local resources or addresses inside the site, so preflight
works on an isolated network.

## Configure the checks

A version 1 TOML file names what to check. Omitted sections are not
checked.

```toml
version = 1
timeout_ms = 2000                 # network checks; default 2000
ports = [8080, 8443]              # must be free to bind
registries = ["registry.site.internal:5000"]
identity_providers = ["idp.site.internal:443"]

[[disks]]
path = "/var/lib/tenkai"
min_free_bytes = 21474836480      # 20 GiB

[memory]                          # Linux hosts (MemAvailable)
min_available_bytes = 4294967296

[clock]
server = "time.site.internal:123" # SNTP server inside the site
max_skew_ms = 500

[[certificates]]
path = "/etc/tenkai/tls/server.pem"
min_remaining_ms = 2592000000     # 30 days
```

| Check | Passes when |
| --- | --- |
| disk | Free space for unprivileged users at `path` is at least `min_free_bytes` (Unix) |
| memory | `MemAvailable` is at least `min_available_bytes` (Linux only; other hosts fail the check) |
| port | The port can be bound on all IPv4 interfaces, and on IPv6 when the host has it |
| clock | One SNTP exchange with a synchronized `server` shows an offset within `max_skew_ms` |
| certificate | The first PEM certificate's `notBefore` has passed and its `notAfter` is at least `min_remaining_ms` away |
| registry, identity provider | A TCP connection to the address succeeds within `timeout_ms` |

Each result is recorded as pass or fail with a reason, for example
`skew 10002 ms, at most 500 ms allowed` or `expired 2020-01-02T00:00:00+00:00`.
A check that cannot run fails with its error.

## Run and record

```sh
tenkaictl preflight prod \
  --config /etc/tenkai/preflight.toml \
  --signing-key /var/lib/tenkai/prod-preflight.ed25519
```

The command prints every result, signs them with the 32-byte Ed25519 seed
(mode `0600`, not a symlink), and stores the signed `tenkai.preflight.v1`
evidence on the environment, replacing the previous one. A failed preflight
is still recorded, and the command exits non-zero. Preflight runs in
embedded mode on the host it checks.

## Trust the signer

Add the seed's public key to `TENKAI_PLAN_APPROVAL_TRUST_ROOTS` with an
explicit environment scope and only the `preflight` provider:

```toml
[[signers]]
key_id = "sha256:<key digest>"
identity = "prod-preflight"
public_key = "<base64 public key>"
environments = ["prod"]
providers = ["preflight"]
```

Trust roots refuse a `preflight` signer without environments or with other
providers. A preflight signer cannot approve plans: a plan approval naming
the `preflight` provider is refused.

## Gate plan execution

Add `require_preflight` to the environment's
[approval policy](plan-approval.md#unattended-approval-policy):

```toml
version = 1
mode = "auto"
ttl_ms = 3600000
auto_signer_key = "/var/lib/tenkai/prod-auto-approver.ed25519"

[require_preflight]
max_age_ms = 86400000             # one day
```

Before executing a plan, human or automatic, Tenkai checks the stored
preflight. Execution and approval are refused when it is missing, failed,
older than `max_age_ms`, from the future, signed by a key outside the
`preflight` scope for this environment, or has a signature that does not
verify. The error names the failed checks. Execution is also refused when
an environment's configured policy file is missing, because Tenkai cannot
tell whether it required a preflight. Policies without `require_preflight`
behave as before.

## Keep time synchronized after install

Preflight checks the clock once. Signatures, plan approvals and leases need
a correct clock for as long as the host runs: tokens allow 60 seconds of
skew, approvals and bundles carry validity intervals, and leases expire by
wall-clock time. Run a time-sync daemon against a time source inside the
site, and keep every Tenkai host within one second of it.

`tenkai-server` checks this at runtime when `TENKAI_TIME_SOURCE` names that
SNTP server (`host:port`; a server inside the site, so the check works
offline):

| Skew | Effect |
| --- | --- |
| At most `TENKAI_CLOCK_WARN_MS` (default 1000) | `ok` |
| Above the warn threshold | `warn` in `/healthz` and `/readyz` and the server log |
| Above `TENKAI_CLOCK_REFUSE_MS` (default 30000) | `refuse`: plan approvals, every new environment lease (applies from reconcile or the API, configuration changes) and runtime lease claims are refused until the clock is back in range; API calls get `503` |

The server measures every `TENKAI_CLOCK_CHECK_SECS` (default 60) and reports
the reading as `clock` in health. A failed measurement reports `unknown`.
It does not start refusing, because an unreachable time server is not
evidence of drift, but it never lifts a refusal either: that takes a good
reading. Readiness stays up in every state, because reads, plans and
in-flight work are unaffected. Renewal of a lease already held continues, so
running applies are not cut off mid-step. Signing happens in `tenkaictl` and
external signers; check those hosts with preflight.
