# ADR 0045: Sealed secrets delivered by the environment runtime

- Status: Accepted
- Date: 2026-11-06 (revised 2026-11-07)
- Issue: [#1020](https://github.com/Sannrox/tenkai/issues/1020)
- Owner: Tenkai maintainers
- Amends: [ADR 0016](0016-same-version-remediation.md) (no secret storage)
- Amended by: [ADR 0048](0048-runtime-runs-built-in-executors.md) (§4 writer,
  host file owner and host hand-off)
- Related: [ADR 0037](0037-multi-party-plan-approval.md),
  [ADR 0041](0041-per-release-executor-and-privileged-host-releases.md),
  [ADR 0044](0044-product-instances-and-dependency-bindings.md),
  [#1019](https://github.com/Sannrox/tenkai/issues/1019),
  [runtime protocol v1](../runtime-protocol-v1.md)

## Context

Tenkai stores no secret values (ADR 0016). Every secret a release reads is
made by hand in the target: a Kubernetes Secret applied with `kubectl`, or a
file on the host. That keeps key material out of the store, but:

- **No approval or audit.** A secret change passes through no plan, approval
  or evidence. Nobody can tell from Tenkai who changed a key, or when.
- **Rotation does nothing.** A new value does not change the configuration
  digest, so the workload keeps the old value until someone restarts it.
- **Not reproducible.** Rebuilding an environment means remembering every
  hand-made secret.
- **Late failure.** A missing key shows up as a failed rollout. #1019 adds
  declared secret names and a presence check, but no way to supply a value.

The property worth keeping from ADR 0016 is that the server cannot read a
secret. Not storing values is one way to get it. Storing only values the
server cannot open is another, and it keeps the plan path.

### Threat model

"The server cannot read a secret" must hold against a compromised server, not
only against a stolen store or backup. A compromised server controls what it
sends to clients and runtimes: the public keys it offers, the runtimes it
enrolls, the plans it hands out, and where a plan says to write. Encryption to
a runtime key alone does not stop it from:

1. offering its own key to `secret set` and reading the value;
2. enrolling a runtime of its own and having a real runtime re-wrap every
   value for it;
3. sealing a value it chose, since anyone with a public key can seal;
4. telling a runtime to write one instance's value into another instance's
   target that it controls.

Today the remote runtime trusts the plans the server hands it. Only the host
applier verifies approvals itself (ADR 0041 §2). This decision moves that
check into every runtime that writes sealed values, and closes each of the
four paths above.

## Decision

### 1. Values are sealed to the environment's runtimes

Each environment runtime instance holds a sealing key pair, separate from its
runner credential. The private key never leaves the runtime. The runtime sends
its public key at enrollment and at certificate renewal, and the server records
it against that runtime instance, so the key is bound to an admitted runner.
An environment that requires a hardware-backed runner key (#675) requires one
for the sealing key too.

Sealing uses HPKE (RFC 9180) in base mode with DHKEM(P-256, HKDF-SHA256),
HKDF-SHA256 and AES-256-GCM. P-256 is the curve hardware key stores offer,
which is why the runner key already uses it.

A sealed value is one ciphertext encrypted under a random data key, plus one
wrap of that data key for each recipient: each enrolled runtime's public key,
and the environment's recovery key when one is set (section 7). The server
stores the ciphertext and the wraps, never the data key or the value.

The ciphertext's associated data names exactly where the value may go:
environment, instance, secret name, key, and a format version. A runtime
refuses to write a value into any other target (section 4), so the server
cannot move a value from one instance to another, or between environments.

### 2. Operators set values from the client

```text
tenkaictl secret set <env> <instance> <secret>/<key>
```

The client reads the value from standard input, never from an argument or an
environment variable it would echo. It fetches the environment's recipient
keys, checks them against its pins (below), seals the value locally, and
submits only the sealed form. `secret list` shows names, keys, the sealed
digest, who set it and when. `secret delete` removes a key. There is no
command that returns a value.

**Recipient pins.** The client keeps a per-environment set of trusted
recipient key fingerprints, the way an SSH client keeps host keys. On first
use it shows the fingerprints and asks the operator to accept them. Later it
seals only to pinned keys. A key the server offers that is not pinned is
refused, naming its fingerprint, until the operator accepts it with
`tenkaictl secret trust <env> <fingerprint>`. A runtime prints its sealing key
fingerprint at enrollment, so the operator can compare out of band. A
compromised server therefore cannot get a new value sealed to a key of its
own.

A secret belongs to an instance (ADR 0044). Its secret name is the name the
release declares (#1019). The target name is Tenkai's (section 4), not one the
operator picks.

### 3. A change is a plan

Setting or deleting a sealed key does not touch the target. It changes the
environment's desired configuration, and the next plan carries it like an
overlay change. Any plan for the instance also carries pending sealed
changes, so they ride with the next delivery or restart.

- The configuration digest covers the digest of each ciphertext, including
  its associated data, but not the wraps. Rotation therefore changes the
  digest and produces the same-version restart that an overlay change does
  (ADR 0016), while re-wrapping (section 5) changes nothing.
- A sealed step names the instance, secret, key and ciphertext digest. It is
  covered by the plan digest, so it goes through the environment's approval
  policy and evidence binding like any other step.
- Deleting a key that a release declares it reads (#1019) is refused, naming
  the release, unless the same key is present in the target by other means.

### 4. The runtime verifies, opens and writes at apply

Before it opens anything, the claiming runtime checks the plan itself, as the
host applier does (ADR 0041 §2):

1. It recomputes the plan digest from the plan it received and finds the
   sealed step.
2. It evaluates the plan's approval envelopes (ADR 0037) against an approval
   policy and trust roots it holds locally, outside the server's reach. They
   are installed with the runtime and changed only on the runtime's host. As
   on the host applier, server-side state such as gate skips, requester
   identity and criticality is not trusted, so the policy is evaluated at its
   strictest quorum.
3. It checks that the ciphertext digest matches the step and that the
   associated data names this environment and the step's instance, secret and
   key.

A runtime with no local approval policy refuses every sealed step with a named
reason. A server-forged value or target therefore never reaches the workload:
it would need approvals from keys the server does not hold.

Then it unwraps the data key with its own private key, decrypts the value,
and writes it to the target:

- **Kubernetes:** an immutable Secret in the instance's namespace, named
  `<instance>-<secret>-<digest>`, where `<digest>` is the first 8 hex
  characters of the sealed digest. It is labelled as Tenkai owned. The
  release receives the name as a value (`tenkai.secrets.<secret>.name`), so a
  chart never hard-codes it. A rotation creates a new Secret, and the rollout
  moves pods to it with the new pod template. Old pods keep the old value
  until they are replaced, and a rollback restores the previous name. Once the
  apply is recorded healthy, the runtime deletes Tenkai-owned Secrets of that
  instance and secret other than the current and the previous one, so a
  rollback still finds its Secret.
- **Host:** a file written to a temporary path and renamed into place, mode
  0600, owned by the release's user. The host applier writes it inside its
  existing verified apply (ADR 0041 §2), so the server never holds the plain
  value on disk.

The plain value exists only in the runtime's memory and in the target. It
never appears in a completion, receipt, log line, support bundle, evidence
record or error. Writing is idempotent: the Kubernetes name is
content-addressed, and the host write is a rename, so a retry after a crash
writes the same value again. The apply is recorded only once the write has
succeeded, so a crash between the two is a retry, not a partial secret.

A runtime that has no wrap for a value it must write refuses the step with a
named, retryable reason. It never applies the rest of the release without it.

### 5. New runtimes are re-wrapped through an approved plan

A runtime enrolled after a value was sealed cannot open it. Adding a
recipient is a plan step that names the new runtime's sealing key
fingerprint. The step is approved like any other, so a server cannot add a
recipient on its own.

A runtime of the same environment that can open the value claims the step,
verifies it exactly as in section 4, then re-wraps the data key for the named
key and submits only the new wrap. Re-wrapping does not change the ciphertext
or the configuration digest. When a client accepts the same fingerprint
(section 2), it seals new values to it directly.

A runtime that is retired or revoked loses its wraps, and its key is no
longer offered to clients. Rotating a runtime's sealing key is the same as
enrolling a new runtime and retiring the old one.

If no recipient that can open a value is left, the value is lost to Tenkai
unless a recovery key is set (section 7). The operator sets it again, and the
plan says which keys need that.

### 6. Hand-made secrets keep working

A release that declares a secret key (#1019) is satisfied either by a sealed
value or by a key already present in the target. Tenkai never overwrites a
Secret or file it does not own, and the content-addressed names cannot
collide with a hand-made one. An environment with no sealed secrets behaves
as today.

### 7. An optional offline recovery key

An environment may record a recovery public key. The private half is held by
the operator offline and never given to Tenkai. When it is set, every sealed
value carries a wrap for it too, and the client pins it like a runtime key.

`tenkaictl secret recover <env>` runs on a machine that holds the recovery
private key. It reads the wraps for that key, opens the data keys locally,
and submits re-wraps for a set of pinned runtime keys. It never submits a
value. The recovered wraps still take effect only through the approved
recipient plan of section 5.

Without a recovery key, `secret list` and `env inspect` show that losing every
runtime loses the environment's sealed values.

## Out of scope

- External secret stores. A later adapter can resolve a reference at apply
  in the same place a sealed value is written.
- Secrets shared across environments, or set per tenant.
- Generated secrets, such as a database password the runtime creates on first
  install. They are the expected next step, and fit the same path: the
  runtime generates, seals to every recipient, and submits only the sealed
  form.
- An in-process executor with no separate runtime. There the private key sits
  on the server's host, so sealing protects the store, backups and the API,
  but not the host. The documentation must say so.

## Consequences

- Secret changes become approved, audited plans, and rotation rolls only what
  reads the key, without affecting pods of the previous version.
- A compromised server cannot read, plant or redirect a value. It can still
  withhold or delete them, which a plan or recovery restores.
- Every runtime that writes sealed values needs a local approval policy and
  trust roots. That is new operational setup for remote runtimes, matching
  what host releases already require.
- Charts that read a sealed secret read its name from
  `tenkai.secrets.<secret>.name` instead of a fixed name.
- Backups of the store contain only ciphertext. Restoring the store without at
  least one surviving runtime key, or the recovery key, restores names and
  history but no values.
- Rolling compatibility: runtimes advertise a `sealed_secrets` capability. A
  plan with a sealed step is offered only to runtimes that advertise it. A
  server that predates sealed secrets ignores the stored records and never
  plans them. Set the first sealed value only once every server and runtime of
  the environment understands them.

## Alternatives considered

- **The server holds the key.** Rejected: compromising the server or its
  store would expose every value, which is what ADR 0016 avoids.
- **One shared environment key.** Rejected: it must be distributed to every
  runtime, and revoking one runtime means rotating it everywhere. Per-runtime
  wraps make enrollment and revocation the same as for runner credentials.
- **Trust the server's key directory and plans.** Rejected: it protects only
  the store and backups. A compromised server could swap keys, enroll its own
  runtime, plant values or redirect them.
- **The setter signs each sealed value.** Rejected as the only check: it stops
  planted values, but not a re-wrap for a server-enrolled runtime. Runtime-side
  approval covers both with one mechanism Tenkai already has.
- **Replace a fixed-name Secret in place.** Rejected: running pods see a new
  value before their rollout, so a bad value breaks the current version, and a
  rollback cannot bring the old value back.
- **X25519 keys.** Rejected: hardware key stores generally offer P-256, and
  #675 requires hardware-backed keys in some environments.
- **Only an external secret store.** Rejected as the only path: it moves the
  approval and rotation gaps into another system and does not help a single
  host install. It stays possible as an adapter.
- **Keep hand-made secrets only.** Rejected as the end state for the reasons
  above. It stays supported.
