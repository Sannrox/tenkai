# ADR 0045: Sealed secrets delivered by the environment runtime

- Status: Proposed
- Date: 2026-11-06
- Issue: [#1020](https://github.com/Sannrox/tenkai/issues/1020)
- Owner: Tenkai maintainers
- Amends: [ADR 0016](0016-same-version-remediation.md) (no secret storage)
- Related: [ADR 0044](0044-product-instances-and-dependency-bindings.md),
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

## Decision

### 1. Values are sealed to the environment's runtimes

Each environment runtime instance holds a sealing key pair, separate from its
runner credential. The private key never leaves the runtime. The runtime sends
its public key at enrollment and at certificate renewal, and the server records
it against that runtime instance, so the key is bound to an admitted runner.
An environment that requires a hardware-backed runner key (#675) requires one
for the sealing key too.

A sealed value is one ciphertext encrypted under a random data key, plus one
wrap of that data key for each enrolled runtime's public key. The server
stores the ciphertext and the wraps, never the data key or the value.

### 2. Operators set values from the client

```text
tenkaictl secret set <env> <instance> <secret>/<key>
```

The client reads the value from standard input, never from an argument or an
environment variable it would echo. It fetches the environment's runtime public
keys, seals the value locally, and submits only the sealed form. `secret list`
shows names, keys, the sealed digest, who set it and when. `secret delete`
removes a key. There is no command that returns a value.

A secret belongs to an instance (ADR 0044) and is named the way the target
names it: a Kubernetes Secret name and key, or a host file name.

### 3. A change is a plan

Setting or deleting a sealed key does not touch the target. It changes the
environment's desired configuration, and the next plan carries it like an
overlay change:

- The configuration digest covers the digest of each ciphertext, not the
  wraps. Rotation therefore changes the digest and produces the same-version
  restart that an overlay change does (ADR 0016), while re-wrapping for a new
  runtime (section 5) changes nothing.
- The plan names the instance, secret and key that change, and goes through
  the environment's approval policy and evidence binding.
- Deleting a key that a release declares it reads (#1019) is refused, naming
  the release, unless the same key is present in the target by other means.

### 4. The runtime opens and writes at apply

At apply, the claiming runtime unwraps the data key with its own private key,
decrypts the value, and writes it to the target:

- **Kubernetes:** a Secret in the instance's namespace, labelled as Tenkai
  owned, created or replaced in one write. The instance's workloads carry the
  sealed digest as a pod template annotation, so a rotation rolls them.
- **Host:** a file written to a temporary path and renamed into place, mode
  0600, owned by the release's user.

The plain value exists only in the runtime's memory and in the target. It
never appears in a completion, receipt, log line, support bundle, evidence
record or error. Writing is idempotent: a retry after a crash writes the same
value again. The apply is recorded only once the write has succeeded, so a
crash between the two is a retry, not a partial secret.

A runtime that has no wrap for a value it must write refuses the step with a
named, retryable reason. It never applies the rest of the release without it.

### 5. New runtimes are re-wrapped by existing ones

A runtime enrolled after a value was sealed cannot open it. Any runtime of the
same environment that can open it re-wraps the data key for the new runtime's
public key and submits only the new wrap. Re-wrapping does not change the
ciphertext or the configuration digest. A runtime that is retired or revoked
loses its wraps, and its key is no longer offered to clients.

If no runtime that can open a value is left, the value is lost to Tenkai. The
operator sets it again, and the plan says which keys need that.

### 6. Hand-made secrets keep working

A release that declares a secret key (#1019) is satisfied either by a sealed
value or by a key already present in the target. Tenkai never overwrites a
Secret or file it does not own. An environment with no sealed secrets behaves
as today.

## Out of scope

- External secret stores. A later adapter can resolve a reference at apply
  in the same place a sealed value is written.
- Secrets shared across environments, or set per tenant.
- Generated secrets, such as a database password Tenkai creates on first
  install.
- An in-process executor with no separate runtime. There the private key sits
  on the server's host, so sealing protects the store, backups and the API,
  but not the host. The documentation must say so.

## Consequences

- Secret changes become approved, audited plans, and rotation restarts what
  reads the key.
- Backups of the store contain only ciphertext. Restoring the store without at
  least one surviving runtime key restores names and history but no values.
- Losing every runtime of an environment loses its sealed values. That is the
  price of a server that cannot read them.
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
- **Only an external secret store.** Rejected as the only path: it moves the
  approval and rotation gaps into another system and does not help a single
  host install. It stays possible as an adapter.
- **Keep hand-made secrets only.** Rejected as the end state for the reasons
  above. It stays supported.
