# Operator commands

Use installed `--help` as the syntax authority. These are the stable operating
patterns in the repository version of Tenkai.

## Select the target

Embedded mode owns local SQLite state:

```sh
tenkaictl --database /path/to/tenkai.db <command>
```

Remote mode requires a server URL and a management token loaded from secret
configuration:

```sh
export TENKAI_MANAGEMENT_TOKEN="<load-from-secret-store>"
TENKAI_SERVER_URL=https://tenkai.example.internal \
  tenkaictl --target remote <command>
```

Remote CLI support can be narrower than embedded support. Do not fall back to
embedded mode when a remote command is unsupported. Never place the management
token in command arguments, logs, or reports.

## Observe

```sh
tenkaictl env list
tenkaictl env inspect <environment>
tenkaictl status --env <environment>
tenkaictl fleet status
tenkaictl inspect
tenkaictl release inspect <product>@<version>
tenkaictl approval inspect <plan-id>
```

Use `inspect` for embedded control-plane totals and `env inspect` for
subscriptions, deployed observations, lease/fence state, and the latest plan.
Use fleet commands for cross-environment posture.

## Publish and promote

```sh
tenkaictl publish <manifest> \
  --signature <release-signature.json> \
  --trust-roots <release-trust.toml>
tenkaictl release verify <product>@<version> \
  --trust-roots <release-trust.toml>
export TENKAI_MANAGEMENT_TOKEN="<load-from-secret-store>"
tenkaictl promote <product>@<version> <channel>
```

Publication creates an immutable release. Republish identical content only to
reconcile an uncertain outcome; changed content requires a new version.

## Configure desired state

```sh
tenkaictl env add <environment> --description "<description>"
tenkaictl env subscribe <environment> <product>=<channel>
tenkaictl env facts list <environment>
tenkaictl env constraints list <environment>
tenkaictl env maintenance list <environment>
```

Consult `tenkaictl env <subcommand> --help` before changing facts,
constraints, maintenance windows, or canary policy. Inspect the environment
again after each configuration mutation.

## Plan and apply

```sh
tenkaictl plan --env <environment>
tenkaictl apply <plan-id> \
  --approval <approval.json> \
  --approval-trust-roots <plan-approvers.toml>
tenkaictl status --env <environment>
tenkaictl env inspect <environment>
```

Plans are stored dry runs over current desired state. Applying an old plan does
not mean applying newly changed desired state. Maintenance-blocked plans do not
resume automatically; rerun the same apply when policy permits.

## Reconcile and roll back

```sh
tenkaictl reconcile --once
tenkaictl rollback <product> --env <environment>
```

Use one-shot reconciliation for a bounded agent operation. Continuous
reconciliation belongs under an operator-managed supervisor. Rollback creates
and executes the normal pinned-release plan path; non-local rollback can stop
at approval-required state and return the plan identifier.

## Machine results

For supported embedded commands, place the global output option before the
subcommand:

```sh
tenkaictl --output json-v1 plan --env <environment>
```

Require `schema = "tenkai.command-result/v1"`. Treat identifiers as opaque.
Reject unknown fields or enum values. Reconcile before retrying when output is
absent, duplicated, malformed, incompatible, or reports an unknown outcome.
