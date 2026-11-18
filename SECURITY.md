# Security policy

## Report a vulnerability

Report a vulnerability privately through
[GitHub private vulnerability reporting](https://github.com/Sannrox/tenkai/security/advisories/new).
Do not open a public Issue, Pull Request or discussion for it.

Include:

- the affected component (`tenkaictl`, `tenkai-server`, `tenkai-runtime`,
  `tenkai-host-applier`, or another crate) and version or commit;
- what an attacker needs, and what they gain;
- steps or a test that reproduces it.

Leave out credentials, keys and details of your own environment.

## Supported versions

Fixes land on `main` and ship in the next release. Only the latest release
receives security fixes.

## More

The [security overview](docs/security.md) covers how to verify a release
download and the known limits. The [threat model](docs/threat-model.md)
covers what Tenkai defends against whom.
