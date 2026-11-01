# Release trains

A release train is a signed set of component releases that were tested
together, for example `train-2026.11`. Its profile is JSON:

```json
{
  "schema": "tenkai.release-train.v1",
  "name": "train-2026.11",
  "components": [
    {"component": "kako", "version": "0.2.0", "digest": "sha256:<family release manifest digest>"}
  ]
}
```

Admit it into the `candidate` channel:

```sh
tenkaictl train admit train-2026.11.json \
  --signature train.sig.json \
  --trust-roots release-trust.toml
```

Admission requires:

- a release signature from the trust roots whose manifest digest is the
  SHA-256 of the profile file and whose artifact digest is the SHA-256 of the
  sorted `<component> <version> <digest>` lines;
- 1 to 128 distinct components, each a published release
  `<component>@<version>`;
- each release published with a [family release manifest](family-release-manifests.md)
  whose digest equals the listed `digest`, so every member is named by digest;
- each release manifest carrying a `[compatibility]` profile, its matrix. A
  component without one is refused.

Promotion to `stable` is a separate, explicit step:

```sh
tenkaictl train promote train-2026.11
tenkaictl train show train-2026.11
```

Admission records the gate flags (`breaking`, `migration`, `realm`) that any
member release carries. A train with gate flags is refused at promotion unless
the operator approves them, as a flagged release holds a single channel:

```sh
tenkaictl train promote train-2026.11 --approve-gates
```

The approving principal is recorded on the train.

A train is immutable: admitting the same profile again is a no-op, and a
different profile under an admitted name is refused. Promoting a stable train
is a no-op. Admitting and promoting need the management credential, like
`promote`, and run with `--target embedded`.
