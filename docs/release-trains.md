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
  component without one is refused;
- members' required contracts satisfied by a matching `provides` on some
  member of the train, using the requiring profile's matching rule (v2 0.y
  minor match; v1 same-major). The refusal names the member and the contract.
  Optional requirements never block admission. Environment observations for
  providers Tenkai does not install are not consulted here.

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

## Automatic channel promotion

Declare a policy so the reconciler promotes a source channel head onto a
target after soak and evidence hold. The promotion is the same guarded
write as `tenkaictl promote`; the record names the policy id and version as
the actor.

```sh
tenkaictl channel policy api stable --from candidate --soak 24h --require-canary
tenkaictl channel policy api stable --pause
tenkaictl channel policy api stable --resume
```

`--soak` is milliseconds with `ms`/`s`/`m`/`h`, or seconds when bare.
`--require-canary`, `--require-health-slo`, and `--require-evaluation` opt
into those evidence kinds. Instance health is always required: an instance
with no health evidence waits, and `fleet status` names it. The policy
never promotes on elapsed time alone. Time with every replica healthy, and
time with any replica failing, are shares of the soak; a failing instance
resets the clock. Soak resets appear as `promotion_soak_reset` in the
change-event stream.

Gate flags on a train still refuse automatic promotion; `--approve-gates`
stays a human action. Pause is durable and does not delete soak state.
`channel policy` runs with `--target embedded`. A replica that does not
advertise `channel_promotion_policy` does not evaluate policies; stored
policies stay inert.
