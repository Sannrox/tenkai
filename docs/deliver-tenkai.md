# Deliver Tenkai with Tenkai

Tenkai publishes its own control-plane host, including the web console the
`ui`-enabled binary serves at `/ui/`, as the signed software product
`tenkai-server`. Channels, approvals, health probes, soak, recall, and
rollback are the same as for any other product.

The coordinating server will not apply `tenkai-server` itself: replacing the
process that is executing the plan is refused, and the environment fence is
released. Deliver the product through an environment runtime (a second hub),
or upgrade the coordinating host in place with
[`tenkaictl self-upgrade`](release-binaries.md#upgrade-a-server-host).

## Pack a catalog release

GitHub Release hosts stay the artifact source. Pack them into a catalog
manifest, sign with the site's publication key, and publish:

```bash
bash scripts/pack-tenkai-release.sh \
  --hosts-dir ./tenkai-hosts/linux-x86_64 \
  --version X.Y.Z \
  --out ./tenkai-server-X.Y.Z
tenkaictl release render ./tenkai-server-X.Y.Z/tenkai.toml --version X.Y.Z
# Sign tenkai.toml with the production signer; see release-signing.md.
tenkaictl publish ./tenkai-server-X.Y.Z/tenkai.toml \
  --signature tenkai.sig.json \
  --trust-roots /etc/tenkai/release-trust.toml
```

The packed inputs are `tenkai-server`, `tenkai-executor-guard`, `tenkaictl`,
and the staging scripts from [`examples/tenkai-server`](../examples/tenkai-server/).
Lab signing stays `tenkaictl dev sign-release`.

## Promote, soak, and apply

```bash
tenkaictl promote tenkai-server@X.Y.Z candidate
tenkaictl channel policy tenkai-server stable \
  --from candidate --soak 1h --recall-on-failing
tenkaictl env subscribe <env> tenkai-server=candidate
tenkaictl plan --env <env>
# Apply needs a signed approval of that exact plan; see plan-approval.md.
```

`<env>` must be runtime-managed. A local apply on the coordinating server
prints `refusing to apply tenkai-server on the coordinating server` and does
not leave the environment fenced.

After soak evidence holds, the reconciler promotes `candidate` to `stable`.
A failing soak with `--recall-on-failing` recalls the soaking source so it
cannot be planned again.

Point the second hub's unit at the staged
`$HOME/tenkai-hubs/<instance>/current/tenkai-server` with its own database,
tokens, and listen address. Health in the example proves the staged binary
and version; once the unit is up, replace `health.sh` with probes of
`/readyz` and `/ui/` and publish a new version.

## Upgrade and roll back

A new packed version follows the same publish → promote → plan → apply path.
If the new release's health probe fails, the runtime restores the previous
pin through that plan. `tenkaictl rollback tenkai-server` plans the previous
release the same way.

Recall a bad build by hand:

```bash
tenkaictl release recall tenkai-server@X.Y.Z
```

Planning then fails closed until another release is promoted.

## Coordinating host

`tenkaictl self-upgrade` remains the in-place swap of the host that is
running the plan: store check, backup, switch, readiness, and rollback.
See [upgrade a server host](release-binaries.md#upgrade-a-server-host).

## Drill

```bash
bash scripts/tenkai-self-delivery-drill.sh
```

The drill records two contracts: the coordinating server refuses `tenkai-server`
without leaving a fence, and a runtime restores the previous pin when a
deliberately bad build fails health, then recall of that build refuses
planning. File findings from a live soak as Issues.

Related: [upgrade and rollback](upgrade-and-rollback.md),
[deploy from GitHub](deploy-from-github.md),
[signed recall notices](recall-notices.md),
[automatic channel promotion](release-trains.md#automatic-channel-promotion).
