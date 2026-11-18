# ADR 0053: Network policy derived from dependency bindings

- Status: Proposed
- Date: 2026-11-18
- Issue: [#1079](https://github.com/Sannrox/tenkai/issues/1079)
- Owner: Tenkai maintainers
- Builds on: [ADR 0043](0043-product-dependencies.md),
  [ADR 0044](0044-product-instances-and-dependency-bindings.md),
  [ADR 0046](0046-workload-identity-and-peer-policy.md)
- Related: [ADR 0016](0016-same-version-remediation.md),
  [software executor](../software-executor.md),
  [manage environments](../manage-environments.md)

## Context

Bindings already say which instances may call each other (ADR 0046 §5), and
the dependency document hands each instance its allowed peers. Only a
product that terminates TLS and checks peer identities enforces that. A
product that does not is reachable from every pod in the cluster, and even
one that does still accepts the connection before refusing it. ADR 0046
left network policy to a later decision.

What Tenkai knows and does not know today:

- **Edges.** It knows the edges: for each provider instance and contract,
  the dependent instances bound to it.
- **Ports.** It does not know ports. Contracts carry versions, not
  endpoints (ADR 0043 §6), and discovery stays with the products.
- **Pod labels.** It does not label pods. `kubectl` and in-process releases
  get `tenkai.product` and `tenkai.instance` on their top-level objects
  after apply. Helm releases get the same names as values. Pod templates are
  the release's own.
- **Objects it owns.** It already writes objects of its own next to a
  release: the dependency ConfigMap `tenkai-dependencies-<instance>` for
  `kubectl` and in-process apply, and the identity Secret
  `<instance>-tenkai-identity` for every Kubernetes executor.
- **Policy objects.** In-process apply already admits `NetworkPolicy`
  (`networking.k8s.io/v1`).

A Kubernetes NetworkPolicy has two properties that shape this design:

- As soon as one policy selects a pod for ingress, every source no policy
  names is denied.
- The API server accepts policies whether or not the cluster's network
  plugin enforces them.

## Decision

### 1. Ingress only, for provider instances that opt in

Tenkai derives one ingress policy per provider instance whose release opts
in. It derives no egress policy: denying egress cuts DNS, registries and
external services that the graph does not describe, and the provider's
ingress policy already closes every edge the graph does not grant.

A release opts in through its signed manifest, naming the ports of each
contract it provides and the pod label its pods carry:

```toml
[deploy.network]
# The release's pods carry tenkai.instance = <instance>.
pods = "instance-label"

[deploy.network.ports]
"platform.customer-api" = [{ port = 8443, protocol = "TCP" }]
"platform.metrics" = [{ port = 9090, protocol = "TCP", from = "any" }]
```

Port rules:

- A contract the release provides with no ports entry gets no rule, so its
  callers are denied once the policy exists. Planning refuses that with the
  contract's name. A release that wants a contract open says `from = "any"`
  on its ports. `"any"` is the only escape: it admits every source on that
  port and is shown in the plan.
- A release without `[deploy.network]` gets no policy, and nothing changes
  for it.

### 2. A binding allows the edge, nothing else

For provider instance P, the policy `tenkai-peers-<P>` in the environment
namespace:

- selects pods labelled `tenkai.instance = P`;
- admits pods labelled `tenkai.instance = P` on every port, so replicas and
  components of one instance keep talking to each other on ports no contract
  names;
- for each contract, admits pods labelled `tenkai.instance = D` on that
  contract's ports, for every dependent D bound to P, or satisfied by P as
  the only provider (ADR 0044 §3);
- admits nothing else from outside the instance, apart from ports marked
  `from = "any"`.

This is the same edge set as the peer grants, from the same bindings, at the
same point in planning. A withdrawn binding withdraws the rule in the same
plan, with the grant's exception (ADR 0046 §5): a provider keeps admitting a
caller that was rebound away until that caller's own step has moved it, and
the next plan withdraws the stale rule.

### 3. The policy is plan content, rendered like the dependency document

The policy is part of the signed plan, not computed at apply.

- **In the plan.** The dependency document of each opted-in provider gains
  its derived ingress rules: dependent instances and ports per contract. An
  opted-in provider with no requirements of its own gets a dependency
  document for that purpose. A
  server therefore cannot add a source the approved bindings and the signed
  release do not contain. A binding change that changes a provider's rules
  re-renders that provider in the same plan, as a same-version remediation
  (ADR 0016), and an approver sees the change.
- **Ownership.** The executor writes `tenkai-peers-<P>` in the environment
  namespace, owned and labelled by Tenkai, with one replace per apply.
- **Executors.**
  - The Helm executor writes it as it already writes the Tenkai-owned
    identity Secret next to a chart (ADR 0046 §4), and never over an object
    it does not own.
  - `kubectl` apply writes it next to the dependency ConfigMap.
  - In-process apply uses its existing `NetworkPolicy` support.
- **Removal.** Removing the instance removes the policy with Tenkai's other
  objects for it.

### 4. Rollout allows before it denies

A new policy denies at once, so ordering is the whole rollout safety:

- **Plan order.** Plan order follows the dependency graph (ADR 0043 §3), so
  a provider's step runs before its dependents' steps. The rule for a new or
  rebound dependent is written in the provider's step, so the edge is open
  before the caller's step runs.
- **Labels before the rule.** A dependent's pods must already carry
  `tenkai.instance` when the provider's step admits them, because its own
  step runs later. Planning refuses a plan that admits a dependent whose
  label arrives only with that dependent's step in the same plan. The fix is
  to deploy the label first, in an earlier plan.
- **Labels are checked on every write.** Each write of a policy that adds a
  source, not only the first, is refused at apply when the provider's own
  pods, or the running pods of any source it adds, do not carry
  `tenkai.instance`. Writing it then would cut a caller. The refusal names
  the instance whose pods lack the label.
- **Per environment.** Enforcement is staged per environment. The
  environment property `network_policy` is `off` (the default) or
  `enforce`, and an operator turns it on in one environment at a time,
  following the channel's promotion order. Turning it on plans a
  re-render of every opted-in provider. Turning it off plans the removal of
  every `tenkai-peers-*` policy. Both are ordinary approved plans.

### 5. Enforcement is declared, not assumed

Tenkai cannot tell from the API whether the network plugin enforces
policies.

- **What `enforce` means.** Setting `network_policy = "enforce"` is the
  operator's statement that the cluster's plugin enforces `NetworkPolicy`.
- **What status shows.** Status shows each environment as "policies
  written, enforcement declared, not verified". It never shows "enforced".
- **Without a plugin.** A cluster with no enforcing plugin keeps `off`.
  Its products still rely on peer identities (ADR 0046 §6).

### 6. Host and container targets get no network policy

Host releases and Docker releases have no Tenkai network policy:

- Host firewalls belong to the host's own configuration. A Docker network
  is not a pod network that a Kubernetes policy selects.
- An opted-in provider whose bound caller is not a pod in the environment
  namespace cannot admit that caller by label. Planning refuses the plan and
  names the caller, rather than writing a policy that cuts it. The provider
  then declares `from = "any"` for that contract or keeps `off`.
- A host or Docker release that declares `[deploy.network]` is refused at
  planning.

### 7. What Tenkai does not do

- **No traffic handling.** No proxy, sidecar, mesh, or traffic rewriting.
- **No egress policy.**
- **No other policy sources:** no host firewall rules, no plugin-specific
  policy kinds, and no policy across namespaces or clusters.
- **No discovery.** Ports come from the signed release, never from
  inspecting Services or containers.

## Kill criteria

Stop and record a no-go if any of these proves true while implementing:

- a supported chart or manifest layout cannot put a Tenkai-chosen label on
  its pods, so `pods = "instance-label"` would exclude it;
- the label check cannot see a source's running pods at apply, so a binding
  change could cut a running caller unnoticed;
- the dependency document cannot carry the rules without changing the
  digest of plans for releases that do not opt in.

## Out of scope

- Detecting whether the network plugin enforces policies.
- Egress control, and admitting sources outside the graph other than
  `from = "any"` (ingress controllers, monitoring by namespace).
- Docker networks and host firewalls.

## Consequences

- An opted-in provider is reachable only by its own pods and, on the ports
  it declares, its bound dependents, in environments that turned
  enforcement on.
- A binding change is visible in the plan as a policy change, and is
  approved with it.
- Releases that opt in must label their pods with `tenkai.instance`, and
  must name a port for every contract they provide.
- Enforcement depends on the cluster's plugin, which Tenkai reports as
  declared, not verified.

## Alternatives considered

- **Compute the policy at apply from the live graph.** Rejected: an approver
  would not see it, and a server could widen it after approval.
- **Egress and ingress pairs.** Rejected: egress denial breaks traffic the
  graph does not describe, for no edge the ingress rule leaves open.
- **Read ports from the release's Services.** Rejected: it ties the policy
  to what a render happens to contain, after approval, and fails for
  headless or external ports.
- **Label pods by mutating rendered templates.** Rejected: it changes the
  release's signed content and breaks charts that own their selectors.
- **A policy per edge.** Rejected: many objects per provider, with no gain
  over one policy whose rules are the edge set.

## Follow-up on acceptance

- Manifest section `[deploy.network]`, its validation, and the refusals in
  §1 and §6.
- The rules in the dependency document, their rendering for each
  Kubernetes executor, the label check, and removal with the instance.
- Environment property `network_policy` and the status line.
- Documentation in [software executor](../software-executor.md) and
  [manage environments](../manage-environments.md).
