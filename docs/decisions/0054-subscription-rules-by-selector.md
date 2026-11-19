# ADR 0054: Subscription rules by selector

- Status: Proposed
- Date: 2026-11-18
- Issue: [#1184](https://github.com/Sannrox/tenkai/issues/1184); §8 added by
  [#1335](https://github.com/Sannrox/tenkai/issues/1335) (2026-11-19, accepted)
- Owner: Tenkai maintainers
- Builds on: [ADR 0044](0044-product-instances-and-dependency-bindings.md),
  [labels and selectors](../manage-environments.md#labels-and-selectors),
  [config presets](../manage-environments.md#presets)
- Related: [plan approval](../plan-approval.md),
  [rollout waves](../rollout-waves.md)

## Context

To bring up an environment, an operator registers it and then runs one
`env subscribe <env> <product>=<channel>` per product. Nothing records that
a group of environments is meant to run the same products. The fiftieth
environment is built from a runbook. Adding a product to every site of one
kind takes one command per environment.

What Tenkai already has:

- **Labels and selectors.** An environment carries labels with provenance.
  A selector is resolved when a command uses it, and the command records
  the selector and the names it resolved to. A later label change never
  rewrites that record.
- **Presets.** A release declares named config presets. An environment
  selects one per product, and its overrides sit on top.
- **Subscriptions.** A subscription is a direct write keyed by instance.
  It changes nothing that is running: the next plan proposes the install
  and plan approval admits it. `env unsubscribe` removes an instance under
  the environment's apply lease.

Three options were considered:

1. **Subscription rules.** A record binds a label selector to
   `product=channel`.
2. **Environment templates.** A document of products, channels and config,
   applied as one change and re-applied when it changes.
3. **Neither.** Keep imperative subscribe and document a script.

Option 2 adds a document format, a renderer and a drift model for what
labels and presets already provide. Option 3 leaves the fleet's intent in
runbooks, where nothing can report drift from it.

## Decision

Option 1. A subscription rule is one new record, and it only proposes. Its
effects go through the existing plan and approval path.

### 1. The record

A rule has:

- a name (an identifier, unique in the fleet);
- a selector;
- `product=channel`;
- an optional instance name, which defaults to the product;
- an optional preset;
- a version, plus the actor, reason and time of each write.

Each create, edit and delete bumps the version and appends a change record,
like a label change. Product and instance are the rule's identity: an edit
may change the selector, channel and preset, and a different product or
instance needs a new rule. Editing a rule writes a new version and never rewrites
plans built from an older one. The record is an operational catalog record
of a new ontology kind. It is not recovery material for any environment: a
deleted or lost rule leaves every subscription and deployment as it was.

### 2. Resolution is recorded per plan, not continuously

Nothing watches labels and writes subscriptions. A rule is resolved when a
plan is computed for an environment, and that is the only place a rule takes
effect:

- If the environment matches the rule and has no subscription for the
  rule's instance, the plan proposes that subscription. The plan records the
  rule's name, version, selector, and the environment's labels that
  satisfied it.
- That record is a plan input inside the content address. Approval
  therefore binds to it, and a label change or a rule edit after approval
  makes the plan stale like any other input change.
- Applying the plan writes the subscription with provenance (rule name and
  version) as its first effect, under the apply lease and before the
  install step. A crash before that write leaves no subscription, and the
  next plan proposes it again. A crash after it leaves an ordinary
  subscription, and the next plan installs it.

`rule status <name>` resolves the rule at read time. It lists:

- matching environments with no subscription yet;
- subscriptions the rule wrote;
- subscriptions that no longer match;
- environments where an explicit subscription takes precedence.

This is a report, not a record. The plan records are the history.

### 3. Removal never follows a rule

When a rule is deleted, or an environment stops matching, Tenkai changes
nothing. Each subscription that rule wrote is reported as
`rule no longer matches` (or `rule deleted`) in `rule status`, `env inspect`
and `status`. Removal stays the existing explicit `env unsubscribe`, which
takes the apply lease and is audited. A rule never proposes a removal step.

`env unsubscribe` on a subscription a rule wrote records the environment's
exclusion from that rule (§4) in the same write. Otherwise the next plan on
a still-matching environment would propose the instance again, and an
unattended approval policy could reinstall it. Subscribing again, or
clearing the exclusion, undoes it.

Editing a rule's channel or preset proposes the change in the next plan for
each environment that matches and still holds a subscription written by the
rule. That plan is approved like any channel change. An environment that no
longer matches keeps the old channel.

### 4. Explicit subscriptions take precedence

For one environment and instance:

- An explicit `env subscribe` always wins. A rule never proposes a change to
  an instance the operator subscribed explicitly, and `rule status` reports
  it as `explicit`.
- Running `env subscribe` on an instance the rule subscribed converts it to
  explicit. From then on, the rule no longer edits it.
- If two rules match one environment for the same instance, planning
  refuses and names both rules. Tenkai never picks one by name, order or
  version.
- An environment can opt out of one rule with `env rule exclude <env>
  <rule>`. This is a reasoned property on the environment, so the
  operator does not need to change labels.

Existing subscriptions carry no provenance and read as explicit, so they are
unchanged.

### 5. Approval

A rule write needs a fleet management credential, a reason, and the current
rule version. An environment-scoped credential and agents are refused. The
write changes nothing that is running.

Each environment's plan is approved under that environment's own approval
policy, as today. The approval brief names the rule and version behind each
proposed subscription. An unattended approval policy admits a rule-proposed
install only if it would admit the same install from an explicit
subscription. A rule widens nothing.

### 6. Instances and bindings

- A rule names one instance. Planning refuses the rule's subscription for
  an environment where that instance name is held by another product, or
  where the release allows one instance and a differently named instance of
  the same product exists (ADR 0044 §2). It reports the reason in
  `rule status`.
- A rule does not create bindings. A requirement with several candidate
  providers stays unmet until the environment owner binds it, exactly as for
  an explicit subscription (ADR 0044 §3).
- The same holds for a provider a dependent needs and the environment lacks.
  Several rules can together give a class of environments a product and its
  provider. Plan order still installs the provider first.

### 7. Config comes from presets

A rule may name a preset. It is selected only when the environment has no
preset for that product. Presets are selected per product, so a rule for a
second instance shares the product's selection and `rule status` reports
when that selection differs from the rule's preset. An environment's own preset selection and its
overrides take precedence and are reported, like an explicit subscription.
A rule never writes overrides. A rule's preset must exist in the channel
head when the rule is written, and planning refuses a candidate that drops
it, as for any selected preset.

### 8. Promotion targets and wave cohorts reuse rules

Added for [#1335](https://github.com/Sannrox/tenkai/issues/1335). A
subscription rule is the one record that says which environments receive a
product's channel. Nothing else stores a selector for that purpose.

- **Promotion targets.** A channel promotion policy moves the head of its
  target channel. It gains no environment selector of its own. The
  environments a promotion reaches are the environments subscribed to the
  target channel: explicit subscriptions plus those written by rules for
  that product and channel. `GET` on the channel's promotion policy reports
  those rules by name and version, and each rule's `rule status` reports
  its environments.
- **Changing the targets.** Adding, editing or deleting a rule for the
  target channel is the only way a selector changes where promotions land.
  That write follows §5, and every subscription it causes goes through each
  environment's plan approval, as in §2. A policy edit never changes which
  environments a promotion reaches.
- **Wave cohorts.** `wave run` and `wave execute` accept `--cohort-rule
  <name>` beside `--cohort`. The wave resolves that rule's selector once, at
  start, exactly as a selector cohort resolves today (see
  [rollout waves](../rollout-waves.md)). It stores the concrete environment
  names together with the rule's name, version and selector as provenance.
  A later rule edit or label change does not rewrite a wave, and the rule is
  not part of the wave identity. No separate cohort record exists.

Rejected for §8:

- **A selector on the promotion policy.** It would be a second answer to
  "which environments get this release", and it could disagree with
  subscriptions. A label write would then change delivery scope with no
  plan in between.
- **A stored cohort record.** It would hold the same selector as a rule
  under a different name and would need its own versioning and audit.

## Out of scope

- Environment templates, and rules that set overrides, secrets, bindings,
  holds or approval policy.
- Automatic removal on deletion or non-match.
- Rule precedence, priorities or weights.
- Reconcile writing subscriptions without a plan.
- Waves that keep resolving a rule after they start.

## Compatibility

- Explicit subscriptions and existing plans are unchanged.
- The new record kind, the provenance on subscriptions and the new plan
  input are a stored-format change. During a rolling upgrade, an older
  server cannot read a plan that carries a rule input. Rule writes are
  refused until every server reads the new format. The same gate is used
  for a second instance (ADR 0044, Consequences).
- Embedded and server hosts resolve rules in the same planning code.

## Consequences

- One command states what a class of environments runs. A new matching
  environment gets the products on its first plan.
- Fleet intent becomes visible: `rule status` shows drift in both
  directions without acting on it.
- An operator who expects labels to remove products must run
  `env unsubscribe`. This is deliberate.

## Revisit if

Operators routinely edit labels only to make a rule stop matching. If so,
the per-environment exclusion is not enough. Either rules need a negative
clause, or exclusion should move into the selector.
