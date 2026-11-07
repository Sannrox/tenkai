# ADR 0044: Product instances and dependency bindings

- Status: Accepted
- Date: 2026-11-06
- Issue: [#1003](https://github.com/Sannrox/tenkai/issues/1003)
- Owner: Tenkai maintainers
- Builds on: [ADR 0043](0043-product-dependencies.md)

## Context

ADR 0043 lets a release depend on a contract that another deployed release
provides. It refuses a contract with two providers as ambiguous. That covers
a shared provider, but not a private one.

A private datastore is the common case: two products each need their own
database, at the same contract, with the same image. Today each product
copies the database's workloads into its own release. A database patch then
waits for both dependents to release, and an install with a managed
database has to switch it off in each product's configuration.

The database cannot become its own product yet, for two reasons:

- **One release per product.** An environment holds at most one release of
  each product. Status, subscriptions, plans and retries are keyed by product
  name. Two databases would need two product names for the same software.
- **No binding.** With two providers of one contract in an environment,
  nothing says which dependent uses which.

## Decision

### 1. An environment holds named instances

An environment's deployed set is keyed by instance, not by product. An
instance has a name, a product and a channel subscription or pinned
version. Deployment records, subscriptions, plan steps, holds, retries and
status name the instance.

An instance that is not named explicitly is named after its product. Every
existing environment therefore keeps its meaning: each product it holds
becomes one instance with the product's name, and existing commands that
take a product keep working.

An instance name is a DNS label of at most 40 characters, unique within its
environment.

### 2. A release opts in to more than one instance

Two copies of the same release would collide on names they create: units,
containers, Kubernetes objects. Tenkai does not rewrite them. A release that
can run more than once in one environment declares it:

```toml
[deploy]
instances = "many"   # default "one"
```

Tenkai refuses a second instance of a release that declares `"one"`, at
planning, naming both instances.

Tenkai gives every deploy the instance name:

- Deploy commands receive `TENKAI_INSTANCE`. `COMPOSE_PROJECT_NAME` and the
  other per-product derived names become per instance.
- In-cluster manifest releases get one documented placeholder for the
  instance name, substituted at apply and nowhere else, and every object is
  labelled with the instance.

### 3. A dependent binds a requirement to an instance

A required or optional contract (ADR 0043 §1) is satisfied as follows:

- **One provider** in the environment satisfies it without a binding.
- **Several providers** need a binding: durable environment configuration
  that says which provider instance satisfies which contract for which
  dependent instance.

```text
tenkaictl env bind <env> <dependent-instance> <contract>=<provider-instance>
```

A binding is part of the environment configuration digest, so it is covered
by plan approval and evidence binding like any other configuration. Binding
to an instance that does not provide the contract is refused. A binding
also selects between a deployed provider and a recorded observation, which
ADR 0043 §2 otherwise refuses as ambiguous.

An unbound requirement with several providers is treated as unmet: a
reconcile holds and names the candidates (ADR 0043 §4), and an explicit plan
refuses. Tenkai never picks a provider by name, order or version.

Removing, rolling back or upgrading a bound provider is protected as in
ADR 0043 §5. Removing a binding whose dependent still needs it is refused
in the same way.

### 4. The dependency document names the instance

The dependency document (ADR 0043 §6) names the provider instance for each
contract. When a binding changes, the dependent is re-rendered as when its
provider changes.

### 5. Sharing stays the product's choice

Whether two dependents share one provider instance or each get their own is
the environment owner's choice, expressed with instances and bindings. A
provider that serves several dependents from one instance (for example one
database server with a database per dependent) needs nothing more from
Tenkai.

## Out of scope

- Generating instances from a template, per tenant or per dependent.
- Bindings across environments.
- Endpoint and credential discovery. The dependency document still carries
  neither.

## Consequences

- A private datastore becomes its own product with its own release cadence.
  Its dependents bind to their own instance, and an install with a managed
  datastore binds to an observation instead.
- The store schema keys deployments, subscriptions and holds by instance.
  The migration names each existing record's instance after its product.
  During a rolling server upgrade both versions read a store with only
  default-named instances; create a second instance or a binding only once
  every server reads the new schema. The HTTP API adds the instance as an
  optional field that defaults to the product.
- A release that has not declared `instances = "many"` behaves as today.

## Alternatives considered

- **Groups instead of bindings.** Put providers and dependents in named
  groups and match within a group. Rejected: it adds a second naming layer
  to get the same edges, and it makes a missed group look satisfied by the
  wrong provider. A binding is one explicit edge per requirement.
- **Distinct product names per copy.** Publish the same software as
  `database-a` and `database-b`. Rejected: one product, two names, two
  release streams, and a patch released twice.
- **Keep bundling private datastores.** Rejected as the default for the
  reasons in ADR 0043 §8. Existing bundles keep working.
- **Tenkai renames objects itself.** Rejected: rewriting another product's
  manifests is guesswork. The release declares that it can run more than
  once and uses the instance name.
