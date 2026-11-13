# Find why a deploy is blocked

Goal: name the checks that currently refuse the next change for one instance, and the next valid action.

```sh
tenkaictl --output json-v1 status --env prod
tenkaictl --output json-v1 explain prod api
tenkaictl --output json-v1 env inspect prod
```

`explain` lists every live gate for that instance. On success, json-v1 prints the explain report JSON (not the generic envelope). A failure still uses an `explain` envelope. `reason.code` is a closed list; map an unknown code to `domain_denied`. `reason.next` names the next action and its actor.

Typical blockers:

- missing, stale, or invalid signed release or plan approval
- maintenance window closed
- environment or channel hold
- agent actor on a mutation other than plan (`agent_budget`)
- stale fencing generation
- failed target held after automatic rollback until `env retry`

Do not apply, approve, or skip gates to "see if it works". Re-plan after desired state or evidence changes.

Contract detail: [command results](../command-results.md), [manage environments](../manage-environments.md).
