---
name: assess-change-impact
description: Assess a proposed or implemented tenkai change across product, trust, protocol, ontology, execution, and operations boundaries. Use when scoping an Issue, planning tests, reviewing a diff, or identifying migration, documentation, compatibility, and security obligations.
---

# Assess Change Impact

Build an evidence-backed impact map before implementation or review.

## Procedure

1. Read the linked Issue or request, `README.md`, `DESIGN.md`, and
   the relevant code. For a diff, inspect every changed file and its direct
   callers or implementors. Complete when the claimed outcome and actual change
   surface are both known.
2. Trace applicable boundaries:
   - immutable catalog facts versus mutable environment and deployment state;
   - planning and canary evidence versus apply, rollback, and reconciliation;
   - local execution versus the planned agent and disconnected execution paths;
   - tenkai ontology records versus vendored sekai-chisei protocol contracts;
   - signing, approval, namespace authorization, audit, lineage, gates, and
     secrets;
   - public `proto/`, manifest, CLI, configuration, status, and operator
     behavior.
   Complete when each applicable boundary has an owner and expected invariant.
3. Identify persistence and compatibility obligations. Include fresh and
   upgraded graph records and runtime state, audit coupling, old
   clients/manifests, error semantics, and rollback or recovery impact where
   relevant. Complete when data-loss and partial-failure paths are accounted for.
4. Map evidence to risk: unit tests for pure logic; integration tests for
   public/multi-component behavior; fixtures for protocol and graph contracts;
   deterministic CLI or local sekai-chisei integration checks where practical;
   ignored live tests only when a real service is essential. Complete when every
   material risk has a proposed check or an explicit residual uncertainty.
5. Determine durable artifacts that must change: docs, examples,
   protocol notes, an ADR, or a repository Skill. Complete when no artifact is
   proposed merely to record temporary planning.

## Output

Return a compact matrix with columns:

| Surface | Evidence found | Required change/check | Risk if missed |
| --- | --- | --- | --- |

Then list scope boundaries, blocking questions, and the smallest safe PR split.
Do not approve an architecture, perform a full security audit, or claim backend
parity without inspecting the implementations.
