---
name: shape-work-item
description: Shape a raw tenkai idea, bug report, refactoring proposal, or research question into a focused GitHub Issue. Use when work needs scope, acceptance evidence, risk routing, or a repository-consistent Issue draft before implementation.
---

# Shape Work Item

Turn intent into a decision-ready unit of work. Produce a draft unless the user
explicitly authorizes publishing to GitHub.

## Procedure

1. Read `README.md`, `DESIGN.md`, repository instructions supplied by the
   environment, and representative live Issues for the maintained body format.
   Inspect affected code or docs when named. Complete when the request is framed
   against actual project boundaries and current Issue conventions.
2. Search open and closed Issues, Discussions, and PRs when GitHub access is
   available. Record possible duplicates or state that the search was not run.
   Complete when overlapping work is linked or ruled out.
3. Classify the work:
   - `bug`: reproducible expected-versus-actual behavior;
   - `feature`: a new observable operator or integration outcome;
   - `refactor`: preserved behavior with concrete structural evidence; or
   - `research`: a time-boxed question that ends in a decision.
   Route sensitive or exploitable behavior through a private maintainer report
   or GitHub security advisory rather than a public Issue. Route cross-boundary,
   public-contract, trust-model, or difficult-to-reverse choices to a Design
   Discussion before implementation. Complete when exactly one primary route
   is selected and exceptions are explained.
4. Draft the work item with a problem statement, observable outcome, non-goals,
   acceptance evidence, affected boundary, and compatibility/security/data
   risks. Preserve uncertainty as an explicit question. Complete when another
   contributor can tell what success means without reconstructing the prompt.
5. Recommend one type label, one status label, relevant area/risk labels, and
   whether a milestone is justified. Do not invent priority, assignment, or a
   milestone. Complete when every recommended label describes supplied
   evidence.

## Output

Return:

1. route and rationale;
2. possible duplicates or search limitation;
3. issue title and body using the repository's problem, observable outcome,
   acceptance evidence, non-goals, dependencies, and impact sections;
4. recommended labels; and
5. unresolved questions that prevent `status:ready`.

Keep implementation design out of the Issue unless it is a validated
constraint. Do not publish, assign, close, or prioritize GitHub work without
explicit authorization.
