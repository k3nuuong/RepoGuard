# RepoGuard ExecPlan Protocol

An ExecPlan is the tracked, self-contained source of truth for a development stage. It must let a new
developer resume work without relying on chat history or ignored scratch files.

## Required Content

Every ExecPlan must:

- state the stage context, scope, constraints, and observable outcome;
- list concrete implementation steps and the files or interfaces they affect;
- define exact validation commands and expected observable results;
- explain which actions are idempotent and how to recover after interruption;
- remain current whenever progress, evidence, assumptions, or the next action changes.

Every ExecPlan must maintain these four living sections:

- `Progress`
- `Surprises & Discoveries`
- `Decision Log`
- `Outcomes & Retrospective`

Progress entries identify completed work and the next safe action. Discoveries record unexpected facts
that affect implementation. Decisions record a choice, its reason, and any rejected alternative.
Outcomes summarize delivered behavior, verification evidence, and remaining risk.

## Stage Lifecycle

Use one ExecPlan and one development conversation for each stage. Before starting a new stage, read the
previous plan and rerun its acceptance gate. Do not edit until the previous stage's result and current
Git state agree.

Update the active plan at meaningful stopping points and before handing work to another conversation.
Ignored files under `.planning/` may contain temporary notes, but they are neither project
specification nor completion evidence. Synchronize every fact required for recovery into the tracked
ExecPlan.

## Failure Handling

For a failed command, record the full command, error, current hypothesis, and next changed approach in
the active ExecPlan. A second attempt must change the method or test a different hypothesis. After
three materially different approaches fail without new evidence, stop repeating the operation, mark
the stage blocker, and perform root-cause diagnosis. Continue work that does not depend on the blocker.

Never resolve a failure by weakening tests, strict typing, lint rules, or coverage thresholds.

## Idempotency And Recovery

Prefer steps that can be rerun without changing an already-correct result. Document destructive or
one-time steps explicitly. After interruption:

1. Read `AGENTS.md`, this protocol, the project charter, and the active ExecPlan.
2. Inspect the repository root, branch, HEAD, status, and recent commits.
3. Rerun the latest recorded acceptance command.
4. Compare the observed result with `Progress` and `Outcomes & Retrospective`.
5. Resume only from the first incomplete step and record any discrepancy before editing.
