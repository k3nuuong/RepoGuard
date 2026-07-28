# Session Recovery

Use this order at the start of a new development conversation:

1. Read all of `AGENTS.md` and `.agent/PLANS.md`.
2. Read `docs/project-charter.md` and the current stage ExecPlan under `docs/execplans/`.
3. Inspect `git status --short --branch`, `git rev-parse HEAD`, and recent commits with
   `git log -5 --oneline --decorate`.
4. Rerun the previous stage's acceptance command. Before M1, rerun the latest M0 gate recorded in its
   ExecPlan.
5. Before editing, verify and state the target, current status, modified files, latest verification
   result, and next action.

If Git state and the ExecPlan disagree, stop editing, record the discrepancy in the active plan, and
resolve which evidence is current. Ignored `.planning/` notes may help locate context but are not
project specification or completion evidence.
