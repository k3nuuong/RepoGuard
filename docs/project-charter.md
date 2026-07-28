# RepoGuard Project Charter

RepoGuard is an evidence-driven Python Agent for pull-request review and security remediation.

RepoGuard is read-only by default. Patches are produced only in isolated Git worktrees, and every
external write requires explicit human approval. Its final product interfaces are a CLI, a GitHub
Action, and FastMCP; RepoGuard will not develop a web frontend.

## Stage Sequence

- **M0 - Foundation:** Deliver an installable Python package, reproducible tooling, quality gates, CI,
  and durable development governance.
- **M1 - Read-Only Evidence:** Model repository and pull-request inputs and produce traceable,
  read-only evidence without model calls or external writes.
- **M2 - Deterministic Review:** Add deterministic review and security checks with structured,
  testable findings.
- **M3 - Agent Reasoning:** Add LLM providers, prompts, and the controlled Agent review workflow.
- **M4 - Context Retrieval:** Add hybrid code retrieval using text, vector, and symbol context where
  evaluation shows value.
- **M5 - Safe Repair:** Produce candidate repairs in isolated worktrees with sandboxed validation and
  explicit approval boundaries.
- **M6 - Product Interfaces:** Deliver the review and repair workflow through the CLI, GitHub Action,
  and FastMCP, with approved GitHub writes.
- **M7 - Evaluation:** Establish RepoGuardBench, regression gates, and verified capability and safety
  metrics.
- **M8 - Optional Training:** Evaluate SFT or GRPO only when benchmark evidence justifies it; training
  is not a condition for completing the main product.

README files, portfolio material, and resumes may cite only capabilities and metrics that have current,
reproducible verification evidence.
