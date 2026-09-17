# AEGIS — Rules

These rules are binding for anyone (human or AI agent) implementing AEGIS. They encode the architecture's non-negotiables. If a task or shortcut conflicts with a rule below, the rule wins — flag the conflict instead of silently working around it.

---

## 1. Sequencing rules

1. **Build one engine to completion before starting the next.** Order is fixed: Runtime Security Agent (Agent 1) → Code Security Agent (Agent 2) → Crypto Engine (ECDAT) → Correlation/Security Graph/Risk Engine → Local LLM layer → Observability/Audit/HITL → Hardening/Deployment. See `phases.md`.
2. **"Complete" means it ships a standalone report on its own evidence**, with no dependency on an engine that hasn't been built yet. Do not build cross-engine correlation logic before at least two engines exist and produce real evidence.
3. Do not skip Phase 0 (Harness skeleton). No engine code is written against an unversioned, ad-hoc execution path — every tool call goes through Tool Registry → Permission Check → Sandbox → Executor from day one, even in Phase 1.
4. Do not move to the next phase until that phase's exit criteria (in `phases.md`) are all checked off.

---

## 2. Truth-flow rules (evidence-first)

1. **Truth flows upward from engines, never downward from the LLM.** The correct path is: Deep Agent selects a tool → Harness executes it → tool produces structured evidence → Evidence Normalizer → Security Graph → Correlation Engine → Risk Engine → LLM explains the already-determined verdict.
2. The LLM **never** independently declares "vulnerability confirmed." It explains, summarizes, and recommends remediation for findings that already have deterministic evidence and a Risk Engine score.
3. Every finding must trace to one or more structured evidence records. No finding without an evidence reference is allowed to reach a report.
4. Confidence must always be explicit and one of: **Confirmed / Probable / Potential.** Never omit it, never invent a fourth state without updating the schema and this document.
5. Binary crypto constant detection is never reported as "active use" — it is reported as a candidate that requires corroboration from another collector (source, container, or protocol).
6. Correlation and Risk scoring are **deterministic**. The Deep Agent may *request* a correlation or risk computation; it may not compute or override the result itself, and the LLM may not override a Risk Engine score.

---

## 3. Scope, authorization, and network rules

1. Scanning any target requires **explicit prior authorization**. No implicit "scan whatever the user pastes" behavior.
2. Scope is checked **before every single tool execution**, not once at the start of a scan.
3. The Deep Agent Supervisor **cannot self-authorize new targets** or expand scope. Scope expansion always requires a Human-in-the-Loop approval.
4. No credential brute-forcing. No credential theft attempts. Test identities must be explicitly supplied by the authorized user.
5. SSRF validation happens **only** via the platform's own local ephemeral canary listener (localhost / internal isolated container network). Never use a third-party webhook/callback SaaS for this, even in a dev/test environment — build the habit now so it can't leak into production.
6. Runtime testing targets are restricted to: localhost, local Docker container networks, or an isolated private intranet the user has explicitly authorized. AEGIS is not a general internet scanner.
7. Outbound egress is blocked by default at the container/firewall boundary (`egress: drop`). Any component that needs an exception must justify it explicitly and it must still resolve to a local/authorized target — never an external cloud endpoint.
8. Rate limits and scan intensity (passive/active/aggressive) are enforced by the Scope & Policy Guard, not left to individual tool implementations to self-limit.

---

## 4. Air-gap / offline rules

1. **Zero external cloud API calls, ever** — not for the LLM, not for embeddings, not for vulnerability databases, not for telemetry, not for crash reporting, not for update checks during a scan.
2. All vulnerability/CVE/CWE data, SAST rules, secret-detection patterns, IaC policies, and crypto risk matrices are **pre-bundled and stored locally** (SQLite/DuckDB or equivalent). Updates happen via an explicit, signed, offline tarball import — never a live sync.
3. The LLM runs on a local inference runtime only (Ollama, llama.cpp, vLLM, or LocalAI/TGI). No code path may fall back to a cloud model, even as an error-handling fallback.
4. Embeddings/RAG use local models only (FastEmbed/BGE-Small class) with a local vector store (ChromaDB/SQLite-vec). No calls to a cloud embeddings API.
5. Any new third-party library or tool introduced into AEGIS must be checked for hidden network calls (telemetry, update pings, license phone-home) before it is added to the Tool Registry or dependency list.
6. Treat "100% offline" and "air-gapped" as a testable property, not a marketing description: every phase's exit criteria includes an egress verification step.

---

## 5. Sandbox and isolation rules

1. Repository code and any potentially dangerous tool execution **never** runs with unrestricted access to the host machine. All code analysis and execution happens inside the sandbox.
2. Every sandboxed task has: CPU limit, memory limit, execution timeout, and output size limit. No unbounded task is allowed to exist, even temporarily "for testing."
3. Filesystem isolation is per-scan (temporary workspace), not shared across scans.
4. Scan credentials and platform credentials are isolated from each other — a scan can never read the platform's own secrets, and vice versa.
5. Secrets discovered during a scan (e.g., by Gitleaks) are **redacted** in logs and reports by default. Raw secret values are never stored in agent memory or persisted un-redacted.
6. Entire repositories and raw secrets are not duplicated into agent memory. Evidence stored in memory/state is a **reference** to the source, not a copy of it.

---

## 6. Harness and orchestration rules

1. The Deep Agent Supervisor may only execute tools that exist in the Tool Registry, with a validated schema and explicit permissions. No dynamic/ad-hoc tool invocation.
2. Every tool call passes through Permission Manager → Sandbox Manager → Tool Executor, in that order, with no bypass path.
3. Budgets (LLM calls, tokens, tool calls, planning iterations, scan duration, CPU/memory, network requests) are enforced by the Budget Manager, not left to individual components to self-police.
4. Retry policy is fixed: retry on timeout / transient network error / tool crash; **never** retry on permission denied, scope violation, or budget exhaustion — these are terminal failures that must be surfaced, not silently retried.
5. Every investigation state transition, tool call, and decision is checkpointed so the scan can resume after failure without restarting from scratch. Long-running engines (especially Crypto Engine's multi-stage pipeline) must be checkpointable at each stage boundary, not just at the whole-engine level.
6. High-impact actions (active testing against production-like targets, destructive tests, scope expansion, budget expansion, overriding scan intensity limits) require Human Approval before execution — this gate cannot be disabled by configuration alone; it must be an explicit, audited policy decision.

---

## 7. Audit and observability rules

1. Every tool call, agent decision, and permission check is logged to the immutable Audit Logger. "Immutable" means append-only storage in PostgreSQL — no update/delete path for audit records in normal operation.
2. An audit record must contain: user, scan_id, agent, tool, target, timestamp, action, permission decision (and why), result, evidence reference, retry info. Missing any of these fields is a bug, not an acceptable gap.
3. Observability (logs, metrics, traces) must cover scan lifecycle, agent lifecycle, task execution, tool calls/latency, LLM calls, evidence creation, findings, and report generation — implement this alongside the feature it observes, not as a later pass.
4. Coverage reporting is mandatory: every report must state what was tested vs. what could not be tested. Silent gaps in coverage are not acceptable.

---

## 8. Data and storage rules

1. PostgreSQL is the **only** durable source of truth (scans, findings, evidence, CBOM, Security Graph, correlations, risk scores, audit trail, investigation state, evaluation results).
2. Redis is ephemeral only — queueing, caching, session state, real-time progress. Nothing that must survive a Redis flush may live only in Redis.
3. Generated artifacts (reports, CBOM, SARIF, VEX, CSV) are written to local file storage, never uploaded anywhere by default.

---

## 9. Reporting rules

1. Every finding in a report must contain: title + category, severity, confidence, affected asset, evidence, source location (where applicable), root cause, impact, remediation, and verification/re-test instructions.
2. Never claim source root-cause without actual source evidence backing it — if only runtime evidence exists (Mode 1), say so explicitly and do not speculate about the underlying code.
3. Reports must state their mode's known limitations explicitly (e.g., Mode 1 → "no source root-cause, no crypto analysis"; Mode 2 → "no runtime exploit proof") rather than let the absence be implicit.

---

## 10. What AEGIS must never do (hard constraints)

Directly from the architecture's Security Controls Summary — treat every line as an automated test, not just a design intent:

- Never makes external cloud API calls or transmits telemetry.
- Never scans without authorized scope.
- Never invents findings from LLM imagination.
- Never claims source root-cause without source evidence.
- Never claims a binary crypto constant equals active use without corroboration.
- Never auto-patches code without human review.
- Never lets the Deep Agent bypass scope or permissions.
- Never exploits internal services via SSRF (only the local canary is used, and only for validation).
- Never sends prompts or code to a cloud LLM provider.
- Never stores raw secrets in agent memory.
- Never runs repository code on the host machine directly.

---

## 11. Change-management rule

Any change to the above rules (e.g., relaxing an air-gap constraint for a specific deployment) must be made explicitly in this file, with a rationale, rather than quietly overridden in code. If an implementer believes a rule is blocking legitimate progress, the correct action is to raise it for a documented exception — not to route around it silently.