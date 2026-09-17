# AEGIS — Build Phases

This plan sequences AEGIS delivery so each engine is built **completely and independently usable** before the next one starts. Order:

1. **Phase 0** — Foundations (Harness + Control Plane skeleton, no engines yet)
2. **Phase 1** — Runtime Security Agent (Agent 1) — build to completion, shippable as Mode 1
3. **Phase 2** — Code Security Agent (Agent 2) — build to completion, shippable as Mode 2 (partial)
4. **Phase 3** — Crypto Engine (ECDAT) — build to completion, completes Mode 2
5. **Phase 4** — Correlation, Security Graph, Risk Engine — unlocks Mode 3
6. **Phase 5** — Local LLM / Sovereign AI Layer (planning + reporting intelligence)
7. **Phase 6** — Observability, Audit, Human-in-the-Loop, Evaluation
8. **Phase 7** — Hardening, Air-Gap Certification, Deployment

Each phase ends with an explicit **exit criteria** checklist. Do not start the next phase until the current one's exit criteria are met — this is a hard rule, not a suggestion (see `rules.md`).

---

## Phase 0 — Foundations (Harness + Control Plane Skeleton)

**Goal:** the minimum scaffolding every engine will run inside. No security logic yet.

### 0.1 Infrastructure
- Provision PostgreSQL (source of truth), Redis (queue/cache), Celery workers
- Docker Compose dev environment, fully offline-buildable (no runtime pulls from cloud AI APIs)
- Base FastAPI app skeleton (Control Plane + API Gateway)

### 0.2 Control Plane (minimal)
- Authentication (single-tenant is fine for now)
- Authorization stub
- Scope Validation stub (target allow-list, no enforcement logic yet beyond schema)
- Policy Validation stub (rate limit, intensity fields — not enforced yet)
- Mode Selector stub: only returns `MODE_1` for URL input for now (unlocked further in later phases)

### 0.3 Agent Harness (core skeleton, engine-agnostic)
- Task Graph (data model + parallel/dependent execution primitives)
- State Manager (per-scan structured state, see Evidence Model in architecture doc)
- Tool Registry (schema-validated tool registration, empty of real tools initially)
- Tool Executor + Permission Manager + Sandbox Manager (container-based isolation, `egress: drop` by default)
- Budget Manager (LLM calls, tool calls, duration caps — enforced from day one)
- Retry Manager (exponential backoff, correct retry/no-retry classification)
- Checkpoint Manager (resume-from-failure semantics)
- Audit Logger (immutable audit record schema, written from day one — every tool call must be audited even before real engines exist)

### 0.4 Evidence Model skeleton
- Common evidence schema (source, confidence, location, relationships)
- Evidence Normalizer stub (pass-through, ready to accept Runtime evidence first)

**Exit criteria for Phase 0:**
- [ ] A dummy "echo" tool can be registered, permission-checked, sandboxed, executed, retried on failure, and audited end-to-end
- [ ] Investigation state persists to PostgreSQL and can be checkpointed/resumed
- [ ] No component has any external network egress path (verified by firewall test)
- [ ] Budget Manager can hard-stop a runaway loop

---

## Phase 1 — Agent 1: Runtime Security Agent (build to completion)

**Goal:** ship a fully working **Mode 1** (URL-only) product. This agent must work standalone, produce real evidence, and generate a real report — before Agent 2 exists.

### 1.1 Scope & Policy Guard (real enforcement, not stub)
- Target authorization (explicit approval required)
- Domain / IP / endpoint / HTTP-method restrictions
- Rate limiting, scan intensity (passive/active/aggressive)
- Controlled-payload-only enforcement
- Local ephemeral canary listener for SSRF validation (localhost/internal only)
- Enforcement point: scope checked before **every** tool execution, not just at scan start

### 1.2 Attack Surface Discovery
- Crawler (spider)
- OpenAPI/Swagger parser
- Browser-based discovery (Playwright headless)

### 1.3 Authentication Analysis
- Detect login mechanisms (JWT, cookies, OAuth)
- Establish two distinct test identities for cross-user testing (required for BOLA)

### 1.4 Application Model Builder
- Map endpoints, parameters, HTTP methods, cookies/tokens, observed responses

### 1.5 Security Test Modules
- BOLA / BFLA (cross-identity authorization testing)
- SSRF (via local canary only — no third-party webhook SaaS)
- Injection (SQL, command, template)
- Auth weakness / broken session testing
- Misconfiguration (headers, debug endpoints, CORS)
- Nuclei template integration (offline template pack)

### 1.6 Evidence Collection
- Full HTTP request/response capture per finding (headers, body, timing, status)
- Auth-identity proof attached to every cross-user finding

### 1.7 Normalization → Evidence Normalizer (real, not stub)
- Severity, confidence, OWASP category, affected asset assigned
- Feeds the Phase 0 Evidence Normalizer with real Runtime Evidence records

### 1.8 Runtime-only Report
- Generate a standalone PDF/HTML report from Runtime evidence alone (no correlation yet — Mode 1 explicitly has no source root-cause, per architecture doc)
- SARIF export for Runtime findings

### 1.9 Deep Agent Supervisor — Runtime slice only
- Planner logic for a single-agent investigation (discovery → auth → tests → evidence)
- Re-planner: adjusts test plan when discovery reveals new endpoints
- **No LLM required yet for this phase** — a rule-based/deterministic planner is enough for Mode 1 v1; Local LLM planning integration happens in Phase 5. (You may stub LLM calls with templated text if a demo report is needed earlier.)

**Exit criteria for Phase 1:**
- [ ] Given a URL only, AEGIS runs Mode 1 end-to-end unattended
- [ ] Produces evidence-backed findings for at least BOLA, SSRF, injection, misconfig
- [ ] Every finding has full HTTP evidence, severity, confidence
- [ ] Report + SARIF generated locally, zero external calls made during the scan (verified)
- [ ] Human Approval gate correctly triggers for active/production-like BOLA tests
- [ ] Audit trail has 100% coverage of tool calls for a full scan

---

## Phase 2 — Agent 2: Code Security Agent (build to completion)

**Goal:** ship the source-code half of **Mode 2**. Built and validated independently of Agent 1 — it does not need Runtime evidence to produce a complete, correct code security report.

### 2.1 Repository Acquisition
- Git clone (GitHub/GitLab) or local source tree access
- Executes strictly inside the sandbox — no host filesystem access

### 2.2 Full Inventory
- Languages, frameworks, dependencies
- API routes, auth code, DB access code
- Config/env files, Docker/IaC files

### 2.3 Code Model (AST)
- Tree-sitter parsing across supported languages
- Function calls, data flows, variable scoping graph

### 2.4 Analysis Engines
- SAST: Semgrep/OpenGrep with bundled offline rule pack (30+ languages)
- Dependency CVEs: OSV-Scanner against bundled offline OSV/NVD/GHSA database
- Secret detection: Gitleaks (local regex/entropy patterns)
- IaC analysis: Checkov (offline policy engine, Docker/Terraform/K8s)

### 2.5 Root-Cause Normalization
- Every finding: exact file path, function name, line number, data-flow trace
- Feeds the Evidence Normalizer with real Code Evidence records

### 2.6 Source-to-Endpoint Mapping (prep for future correlation)
- Build the mapping table (endpoint → handler function → file/line) now, even though correlation itself is Phase 4
- This is Code Agent's own deliverable — do not wait for Runtime Agent

### 2.7 Code + Crypto-ready Report (crypto section deferred)
- Generate a standalone Code Security report (Mode 2 partial — architecture doc notes Mode 2 = Code + Crypto; ship the Code half first, crypto half arrives in Phase 3)
- SARIF export for code findings

**Exit criteria for Phase 2:**
- [ ] Given a repo only, AEGIS produces a complete, evidence-backed code security report with zero dependency on the Runtime Agent
- [ ] SAST, dependency, secret, and IaC findings all carry file/function/line evidence
- [ ] Source-to-endpoint mapping table exists and is queryable
- [ ] Sandbox isolation verified: no repo code executes with host-level privileges
- [ ] Report + SARIF generated locally

---

## Phase 3 — Crypto Engine (ECDAT) (build to completion)

**Goal:** complete the second half of Mode 2. Independent of both Agent 1 and Agent 2's runtime results — it can run against source, dependencies, certs, binaries, containers, and live protocols on its own.

### 3.1 Stage 1 — Discovery (6 collectors)
- Source Collector (Semgrep + Tree-sitter) — reuse Agent 2's AST/SAST infra where possible
- Dependency Collector (Syft + manifest parsers)
- Certificate & Key Collector (Python `cryptography` + pyjks)
- Binary Collector (YARA/findcrypt + LIEF, best-effort)
- Container Collector (cbomkit-theia)
- Protocol Collector (CryptoLyzer + tshark) — only against authorized local/intranet targets, same Scope & Policy Guard as Agent 1

### 3.2 Stage 2 — Normalization
- Unify all 6 collectors' output into a single CBOM schema (CycloneDX)

### 3.3 Stage 3 — Context Enrichment
- Tag prod/test, security-sensitive, exposure level

### 3.4 Stage 4 — Risk Assessment
- Quantum classification: Shor-broken / Grover-weakened / Legacy-broken / Safe-PQC
- Mosca inequality (X + Y > Z) computation for migration urgency

### 3.5 Migration Tiers & Crypto-Agility Scoring
- Tiering: Already Exposed / Act Now / Monitor / Safe
- Crypto-agility dimensions: algorithm coupling, provider coupling, parameter coupling, decoupling mechanism, spread, ownership, runtime availability

### 3.6 CBOM Export
- cyclonedx-python-lib based CBOM generation, locally signed/timestamped

**Exit criteria for Phase 3:**
- [ ] All 6 collectors run and merge into one CBOM for a test repo/container/target
- [ ] Every crypto asset has a quantum-risk classification and migration tier
- [ ] CBOM export validates against CycloneDX schema
- [ ] Mode 2 is now fully complete: Code Security Agent + Crypto Engine ship one combined report
- [ ] Protocol Collector obeys the same Scope & Policy Guard as the Runtime Agent (no unauthorized network probing)

---

## Phase 4 — Correlation, Security Graph, Risk Engine (unlocks Mode 3)

**Goal:** now that all three engines exist independently, wire them together. This phase is deliberately *after* all three agents are individually complete.

### 4.1 Security Graph
- PostgreSQL + JSONB implementation (no separate graph DB for MVP)
- Entities: App, Endpoint, Function, Data Asset, Finding, Library, Crypto Asset, Certificate

### 4.2 Correlation Engine (deterministic, not LLM-driven)
- BOLA correlation: Runtime proof + Code no-authz-check same endpoint/function
- Crypto chain correlation: same algorithm across source/container/protocol evidence
- Attack path correlation: hardcoded secret + public endpoint + sensitive data access

### 4.3 Risk Engine (deterministic composite scoring)
- Inputs: severity, confidence, exploitability, exposure, asset criticality, evidence strength, graph connectivity
- Output: ranked, prioritized remediation queue (not an unordered list)

### 4.4 Mode Selector upgrade
- Now correctly resolves Mode 1 / Mode 2 / Mode 3 based on available inputs, since all three engines exist
- Task Graph gains the full parallel/dependent structure from the architecture doc (§8)

**Exit criteria for Phase 4:**
- [ ] Given URL + Repo, AEGIS runs all three engines in parallel/dependent order and produces at least one correlated finding
- [ ] Risk Engine output is deterministic and reproducible for identical evidence input
- [ ] Correlation results never come from LLM reasoning alone — verified by a test that disables the LLM and confirms correlation still works

---

## Phase 5 — Local LLM / Sovereign AI Layer

**Goal:** replace the deterministic/stub planner from Phase 1 and templated report text with real local LLM reasoning, fully air-gapped.

### 5.1 Local Model Gateway
- Abstraction layer over Ollama / llama.cpp / vLLM / LocalAI-TGI
- CPU and GPU hardware support

### 5.2 Role 1 — Harness Intelligence
- Investigation planning, tool selection, re-planning, state reasoning
- Replaces the Phase 1 rule-based planner

### 5.3 Role 2 — Security Intelligence
- Evidence interpretation and explanation
- Attack-path summarization
- Remediation code generation
- Final report synthesis (natural-language layer on top of deterministic Risk Engine output — never overrides it)

### 5.4 Local RAG / Vector Search
- FastEmbed/BGE-Small embeddings, ChromaDB/SQLite-vec, fully in-process

**Exit criteria for Phase 5:**
- [ ] Zero outbound calls to any cloud LLM API during a full scan (verified by egress monitoring)
- [ ] LLM-authored report text never contradicts Risk Engine scores or Correlation Engine verdicts (automated consistency check)
- [ ] Swapping the underlying local model (e.g., Qwen2.5-Coder → Llama-3.1) requires no changes outside the Gateway

---

## Phase 6 — Observability, Audit, Human-in-the-Loop, Evaluation

- Full observability: scan lifecycle, agent lifecycle, task execution, tool calls/latency, LLM calls, evidence, findings, report generation
- Structured JSON logs, metrics, distributed traces, agent execution history
- Human-in-the-loop approval gates wired to real policy rules (active testing, destructive tests, scope expansion, production targets, budget expansion)
- Evaluation harness covering: planning quality, tool selection, tool arguments, policy/scope compliance, evidence quality, investigation completeness, correlation accuracy, hallucination detection, efficiency, failure recovery, checkpoint recovery

**Exit criteria for Phase 6:**
- [ ] Every scan produces a complete, immutable audit record chain
- [ ] Evaluation suite runs automatically after each scan and flags hallucinated findings (LLM claims unsupported by evidence)

---

## Phase 7 — Hardening, Air-Gap Certification, Deployment

- Firewall-level `egress: drop` verified at container/network boundary in production topology
- Docker Compose (dev) and air-gapped Kubernetes / bare metal (prod) deployment manifests
- Offline ruleset update mechanism (signed tarball synchronizer for CVE/CWE/rule updates) — no live sync
- Secret redaction pass across all logs/reports
- Full run of the Security Controls Summary checklist (§33 of architecture doc) as a release gate

**Exit criteria for Phase 7:**
- [ ] Independent air-gap audit confirms zero egress under adversarial test conditions
- [ ] All items in the "AEGIS NEVER" list are covered by an automated test
- [ ] Release candidate passes the full Evaluation harness on a benchmark set of intentionally vulnerable targets/repos

---

## Why this order (rationale)

- **Agent 1 first**: it has the shortest path to a demonstrable, evidence-producing product (Mode 1) and forces the Harness's sandboxing/scope/audit machinery to be correct against live network targets early — the highest-risk surface.
- **Agent 2 second**: reuses Phase 0 harness + Phase 1's evidence/report pipeline patterns, but is lower operational risk (static analysis, no live network testing), so it's a good second increment.
- **Crypto Engine third**: it depends on infrastructure (AST/source scanning) already built in Phase 2, and its protocol collector reuses Phase 1's scope-guarded network testing — so it naturally comes after both agents exist.
- **Correlation/Risk/LLM last**: correlation is meaningless until at least two independent evidence sources exist; building it earlier would mean stubbing evidence, which risks baking in wrong assumptions.