# AEGIS — Tech Stack

Organized by which build phase (see `phases.md`) first needs each piece, so the stack can be introduced incrementally rather than provisioned all at once.

---

## Phase 0 — Foundations

| Technology | Role | Why |
|---|---|---|
| **Python 3.12** | Core language | Best ecosystem for security tooling; all downstream tools are Python-native |
| **FastAPI** | API framework | Async-native, auto-docs, type-safe (Flask lacks async, Django is too heavy) |
| **PostgreSQL** | Primary database / source of truth | JSONB for flexible evidence storage + relational for structured queries |
| **Redis** | Queue / cache / ephemeral state | Fast in-memory queue, mature Celery integration |
| **Celery** | Async task workers | Distributed execution for long-running scans |
| **Docker / Docker Compose** | Dev environment, sandboxing | Container isolation for Tool Executor/Sandbox Manager; air-gapped dev setup |

---

## Phase 1 — Runtime Security Agent (Agent 1)

| Technology | Role | Problem Solved |
|---|---|---|
| **Python** | Orchestration & test logic | Glues discovery → auth → tests → evidence pipeline together |
| **httpx** | Async HTTP client, full capture | Raw evidence (headers, body, timing) for every finding |
| **Playwright** | Headless browser automation | JS-heavy login, SPAs, OAuth flows raw HTTP can't reach |
| **OpenAPI/Swagger parser** | API spec parsing | Auto-discovers endpoints from spec files |
| **Crawler** | Web crawling | Finds hidden pages/routes not present in any spec |
| **Nuclei** | Template-based vulnerability checks | 8000+ community check templates (bundled offline) |
| **Local ephemeral canary daemon** | SSRF validation | Confirms SSRF without any external webhook SaaS |

---

## Phase 2 — Code Security Agent (Agent 2)

| Technology | Role | Problem Solved |
|---|---|---|
| **Python + FastAPI** | Orchestration & service layer | Coordinates the code analysis pipeline |
| **Semgrep / OpenGrep** | SAST (30+ languages) | Pattern-based vulnerability detection, offline rule pack |
| **Tree-sitter** | AST parsing | Structural code understanding vs. text/regex matching |
| **OSV-Scanner** | Dependency CVE scanning | Google-backed vulnerability database, bundled offline (SQLite/DuckDB cache) |
| **Gitleaks** | Secret detection | Low false-positive credential scanning via local regex/entropy rules |
| **Checkov** | IaC security | 1000+ Docker/Terraform/K8s checks, offline policy engine |

---

## Phase 3 — Crypto Engine (ECDAT)

| Technology | Role | Problem Solved |
|---|---|---|
| **Semgrep + Tree-sitter** | Source crypto collector | Reuses Agent 2's AST/SAST infra to find crypto usage in source |
| **Syft** | Dependency crypto collector | Deep transitive dependency graph resolution |
| **Python `cryptography` + pyjks** | Certificate & key collector | Parses PEM, DER, PKCS#12, JKS formats |
| **YARA / findcrypt + LIEF** | Binary crypto collector | Detects crypto constants in compiled binaries (best-effort) |
| **cbomkit-theia** | Container crypto collector | Finds crypto in Docker image layers |
| **CryptoLyzer + tshark** | Protocol collector | Captures actual negotiated TLS/SSH algorithms on authorized targets |
| **cyclonedx-python-lib** | CBOM generation | Industry-standard Cryptography Bill of Materials output |

---

## Phase 4 — Correlation, Security Graph, Risk Engine

| Technology | Role | Why |
|---|---|---|
| **PostgreSQL + JSONB** | Security Graph storage | No separate graph database needed for MVP; relational + JSONB is sufficient |
| **Deterministic rules/scoring code (Python)** | Correlation Engine, Risk Engine | Must be reproducible and explainable — no ML/LLM involvement in the scoring path itself |

---

## Phase 5 — Local LLM / Sovereign AI Layer

| Technology | Role | Why |
|---|---|---|
| **Local Model Gateway (custom abstraction)** | Inference abstraction | Decouples the Harness from any specific local inference runtime |
| **Ollama** | Local quantized model management | Simple local model lifecycle management |
| **llama.cpp** | High-efficiency CPU/Metal/CUDA inference | Runs well even without dedicated GPU hardware |
| **vLLM** | High-throughput on-prem GPU inference | For larger deployments with GPU capacity |
| **LocalAI / TGI** | Self-hosted containerized inference endpoints | Alternative self-hosted serving option |
| **Candidate local models** | Qwen2.5-Coder, Llama-3.1, Mistral | Reasoning/planning + code-aware remediation generation, all runnable fully offline |
| **FastEmbed / BGE-Small (or Nomic)** | Local embedding models | Offline vector generation, no cloud embeddings API |
| **ChromaDB / SQLite-vec** | Local vector store | In-process retrieval for security knowledge base / RAG |

---

## Phase 6 — Observability, Audit, Human-in-the-Loop, Evaluation

| Technology | Role | Why |
|---|---|---|
| **Structured JSON logging (Python `logging`/`structlog`)** | Logs | Every action machine-parseable for audit and debugging |
| **Metrics library (e.g., Prometheus client)** | Metrics | Counters/histograms for tool latency, LLM calls, etc. |
| **Distributed tracing (e.g., OpenTelemetry, self-hosted collector)** | Traces | Harness → Tool → Engine call chains, no external SaaS backend |
| **PostgreSQL** | Audit trail storage | Immutable, append-only audit records |

---

## Phase 7 — Hardening, Deployment

| Technology | Role | Why |
|---|---|---|
| **Docker Compose** | Dev deployment | Simple, air-gapped local dev/test topology |
| **Kubernetes (air-gapped) / Bare Metal** | Production deployment | Scales Celery workers and Agent Harness instances on sovereign hardware |
| **Firewall / network policy tooling (e.g., Calico, iptables)** | Egress enforcement | Enforces `egress: drop` at the container/network boundary |
| **Signed offline tarball mechanism (custom)** | Ruleset/CVE data updates | Keeps SAST rules, CVE databases, crypto risk matrices current without any live network sync |

---

## Frontend (can be developed in parallel from Phase 1 onward)

| Technology | Role | Why |
|---|---|---|
| **React + TypeScript** | UI framework | Component model suited to complex, data-dense dashboards |
| **Vite** | Build tool | Fastest HMR, modern ESM-native tooling |

---

## Output formats (introduced per-phase, as each engine ships its own exports)

| Format | Introduced in | Purpose |
|---|---|---|
| **PDF / HTML report** | Phase 1 (Runtime-only), extended each phase | Human-readable assessment |
| **SARIF** | Phase 1 (Runtime), Phase 2 (Code) | IDE/CI integration |
| **CycloneDX CBOM** | Phase 3 (Crypto Engine) | Cryptography Bill of Materials |
| **VEX** | Phase 4 (after Risk Engine exists) | Vulnerability exploitability exchange, needs risk context |
| **CSV** | Any phase | Custom/ad-hoc analysis export |

---

## Explicitly excluded / never introduced

Per the air-gap rules in `rules.md`, the following categories of technology are **never** part of this stack, at any phase:

- Cloud LLM APIs (OpenAI, Anthropic, Google, etc. as a runtime dependency) — local inference only
- Cloud embeddings APIs — local embedding models only
- External CVE/vulnerability lookup services queried at scan time — bundled offline databases only
- Third-party SSRF/webhook validation SaaS — local ephemeral canary only
- Any telemetry/analytics SDK that phones home (crash reporting, product analytics, license servers) — if a chosen library ships one, it must be disabled or the library replaced