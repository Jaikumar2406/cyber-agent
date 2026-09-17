# AEGIS — System Architecture

**A 100% Offline & Air-Gapped Agentic Application Security Platform powered by a Secure Agent Harness.**

---

## 1. AEGIS Overview

AEGIS is an adaptive application-security platform that consolidates runtime security testing, static code analysis, and cryptographic risk assessment into a single, correlated security assessment.

AEGIS is built around a secure **Agent Harness** — a controlled execution environment that orchestrates a **Deep Agent Supervisor** to plan, execute, and reason over security investigations using deterministic security engines and a local AI model. The entire platform operates in a **100% offline, air-gapped, sovereign environment** with zero external cloud dependencies.

### Core Architectural Principle

```
  ┌──────────────────────────────────────────────────────────────┐
  │                                                              │
  │  The HARNESS decides HOW the investigation runs.             │
  │                                                              │
  │  The SECURITY ENGINES determine WHAT the evidence says.      │
  │                                                              │
  │  The CORRELATION and RISK ENGINES determine                  │
  │  WHAT IS SIGNIFICANT.                                        │
  │                                                              │
  │  The LOCAL LLM explains WHY and WHAT TO FIX.                 │
  │                                                              │
  │  The AIR-GAPPED BOUNDARY ensures ZERO data leaves the host.  │
  │                                                              │
  └──────────────────────────────────────────────────────────────┘
```

### Responsibility Boundaries

```
  CONTROL PLANE               AGENT HARNESS             SECURITY ENGINES
  ─────────────               ─────────────             ────────────────
  Controls:                   Controls:                 Determine:
  • WHO can scan              • HOW to investigate      • WHAT evidence exists
  • WHAT targets are allowed  • WHEN to run each tool   • WHAT patterns match
  • WHERE scope boundaries    • WHICH tools to use      • WHAT is observed
  • WHETHER policy permits    • Task ordering           
  • Authorization             • State / retries         INTELLIGENCE LAYER
  • Air-gap egress policy     • Checkpoints / budgets   ──────────────────
  • Policy enforcement        • Execution sandboxing    Determines:
                                                        • HOW evidence connects
  LOCAL LLM (100% OFFLINE)                              • WHAT risk exists
  ────────────────────────                              • WHAT is prioritized
  Provides:
  • Planning assistance
  • Reasoning over evidence
  • Explanation of findings
  • Remediation guidance
  • Report generation
```

---

## 2. Problem Statement

Application security is fragmented across disconnected tools:

- **Runtime blind spot:** Live scanners show what is vulnerable but not which code caused it.
- **Source-code blind spot:** Code scanners find patterns but can't prove real-world exploitability.
- **Cryptography disconnect:** Weak algorithms and key handling are reported in isolation.
- **Cloud/Privacy leak risk:** Sending proprietary code or internal vulnerabilities to third-party cloud APIs poses unacceptable enterprise risk.

AEGIS eliminates these blind spots by correlating runtime proof, source root cause, and cryptographic posture into one evidence-backed assessment — executed **entirely within your private, air-gapped perimeter**.

---

## 3. Design Principles

1. **Evidence-first** — Every finding must trace to deterministic, structured evidence. The LLM never invents findings.
2. **100% Offline & Air-Gapped** — All core processing, deterministic security engines, AST parsers, vulnerability databases, local security graph, and AI models execute strictly locally. Zero telemetry, zero cloud dependencies, zero external data leakage.
3. **Harness-controlled** — All tool execution flows through the Agent Harness with permissions, sandboxing, and budgets.
4. **Deterministic truth** — Security verdicts come from engines and correlation, not from LLM reasoning alone.
5. **Adaptive** — AEGIS auto-selects scan mode based on available inputs. No manual scanner selection.
6. **Modular** — Each engine is independently useful; combined output through correlation is the differentiator.
7. **Auditable & Sovereign** — Every action, tool call, and decision is logged locally with full traceability.

---

## 4. High-Level Architecture

```
  ┌──────────────────────────────────────────────────────────────────┐
  │                        👤 USER                                    │
  └────────────────────────────┬─────────────────────────────────────┘
                               │
  ┌────────────────────────────┴─────────────────────────────────────┐
  │                    PRESENTATION LAYER                             │
  │         🖥️ Dashboard    ⌨️ CLI    🔌 REST API    🔄 CI/CD          │
  └────────────────────────────┬─────────────────────────────────────┘
                               │
  ┌────────────────────────────┴─────────────────────────────────────┐
  │                      CONTROL PLANE                               │
  │     Authentication → Authorization → Scope Validation            │
  │                    → Policy Validation                           │
  └────────────────────────────┬─────────────────────────────────────┘
                               │
  ┌────────────────────────────┴─────────────────────────────────────┐
  │                      MODE SELECTOR                               │
  │     Inspects inputs → selects required capabilities              │
  │     (URL → Runtime) (Repo → Code + Crypto) (Both → All)         │
  └────────────────────────────┬─────────────────────────────────────┘
                               │
  ╔════════════════════════════╧═════════════════════════════════════╗
  ║                      AGENT HARNESS                               ║
  ║                                                                  ║
  ║  ┌────────────────────────────────────────────────────────────┐  ║
  ║  │            🧠 DEEP AGENT SUPERVISOR                        │  ║
  ║  │     Planner → Re-planner → Investigation Controller       │  ║
  ║  └────────────────────────┬───────────────────────────────────┘  ║
  ║                           │                                      ║
  ║  ┌────────────────────────┴───────────────────────────────────┐  ║
  ║  │                    TASK GRAPH                               │  ║
  ║  │     Parallel tasks ─── Independent (Runtime ∥ Code)        │  ║
  ║  │     Dependent tasks ── Sequential (Discovery → BOLA test)  │  ║
  ║  └────────────────────────┬───────────────────────────────────┘  ║
  ║                           │                                      ║
  ║  ┌────────────────────────┴───────────────────────────────────┐  ║
  ║  │                    TOOL REGISTRY                            │  ║
  ║  │     Registered tools with schemas, permissions, quotas     │  ║
  ║  └────────────────────────┬───────────────────────────────────┘  ║
  ║                           │                                      ║
  ║  ┌────────────────────────┴───────────────────────────────────┐  ║
  ║  │              PERMISSION + SANDBOX                           │  ║
  ║  │     Permission check → Sandbox isolation → Execution       │  ║
  ║  └────────────────────────┬───────────────────────────────────┘  ║
  ║                           │                                      ║
  ║  ┌─────────┐ ┌──────────┐│┌───────────┐                         ║
  ║  │  State  │ │Checkpoint│││  Memory   │  Cross-cutting services  ║
  ║  │ Manager │ │ Manager  │││ Manager   │                         ║
  ║  └─────────┘ └──────────┘│└───────────┘                         ║
  ║  ┌─────────┐ ┌──────────┐│┌───────────┐                         ║
  ║  │  Retry  │ │  Budget  │││ Observa-  │                         ║
  ║  │ Manager │ │ Manager  │││  bility   │                         ║
  ║  └─────────┘ └──────────┘│└───────────┘                         ║
  ║  ┌─────────┐ ┌──────────┘│                                      ║
  ║  │  Audit  │ │  Human   ││                                      ║
  ║  │ Logger  │ │ Approval ││                                      ║
  ║  └─────────┘ └──────────┘│                                      ║
  ╚═══════════════════════════╧══════════════════════════════════════╝
                              │
          ┌───────────────────┼───────────────────┐
          │                   │                   │
          ▼                   ▼                   ▼
  ┌──────────────┐   ┌──────────────┐   ┌──────────────┐
  │🌐 Runtime     │   │📝 Code        │   │🔐 Crypto      │
  │  Security    │   │  Security    │   │  Engine      │
  │  Agent       │   │  Agent       │   │  (ECDAT)     │
  └──────┬───────┘   └──────┬───────┘   └──────┬───────┘
         │                  │                   │
         │ Runtime Evidence │ Source Evidence    │ Crypto Evidence
         │                  │                   │
         ▼                  ▼                   ▼
  ┌──────────────────────────────────────────────────────┐
  │                📋 EVIDENCE NORMALIZER                  │
  └────────────────────────┬─────────────────────────────┘
                           │
                           ▼
  ┌──────────────────────────────────────────────────────┐
  │                 🕸️ SECURITY GRAPH                      │
  └────────────────────────┬─────────────────────────────┘
                           │
                           ▼
  ┌──────────────────────────────────────────────────────┐
  │               🔗 CORRELATION ENGINE                    │
  └────────────────────────┬─────────────────────────────┘
                           │
                           ▼
  ┌──────────────────────────────────────────────────────┐
  │                 ⚖️ RISK ENGINE                         │
  └────────────────────────┬─────────────────────────────┘
                           │
                           ▼
  ┌──────────────────────────────────────────────────────┐
  │             🏠 LOCAL MODEL GATEWAY                     │
  │             Local LLM (Reasoning + Reports)           │
  └────────────────────────┬─────────────────────────────┘
                           │
               ┌───────────┼───────────┐
               ▼           ▼           ▼
        ┌───────────┐ ┌────────┐ ┌──────────┐
        │📊 Report   │ │📦 CBOM  │ │📋 SARIF / │
        │ PDF/HTML  │ │        │ │  VEX     │
        └───────────┘ └────────┘ └──────────┘
```

---

## 5. Control Plane

The Control Plane is the gateway that validates every request before it reaches the Agent Harness. It controls WHO, WHAT, WHERE, and WHETHER.

```
  👤 User Request
       │
       ▼
  ┌──────────────────────────────────────────────┐
  │  AUTHENTICATION                               │
  │  Verify user identity                         │
  └────────────────────┬─────────────────────────┘
                       │
                       ▼
  ┌──────────────────────────────────────────────┐
  │  AUTHORIZATION                                │
  │  Verify user has permission for this action   │
  └────────────────────┬─────────────────────────┘
                       │
                       ▼
  ┌──────────────────────────────────────────────┐
  │  SCOPE VALIDATION                             │
  │  Verify targets are within authorized scope   │
  └────────────────────┬─────────────────────────┘
                       │
                       ▼
  ┌──────────────────────────────────────────────┐
  │  POLICY VALIDATION                            │
  │  Check scan intensity, rate limits, rules     │
  └────────────────────┬─────────────────────────┘
                       │
                       ▼
  ┌──────────────────────────────────────────────┐
  │  MODE SELECTOR                                │
  │  Inspect inputs → determine required engines  │
  └────────────────────┬─────────────────────────┘
                       │
                       ▼
                 Agent Harness
```

---

## 6. Agent Harness Architecture

The Agent Harness is the central execution and control layer. It provides the infrastructure for secure, observable, and recoverable investigation execution.

```
  Agent Harness
  │
  ├── 🧠 Deep Agent Supervisor
  │   ├── Planner
  │   ├── Re-planner
  │   └── Investigation Controller
  │
  ├── 📊 Task Graph
  ├── 📦 State Manager
  ├── 💾 Checkpoint Manager
  ├── 🧠 Memory Manager
  ├── 🔧 Tool Registry
  ├── ⚡ Tool Executor
  ├── 🔒 Permission Manager
  ├── 📦 Sandbox Manager
  ├── 🌐 Network Policy
  ├── 💰 Budget Manager
  ├── 🔄 Retry Manager
  ├── 👤 Human Approval
  ├── 📈 Observability
  └── 📝 Audit Logger
```

### What the Harness controls

| Component | Responsibility |
|---|---|
| **Deep Agent Supervisor** | Plans investigation, selects tools, observes results, re-plans |
| **Task Graph** | Tracks task dependencies, parallel vs sequential execution |
| **State Manager** | Maintains structured investigation state per scan |
| **Checkpoint Manager** | Saves progress; enables resume after failure |
| **Memory Manager** | Short-term investigation context + persistent metadata |
| **Tool Registry** | Catalog of approved tools with schemas and permissions |
| **Tool Executor** | Runs tools inside sandbox with timeout enforcement |
| **Permission Manager** | Checks tool permissions before every execution |
| **Sandbox Manager** | Isolates untrusted code execution (CPU, memory, filesystem) |
| **Network Policy** | Controls which network targets are reachable |
| **Budget Manager** | Limits LLM calls, tokens, tool calls, scan duration |
| **Retry Manager** | Handles failures with exponential backoff |
| **Human Approval** | Blocks high-impact actions until human approves |
| **Observability** | Logs, metrics, traces for every action |
| **Audit Logger** | Immutable record of every decision and action |

---

## 7. Deep Agent Supervisor

The Deep Agent Supervisor is the orchestration and investigation layer. It plans and coordinates security investigations — it is NOT a vulnerability scanner and is NOT the source of security truth.

### What the Deep Agent DOES

- Understand investigation objectives from the Mode Selector
- Plan investigation steps
- Select appropriate tools from the Tool Registry
- Execute tools through the Harness (never directly)
- Observe structured results
- Maintain investigation state
- Re-plan when new evidence changes the investigation
- Coordinate the Runtime Security Agent, Code Security Agent, and Crypto Engine
- Request additional evidence when needed
- Trigger correlation, risk analysis, and report generation

### What the Deep Agent does NOT do

- Independently declare "vulnerability confirmed" based on LLM reasoning
- Execute tools outside the Tool Registry
- Bypass scope or permission controls
- Override deterministic Risk Engine scores
- Expand testing scope without authorization

### Truth flows UPWARD from engines, not DOWNWARD from the agent

```
  ┌──────────────────────────────────────────────────────────────┐
  │                                                              │
  │  ❌ WRONG:                                                    │
  │     Deep Agent → LLM thinks → "vulnerability found"          │
  │                                                              │
  │  ✅ CORRECT:                                                  │
  │     Deep Agent → selects tool → Harness executes tool        │
  │     → Tool produces structured evidence                      │
  │     → Evidence Normalizer → Security Graph                   │
  │     → Correlation Engine → Risk Engine                       │
  │     → LLM EXPLAINS the verified evidence                     │
  │                                                              │
  └──────────────────────────────────────────────────────────────┘
```

---

## 8. Planning and Task Graph

The Deep Agent Supervisor creates a task graph for each investigation. The Harness determines execution order.

### Parallel vs Dependent Tasks

```
  ┌──────────────────────────────────────────────────────────────┐
  │  MODE 3 TASK GRAPH EXAMPLE                                    │
  │                                                              │
  │  PARALLEL TASKS (no dependencies, run simultaneously):       │
  │  ─────────────────────────────────────────────────           │
  │                                                              │
  │  ┌──────────────────┐  ┌──────────────────┐                  │
  │  │ Runtime: Discover │  │ Code: Inventory  │  These can run  │
  │  │ endpoints        │  │ repository       │  at the same    │
  │  └────────┬─────────┘  └────────┬─────────┘  time           │
  │           │                     │                            │
  │  DEPENDENT TASKS (need prior evidence):                      │
  │  ─────────────────────────────────────                       │
  │           │                     │                            │
  │           ▼                     ▼                            │
  │  ┌──────────────────┐  ┌──────────────────┐                  │
  │  │ Runtime: Auth     │  │ Code: AST +      │                  │
  │  │ analysis         │  │ SAST analysis    │                  │
  │  └────────┬─────────┘  └────────┬─────────┘                  │
  │           │                     │                            │
  │           ▼                     │                            │
  │  ┌──────────────────┐          │                            │
  │  │ Runtime: BOLA     │          │                            │
  │  │ testing          │          │                            │
  │  │ (needs auth +    │          │                            │
  │  │  two identities) │          │                            │
  │  └────────┬─────────┘          │                            │
  │           │                     │                            │
  │  CORRELATION (needs evidence from both sides):               │
  │  ─────────────────────────────────────────────               │
  │           │                     │                            │
  │           └──────────┬──────────┘                            │
  │                      ▼                                       │
  │           ┌──────────────────┐                               │
  │           │ Correlate:       │                               │
  │           │ Runtime BOLA +   │                               │
  │           │ Source root cause │                               │
  │           └──────────────────┘                               │
  └──────────────────────────────────────────────────────────────┘
```

The Harness dynamically determines whether tasks can execute concurrently or must wait for dependencies.

---

## 9. Tool Registry

The Deep Agent does not directly execute arbitrary functions. Every tool must be registered, permission-checked, and sandboxed.

### Tool Execution Flow

```
  Deep Agent Supervisor
       │
       │ "I need to run SAST analysis"
       │
       ▼
  ┌──────────────────────────┐
  │  TOOL REGISTRY            │
  │  Find tool, check schema  │
  └────────────┬─────────────┘
               │
               ▼
  ┌──────────────────────────┐
  │  PERMISSION CHECK         │
  │  Is this tool allowed for │
  │  this target and scope?   │
  └────────────┬─────────────┘
               │
               ▼
  ┌──────────────────────────┐
  │  TOOL EXECUTOR            │
  │  Run inside sandbox with  │
  │  timeout and resource cap │
  └────────────┬─────────────┘
               │
               ▼
  ┌──────────────────────────┐
  │  SANDBOX                  │
  │  Isolated environment     │
  └────────────┬─────────────┘
               │
               ▼
  ┌──────────────────────────┐
  │  STRUCTURED RESULT        │
  │  Evidence returned to     │
  │  Agent State              │
  └──────────────────────────┘
```

### Registered Tool Categories

**Runtime Tools**
- Endpoint discovery (crawler, OpenAPI parser, browser discovery)
- HTTP request execution (httpx)
- Authentication testing
- Authorization / BOLA testing
- SSRF testing (controlled canary)
- Injection testing
- Misconfiguration checking
- Browser automation (Playwright)
- Template-based checks (Nuclei)

**Code Tools**
- Repository acquisition (Git clone / local access)
- Repository inventory
- AST analysis (Tree-sitter)
- SAST rule execution (Semgrep / OpenGrep)
- Dependency vulnerability analysis (OSV-Scanner)
- Secret detection (Gitleaks)
- IaC analysis (Checkov)
- Source-to-endpoint mapping

**Crypto Tools**
- Source crypto detection (Semgrep + Tree-sitter)
- Dependency crypto detection (Syft + manifest parsers)
- Certificate and key parsing (Python cryptography + pyjks)
- Binary crypto detection (YARA/findcrypt + LIEF)
- Container layer scanning (cbomkit-theia)
- Protocol analysis (CryptoLyzer + tshark)
- CBOM generation (cyclonedx-python-lib)

**Intelligence Tools**
- Evidence normalization
- Security Graph operations
- Correlation execution
- Risk calculation

**Output Tools**
- Report generation (PDF/HTML)
- SARIF export
- VEX export
- CBOM export
- CSV export

---

## 10. Scope & Policy Guard

Consolidated security controls that govern all scanning activity. The Runtime Security Agent must never autonomously expand outside authorized scope.

```
  ┌──────────────────────────────────────────────────────────────┐
  │                    SCOPE & POLICY GUARD                       │
  │                                                              │
  │  TARGET AUTHORIZATION                                        │
  │  ├── Explicit target approval required before scanning       │
  │  ├── Domain restrictions (allowed domains only)              │
  │  ├── IP restrictions (allowed ranges only)                   │
  │  ├── Endpoint restrictions (path allow/deny lists)           │
  │  └── HTTP method restrictions (GET-only vs full testing)     │
  │                                                              │
  │  SCAN CONTROLS                                               │
  │  ├── Rate limits (max requests per second)                   │
  │  ├── Scan intensity (passive / active / aggressive)          │
  │  ├── Controlled payloads only (no arbitrary exploitation)    │
  │  └── SSRF validation via controlled canary only              │
  │                                                              │
  │  AUTHENTICATION REQUIREMENTS                                 │
  │  ├── Test identities must be explicitly provided             │
  │  ├── No credential brute-forcing                             │
  │  └── No credential theft attempts                            │
  │                                                              │
  │  NETWORK POLICIES                                            │
  │  ├── Outbound connections restricted to authorized targets   │
  │  ├── No scanning of unrelated internal services              │
  │  └── Callback/canary infrastructure is platform-controlled   │
  │                                                              │
  │  ENFORCEMENT                                                 │
  │  ├── Scope checked BEFORE every tool execution               │
  │  ├── Runtime Agent cannot self-authorize new targets         │
  │  └── Violations logged and investigation halted              │
  └──────────────────────────────────────────────────────────────┘
```

---

## 11. Execution Sandbox

Untrusted repository code and potentially dangerous tool execution must be isolated.

```
  ┌──────────────────────────────────────────────────────────────┐
  │                    EXECUTION SANDBOX                          │
  │                                                              │
  │  RESOURCE LIMITS                                             │
  │  ├── CPU limits per task                                     │
  │  ├── Memory limits per task                                  │
  │  ├── Execution timeout per tool call                         │
  │  └── Output size limits                                      │
  │                                                              │
  │  ISOLATION                                                   │
  │  ├── Filesystem isolation (temporary workspace per scan)     │
  │  ├── Process isolation                                       │
  │  ├── Network restrictions (only authorized targets)          │
  │  ├── Secret isolation (scan credentials separated from       │
  │  │   platform credentials)                                   │
  │  └── Resource quotas enforced by container runtime           │
  │                                                              │
  │  CRITICAL RULE                                               │
  │  Repository code must NEVER have unrestricted access         │
  │  to the host machine. Code analysis tools run inside         │
  │  the sandbox, not on the host directly.                      │
  └──────────────────────────────────────────────────────────────┘
```

---

## 12. Runtime Security Agent

### What it does
Tests the **live, deployed application** from the outside — like a skilled penetration tester sending real HTTP requests through the Harness.

### The problem it solves
Code scanners find patterns but **can't prove** an app is actually exploitable. The Runtime Security Agent proves it with real HTTP evidence.

### Workflow (executed via Harness)

```
  Tool Registry receives task from Deep Agent Supervisor
       │
       ▼
  ┌──────────────────────────────────────────────────────────┐
  │  1️⃣  VALIDATE & SCOPE                                    │
  │  Check URL, protocol, redirects. Enforce authorized      │
  │  testing boundary. No scanning outside approved scope.   │
  └────────────────────────┬─────────────────────────────────┘
                           │
                           ▼
  ┌──────────────────────────────────────────────────────────┐
  │  2️⃣  DISCOVER ATTACK SURFACE                             │
  │                                                          │
  │  ┌──────────┐  ┌───────────────┐  ┌──────────────────┐  │
  │  │ Crawler  │  │ OpenAPI/      │  │ Browser-based    │  │
  │  │ (spider  │  │ Swagger       │  │ Discovery        │  │
  │  │  pages)  │  │ Parser        │  │ (Playwright)     │  │
  │  └──────────┘  └───────────────┘  └──────────────────┘  │
  │                                                          │
  │  Finds: All pages, API endpoints, hidden routes          │
  └────────────────────────┬─────────────────────────────────┘
                           │
                           ▼
  ┌──────────────────────────────────────────────────────────┐
  │  3️⃣  ANALYZE AUTHENTICATION                              │
  │  Identify login mechanisms (JWT, cookies, OAuth).        │
  │  Establish TWO test identities for cross-user testing.   │
  └────────────────────────┬─────────────────────────────────┘
                           │
                           ▼
  ┌──────────────────────────────────────────────────────────┐
  │  4️⃣  BUILD APPLICATION MODEL                             │
  │  Map: endpoints, parameters, HTTP methods,               │
  │  cookies/tokens, observed responses                      │
  └────────────────────────┬─────────────────────────────────┘
                           │
                           ▼
  ┌──────────────────────────────────────────────────────────┐
  │  5️⃣  EXECUTE SECURITY TESTS                              │
  │                                                          │
  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────┐  │
  │  │ 🔓 BOLA      │  │ 🔗 SSRF      │  │ 💉 Injection     │  │
  │  │ Can User A  │  │ Can server  │  │ SQL, command,   │  │
  │  │ access      │  │ be tricked  │  │ template        │  │
  │  │ User B's    │  │ into fetch- │  │ injection       │  │
  │  │ data?       │  │ ing URLs?   │  │ possible?       │  │
  │  └─────────────┘  └─────────────┘  └─────────────────┘  │
  │                                                          │
  │  ┌─────────────┐  ┌─────────────────────────────────┐    │
  │  │ 🔑 Auth      │  │ ⚙️ Misconfiguration              │    │
  │  │ Weakness    │  │ Missing security headers?       │    │
  │  │ Broken      │  │ Exposed debug endpoints?        │    │
  │  │ sessions?   │  │ CORS misconfig?                 │    │
  │  └─────────────┘  └─────────────────────────────────┘    │
  └────────────────────────┬─────────────────────────────────┘
                           │
                           ▼
  ┌──────────────────────────────────────────────────────────┐
  │  6️⃣  COLLECT EVIDENCE                                    │
  │  For every finding: full HTTP request + response,        │
  │  status codes, timing, headers, auth identity proof      │
  └────────────────────────┬─────────────────────────────────┘
                           │
                           ▼
  ┌──────────────────────────────────────────────────────────┐
  │  7️⃣  NORMALIZE FINDINGS                                  │
  │  Assign: severity, confidence, OWASP category,           │
  │  affected asset → pass to Evidence Normalizer            │
  └──────────────────────────────────────────────────────────┘
```

### Runtime Security Agent — Technology

| Tool | Why | Problem Solved |
|---|---|---|
| **Python** | Orchestration & test logic | Glues pipeline together; state management, sequencing |
| **httpx** | Async HTTP with full capture | Raw evidence (headers, body, timing) for every finding |
| **Playwright** | Headless browser | JS-heavy login, SPAs, OAuth flows that raw HTTP can't handle |
| **OpenAPI Parser** | API spec parsing | Auto-discovers every endpoint from Swagger/OpenAPI |
| **Crawler** | Web crawling | Finds hidden pages, routes, attack surface not in specs |
| **Nuclei** | Template-based checks | 8000+ community vulnerability check templates |

---

## 13. Code Security Agent

### What it does
Analyzes the **source code repository** to find vulnerabilities — the *why* behind every security problem.

### The problem it solves
Runtime scanners prove exploitability but **can't tell you which line of code to fix**. The Code Security Agent pinpoints the exact file, function, and line number.

### Workflow (executed via Harness)

```
  Tool Registry receives task from Deep Agent Supervisor
       │
       ▼
  ┌──────────────────────────────────────────────────────────┐
  │  1️⃣  ACQUIRE REPOSITORY                                  │
  │  Clone from GitHub / GitLab or access local source tree  │
  │  (inside sandbox — no host filesystem access)            │
  └────────────────────────┬─────────────────────────────────┘
                           │
                           ▼
  ┌──────────────────────────────────────────────────────────┐
  │  2️⃣  FULL INVENTORY                                      │
  │                                                          │
  │  ┌───────────┐ ┌───────────┐ ┌────────────┐             │
  │  │ Languages │ │Frameworks │ │Dependencies│             │
  │  └───────────┘ └───────────┘ └────────────┘             │
  │  ┌───────────┐ ┌───────────┐ ┌────────────┐             │
  │  │API Routes │ │ Auth Code │ │ DB Access  │             │
  │  └───────────┘ └───────────┘ └────────────┘             │
  │  ┌───────────┐ ┌───────────┐                             │
  │  │Config/Env │ │Docker/IaC │                             │
  │  └───────────┘ └───────────┘                             │
  └────────────────────────┬─────────────────────────────────┘
                           │
                           ▼
  ┌──────────────────────────────────────────────────────────┐
  │  3️⃣  BUILD CODE MODEL (AST)                              │
  │  Parse source into Abstract Syntax Trees.                │
  │  Understand: function calls, data flows, variable        │
  │  scoping — across multiple languages.                    │
  └────────────────────────┬─────────────────────────────────┘
                           │
                           ▼
  ┌──────────────────────────────────────────────────────────┐
  │  4️⃣  RUN ANALYSIS ENGINES                                │
  │                                                          │
  │  ┌──────────────────┐  ┌──────────────────────────────┐  │
  │  │ 🔍 SAST Rules     │  │ 📦 Dependency Scan            │  │
  │  │ Pattern-match    │  │ Check every library for      │  │
  │  │ known vuln       │  │ known CVEs (OSV database)    │  │
  │  │ signatures       │  │                              │  │
  │  └──────────────────┘  └──────────────────────────────┘  │
  │                                                          │
  │  ┌──────────────────┐  ┌──────────────────────────────┐  │
  │  │ 🔑 Secret Detect  │  │ 🏗️ IaC Analysis               │  │
  │  │ Find hardcoded   │  │ Docker, Terraform, K8s      │  │
  │  │ passwords, API   │  │ misconfigurations            │  │
  │  │ keys, tokens     │  │                              │  │
  │  └──────────────────┘  └──────────────────────────────┘  │
  └────────────────────────┬─────────────────────────────────┘
                           │
                           ▼
  ┌──────────────────────────────────────────────────────────┐
  │  5️⃣  NORMALIZE WITH ROOT CAUSE                           │
  │  Every finding gets: exact file path, function name,     │
  │  line number, data-flow trace                            │
  │  → Pass to Evidence Normalizer                           │
  └──────────────────────────────────────────────────────────┘
```

### Code Security Agent — Technology

| Tool | Why | Problem Solved |
|---|---|---|
| **Python + FastAPI** | Orchestration & service layer | Coordinates analysis pipeline |
| **Semgrep / OpenGrep** | SAST (30+ languages) | Pattern-based vulnerability detection |
| **Tree-sitter** | AST parsing | Structural code understanding, not text matching |
| **OSV-Scanner** | Dependency CVEs | Google-backed open-source vulnerability database |
| **Gitleaks** | Secret detection | Fast, low false-positive credential scanning |
| **Checkov** | IaC security | 1000+ Docker/Terraform/K8s checks |

---

## 14. Crypto Engine (ECDAT)

### What it does
Discovers every cryptographic asset in the codebase, builds a Cryptography Bill of Materials (CBOM), assesses quantum and classical risk, and plans migration priorities.

### The problem it solves
Organizations don't know what crypto they use, where it lives, whether it's quantum-vulnerable, or how hard it would be to replace.

### ECDAT Pipeline

```
  EVIDENCE SOURCES
  ┌──────────┐ ┌──────────┐ ┌───────────┐ ┌─────────┐
  │📝 Source  │ │📦 Package │ │🔒 Certs /  │ │⚙️ Binar- │
  │  Code    │ │ Manifests│ │ Keystores │ │  ies    │
  └──────────┘ └──────────┘ └───────────┘ └─────────┘
  ┌──────────┐ ┌──────────┐
  │🐳 Contain-│ │🌐 Live    │
  │ er Images│ │ Protocols│
  └──────────┘ └──────────┘
       │
       ▼
  STAGE 1 — DISCOVERY (6 Plugin Collectors)
  ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
  │ Source Collector │ │ Dependency      │ │ Certificate &   │
  │ Semgrep +       │ │ Collector       │ │ Key Collector   │
  │ Tree-sitter     │ │ Syft + parsers  │ │ Python crypto   │
  └─────────────────┘ └─────────────────┘ └─────────────────┘
  ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
  │ Binary          │ │ Container       │ │ Protocol        │
  │ Collector       │ │ Collector       │ │ Collector       │
  │ YARA + LIEF     │ │ cbomkit-theia   │ │ CryptoLyzer     │
  │ (best-effort)   │ │                 │ │ + tshark        │
  └─────────────────┘ └─────────────────┘ └─────────────────┘
       │
       ▼
  STAGE 2 — NORMALIZATION → Unified CBOM
  STAGE 3 — CONTEXT ENRICHMENT → prod/test, security-sensitive, exposure
  STAGE 4 — RISK ASSESSMENT → Quantum classification + Mosca X+Y>Z
       │
       ▼
  MIGRATION TIERS
  ┌───────────────────┬──────────────────────────────────────────┐
  │ 🔴 ALREADY EXPOSED │ Data capturable now, X+Y > Z → migrate  │
  │ 🟡 ACT NOW         │ Near boundary or hard deadline           │
  │ 🔵 MONITOR         │ Vulnerable but low criticality           │
  │ 🟢 SAFE            │ Quantum-safe or non-security use         │
  └───────────────────┴──────────────────────────────────────────┘
```

### Quantum Risk Classification

| Class | Examples | Meaning |
|---|---|---|
| **Shor-broken** | RSA, DH, ECDH, ECDSA, EdDSA, X25519 | Quantum computer breaks completely |
| **Grover-weakened** | AES-128, some hash uses | Security margin halved |
| **Legacy-broken** | MD5, SHA-1, DES, 3DES, RC4 | Already broken classically |
| **Safe / PQC** | AES-256, SHA-3, ML-KEM, ML-DSA | Quantum-safe or strong enough |

### Crypto-Agility Dimensions

| Dimension | What it measures |
|---|---|
| Algorithm coupling | Is the algorithm hardcoded? |
| Provider coupling | Direct lib dependency or abstracted? |
| Parameter coupling | Hardcoded key sizes, modes, curves? |
| Decoupling mechanism | Config, env var, runtime negotiation? |
| Spread | How many files/call-sites affected? |
| Ownership | First-party, vendored, or binary? |
| Runtime availability | Are replacement primitives ready? |

Dashboard shows **risk × migration difficulty**, not just severity alone.

---

## 15. Adaptive Scan Modes

The user does NOT choose which engines to run. The Mode Selector (in the Control Plane) inspects inputs and selects required capabilities. The Harness determines HOW those capabilities are executed.

```
  Input → Control Plane → Scope/Policy → Mode Selector → Agent Harness → Task Graph → Tools

  ┌───────────────────┐ ┌──────────────────┐ ┌────────────────────┐
  │   ⚡ MODE 1        │ │   ⚡ MODE 2       │ │   ⚡ MODE 3         │
  │                   │ │                  │ │                    │
  │  Input: URL only  │ │  Input: Repo only│ │  Input: URL + Repo │
  │                   │ │                  │ │                    │
  │  Capabilities:    │ │  Capabilities:   │ │  Capabilities:     │
  │  Runtime Security │ │  Code Security   │ │  Runtime Security  │
  │  Agent            │ │  Agent +         │ │  Agent +           │
  │                   │ │  Crypto Engine   │ │  Code Security     │
  │  Output:          │ │                  │ │  Agent +           │
  │  Runtime report   │ │  Output:         │ │  Crypto Engine     │
  │                   │ │  Code + Crypto   │ │                    │
  │  ⚠️ No source     │ │  report          │ │  Output:           │
  │    root-cause     │ │                  │ │  FULL correlated   │
  │  ⚠️ No crypto     │ │  ⚠️ No runtime    │ │  assessment        │
  │    analysis       │ │    exploit proof  │ │                    │
  │                   │ │                  │ │  ✅ Runtime proof    │
  │                   │ │                  │ │  ✅ Source root cause│
  │                   │ │                  │ │  ✅ Crypto posture   │
  └───────────────────┘ └──────────────────┘ └────────────────────┘
```

---

## 16. Execution Model

### Parallel vs Dependent Execution

The Harness dynamically determines execution order:

| Task Type | Example | Rule |
|---|---|---|
| **Parallel** | Runtime discovery ∥ Code inventory ∥ Crypto source scan | No dependencies — run simultaneously |
| **Dependent** | BOLA test depends on auth analysis + endpoint discovery | Wait for prerequisites |
| **Cross-engine** | Correlation depends on evidence from all active engines | Wait for all engines to complete |

### Task Lifecycle

```
  QUEUED → RUNNING → COMPLETED
                  → FAILED → RETRY (if retries remain)
                           → FAILED_FINAL
                  → TIMED_OUT → RETRY or FAILED_FINAL
                  → AWAITING_APPROVAL (human-in-the-loop)
```

---

## 17. Evidence Model

All security truth flows from structured evidence. Every finding must trace to one or more evidence records.

```
  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐
  │ 🌐 Runtime        │  │ 📝 Code           │  │ 🔐 Crypto         │
  │    Evidence       │  │    Evidence       │  │    Evidence       │
  │                  │  │                  │  │                  │
  │ HTTP requests,   │  │ File paths,      │  │ Algorithms,      │
  │ responses,       │  │ functions,       │  │ keys, certs,     │
  │ exploit proofs   │  │ line numbers,    │  │ CBOM entries     │
  └────────┬─────────┘  └────────┬─────────┘  └────────┬─────────┘
           │                     │                      │
           └─────────────────────┼──────────────────────┘
                                 │
                                 ▼
  ┌──────────────────────────────────────────────────────────────┐
  │                   📋 EVIDENCE NORMALIZER                      │
  │                                                              │
  │  • Converts ALL observations into ONE common schema          │
  │  • Deduplicates related findings while preserving evidence   │
  │  • Assigns source, confidence, location, relationships       │
  │                                                              │
  │  Without this, you get 3 reports in 3 formats.               │
  │  This creates one unified evidence language.                 │
  └──────────────────────────────────────────────────────────────┘
```

---

## 18. Security Graph

The graph connects entities across all evidence layers, enabling cross-layer correlation.

```
  ┌──────────────────────────────────────────────────────────────────┐
  │                      🕸️ SECURITY GRAPH                           │
  │                                                                  │
  │   ┌───────────┐                                                  │
  │   │🏢 App      │                                                  │
  │   └─────┬─────┘                                                  │
  │         │                                                        │
  │    ┌────┴────────────┐                                           │
  │    │                 │                                           │
  │    ▼                 ▼                                           │
  │  ┌──────────┐  ┌──────────┐  ┌──────────┐                       │
  │  │🌐Endpoint │  │⚡Function │  │💾Data     │                       │
  │  │/api/users │  │get_user()│  │ Asset    │                       │
  │  └─────┬────┘  └────┬─────┘  └──────────┘                       │
  │        │            │                                            │
  │        ├────────────┤                                            │
  │        │            │                                            │
  │        ▼            ▼                                            │
  │  ┌──────────┐  ┌──────────┐                                     │
  │  │🚨Finding  │  │📦Library  │                                     │
  │  │  BOLA    │  │ flask    │                                     │
  │  └──────────┘  └────┬─────┘                                     │
  │                     │                                            │
  │                     ▼                                            │
  │               ┌──────────┐  ┌──────────┐                        │
  │               │🔐Crypto   │──│📜Certifi- │                        │
  │               │ Asset    │  │  cate    │                        │
  │               └──────────┘  └──────────┘                        │
  │                                                                  │
  │  The graph reveals hidden connections. A "low severity"          │
  │  credential becomes "critical" when the graph shows it           │
  │  connects to a reachable endpoint accessing sensitive data.     │
  │                                                                  │
  │  Implementation: PostgreSQL with JSONB — no separate graph       │
  │  database required for MVP.                                      │
  └──────────────────────────────────────────────────────────────────┘
```

---

## 19. Correlation Engine

The Correlation Engine is **deterministic** — it is NOT replaced by LLM reasoning. The Deep Agent can request correlation, but the engine performs the actual matching.

```
  CORRELATION EXAMPLE 1: BOLA

  🌐 Runtime Agent proves:       📝 Code Agent finds:
  User A accessed                users.py:get_user()
  User B's data at               has NO authorization
  GET /api/users/102             check at line 47
         │                             │
         └────────────┬────────────────┘
                      ▼
              ┌──────────────┐
              │ ✅ CONFIRMED  │   Deterministic match:
              │    BOLA      │   Same endpoint +
              │              │   same function +
              │ Runtime proof│   matching behavior
              │ + Source root │
              │   cause      │
              └──────────────┘


  CORRELATION EXAMPLE 2: CRYPTO CHAIN

  📝 Source:        🐳 Container:     🌐 Protocol:
  RSA config        Same RSA config    RSA-based TLS
  in app code       in Docker layer    in live handshake
         │                │                  │
         └────────────────┼──────────────────┘
                          ▼
             ┌───────────────────┐
             │  ONE crypto asset  │
             │  THREE evidence    │
             │  sources           │
             └───────────────────┘


  CORRELATION EXAMPLE 3: ATTACK PATH

  🔑 Hardcoded      🌐 Endpoint is     💾 Accesses sensitive
  API key in    +   publicly reach-  + user payment
  config             able               data
         │                │                  │
         └────────────────┼──────────────────┘
                          ▼
             ┌───────────────────────┐
             │ 🚨 HIGH-PRIORITY       │
             │    ATTACK PATH        │
             └───────────────────────┘
```

---

## 20. Risk Engine

Risk calculation is **deterministic**. The LLM can explain the result but cannot arbitrarily override it.

```
  ┌────────────────────────┐
  │ Severity               │──┐
  │ (Critical/High/Med/Low)│  │
  └────────────────────────┘  │
  ┌────────────────────────┐  │
  │ Confidence             │──┤
  │ (Confirmed/Probable)   │  │
  └────────────────────────┘  │
  ┌────────────────────────┐  │    ┌──────────────────────┐    ┌─────────────────────┐
  │ Exploitability         │──┤    │                      │    │                     │
  │ (Can it be attacked?)  │  ├───▶│   ⚖️ RISK ENGINE       │───▶│ 📋 PRIORITIZED       │
  └────────────────────────┘  │    │                      │    │   REMEDIATION QUEUE  │
  ┌────────────────────────┐  │    │  Deterministic       │    │                     │
  │ Exposure               │──┤    │  composite scoring   │    │  Not an unordered   │
  │ (Internal vs external) │  │    │                      │    │  list — a RANKED    │
  └────────────────────────┘  │    └──────────────────────┘    │  action plan        │
  ┌────────────────────────┐  │                                └─────────────────────┘
  │ Asset Criticality      │──┤
  │ (How sensitive?)       │  │
  └────────────────────────┘  │
  ┌────────────────────────┐  │
  │ Evidence Strength      │──┤
  │ (How much proof?)      │  │
  └────────────────────────┘  │
  ┌────────────────────────┐  │
  │ Graph Connectivity     │──┘
  │ (What connects to it?) │
  └────────────────────────┘
```

---

## 21. 100% Offline & Air-Gapped Sovereign Architecture

AEGIS is designed from the ground up to operate **100% offline in air-gapped and high-security environments**. No telemetry, no external API calls, and no proprietary code or vulnerability data ever leaves the local environment.

### Local Model Gateway

```
  Agent Harness
       │
       ▼
  ┌──────────────────────────────────────────────────────────────┐
  │              🏠 SOVEREIGN LOCAL MODEL GATEWAY                │
  │                                                              │
  │  Unified interface to air-gapped local inference runtimes.   │
  │  The gateway abstracts the local model runner so the Harness  │
  │  operates seamlessly across CPU and GPU hardware.            │
  │                                                              │
  │  Supported Local Runtimes (100% Offline):                    │
  │  ├── Ollama (Local quantized model management)               │
  │  ├── llama.cpp (High-efficiency CPU/Metal/CUDA inference)    │
  │  ├── vLLM (High-throughput on-premise GPU inference)         │
  │  └── LocalAI / TGI (Self-hosted containerized endpoints)     │
  │                                                              │
  │  STRICT AIR-GAP GUARANTEE:                                   │
  │  • Zero outbound connections to external cloud LLM APIs      │
  │  • Zero telemetry or prompt logging to external endpoints    │
  │  • Complete data sovereignty within the local perimeter      │
  └────────────────────────┬─────────────────────────────────────┘
                           │
                           ▼
  ┌──────────────────────────────────────────────────────────────┐
  │               LOCAL INFERENCE SERVER                          │
  │               Running on-premise / on the local machine      │
  │               (e.g., Qwen2.5-Coder, Llama-3.1, Mistral)      │
  └────────────────────────┬─────────────────────────────────────┘
                           │
                           ▼
  ┌──────────────────────────────────────────────────────────────┐
  │                     LOCAL LLM                                 │
  │                                                              │
  │  Two offline responsibilities:                               │
  │                                                              │
  │  ROLE 1 — Harness Intelligence:                              │
  │  ├── Investigation planning                                  │
  │  ├── Tool selection & task graph assembly                    │
  │  ├── Re-planning based on tool execution results             │
  │  └── Investigation state reasoning                           │
  │                                                              │
  │  ROLE 2 — Security Intelligence:                             │
  │  ├── Evidence interpretation                                 │
  │  ├── Finding explanation & attack-path summarization         │
  │  ├── Actionable remediation code generation                  │
  │  └── Final report synthesis                                  │
  │                                                              │
  │  The LLM is NEVER responsible for:                           │
  │  ├── Authorization or scope validation (Harness enforces)   │
  │  ├── Tool permissions & sandbox containment                  │
  │  ├── Deterministic vulnerability confirmation                │
  │  └── Final mathematical risk scoring                         │
  └──────────────────────────────────────────────────────────────┘
```

### Complete Offline Subsystems

```
  ┌──────────────────────────────────────────────────────────────────┐
  │                  SOVEREIGN OFFLINE ECOSYSTEM                     │
  │                                                                  │
  │  📦 LOCAL VULNERABILITY DATABASE                                 │
  │  ├── Pre-bundled offline OSV / NVD / GitHub Advisory database    │
  │  ├── Stored in local embedded SQLite / DuckDB                    │
  │  └── Zero runtime queries to external CVE services               │
  │                                                                  │
  │  📜 PRE-PACKAGED RULESETS & SIGNATURES                           │
  │  ├── Semgrep / OpenGrep offline security rule pack (30+ langs)   │
  │  ├── Gitleaks local regex & entropy secret patterns              │
  │  ├── Checkov offline IaC policy engine                           │
  │  └── Crypto rule catalog (NIST PQC, Shor/Grover risk matrices)   │
  │                                                                  │
  │  🕊️ LOCAL EPHEMERAL CANARY LISTENER (SSRF Validation)           │
  │  ├── Embedded internal HTTP/DNS canary daemon                    │
  │  ├── Runs on localhost / internal isolated container network     │
  │  └── Validates SSRF without external third-party webhook SaaS    │
  │                                                                  │
  │  🧠 EMBEDDED LOCAL RAG & VECTOR SEARCH                           │
  │  ├── FastEmbed / local embedding models (e.g. BGE-Small / Nomic) │
  │  ├── ChromaDB / SQLite-vec running fully in-process              │
  │  └── Security knowledge retrieval with zero external calls       │
  └──────────────────────────────────────────────────────────────────┘
```

### Air-Gapped Network & Target Scope Clarification

- **"100% Offline"** means AEGIS requires zero internet access to perform full static code analysis, cryptographic discovery, CBOM generation, correlation, risk scoring, AI reasoning, and report generation.
- **Runtime Testing in Air-Gapped Environments:** Runtime security testing tests authorized targets running on the **local machine (localhost)**, **local Docker container network**, or an **isolated private intranet**.
- **Outbound Egress Block:** Outbound internet traffic is strictly blocked by default at the container/firewall boundary (`egress: drop`), preventing any data exfiltration.

---

## 22. Agent State

Every investigation maintains structured state. This is investigation state, not conversational memory.

```
  ┌──────────────────────────────────────────────────────────────┐
  │                     INVESTIGATION STATE                      │
  │                                                              │
  │  scan_id ──────────── Unique investigation identifier        │
  │  target ───────────── URL and/or repository                  │
  │  scope ────────────── Authorized testing boundaries          │
  │  mode ─────────────── MODE 1 / MODE 2 / MODE 3               │
  │  plan ─────────────── Current investigation plan             │
  │  task_graph ───────── Tasks with dependencies and status     │
  │  current_task ─────── Currently executing task               │
  │  agent_states ─────── Per-engine progress tracking           │
  │  tool_calls ───────── Log of every tool invocation           │
  │  evidence ─────────── Collected structured evidence          │
  │  findings ─────────── Normalized security findings           │
  │  graph_entities ───── Security Graph nodes and edges         │
  │  correlations ─────── Cross-layer correlation results        │
  │  risk_results ─────── Scored and prioritized findings        │
  │  artifacts ────────── Reports, CBOM, SARIF, VEX              │
  │  errors ───────────── Error log with context                 │
  │  budgets ──────────── Remaining LLM calls, tokens, time      │
  │  status ───────────── RUNNING / PAUSED / COMPLETED / FAILED  │
  └──────────────────────────────────────────────────────────────┘
```

### Memory Manager

| Type | Contents | Scope |
|---|---|---|
| **Short-term** | Current investigation context, intermediate results, tool outputs | Per-scan, ephemeral |
| **Persistent** | Previous finding status, remediation history, asset metadata, evidence references | Cross-scan, in PostgreSQL |

Entire repositories and raw secrets are NOT stored in agent memory. Evidence references point to the source — they don't duplicate it.

---

## 23. Checkpoint & Resume

The Harness saves checkpoints so investigations can resume after failure without restarting from scratch.

```
  EXAMPLE: Crypto Engine fails mid-scan

  ┌────────────────────────────────────────────────┐
  │  CHECKPOINT STATE                               │
  │                                                │
  │  Runtime Security Agent  ✅ COMPLETED            │
  │  Code Security Agent     ✅ COMPLETED            │
  │  Crypto Engine           ❌ FAILED at Stage 3    │
  │  Correlation             ⏳ PENDING              │
  │  Risk Engine             ⏳ PENDING              │
  │  Report                  ⏳ PENDING              │
  └────────────────────────┬───────────────────────┘
                           │
                           ▼ RESUME
  ┌────────────────────────────────────────────────┐
  │  RESUMED EXECUTION                              │
  │                                                │
  │  Runtime Security Agent  ⏭️ SKIPPED (done)       │
  │  Code Security Agent     ⏭️ SKIPPED (done)       │
  │  Crypto Engine           🔄 RETRY from Stage 3   │
  │  Correlation             ⏳ PENDING              │
  │  Risk Engine             ⏳ PENDING              │
  │  Report                  ⏳ PENDING              │
  └────────────────────────────────────────────────┘
```

---

## 24. Retry, Timeout & Budget Management

### Retry Manager

| Setting | Value |
|---|---|
| Max retries per tool call | Configurable (default: 3) |
| Backoff strategy | Exponential with jitter |
| Retry on | Timeout, transient network error, tool crash |
| Do not retry on | Permission denied, scope violation, budget exhausted |

### Timeout Manager

| Setting | Scope |
|---|---|
| Tool call timeout | Per individual tool execution |
| Task timeout | Per task in the task graph |
| Scan duration limit | Entire investigation |

### Budget Manager

| Budget | Purpose |
|---|---|
| Max LLM calls | Prevent infinite agent reasoning loops |
| Max tokens consumed | Control inference cost |
| Max tool calls | Prevent runaway tool execution |
| Max planning iterations | Prevent infinite re-planning |
| Scan duration cap | Hard time limit for investigation |
| CPU / memory limits | Per-sandbox resource caps |
| Network request limits | Rate limit for runtime testing |

---

## 25. Observability

### Agent Observability

| Category | What is tracked |
|---|---|
| **Scan lifecycle** | Created, started, mode selected, engines dispatched, completed/failed |
| **Agent lifecycle** | Deep Agent planning, re-planning, task transitions |
| **Task execution** | Task queued, started, completed, failed, retried |
| **Tool calls** | Tool name, arguments, duration, result status, evidence produced |
| **Tool latency** | Per-tool execution time for performance monitoring |
| **LLM calls** | Prompt, tokens used, response time, role (planning vs. reasoning) |
| **Evidence** | Evidence records created, normalized, deduplicated |
| **Findings** | Findings generated, correlated, risk-scored |
| **Report generation** | Export format, size, generation time |

### Outputs

- **Logs** — Structured JSON logs for every action
- **Metrics** — Counters and histograms for performance monitoring
- **Traces** — Distributed tracing across Harness → Tool → Engine
- **Agent execution history** — Full timeline of investigation decisions

---

## 26. Audit Trail

AEGIS is a security platform — its own actions must be fully auditable.

```
  ┌──────────────────────────────────────────────────────────────┐
  │                      AUDIT RECORD                             │
  │                                                              │
  │  user ────────────── Who initiated the scan                  │
  │  scan_id ─────────── Which investigation                     │
  │  agent ───────────── Which component acted                   │
  │  tool ────────────── Which tool was called                   │
  │  target ──────────── What was the target                     │
  │  timestamp ───────── When it happened                        │
  │  action ──────────── What was done                           │
  │  permission ──────── Was it allowed? Why/why not?            │
  │  result ──────────── Success / failure / timeout             │
  │  evidence_ref ────── Link to evidence produced               │
  │  retry_info ──────── Retry count, failure reason             │
  └──────────────────────────────────────────────────────────────┘
```

Audit records are immutable and stored in PostgreSQL.

---

## 27. Human-in-the-Loop

Optional approval gates for high-impact actions.

```
  Deep Agent Supervisor
       │
       │ "I want to run active BOLA testing
       │  against production-like endpoint"
       │
       ▼
  ┌──────────────────────────┐
  │  APPROVAL REQUIRED?       │
  │  Check policy rules       │
  └────────────┬─────────────┘
               │ yes
               ▼
  ┌──────────────────────────┐
  │  👤 HUMAN REVIEW          │
  │                          │
  │  Target: /api/users/{id} │
  │  Action: Active BOLA     │
  │  Risk: May modify state  │
  │                          │
  │  [Approve] [Reject]      │
  │  [Modify scope]          │
  └────────────┬─────────────┘
               │
               ▼
  Continue / Halt / Modify
```

### Approval may be required for

- High-impact active testing
- Destructive tests
- Scope expansion requests
- Sensitive / production targets
- Budget expansion
- Overriding scan intensity limits

---

## 28. Evaluation

AEGIS is an agentic system — its own performance must be measurable.

### Evaluation Dimensions

| Dimension | What is evaluated |
|---|---|
| **Planning quality** | Are investigation plans complete and efficient? |
| **Tool selection** | Are the right tools chosen for each task? |
| **Tool arguments** | Are tool arguments correct and well-formed? |
| **Security policy compliance** | Are scope and permission rules followed? |
| **Scope compliance** | Does the agent stay within authorized boundaries? |
| **Evidence quality** | Is evidence structured, complete, and reproducible? |
| **Investigation completeness** | Were all required checks performed? |
| **Correlation accuracy** | Are cross-layer correlations correct? |
| **Hallucination detection** | Does the LLM claim things not supported by evidence? |
| **Efficiency** | LLM calls, tool calls, total time vs. findings produced |
| **Failure recovery** | Does the system recover gracefully from tool failures? |
| **Checkpoint recovery** | Can investigations resume correctly from checkpoints? |

---

## 29. Storage Architecture

### Data Responsibility

| Store | Role | Contents |
|---|---|---|
| **PostgreSQL** | Persistent source of truth | Scans, findings, evidence, CBOM, Security Graph, correlations, risk scores, audit trail, investigation state, agent evaluation |
| **Redis** | Queue / cache / ephemeral state | Celery task queue, session cache, real-time scan progress, temporary coordination |
| **File Storage** | Generated artifacts | Reports (PDF/HTML), CBOM exports, SARIF files, VEX documents, CSV exports |

Redis is NOT the permanent source of truth. All durable data lives in PostgreSQL.

---

## 30. Technology Stack

### Backend & Orchestration

| Technology | Role | Why |
|---|---|---|
| **Python 3.12** | Core language | Best ecosystem for security tooling — all tools Python-native |
| **FastAPI** | API framework | Async-native, auto-docs, type-safe (Flask lacks async, Django too heavy) |
| **Redis** | Queue / cache | Fast in-memory queue, mature Celery integration |
| **Celery** | Async workers | Distributed task execution for long-running scans |
| **PostgreSQL** | Primary database | JSONB for flexible evidence + relational for structured queries |

### Security Tooling (100% Offline)

| Technology | Role | Problem Solved |
|---|---|---|
| **httpx** | HTTP requests | Async, HTTP/2, full response capture for runtime evidence |
| **Playwright** | Browser automation | JS-heavy login, SPAs, OAuth flows (runs headless browser locally) |
| **Nuclei** | Vuln templates | Pre-packaged offline community check templates |
| **Semgrep / OpenGrep** | SAST | Fast pattern-based detection with bundled offline rules, 30+ languages |
| **Tree-sitter** | AST parsing | High-speed structural code understanding without external dependencies |
| **OSV-Scanner** | Dependency CVEs | Bundled offline vulnerability database cache (SQLite/DuckDB) |
| **Gitleaks** | Secret detection | Low false-positive credential scanning with local regex/entropy rules |
| **Checkov** | IaC security | Docker/Terraform/K8s checks with pre-packaged local policies |

### Crypto Tooling

| Technology | Role | Problem Solved |
|---|---|---|
| **Python cryptography + pyjks** | Cert/key parsing | PEM, DER, PKCS#12, JKS formats |
| **YARA/findcrypt + LIEF** | Binary analysis | Crypto constants in compiled binaries |
| **cbomkit-theia** | Container crypto | Crypto in Docker layers |
| **CryptoLyzer + tshark** | Protocol analysis | Actual negotiated TLS/SSH algorithms |
| **cyclonedx-python-lib** | CBOM generation | Industry-standard crypto BOM |
| **Syft** | Dependency graph | Deep transitive dependency resolution |

### Frontend

| Technology | Role | Why |
|---|---|---|
| **React + TypeScript** | UI framework | Component model for complex dashboards |
| **Vite** | Build tool | Fastest HMR, modern ESM-native |

### Sovereign Local AI & Embeddings (100% Offline)

| Technology | Role | Why |
|---|---|---|
| **Local Model Gateway** | Inference abstraction | Decouples Harness from local inference runtimes |
| **Ollama / llama.cpp / vLLM** | Local inference engines | 100% air-gapped local execution (Qwen2.5-Coder, Llama-3.1, Mistral) |
| **FastEmbed / BGE-Small** | Local embedding engine | Offline vector generation without external cloud API calls |
| **ChromaDB / SQLite-vec** | Local vector store | In-process retrieval for security rules and knowledge base |

---

## 31. Reporting / CBOM / SARIF / VEX

```
  ┌──────────────────────────────────────────────────────────────────┐
  │                    📊 AEGIS FINAL REPORT                          │
  │                                                                  │
  │  COVERAGE: Shows what was tested vs. what could not be tested    │
  │                                                                  │
  │  EACH FINDING CONTAINS:                                          │
  │  ├── Title + OWASP/crypto category                               │
  │  ├── Severity (Critical/High/Medium/Low)                         │
  │  ├── Confidence (Confirmed/Probable/Potential)                    │
  │  ├── Affected asset (endpoint, function, crypto asset)           │
  │  ├── Evidence (HTTP request/response, code snippet, crypto obs)  │
  │  ├── Source location (file, function, line)                      │
  │  ├── Root cause (why the vulnerability exists)                   │
  │  ├── Impact (business/security impact)                           │
  │  ├── Remediation (specific fix recommendation)                   │
  │  └── Verification state (re-test instructions)                   │
  │                                                                  │
  │  EXPORTS (Generated 100% Locally):                               │
  │  ├── PDF / HTML Report                                           │
  │  ├── CycloneDX CBOM (crypto bill of materials)                   │
  │  ├── SARIF (IDE/CI integration)                                  │
  │  ├── VEX (vulnerability exploitability exchange)                  │
  │  └── CSV (custom analysis)                                       │
  └──────────────────────────────────────────────────────────────────┘
```

---

## 32. Deployment Architecture (Air-Gapped & Sovereign)

```
  ┌──────────────────────────────────────────────────────────────────┐
  │                       Load Balancer                              │
  └───────────────────────────┬──────────────────────────────────────┘
                              │
  ┌───────────────────────────┴──────────────────────────────────────┐
  │              FastAPI Application Server(s)                       │
  │              Control Plane + API Gateway                         │
  └───────────────────────────┬──────────────────────────────────────┘
                              │
              ┌───────────────┼───────────────┐
              │               │               │
      ┌───────┴───────┐ ┌────┴────┐ ┌────────┴───────────────┐
      │  PostgreSQL   │ │  Redis  │ │ Celery Workers          │
      │               │ │ Broker  │ │                         │
      │  Source of    │ │         │ │  ┌───────────────────┐  │
      │  truth:       │ │ Queue,  │ │  │ Agent Harness     │  │
      │  Scans,       │ │ Cache,  │ │  │  ├─ Deep Agent    │  │
      │  Findings,    │ │ Sessions│ │  │  ├─ Tool Executor │  │
      │  Evidence,    │ │         │ │  │  └─ Sandbox       │  │
      │  Audit        │ │         │ │  ├───────────────────┤  │
      │               │ │         │ │  │ Security Engines  │  │
      │               │ │         │ │  │  ├─ Runtime Agent │  │
      │               │ │         │ │  │  ├─ Code Agent    │  │
      │               │ │         │ │  │  └─ Crypto Engine │  │
      │               │ │         │ │  └───────────────────┘  │
      └───────┬───────┘ └─────────┘ └────────────┬────────────┘
              │                                  │
      ┌───────┴───────┐                    ┌─────┴──────┐
      │ Local Chroma/ │                    │ Local LLM  │
      │ SQLite-vec DB │                    │ (Ollama /  │
      │ (Local RAG)   │                    │  llama.cpp)│
      └───────────────┘                    └────────────┘

  Dev: Docker Compose (Air-Gapped)  │  Production: Air-Gapped Kubernetes / Bare Metal
  All components run locally on sovereign hardware — zero external cloud egress.
```

---

## 33. Security Controls Summary

```
  ┌──────────────────────────────────────────────────────────────────┐
  │                                                                  │
  │  🚫 AEGIS NEVER:                           ✅ AEGIS ALWAYS:      │
  │  ──────────────                            ─────────────────     │
  │                                                                  │
  │  • Makes external cloud API calls         • Operates 100%        │
  │    or transmits telemetry                   offline & air-gapped │
  │                                                                  │
  │  • Scans without authorized scope         • Requires scope       │
  │                                             authorization        │
  │  • Invents findings from LLM                                     │
  │    imagination                            • Attaches confidence  │
  │                                             to every finding     │
  │  • Claims source root-cause                                      │
  │    without source evidence                • Distinguishes:       │
  │                                             Confirmed /          │
  │  • Claims binary crypto constant            Probable /           │
  │    = active use                             Potential            │
  │                                                                  │
  │  • Auto-patches code without              • Redacts secrets in   │
  │    review                                   logs and reports     │
  │                                                                  │
  │  • Lets Deep Agent bypass scope           • Uses local ephemeral │
  │    or permissions                           canary for SSRF      │
  │                                                                  │
  │  • Exploits internal services             • Constrains LLM by   │
  │    via SSRF                                 structured evidence  │
  │                                                                  │
  │  • Sends prompts/code to cloud            • Runs local inference │
  │    LLM providers                            (Ollama / llama.cpp) │
  │                                                                  │
  │  • Stores raw secrets in                  • Rate-limits all      │
  │    agent memory                             test payloads        │
  │                                                                  │
  │  • Runs repo code on the                  • Sandboxes all tool   │
  │    host machine directly                    execution            │
  └──────────────────────────────────────────────────────────────────┘
```

---

## 34. End-to-End Flow — Mode 3 (Full Assessment)

```
  👤 User submits URL + Repository (within local / air-gapped network)
       │
       ▼
  CONTROL PLANE
  ├── Authenticate user
  ├── Authorize scan
  ├── Validate scope (URL domain, repo access)
  ├── Validate policy (rate limits, intensity, air-gap boundary)
  └── Mode Selector → MODE 3 (all engines)
       │
       ▼
  AGENT HARNESS
  ├── Create investigation state
  ├── Deep Agent Supervisor plans investigation (via Local LLM)
  ├── Task Graph created:
  │   ├── [PARALLEL] Runtime discovery + Code inventory + Crypto source scan
  │   ├── [DEPENDENT] Runtime auth analysis (after discovery)
  │   ├── [DEPENDENT] Runtime BOLA/SSRF/injection (after auth)
  │   ├── [DEPENDENT] Code SAST/deps/secrets (after inventory + AST)
  │   └── [DEPENDENT] Correlation (after all engines complete)
  │
  ├── Tool Registry → Permission Check → Sandbox → Execute
  │
  │   ┌─── PARALLEL ──────────────────────────────────────────┐
  │   │                                                        │
  │   │  🌐 Runtime Security Agent    📝 Code Security Agent    │
  │   │  Discover → Auth → BOLA      Inventory → AST → SAST   │
  │   │  → SSRF (Local Canary)       → Offline CVEs → Secrets │
  │   │  → Injection → Misconfig     → IaC Policy Checks      │
  │   │         │                            │                 │
  │   │         │                     🔐 Crypto Engine          │
  │   │         │                     6 Collectors → CBOM      │
  │   │         │                     → Enrich → Risk          │
  │   │         │                            │                 │
  │   └─────────┼────────────────────────────┘                 │
  │             │                                              │
  │             ▼                                              │
  │   📋 Evidence Normalizer (common schema)                    │
  │             │                                              │
  │             ▼                                              │
  │   🕸️ Security Graph (connect entities in PostgreSQL)        │
  │             │                                              │
  │             ▼                                              │
  │   🔗 Correlation Engine (deterministic matching)            │
  │             │                                              │
  │             ▼                                              │
  │   ⚖️ Risk Engine (deterministic scoring)                    │
  │             │                                              │
  │             ▼                                              │
  │   🏠 Sovereign Local Model Gateway → Local LLM              │
  │   ├── Explain findings                                     │
  │   ├── Generate remediation                                 │
  │   └── Generate report                                      │
  │             │                                              │
  │   Store results in PostgreSQL                              │
  │   Checkpoint: COMPLETED                                    │
  │                                                            │
  └── Deliver unified report + CBOM + SARIF + VEX (Local files)│
       │
       ▼
  👤 User receives one evidence-backed security assessment
```

---

## 35. Future Enhancements

- Air-gapped offline model quantization & specialized SLM fine-tuning (LoRA / GGUF)
- Offline ruleset update bundles (air-gapped tarball synchronizer for CVE/CWE data)
- Additional security engine plugins (API fuzzing, mobile analysis)
- Multi-tenant scan management
- Scheduled / recurring scans on internal network schedules
- IDE plugins for developer workflows
- Advanced attack path simulation
- Compliance framework overlays (SOC2, ISO 27001, NIST)
- PQC/hybrid recommendation engine with migration optimizer
- Signed CBOM with cryptographic attestation
- CI/CD pipeline gates with configurable thresholds
