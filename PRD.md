# AEGIS — Product Requirements Document (PRD)

## 1. Executive Summary

**AEGIS** (Adaptive Application Security & Cryptographic Risk Platform) is a unified, **100% offline and air-gapped** application-security platform that consolidates runtime security testing, static code analysis, and cryptographic risk assessment into a single, correlated assessment.

Operating entirely within sovereign on-premise or air-gapped enterprise environments, AEGIS uses local AI models and deterministic security engines to answer one critical question:

> *"What is actually wrong with my application, where is the root cause, and what should I fix first?"*

---

## 2. Problem Statement

Application security is fragmented across disconnected tools, creating three critical blind spots:

| Blind Spot | Description |
|---|---|
| **Runtime Blind Spot** | A live scanner can show an app is vulnerable, but cannot explain *which source-code component* caused the problem |
| **Source-Code Blind Spot** | A code scanner can find dangerous patterns, but cannot prove the deployed application is *actually exploitable* |
| **Cryptography Disconnect** | Weak algorithms, bad key handling, certificates, and insecure crypto settings are reported in isolation from application-security findings |

**Result:** Security teams receive a large, unordered collection of findings instead of one clear, prioritized, correlated assessment.

---

## 3. Product Vision

> **Agent 1 tells us *what* is happening. Agent 2 tells us *why* it is happening. The Crypto Engine tells us *what is wrong with the cryptography*. AEGIS connects all of this information.**

AEGIS adapts its assessment to the evidence available — a URL enables runtime testing, a repository enables source and crypto analysis, and providing both enables the platform's most powerful capability: **cross-layer correlation and decision support**.

---

## 4. Target Users

| Persona | Needs |
|---|---|
| **Application Security Engineers** | Unified vulnerability assessment with root-cause analysis |
| **Development Teams** | Actionable remediation guidance tied to specific code locations |
| **CISOs / Security Leadership** | Prioritized risk view with cryptographic posture and quantum readiness |
| **DevSecOps / CI-CD Integrators** | Automated scanning with CI gate integration and exportable reports |
| **Cryptography / Compliance Teams** | CBOM-based crypto inventory, quantum risk assessment, and migration planning |

---

## 5. Core Capabilities

### 5.1 Three Security Engines

#### Agent 1 — Runtime Security Agent
Tests the live website/API from the outside. Covers:
- **Authentication** — Weak login/session behavior
- **Authorization / BOLA** — Cross-user object access (Broken Object Level Authorization)
- **SSRF** — Server-Side Request Forgery via controlled callback/canary
- **Injection** — Basic SQL/command/template injection indicators
- **Misconfiguration** — Unsafe headers, exposed services, security configuration issues

#### Agent 2 — Code Security Agent
Scans the repository for source-level weaknesses. Covers:
- Multi-language code model via AST-aware parsing
- SAST rules and vulnerability pattern detection
- Dependency analysis and known CVE detection
- Secret and credential detection
- Infrastructure-as-Code (IaC) security checks
- File/function/line/data-flow evidence attachment

#### Crypto Engine (ECDAT-based)
Enterprise Cryptographic Discovery & Analysis Tool. Covers:
- **Discovery** — Crypto APIs, algorithms, keys, certificates, binary constants, protocol negotiations
- **Normalization** — Unified Cryptography Bill of Materials (CBOM)
- **Enrichment** — Production/test classification, security-sensitive usage, exposure context
- **Quantum Risk** — Shor/Grover/legacy/safe classification with Mosca-style X+Y>Z reasoning
- **Migration Planning** — EXPOSED / ACT NOW / MONITOR / SAFE tiers with crypto-agility assessment

### 5.2 Correlation Engine (The Differentiator)
The **Common Intelligence Layer** is what transforms individual scanners into AEGIS:
- **Evidence Normalizer** — Common schema for runtime, code, and crypto observations
- **Security Graph** — Relationships: Endpoint ↔ Function ↔ Finding ↔ Library ↔ CryptoAsset ↔ Certificate
- **Correlation** — Connects runtime proof-of-exploitation with source-code root causes
- **Risk Engine** — Prioritized remediation queue (severity × confidence × exploitability × exposure × criticality)
- **LLM Reasoning** — Explains findings, summarizes attack paths, generates remediation guidance — constrained by structured evidence (never invents test results)

---

## 6. Three Scan Modes

AEGIS automatically selects the appropriate mode based on user-provided inputs — no manual mode selection required.

### Mode 1 — URL Only
| Aspect | Detail |
|---|---|
| **Input** | Live application URL |
| **Engines** | Agent 1 only |
| **Output** | Runtime security report |
| **Limitation** | No source-code root-cause analysis; no crypto analysis |

### Mode 2 — Repository Only
| Aspect | Detail |
|---|---|
| **Input** | GitHub / repository URL |
| **Engines** | Agent 2 + Crypto Engine |
| **Output** | Code + Cryptography report |
| **Limitation** | No runtime exploitation proof |

### Mode 3 — URL + Repository (Full Assessment)
| Aspect | Detail |
|---|---|
| **Input** | Both deployed URL and repository |
| **Engines** | Agent 1 + Agent 2 + Crypto Engine |
| **Output** | Full correlated report |
| **Value** | Cross-layer correlation — runtime proof + source root cause + crypto posture |

---

## 7. Functional Requirements

### 7.1 Input Handling
- FR-1: Accept a live application URL as input
- FR-2: Accept a GitHub/repository URL or local source tree as input
- FR-3: Accept both URL and repository simultaneously
- FR-4: Auto-detect scan mode based on provided inputs
- FR-5: Validate URL, scope, protocol, and redirect behavior before scanning

### 7.2 Agent 1 — Runtime Security
- FR-10: Crawl and discover endpoints (crawling, browser navigation, known API paths, OpenAPI/Swagger)
- FR-11: Identify authentication mechanisms and establish test identities
- FR-12: Build application model (endpoints, parameters, methods, cookies/tokens, responses)
- FR-13: Execute BOLA tests with two authenticated identities
- FR-14: Execute SSRF tests with controlled callback/canary infrastructure
- FR-15: Execute basic injection tests (SQL, command, template)
- FR-16: Check security headers and misconfiguration
- FR-17: Collect full request/response evidence for every finding
- FR-18: Normalize findings with severity and confidence scores

### 7.3 Agent 2 — Code Security
- FR-20: Inventory languages, frameworks, package manifests, entry points, API routes
- FR-21: Build multi-language code model using AST-aware parsing (Tree-sitter)
- FR-22: Run SAST rules via Semgrep/OpenGrep
- FR-23: Analyze dependencies for known vulnerabilities (OSV-Scanner)
- FR-24: Detect secrets and credentials (Gitleaks)
- FR-25: Analyze IaC and deployment configuration (Checkov)
- FR-26: Attach file/function/line/data-flow evidence to every finding

### 7.4 Crypto Engine
- FR-30: Source collector — scan code for crypto APIs, algorithms, modes, key sizes, hardcoded keys
- FR-31: Dependency collector — identify crypto libraries and transitive packages
- FR-32: Certificate & Key collector — parse PEM/DER/PKCS#12/JKS material
- FR-33: Binary collector — detect crypto constants, symbols, library indicators (best-effort)
- FR-34: Container collector — unpack OCI/TAR image layers and re-run collectors
- FR-35: Protocol collector — analyze negotiated TLS/SSH/IKE algorithms and certificates
- FR-36: Normalize all findings into a Cryptography Bill of Materials (CBOM)
- FR-37: Classify quantum impact (Shor-broken / Grover-weakened / Legacy-broken / Safe-PQC)
- FR-38: Implement Mosca-style X+Y>Z migration reasoning
- FR-39: Assign risk tiers: EXPOSED / ACT NOW / MONITOR / SAFE
- FR-40: Calculate crypto-agility across multiple dimensions (algorithm coupling, provider coupling, parameter coupling, spread, ownership)

### 7.5 Correlation & Intelligence
- FR-50: Normalize evidence from all engines into a common schema
- FR-51: Build a Security Graph connecting endpoints, functions, findings, libraries, crypto assets
- FR-52: Correlate runtime findings with source-code root causes (e.g., BOLA endpoint → missing auth function)
- FR-53: Calculate composite risk scores incorporating severity, confidence, exploitability, and exposure
- FR-54: Generate prioritized remediation queue
- FR-55: LLM-powered explanation and guidance generation — always grounded in structured evidence

### 7.6 Reporting & Export
- FR-60: Generate unified assessment report (HTML/PDF)
- FR-61: Clearly distinguish what was tested vs. what could not be tested
- FR-62: Each finding includes: title, OWASP/crypto category, severity, confidence, affected asset, evidence, source location, root cause, impact, remediation, verification state
- FR-63: Export CycloneDX CBOM
- FR-64: Export VEX-style status documents
- FR-65: Export SARIF format for IDE/CI integration
- FR-66: Export CSV for custom analysis

### 7.7 Security & Safety Controls
- FR-70: Require authorized scope for runtime testing
- FR-71: Enforce rate limits and controlled payloads
- FR-72: Use local ephemeral callback/canary listener for SSRF validation (no third-party cloud webhook dependencies)
- FR-73: Never claim source-level root cause without source evidence
- FR-74: Never claim a binary constant proves active cryptographic use
- FR-75: Attach confidence levels to every finding
- FR-76: Constrain LLM reasoning strictly by structured evidence
- FR-77: Redact discovered secrets in logs and reports
- FR-78: 100% Offline & Air-Gapped Operation — zero outbound internet requests, zero telemetry, zero cloud LLM dependencies
- FR-79: Distinguish confirmed / probable / potential findings

---

## 8. Non-Functional Requirements

| Category | Requirement |
|---|---|
| **Performance** | Scan a medium-sized application (50 endpoints, 100K LOC) within 30 minutes |
| **Scalability** | Async worker architecture to handle concurrent scans |
| **Reliability** | Graceful handling of scan failures; partial results preserved |
| **Data Sovereignty & Security** | 100% air-gapped; zero external telemetry or cloud egress; secrets redacted; scoped testing only |
| **Extensibility** | Plugin-based collector architecture; hot-swappable crypto collectors |
| **Auditability** | All evidence preserved; CBOM cryptographically signed; reproducible findings |
| **Usability** | Single-input simplicity; auto-mode selection; developer-friendly reports |

---

## 9. User Experience Flow

```
1. User enters URL and/or Repository → 
2. AEGIS auto-selects scan mode → 
3. Appropriate engines execute in parallel → 
4. Evidence normalized and correlated → 
5. Security Graph built → 
6. Risk scored and prioritized → 
7. LLM generates explanations and remediation → 
8. Final unified report presented → 
9. User can fix and re-test for verification
```

---

## 10. Report Structure

### Findings Card Format
Each finding in the report contains:

| Field | Description |
|---|---|
| **Title** | Descriptive vulnerability name |
| **Category** | OWASP / Crypto classification |
| **Severity** | Critical / High / Medium / Low / Info |
| **Confidence** | Confirmed / Probable / Potential |
| **Affected Asset** | Endpoint, function, crypto asset |
| **Evidence** | HTTP request/response, code snippet, crypto observation |
| **Source Location** | File, function, line number |
| **Root Cause** | Why the vulnerability exists |
| **Impact** | Business/security impact |
| **Remediation** | Specific fix recommendation |
| **Verification** | Re-test instructions |

---

## 11. Implementation Phases

### Phase 1 — AEGIS Foundation
- Build orchestrator and input router
- Agent 1 MVP: discovery, authentication, BOLA, SSRF, basic injection, misconfiguration
- Agent 2 MVP: repository inventory, SAST, dependencies, secrets
- Define common finding/evidence schema

### Phase 2 — Crypto Engine Foundation
- Source crypto collector
- Dependency and certificate/key collectors
- CBOM normalization and initial emission
- Algorithm knowledge base and basic risk classification

### Phase 3 — Full Correlation
- Security Graph implementation
- Runtime-to-source finding correlation
- Container, binary, and live protocol collectors
- Crypto-agility and risk × agility visualization

### Phase 4 — Decision Layer
- HNDL-aware Mosca-style model
- Migration tiers with user-adjustable Z assumption
- PQC/hybrid recommendation mappings
- Migration optimizer, VEX, CI gate, signed CBOM, richer reports

---

## 12. Hackathon Demo Plan

1. Enter deployed URL → run URL-only scan
2. Show Agent 1 discovering exploitable BOLA and SSRF with concrete evidence
3. Add GitHub repository → rerun complete assessment
4. Show Agent 2 mapping BOLA to the responsible source function
5. Show Crypto Engine finding weak crypto or hardcoded key
6. Open Security Graph → demonstrate endpoint ↔ function ↔ finding ↔ crypto asset relationships
7. Show risk prioritization and remediation recommendations
8. Fix one vulnerability → run focused re-test for verification
9. Export final report/CBOM

---

## 13. Success Metrics

| Metric | Target |
|---|---|
| **Correlation accuracy** | ≥80% of runtime findings correctly linked to source root causes |
| **False positive rate** | <15% across all engines |
| **CBOM completeness** | ≥90% of crypto assets discovered in labelled test corpus |
| **Scan time** | <30 min for medium applications |
| **User comprehension** | Report is actionable without external security expertise |

---

## 14. Interfaces

| Interface | Purpose |
|---|---|
| **CLI** | Scriptable scanning for power users and CI/CD |
| **REST API** | Programmatic integration with security workflows |
| **Web Dashboard** | Interactive exploration of findings, Security Graph, and reports |
| **CI/CD Gate** | Pass/fail decisions based on configured risk thresholds |
