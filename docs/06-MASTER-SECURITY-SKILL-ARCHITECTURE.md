# NG's Hachiman Agent
## Master Security Skill & Autonomous Offensive Security Architecture

> **HACHIMAN — The AI-native ethical hacker that thinks like an adversary, tests like a security engineer, proves what it finds, explains why it exists, gives the AI builder an exact repair contract, and independently verifies the fix.**

**Core loop:** `DISCOVER → MAP → HYPOTHESIZE → ATTACK → ADAPT → CHAIN → VALIDATE → EXPLAIN → FIX → RETEST`

---

# 1. Executive Vision

Hachiman is an authorized, AI-native offensive-security skill and autonomous security agent. It is designed to behave more like a skilled ethical hacker than a traditional vulnerability scanner.

The central workflow is:

```text
Understand target
   ↓
Map attack surface
   ↓
Form security hypotheses
   ↓
Select relevant attacks
   ↓
Test
   ↓
Observe behavior
   ↓
Adapt
   ↓
Chain weaknesses
   ↓
Validate impact
   ↓
Prove vulnerability
   ↓
Explain root cause
   ↓
Create AI Repair Contract
   ↓
AI builder fixes
   ↓
Hachiman retests
   ↓
Verified / unresolved
```

Hachiman's AI reasoning layer determines what should be investigated; its security engine enforces authorization, scope, policy, resource limits and safe execution boundaries.

---

# 2. Product Architecture

```text
┌─────────────────────────────────────────────┐
│              HACHIMAN SKILL                 │
│ AI-builder-facing instructions/orchestration │
└──────────────────────┬──────────────────────┘
                       │
┌──────────────────────▼──────────────────────┐
│              HACHIMAN AGENT                 │
│ adversarial reasoning + orchestration       │
└──────────────────────┬──────────────────────┘
                       │
┌──────────────────────▼──────────────────────┐
│          HACHIMAN SECURITY ENGINE            │
│ scope + policy + execution + validation     │
└──────────────────────┬──────────────────────┘
                       │
┌──────────────────────▼──────────────────────┐
│             SECURITY TOOL LAYER              │
│ browser/API/mobile/cloud/container/etc.     │
└─────────────────────────────────────────────┘
```

---

# 3. Mission

1. **Discover** — understand the authorized target.
2. **Attack** — test realistic security hypotheses.
3. **Prove** — validate findings with evidence.
4. **Explain** — identify root cause and impact.
5. **Repair and Verify** — produce an AI Repair Contract and independently retest the fix.

---

# 4. Authorization and Rules of Engagement

Every engagement begins with:

```text
IDENTITY → AUTHORIZATION → TARGET SCOPE → RULES OF ENGAGEMENT → TEST
```

Targets must be owned, explicitly authorized, local labs, sanctioned staging systems, or otherwise within documented permission.

Machine-readable engagement policy should define:

```yaml
engagement:
  target: authorized-target
  environment: staging
  allowed_domains: []
  allowed_networks: []
  test_categories: []
  destructive_testing: false
  data_exfiltration: prohibited
  persistence: prohibited
  max_duration: configured
  max_concurrency: configured
```

Hachiman must stop when an operation exceeds the authorized scope.

---

# 5. Hacker Psychology Model

Hachiman models professional adversarial reasoning:

- **Curiosity:** What exists that the owner may not realize is exposed?
- **Enumeration:** What are all possible entry points?
- **Trust skepticism:** What does the system trust that it should verify?
- **Boundary testing:** Can a user cross a boundary they should not cross?
- **Assumption breaking:** What developer assumption can be invalidated?
- **Privilege thinking:** If this capability is obtained, what can it reach next?
- **Chaining:** Can multiple moderate weaknesses create a critical path?
- **Adaptation:** What did the previous response reveal?
- **Evidence:** Can the behavior be reproduced?
- **Root cause:** Why does the vulnerability exist?

The objective is realistic security reasoning, not uncontrolled destructive behavior.

---

# 6. Universal Offensive Lifecycle

```text
AUTHORIZATION
      ↓
RECONNAISSANCE
      ↓
TECHNOLOGY IDENTIFICATION
      ↓
ATTACK-SURFACE MAPPING
      ↓
THREAT MODEL
      ↓
HYPOTHESIS GENERATION
      ↓
TEST PRIORITIZATION
      ↓
CONTROLLED ATTACK
      ↓
OBSERVATION
      ↓
ADAPTIVE NEXT ACTION
      ↓
EXPLOIT VALIDATION
      ↓
ATTACK CHAINING
      ↓
IMPACT ASSESSMENT
      ↓
ROOT-CAUSE ANALYSIS
      ↓
AI REPAIR CONTRACT
      ↓
BUILDER FIX
      ↓
ORIGINAL-ATTACK RETEST
      ↓
REGRESSION VALIDATION
```

---

# 7. Target Families

Hachiman should recognize and adapt to:

- websites and web applications;
- REST APIs;
- GraphQL;
- WebSockets;
- webhooks;
- backend services;
- databases;
- desktop software;
- Android applications;
- iOS applications;
- games and game backends;
- AI applications;
- AI agents;
- MCP servers;
- cloud infrastructure;
- containers;
- Kubernetes;
- CI/CD;
- storage;
- enterprise software;
- microservices;
- serverless systems;
- IoT/embedded systems.

---

# 8. Technology Detection

Hachiman creates a technology fingerprint before selecting attacks.

### Frontend

React, Next.js, Angular, Vue, Svelte, Nuxt, static HTML/JS, Electron and related technologies.

### Backend

Node.js, Express, NestJS, Django, Flask, FastAPI, Spring, Kotlin, ASP.NET/.NET, PHP/Laravel, Ruby on Rails, Go, Rust and related stacks.

### Databases

PostgreSQL, MySQL, MariaDB, SQL Server, SQLite, MongoDB, Redis, Elasticsearch, Cassandra and other authorized datastores.

### Infrastructure

Docker, Kubernetes, Nginx, Apache, serverless, service meshes, queues and cloud gateways.

### AI

Model APIs, local model runtimes, agent frameworks, tool systems, MCP, vector databases and retrieval pipelines.

Technology detection determines which specialists and tests are relevant.

---

# 9. Web Security

## Recon

Map routes, parameters, forms, authentication boundaries, cookies, headers, APIs, JavaScript-discovered endpoints, upload/download functionality and administrative surfaces.

## Authentication

Assess authorized environments for authentication bypass, weak authentication logic, session weaknesses, password-reset weaknesses, recovery weaknesses, token/JWT handling, MFA implementation, session fixation and invalidation.

## Authorization

Assess IDOR/BOLA, horizontal and vertical privilege escalation, function/object-level authorization, cross-tenant access and hidden administrative routes.

## Injection

Relevant families include SQL, NoSQL, command, LDAP, XPath, template, expression-language, header, log and ORM/query-layer injection.

## Browser

Assess reflected/stored/DOM XSS, CSRF, clickjacking-related weaknesses, insecure client-side state and browser storage.

## Server

Assess SSRF, unsafe deserialization, path traversal, file inclusion where applicable, unsafe file processing, server-side template injection, request smuggling, response splitting and cache-related weaknesses.

## Configuration

Assess debug exposure, administrative exposure, default configuration, security headers, CORS and unintended public resources.

---

# 10. API Security

Support REST, GraphQL, WebSocket, webhook and authorized RPC/gRPC-style interfaces.

```text
Discovery
 ↓
Authentication
 ↓
Authorization
 ↓
Schema
 ↓
Input validation
 ↓
Output exposure
 ↓
Rate controls
 ↓
Business logic
 ↓
Object boundaries
 ↓
Cross-service trust
```

---

# 11. Backend Security

Analyze authorized route handlers, controllers, middleware, authentication/authorization layers, data-access layers, queues, background workers, file systems, serialization, secrets and environment configuration.

Combine source analysis and runtime behavior where permitted.

---

# 12. Database Security

Relevant technologies:

- PostgreSQL
- MySQL
- MariaDB
- SQL Server
- SQLite
- MongoDB
- Redis
- Elasticsearch

Test categories:

- injection;
- unsafe query construction;
- excessive database privileges;
- insecure exposure;
- authorization failures;
- sensitive-data exposure;
- unsafe administrative operations;
- tenant isolation;
- secret handling.

Prefer non-destructive proof where sufficient.

---

# 13. Mobile Security

## Android

Assess authorized APK/AAB targets for permissions, exported components, intents, deep links, WebViews, local storage, API communication, authentication, cryptographic usage and platform boundaries.

Potential lab/tool integrations include Android SDK, Android Emulator, ADB, JADX, apktool and Frida.

## iOS

Assess authorized IPA/application targets for URL schemes, universal links, permissions, Keychain usage, local storage, network security, authentication, WebViews and runtime behavior.

Potential lab/tool integrations include Xcode tooling, iOS Simulator, Frida and LLDB.

### Mobile workflow

```text
Package discovery
 ↓
Static analysis
 ↓
Permission analysis
 ↓
Runtime observation
 ↓
API mapping
 ↓
Authentication
 ↓
Authorization
 ↓
Storage
 ↓
Platform boundaries
 ↓
Evidence
 ↓
Repair / Retest
```

---

# 14. Game Security

Treat games as:

```text
Game Client
 ├── Local state
 ├── Authentication
 ├── Assets
 ├── Configuration
 └── Network client
          ↓
     Game Backend
       ├── API
       ├── Match logic
       ├── Economy
       └── Persistence
```

Assess authorized environments for:

- client/server trust;
- authentication;
- authorization;
- API security;
- multiplayer state validation;
- economy/business logic;
- transaction validation;
- save/state integrity;
- local storage;
- debug functionality;
- backend privilege boundaries;
- anti-cheat/security boundaries.

Detect common engines such as Unity, Unreal Engine, Godot and custom engines.

Do not treat live third-party game services as authorized targets merely because they are reachable.

---

# 15. AI Application Security

Dedicated AI testing includes:

- direct prompt injection;
- indirect prompt injection;
- instruction hijacking;
- system/context leakage;
- sensitive-context exposure;
- tool abuse;
- excessive agency;
- unsafe tool chaining;
- data exfiltration;
- memory/context poisoning;
- retrieval poisoning;
- goal manipulation;
- multi-agent trust abuse;
- unsafe autonomous actions.

Example attack path:

```text
Untrusted Content
      ↓
Indirect Prompt Injection
      ↓
Agent follows instruction
      ↓
Privileged Tool
      ↓
Sensitive Data
      ↓
External Destination
```

---

# 16. MCP Security

MCP is a first-class Hachiman security domain.

```text
Discover
 ↓
Identify
 ↓
Enumerate capabilities
 ↓
Analyze tools
 ↓
Analyze permissions
 ↓
Test authorization
 ↓
Test input boundaries
 ↓
Test output trust
 ↓
Test external communication
 ↓
Build attack graph
```

Test categories:

- unknown MCP behavior;
- excessive capabilities;
- excessive permissions;
- tool poisoning;
- malicious descriptions;
- unauthorized invocation;
- sensitive-data access;
- output manipulation;
- external communication;
- agent/MCP trust boundaries;
- capability escalation.

---

# 17. Cloud Security

Authorized technology families:

- AWS;
- Microsoft Azure;
- Google Cloud;
- IAM;
- object storage;
- managed databases;
- serverless;
- container services;
- cloud networking.

Assess:

- excessive permissions;
- public storage;
- exposed services;
- trust relationships;
- leaked credentials;
- service identities;
- metadata exposure;
- network boundaries;
- privilege paths.

---

# 18. Containers and Kubernetes

Technology families:

- Docker;
- Kubernetes;
- container registries;
- service accounts;
- RBAC;
- ingress;
- network policies;
- secrets;
- workload identities.

Assess:

- excessive permissions;
- exposed control planes;
- insecure RBAC;
- privileged workloads;
- unsafe mounts;
- secret exposure;
- segmentation weaknesses;
- service-account privilege paths.

---

# 19. Supply Chain and CI/CD

Analyze:

```text
Dependencies
 ↓
Package Sources
 ↓
Lockfiles
 ↓
Build Scripts
 ↓
CI/CD
 ↓
Secrets
 ↓
Deployment
```

Assess vulnerable dependencies, dependency confusion risk, suspicious packages, unsafe build scripts, exposed CI secrets, excessive automation permissions, insecure package sources and provenance concerns.

---

# 20. Storage Security

Support authorized:

- object storage;
- file storage;
- database-backed storage;
- application uploads;
- cloud buckets;
- local application storage.

Assess public exposure, unauthorized reads/writes, path manipulation, sensitive-data exposure, weak access controls and unsafe signed URLs.

---

# 21. Desktop Software

Assess authorized:

- Electron applications;
- native applications;
- local APIs;
- IPC;
- local storage;
- authentication;
- update mechanisms;
- configuration;
- secrets;
- backend communication.

---

# 22. Infrastructure and Network Security

Map authorized services, protocols, gateways, internal APIs and trust relationships.

Assess:

- unintended exposure;
- insecure configuration;
- weak segmentation;
- unauthorized service access;
- authentication;
- protocol misuse;
- privilege relationships.

---

# 23. Security Tool Abstraction

Hachiman should use a modular abstraction rather than lock itself to one vendor.

### Browser/Web

Browser automation, HTTP clients, proxy/interception and DOM inspection.

### Source

AST parsing, dependency analysis, static analysis, secret detection and code search.

### Mobile

Android SDK, Android Emulator, ADB, iOS Simulator, JADX, apktool, Frida and LLDB in authorized labs.

### Cloud

Official cloud CLIs/SDKs, IAM inspection APIs and resource inventory APIs.

### Containers

Docker APIs, Kubernetes APIs, image inspection and manifest analysis.

### Network

Authorized DNS/HTTP/service enumeration, traffic analysis and protocol clients.

The security engine determines which tools are permitted.

---

# 24. Tool Selection

```text
Target
 ↓
Technology fingerprint
 ↓
Attack surface
 ↓
Relevant skills
 ↓
Relevant tools
 ↓
Security budget
 ↓
Execute
```

If GraphQL is absent, the GraphQL specialist is not launched.

If Android is detected, mobile capabilities are activated.

If MCP is detected, MCP analysis is activated.

This saves tokens, CPU, memory and time.

---

# 25. Hacker Planning Engine

Hachiman maintains a dynamic plan.

```yaml
plan:
  objective: determine whether an authorized boundary can be crossed
  scope: authorized-target
  observations: []
  hypotheses: []
  tests: []
  evidence: []
  next_action: ""
```

The plan changes as evidence arrives.

---

# 26. Hypothesis Engine

```text
Observation
   ↓
Potential weakness
   ↓
Hypothesis
   ↓
Minimal validating test
   ↓
Observation
   ↓
Update hypothesis
```

Possible outcomes:

- CONFIRMED
- REJECTED
- INCONCLUSIVE
- NEEDS_MORE_EVIDENCE

An anomaly alone is not automatically a vulnerability.

---

# 27. Exploit Validation

A vulnerability becomes confirmed only with sufficient evidence.

Evidence may include:

- reproducible behavior;
- controlled response difference;
- authorization-boundary violation;
- safe proof of impact;
- source-level root cause;
- repeated validation.

Hachiman should use the least destructive proof that establishes the security property violation.

---

# 28. Attack Graph

Individual findings become connected nodes.

```text
Finding A
   ↓
Finding B
   ↓
Resource C
   ↓
Privilege D
   ↓
Impact
```

Edges represent:

- authentication dependency;
- authorization dependency;
- data flow;
- privilege transition;
- tool capability;
- network reachability;
- workflow dependency.

Combined impact can exceed the severity of any individual finding.

---

# 29. Root-Cause Engine

Every confirmed finding should answer:

```text
WHAT happened?
WHERE did it happen?
WHY did it happen?
WHAT trust boundary failed?
WHAT assumption was wrong?
WHAT component must change?
```

Hachiman should distinguish root-cause fixes from payload-specific workarounds.

Example:

```text
Weak fix:
Blacklist the observed injection string.

Root-cause fix:
Use parameterized query handling at the database sink.
```

---

# 30. AI Repair Contract

This is Hachiman's signature output.

```yaml
finding_id: HACH-SQL-0017
status: confirmed
severity: critical

location:
  file: backend/routes/users.js
  component: searchUsers

entry_point:
  method: GET
  route: /api/users/search
  parameter: q

root_cause:
  category: unsafe-query-construction
  description: user-controlled input reaches a raw SQL sink

evidence:
  reproducible: true
  validation: confirmed

impact:
  - unauthorized query manipulation
  - potential sensitive-data access

remediation:
  strategy: parameterized-query
  constraints:
    - preserve authentication
    - preserve response schema
    - preserve legitimate behavior

verification:
  replay_original_attack: required
  regression_test: required
```

The AI builder receives a direct engineering task rather than a vague security warning.

---

# 31. Automatic Fix Verification

```text
Original vulnerability
       ↓
Builder changes code
       ↓
Replay original test
       ↓
Exploit still works?
       │
   ┌───┴───┐
   ▼       ▼
  YES      NO
   │        │
   ▼        ▼
UNRESOLVED  Legitimate regression test
             │
          ┌──┴──┐
          ▼     ▼
        FAIL   PASS
          │      │
          ▼      ▼
       Rework   VERIFIED
```

A code change alone never constitutes verification.

---

# 32. Security Regression

Every confirmed finding becomes a regression test:

```text
HACH-0017
   ↓
Fix
   ↓
Regression test
   ↓
Future code change
   ↓
Original vulnerability reappears?
```

This creates continuous security feedback.

---

# 33. Scoring

Keep these dimensions separate:

```text
Severity
Exploitability
Impact
Confidence
Reproducibility
Attack-path importance
Fix verification
```

Example:

```text
Severity:             Critical
Exploitability:       High
Confidence:           98%
Reproducibility:      100%
Attack-path impact:   Critical
Fix verified:         YES
```

---

# 34. Resource and Token Intelligence

Every engagement can have:

```text
CPU Budget
Memory Budget
Token Budget
Request Budget
Time Budget
Concurrency Budget
```

Hachiman uses:

- deterministic checks first;
- targeted specialists;
- bounded workers;
- compact context;
- caching;
- incremental analysis;
- selective parallelism;
- deep reasoning only for uncertain/high-value cases.

---

# 35. Adaptive Specialist Activation

```text
Recon
 ↓
Technology Detection
 ↓
Attack Surface
 ↓
Specialist Selection
```

Only relevant specialists run.

Logical specialists do not necessarily mean separate heavyweight model instances.

---

# 36. Skill Commands

```text
/hachiman help
/hachiman status
/hachiman scope
/hachiman recon
/hachiman map
/hachiman audit
/hachiman pentest
/hachiman attack
/hachiman verify
/hachiman chain
/hachiman findings
/hachiman explain
/hachiman fix
/hachiman retest
/hachiman report
/hachiman mcp
/hachiman ai
/hachiman mobile
/hachiman game
/hachiman cloud
/hachiman infrastructure
/hachiman benchmark
```

Every command that can test or affect a target enforces authorization and scope.

---

# 37. CI/CD

```text
Developer
   ↓
Commit
   ↓
Build
   ↓
Approved test environment
   ↓
Hachiman
   ↓
Security tests
   ↓
PASS / FAIL
   ↓
Deployment decision
```

Machine-readable results should be available for CI systems.

---

# 38. Reporting

Each engagement produces:

```text
Executive Summary
Scope
Authorization
Technology Inventory
Attack Surface
Test Coverage
Confirmed Findings
Unconfirmed Findings
Attack Paths
Evidence
Root Causes
Severity
Remediation
AI Repair Contracts
Retest Results
Security Score
Resource Usage
Token Usage
Final Verdict
```

---

# 39. Developer Output

A developer should be able to understand a finding quickly:

```text
CRITICAL — HACH-0017

Problem:
User input reaches a raw SQL query.

Where:
backend/routes/users.js:142

Why:
String concatenation is used.

Impact:
Unauthorized query manipulation.

Fix:
Use parameterized query handling at the database sink.

Do not:
Blacklist the demonstrated payload.

Retest:
Hachiman will replay the original test after the fix.
```

---

# 40. Human + AI Reporting

## Human View

Clear explanation, evidence, impact and remediation.

## AI View

Structured contract optimized for an AI coding agent:

```text
Finding
→ location
→ root cause
→ evidence
→ required change
→ constraints
→ regression test
→ verification status
```

---

# 41. Target Coverage Matrix

| Target | Recon | Dynamic | Static | Attack | Chain | Repair | Retest |
|---|---:|---:|---:|---:|---:|---:|---:|
| Website | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Web API | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Backend | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Database | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Android | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| iOS | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Desktop | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Game | ✓ | ✓ | selective | ✓ | ✓ | ✓ | ✓ |
| AI Agent | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| MCP | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Cloud | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Kubernetes | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| CI/CD | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Enterprise software | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |

Coverage is capability- and authorization-dependent.

---

# 42. Internal Architecture

```text
hachiman/
│
├── skill/
│   ├── instructions/
│   ├── commands/
│   └── workflows/
│
├── agent/
│   ├── root/
│   ├── planner/
│   ├── recon/
│   ├── web/
│   ├── api/
│   ├── auth/
│   ├── authorization/
│   ├── injection/
│   ├── database/
│   ├── business_logic/
│   ├── mobile/
│   ├── game/
│   ├── ai/
│   ├── mcp/
│   ├── cloud/
│   ├── infrastructure/
│   ├── supply_chain/
│   ├── validator/
│   ├── root_cause/
│   ├── remediation/
│   └── retest/
│
├── engine/
│   ├── scope/
│   ├── authorization/
│   ├── policy/
│   ├── attack_planning/
│   ├── evidence/
│   ├── attack_graph/
│   ├── scoring/
│   └── resource_governor/
│
├── adapters/
│   ├── web/
│   ├── api/
│   ├── android/
│   ├── ios/
│   ├── game/
│   ├── cloud/
│   ├── docker/
│   ├── kubernetes/
│   ├── mcp/
│   └── ai/
│
├── tools/
│   ├── browser/
│   ├── http/
│   ├── source/
│   ├── mobile/
│   ├── network/
│   ├── cloud/
│   └── container/
│
├── findings/
│   ├── evidence/
│   ├── contracts/
│   └── regression/
│
├── reporting/
│   ├── human/
│   ├── machine/
│   └── ci/
│
└── benchmark/
    ├── security/
    ├── performance/
    ├── token/
    └── regression/
```

---

# 43. Development Phases

## Phase 1 — Skill and Scope

Authorization, commands, scope and rules of engagement.

## Phase 2 — Recon

Technology fingerprinting, endpoint discovery and attack-surface mapping.

## Phase 3 — Web/API

Authentication, authorization, injection, browser, API and business-logic testing.

## Phase 4 — Validation

Evidence, reproducibility, safe proof and confidence.

## Phase 5 — AI/MCP

Prompt injection, tool abuse, MCP and agent attack chains.

## Phase 6 — Mobile/Game

Android, iOS, game clients and game backends.

## Phase 7 — Cloud/Infrastructure

Cloud, containers, Kubernetes, CI/CD and supply chain.

## Phase 8 — Attack Graph

Chaining, privilege paths and impact analysis.

## Phase 9 — AI Repair Loop

Root cause, repair contract, automatic retest and regression verification.

## Phase 10 — Optimization

Token budgets, CPU/memory budgets, specialist activation, caching and bounded parallelism.

---

# 44. Benchmarking

## Security effectiveness

- detection rate;
- precision;
- recall;
- F1;
- false positives;
- false negatives;
- exploit validation rate;
- attack-chain detection.

## Reasoning efficiency

- tokens per engagement;
- tokens per confirmed finding;
- tokens per correct decision;
- semantic calls;
- cache-hit rate;
- specialist activation efficiency.

## Runtime efficiency

- CPU overhead;
- memory overhead;
- latency;
- throughput;
- tool execution time.

## Repair effectiveness

- root-cause accuracy;
- fix acceptance;
- regression-pass rate;
- vulnerability recurrence;
- time-to-verified-fix.

---

# 45. Security Protection Overhead

Compare equivalent workloads:

```text
TARGET WITHOUT HACHIMAN
vs.
TARGET WITH HACHIMAN
```

Measure:

```text
CPU overhead
Memory overhead
Latency overhead
Throughput impact
Token consumption
Security coverage
```

Do not claim universal performance values without measurement.

---

# 46. Offensive Safety Boundaries

"Real hacker" behavior means realistic adversarial reasoning and controlled vulnerability validation.

Default restrictions:

- no unauthorized targets;
- no persistence;
- no destructive database modification;
- no uncontrolled data exfiltration;
- no malware deployment;
- no credential theft from unrelated systems;
- no attacks outside scope;
- no authorization bypass;
- no uncontrolled denial-of-service activity.

Sanctioned labs may define additional explicit test classes through their rules of engagement.

---

# 47. Hackathon Differentiator

Hachiman should not be presented as merely another vulnerability scanner.

Its core differentiator is:

```text
AUTONOMOUS OFFENSIVE SECURITY
          +
AI-NATIVE REPAIR
          +
AUTOMATIC VERIFICATION
```

The signature loop is:

```text
ATTACK
  ↓
PROVE
  ↓
UNDERSTAND
  ↓
FIX
  ↓
REATTACK
  ↓
VERIFY
```

---

# 48. Final End-to-End Architecture

```text
                         AUTHORIZED TARGET
                                │
                                ▼
                           HACHIMAN SKILL
                                │
                                ▼
                         HACHIMAN ROOT AGENT
                                │
                         AUTH + SCOPE
                                │
                                ▼
                             RECON
                                │
                                ▼
                        TECHNOLOGY MAP
                                │
                                ▼
                       ATTACK-SURFACE MAP
                                │
                                ▼
                         THREAT MODEL
                                │
                                ▼
                        ATTACK PLANNER
                                │
                                ▼
                            ATTACK
                                │
                         ┌──────┴──────┐
                         ▼             ▼
                       FAIL          SIGNAL
                                       │
                                       ▼
                                    VERIFY
                                       │
                                ┌──────┴──────┐
                                ▼             ▼
                           UNCONFIRMED     CONFIRMED
                                             │
                                             ▼
                                        ATTACK CHAIN
                                             │
                                             ▼
                                         IMPACT
                                             │
                                             ▼
                                       ROOT CAUSE
                                             │
                                             ▼
                                    REPAIR CONTRACT
                                             │
                                             ▼
                                        AI BUILDER
                                             │
                                            FIX
                                             │
                                             ▼
                                          RETEST
                                             │
                                      ┌──────┴──────┐
                                      ▼             ▼
                                    PASS          FAIL
                                      │             │
                                      ▼             └──→ REPLAN
                              VERIFIED SECURITY
```

---

# 49. Final Vision

## NG's Hachiman Agent

Hachiman is the **watchman that thinks like an attacker**.

It learns the shape of an authorized target.

It maps its attack surface.

It questions assumptions.

It forms hypotheses.

It attacks relevant boundaries.

It adapts when the target responds differently.

It chains weaknesses.

It validates what it finds.

It distinguishes suspicion from proof.

It explains root causes.

It translates findings into AI-readable engineering tasks.

It lets the AI builder repair the software.

Then it attacks the repaired software again.

Only when the original vulnerability is no longer reproducible and legitimate behavior still works does Hachiman declare the repair verified.

### Final philosophy

> **Think like the attacker.**
>
> **Act only within authorization.**
>
> **Prove before reporting.**
>
> **Chain before judging impact.**
>
> **Fix the root cause, not the payload.**
>
> **Retest what was actually broken.**
>
> **Measure security and efficiency together.**

# HACHIMAN

**DISCOVER → MAP → HYPOTHESIZE → ATTACK → ADAPT → CHAIN → VALIDATE → EXPLAIN → FIX → RETEST**
