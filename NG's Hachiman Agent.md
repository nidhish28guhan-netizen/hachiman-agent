# NG's Hachiman Agent

## Final Architecture & Product Specification

> **Hachiman — The Autonomous Security Layer for AI Agents and MCP**
>
> **Core principle:** Scan before deployment. Authorize before access. Monitor during execution. Contain when compromised. Report everything.

---

## 1. Vision

NG's Hachiman Agent is a self-contained, platform-independent AI security system designed to protect AI agents, AI applications, MCP servers, MCP tools, business AI systems, and connected resources.

Hachiman operates in two complementary modes:

1. **Pre-Deployment Security**
   - Inspect and test an AI agent or MCP before it is trusted.
   - Discover its capabilities and attack surface.
   - Run context-appropriate security tests.
   - Calculate a Production Safety Score.
   - Generate a detailed security report.
   - Recommend or enforce remediation requirements before production.

2. **Runtime Security**
   - Operate continuously in the background after deployment.
   - Mediate AI-to-tool/MCP interactions.
   - Treat unknown or unverified MCPs as untrusted by default.
   - Verify authorization before allowing actions.
   - Detect suspicious behavior, data leakage, prompt injection, excessive agency, and abnormal tool usage.
   - Automatically block, restrict, quarantine, revoke, or alert when policy permits.

Hachiman is not intended to replace an AI model or become another AI platform. It is a security control layer around AI systems.

---

## 2. Product Goal

Hachiman answers two questions:

### Before deployment

> **"Is this AI agent/MCP/tool safe enough to deploy?"**

### During runtime

> **"Is this action safe and authorized right now?"**

The complete lifecycle is:

```text
DISCOVER → SCAN → TEST → SCORE → AUTHORIZE → DEPLOY
    → MONITOR → DETECT → DECIDE → RESPOND → REPORT → REASSESS
```

---

## 3. Product Identity

Hachiman has two primary roles.

### A. MCP Security Interface

Hachiman can operate as an MCP-facing security gateway.

```text
AI Agent
   │ MCP / tool request
   ▼
HACHIMAN MCP SECURITY GATEWAY
   │
   ├── identity verification
   ├── authorization
   ├── policy validation
   ├── risk analysis
   ├── parameter validation
   └── data protection
   │
   ├── ALLOW
   ├── REVIEW
   └── BLOCK
   │
   ▼
Downstream MCP / Tool
```

### B. Autonomous Security Agent

Hachiman continuously observes and protects the environment.

It can:

- discover MCPs;
- inspect capabilities;
- evaluate trust;
- monitor agent behavior;
- detect attacks;
- calculate risk;
- enforce policies;
- block dangerous actions;
- quarantine compromised integrations;
- revoke access;
- create incidents;
- generate reports.

The security agent itself must operate under explicit permissions and least privilege.

---

## 4. Design Principles

### Zero Trust

No MCP, tool, agent, or integration is trusted merely because it is available.

Unknown does not automatically mean malicious.

**Unknown means untrusted until evaluated and authorized.**

### Authorization First

Hachiman must only inspect, control, modify, or isolate resources for which it has explicit authorization.

It must never scan arbitrary systems or bypass platform restrictions.

### The Model Is Not the Security Authority

An AI model may request an action. It must not authorize its own action.

```text
AI Model
   │ REQUEST
   ▼
Hachiman Security Engine
   │
   ├── Identity
   ├── Permission
   ├── Policy
   ├── Risk
   └── Context
   ▼
ALLOW / REVIEW / BLOCK
```

### Least Privilege

Hachiman itself receives only the permissions required for its security duties.

### Fail Closed for Security-Critical Decisions

If authorization cannot be verified for a sensitive operation, Hachiman must not blindly allow it.

### Deterministic First, AI When Necessary

Routine decisions use deterministic checks. Semantic AI analysis is reserved for ambiguous or high-risk cases.

---

# 5. High-Level Architecture

```text
                         USERS / DEVELOPERS
                                │
                                ▼
                   ┌─────────────────────────┐
                   │    AI APPLICATIONS      │
                   │ Business AI / Agents    │
                   │ Local / Cloud AI        │
                   └────────────┬────────────┘
                                │ authorized integration
                                ▼
              ╔══════════════════════════════════════════╗
              ║              HACHIMAN                    ║
              ║                                          ║
              ║  ┌────────────────────────────────────┐  ║
              ║  │        MCP SECURITY GATEWAY        │  ║
              ║  │ MCP interface                      │  ║
              ║  │ Request interception               │  ║
              ║  │ Response inspection                │  ║
              ║  │ Protocol validation                │  ║
              ║  └──────────────────┬─────────────────┘  ║
              ║                     │                    ║
              ║  ┌──────────────────▼─────────────────┐  ║
              ║  │       SECURITY AGENT CORE          │  ║
              ║  │ Discovery / Scanner                │  ║
              ║  │ Threat Detection                   │  ║
              ║  │ Behavior Analysis                  │  ║
              ║  │ Data Protection                    │  ║
              ║  │ Risk / Trust / Policy Engines      │  ║
              ║  │ Decision / Response Engines        │  ║
              ║  └──────────────────┬─────────────────┘  ║
              ║                     │                    ║
              ║  ┌──────────────────▼─────────────────┐  ║
              ║  │        SECURITY DECISION           │  ║
              ║  │ Risk Score       0–100             │  ║
              ║  │ Decision Confidence 0–100%         │  ║
              ║  │ Agent/MCP Trust   0–100             │  ║
              ║  │ ALLOW / REVIEW / BLOCK             │  ║
              ║  └──────────────────┬─────────────────┘  ║
              ╚═════════════════════╪════════════════════╝
                                    │ authorized requests
                                    ▼
                       ┌────────────────────────┐
                       │    MCP ECOSYSTEM       │
                       │ Trusted / Unknown MCPs │
                       │ Internal / External    │
                       └────────────┬───────────┘
                                    │
                 ┌──────────────────┼──────────────────┐
                 ▼                  ▼                  ▼
             Databases           Files               APIs
```

---

# 6. Trust Boundaries

Hachiman explicitly models:

1. **User → AI Application**
   - authentication, authorization, role and tenant checks.

2. **AI Agent → Model**
   - context inspection, sensitive-data detection, secrets/PII handling, minimization and redaction.

3. **External Content → Agent Context**
   - indirect prompt-injection detection, content trust and instruction/data separation.

4. **Agent → MCP / Tool**
   - identity, authorization, allowlists, parameter validation, risk and policy.

5. **Tool → Data / External System**
   - data-access policy, export controls, destination restrictions, rate limits and auditing.

---

# 7. Automatic Platform Adaptation

Hachiman is designed for:

- cloud AI agent platforms;
- local AI agents;
- desktop AI applications;
- CLI agents;
- enterprise AI assistants;
- coding agents;
- autonomous agents;
- MCP-based agents;
- custom business AI systems;
- internally developed AI platforms.

The security core remains platform-independent.

```text
                   HACHIMAN CORE
                        │
          ┌─────────────┼─────────────┐
          ▼             ▼             ▼
       MCP Adapter   API Adapter   Platform Adapter
          │             │             │
          ▼             ▼             ▼
       MCP Agent     AI Service    Custom Agent
```

Adapters only translate an authorized platform interface into Hachiman's normalized security event format.

**No adapter may bypass platform security or authorization.**

If a platform does not expose an authorized, observable integration boundary, Hachiman must not attempt to circumvent it.

---

# 8. MCP Security Gateway

Every protected request is normalized into:

```text
Request
├── user_id
├── tenant_id
├── agent_id
├── session_id
├── source
├── MCP identity
├── tool
├── action
├── parameters
├── requested data
├── destination
├── context metadata
└── authorization context
```

Evaluation flow:

```text
Identity
   ↓
Authorization
   ↓
Tool legitimacy
   ↓
Parameter validity
   ↓
Data sensitivity
   ↓
Context risk
   ↓
Behavioral risk
   ↓
Policy
   ↓
Decision
```

---

# 9. Unknown MCP Handling

Unknown MCPs are not automatically malicious.

```text
Unknown MCP
     ↓
Authorized discovery
     ↓
Capability inspection
     ↓
Permission analysis
     ↓
Security testing
     ↓
Trust assessment
     ↓
Restricted state
     ↓
ALLOW / RESTRICT / QUARANTINE
```

Trust states:

```text
UNKNOWN → UNVERIFIED → ASSESSED → RESTRICTED → TRUSTED
```

A dangerous MCP can become:

```text
UNVERIFIED → HIGH RISK → QUARANTINED
```

Trust never overrides explicit authorization.

---

# 10. Pre-Deployment Security Scanner

The scanner answers:

> **Is this agent/MCP/tool production-ready?**

It discovers the actual attack surface and runs only applicable tests.

### AI / Agent Security

- direct prompt injection;
- indirect prompt injection;
- instruction manipulation;
- context manipulation;
- tool poisoning;
- excessive agency;
- unsafe autonomous actions;
- memory contamination;
- unsafe agent chaining.

### MCP / Tool Security

- tool authorization;
- capability exposure;
- excessive permissions;
- unsafe parameters;
- schema validation;
- tool impersonation;
- unexpected tool behavior;
- unauthorized tool chaining.

### Application / Data Security

Where applicable:

- SQL injection;
- command injection;
- path traversal;
- SSRF;
- unsafe file operations;
- output injection;
- unsafe deserialization;
- authentication flaws;
- authorization flaws;
- sensitive-data exposure;
- secret exposure.

Hachiman must first determine whether the relevant attack surface exists before running the test.

---

# 11. Security Test Lifecycle

```text
Target
  ↓
Authorization Verification
  ↓
Discovery
  ↓
Attack-Surface Mapping
  ↓
Capability Analysis
  ↓
Applicable Test Selection
  ↓
Controlled Security Tests
  ↓
Evidence Collection
  ↓
Finding Validation
  ↓
Risk Classification
  ↓
Remediation Guidance
  ↓
Retest
  ↓
Production Safety Score
```

All active testing remains within the authorized scope.

---

# 12. Production Safety Score

The pre-deployment score is separate from runtime risk.

Dimensions:

```text
Authentication
Authorization
MCP / Tool Security
Injection Resistance
Data Protection
Permission Boundaries
Agent Behavior
External Communication
Secrets Handling
Observability
Reliability
```

Example:

```text
PRODUCTION SAFETY SCORE

Overall                    86/100

Authentication             94
Authorization               81
MCP Security                88
Injection Resistance        91
Data Protection             79
Permission Boundaries       84
Agent Behavior              90
External Communication      76
Secrets Handling            97
Observability               92

Critical Findings:           0
High Findings:               1
Medium Findings:             3
Low Findings:                4

STATUS:
PRODUCTION READY WITH RESTRICTIONS
```

---

# 13. Runtime Risk Model

Risk should consider:

```text
Identity Risk
Tool Risk
Permission Risk
Data Risk
Context / Injection Risk
Behavioral Anomaly
Destination Risk
Action Impact
```

The initial model can use configurable weighted factors and should be validated against benchmark scenarios rather than treated as a universal fixed formula.

---

# 14. Three Security Values

### Risk Score — 0–100

How dangerous is this action?

### Decision Confidence — 0–100%

How strong is the evidence supporting the decision?

### Trust Score — 0–100

How trustworthy is this agent/MCP based on verified identity, assessment, permissions and observed history?

Example:

```text
Risk Score:             88/100
Decision Confidence:    97%
MCP Trust:              42/100

Decision: BLOCK
```

These values must remain separate.

---

# 15. Runtime Decision Model

```text
                  ACTION
                    │
                    ▼
             SECURITY ANALYSIS
                    │
          ┌─────────┼─────────┐
          ▼         ▼         ▼
         Risk   Confidence   Trust
          │         │         │
          └─────────┼─────────┘
                    ▼
              POLICY ENGINE
                    │
          ┌─────────┼─────────┐
          ▼         ▼         ▼
        ALLOW     REVIEW     BLOCK
```

Typical behavior:

```text
Low risk + high confidence
        → ALLOW

Medium risk / uncertainty
        → REVIEW or RESTRICT

High risk + high confidence
        → BLOCK

Critical risk
        → BLOCK + CONTAIN

Authorization unavailable
        → BLOCK/REVIEW according to resource sensitivity
```

---

# 16. Automatic Response Engine

Authorized responses include:

- block current request;
- deny tool call;
- redact sensitive data;
- restrict tool capabilities;
- revoke temporary permission;
- suspend an MCP;
- quarantine an MCP;
- isolate an agent;
- terminate a security session;
- require human approval;
- create an incident;
- notify administrators;
- preserve evidence.

Example:

```text
Threat detected
      ↓
Risk = 94
Confidence = 98%
      ↓
Critical policy triggered
      ↓
BLOCK ACTION
      ↓
QUARANTINE MCP
      ↓
REVOKE TOOL ACCESS
      ↓
CREATE INCIDENT
      ↓
GENERATE REPORT
```

Hachiman's own authority must always be constrained by policy and authorization.

---

# 17. Token-Efficient Security

Token efficiency is a core requirement.

Hachiman does not send the entire conversation to an LLM for every request.

## Fast Path

Use deterministic checks for:

- identity;
- authorization;
- allowlists;
- schema validation;
- parameter validation;
- known attack patterns;
- data classification;
- rate limits;
- policy rules;
- cached decisions.

```text
Request
  ↓
Deterministic checks
  ↓
Clearly safe?
  ├── YES → ALLOW
  └── NO → Semantic analysis
```

## Semantic Path

Only suspicious or ambiguous requests receive deeper analysis.

The semantic engine receives compact security context instead of the entire conversation.

Optimization techniques:

- context compression;
- structured security state;
- decision caching;
- tool-risk metadata;
- policy precomputation;
- risk-based escalation;
- minimal model calls;
- compact event representations;
- reusable security fingerprints.

Metrics:

```text
Tokens per request
Tokens per security decision
Tokens per correct decision
LLM calls per request
Cache-hit rate
Security latency
```

---

# 18. Runtime Agent Behavior

Hachiman continuously monitors:

```text
Agent
 ↓
Context
 ↓
MCP
 ↓
Tool
 ↓
Data
 ↓
External destination
```

It looks for:

- unexpected tool sequences;
- privilege escalation;
- unusual data volume;
- sensitive-data movement;
- new MCP behavior;
- suspicious external destinations;
- repeated failed authorization;
- prompt-injection indicators;
- policy violations;
- behavioral drift.

---

# 19. Continuous Trust

Trust is dynamic.

Example:

```text
Initial assessment       Trust 50
Verified + passed tests  Trust 82
Stable operation         Trust 91
Policy violation         Trust 28
Quarantine               Restricted
Remediated + retested    Trust may recover
```

Historical trust never replaces current authorization.

---

# 20. Enterprise Deployment

Hachiman can protect a single AI application or an enterprise AI environment.

```text
                 ENTERPRISE
                     │
       ┌─────────────┼─────────────┐
       ▼             ▼             ▼
   AI App A       AI App B       AI App C
       │             │             │
       └─────────────┼─────────────┘
                     ▼
              HACHIMAN SECURITY
                     │
       ┌─────────────┼─────────────┐
       ▼             ▼             ▼
     Agents         MCPs          Tools
       │             │             │
       └─────────────┼─────────────┘
                     ▼
               Business Data
```

For large environments:

- local Hachiman runtime instances perform enforcement;
- a central control plane provides fleet-level visibility;
- enterprise policies are centrally governed;
- tenant and organization data remain isolated.

---

# 21. Multi-Tenant Isolation

Business deployments must separate:

- organizations;
- users;
- agents;
- MCPs;
- credentials;
- policies;
- logs;
- incidents;
- reports.

No tenant may access another tenant's security data.

---

# 22. Security Event Model

```text
SecurityEvent
├── event_id
├── timestamp
├── tenant_id
├── user_id
├── agent_id
├── MCP_id
├── tool_id
├── action
├── resource
├── data_classification
├── risk_score
├── confidence
├── trust_score
├── policy
├── decision
├── response
└── evidence
```

This supports monitoring, auditing, incident response, reports and benchmarking.

---

# 23. Security Dashboard

### Environment

- active agents;
- active MCPs;
- unknown MCPs;
- protected tools;
- protected resources.

### Security

- current risk;
- active threats;
- blocked actions;
- quarantined integrations;
- policy violations.

### Trust

- MCP trust scores;
- agent trust scores;
- newly discovered integrations;
- trust changes.

### Performance

- token usage;
- security latency;
- LLM calls;
- deterministic vs semantic decisions.

### Reports

- production readiness;
- vulnerabilities;
- remediation;
- historical changes.

---

# 24. Example Runtime Incident

```text
Unknown MCP detected
        ↓
Authorized discovery
        ↓
MCP requests database access
        ↓
Sensitive data identified
        ↓
External instruction influences agent context
        ↓
Indirect prompt injection detected
        ↓
Tool requests external data transfer
        ↓
Risk Score: 94
Confidence: 98%
MCP Trust: 31
        ↓
CRITICAL POLICY
        ↓
BLOCK
        ↓
QUARANTINE MCP
        ↓
REVOKE TOOL ACCESS
        ↓
CREATE INCIDENT
        ↓
GENERATE SECURITY REPORT
```

---

# 25. Pre-Deployment to Runtime Continuity

The scanner and runtime agent share the same security model.

```text
PRE-DEPLOYMENT
      │
 Security Scan
      │
Production Score
      │
Security Baseline
      ▼
   DEPLOY
      │
      ▼
   RUNTIME
      │
Behavioral Drift
      │
      ▼
Reassessment
      │
 ┌────┴────┐
 ▼         ▼
Stable   Changed
            │
            ▼
          Rescan
```

A previous approval is never a permanent guarantee of safety.

---

# 26. Hachiman Command Interface

Hachiman uses:

```text
/hachiman
```

Core commands:

```text
/hachiman status
/hachiman guard
/hachiman scan
/hachiman inspect
/hachiman trust
/hachiman threats
/hachiman quarantine
/hachiman policy
/hachiman audit
/hachiman report
/hachiman test
/hachiman mcp
/hachiman agents
/hachiman config
/hachiman help
```

Examples:

```text
/hachiman status
/hachiman guard
/hachiman scan ./customer-mcp --production
/hachiman inspect mcp:customer-db
/hachiman trust mcp:unknown-server
/hachiman threats active
/hachiman quarantine mcp:unknown-server
/hachiman report production
/hachiman test ./mcp --full
/hachiman mcp list
/hachiman agents
```

Commands should remain deterministic and token-efficient wherever possible.

---

# 27. Self-Contained Project Principle

Hachiman's core security logic belongs to the project.

Core modules:

```text
Hachiman Core
├── Identity Engine
├── Authorization Engine
├── Policy Engine
├── MCP Gateway
├── MCP Discovery
├── Security Scanner
├── Attack-Surface Mapper
├── Data Classifier
├── Injection Detector
├── Tool Security Engine
├── Risk Engine
├── Trust Engine
├── Decision Engine
├── Response Engine
├── Quarantine Manager
├── Audit Engine
├── Report Engine
├── Benchmark Engine
└── Platform Adapter Layer
```

Standard libraries may be used for protocol parsing, networking, cryptography, storage and runtime functionality, but Hachiman's security decisions, policies, scoring, detection workflow, runtime enforcement and reporting remain first-party project logic.

---

# 28. What Hachiman Is Not

Hachiman is not:

- a replacement for Claude or another AI model;
- a replacement for MCP;
- a generic antivirus;
- a generic web application scanner;
- a mechanism for bypassing AI-provider restrictions;
- a tool for unauthorized penetration testing;
- a system that blindly trusts an LLM's security judgment;
- a collection of third-party security plugins.

Hachiman is:

> **An authorized AI security control layer combining pre-deployment assessment, MCP mediation, runtime agent protection, risk-based authorization and automated containment.**

---

# 29. Development Architecture

Suggested logical structure:

```text
hachiman/
│
├── core/
│   ├── identity/
│   ├── authorization/
│   ├── policy/
│   ├── risk/
│   ├── trust/
│   └── decision/
│
├── mcp/
│   ├── gateway/
│   ├── protocol/
│   ├── discovery/
│   ├── registry/
│   └── adapters/
│
├── agent/
│   ├── runtime/
│   ├── planner/
│   ├── context/
│   ├── behavior/
│   └── response/
│
├── scanner/
│   ├── discovery/
│   ├── attack_surface/
│   ├── injection/
│   ├── data/
│   ├── authorization/
│   ├── tool_security/
│   └── test_runner/
│
├── runtime/
│   ├── monitor/
│   ├── interceptor/
│   ├── anomaly/
│   ├── enforcement/
│   └── quarantine/
│
├── reporting/
│   ├── findings/
│   ├── scoring/
│   ├── reports/
│   └── evidence/
│
├── benchmark/
│   ├── datasets/
│   ├── scenarios/
│   ├── metrics/
│   └── evaluator/
│
├── adapters/
│   ├── mcp/
│   ├── api/
│   └── platform/
│
└── interface/
    ├── cli/
    ├── dashboard/
    └── commands/
```

---

# 30. Development Phases

## Phase 1 — Core Security

- normalized security request;
- authorization engine;
- policy engine;
- risk scoring;
- decision engine;
- audit events.

## Phase 2 — MCP Gateway

- MCP interface;
- MCP discovery;
- tool registry;
- request interception;
- response inspection;
- authorization.

## Phase 3 — Pre-Deployment Scanner

- capability discovery;
- attack-surface mapping;
- applicable test selection;
- controlled testing;
- findings;
- production score;
- reports.

## Phase 4 — Runtime Agent

- continuous monitoring;
- behavior analysis;
- anomaly detection;
- automatic response;
- quarantine;
- trust updates.

## Phase 5 — Token Efficiency

- deterministic fast path;
- compact context;
- caching;
- semantic escalation;
- token metrics.

## Phase 6 — Enterprise

- multi-tenant isolation;
- centralized control plane;
- fleet management;
- organization policies;
- incident management.

---

# 31. Benchmarking Hachiman

Hachiman should continuously evaluate itself.

### Security

- detection rate;
- false-positive rate;
- false-negative rate;
- precision;
- recall;
- F1;
- attack-chain detection.

### Efficiency

- tokens per request;
- tokens per correct decision;
- LLM calls;
- cache-hit rate;
- deterministic decision percentage.

### Performance

- P50 latency;
- P95 latency;
- P99 latency;
- throughput.

### Reliability

- failed security decisions;
- fail-closed behavior;
- recovery;
- policy consistency.

### Explainability

- evidence completeness;
- policy traceability;
- decision explanation quality.

---

# 32. Example End-to-End Workflow

A developer receives an unknown MCP.

```text
/hachiman inspect mcp:unknown
```

Hachiman discovers:

```text
Capabilities:
- database.read
- database.export
- http.request
- filesystem.read
```

The developer runs:

```text
/hachiman scan mcp:unknown --production
```

Result:

```text
Score: 64/100

High:
- excessive database access
- unrestricted external HTTP destination

Medium:
- weak parameter validation
- sensitive data exposure
```

After remediation:

```text
/hachiman scan mcp:unknown --production
```

New result:

```text
Score: 91/100
Production Ready
```

The user explicitly authorizes it:

```text
/hachiman mcp allow mcp:unknown
```

During runtime:

```text
MCP → database.read
       ↓
ALLOW

MCP → external HTTP POST
       ↓
Risk = 93
Confidence = 97%
       ↓
BLOCK
       ↓
QUARANTINE
```

The user can then run:

```text
/hachiman report incident
```

---

# 33. Final Architecture Workflow

```text
                         HACHIMAN
                             │
                             ▼
                    ┌─────────────────┐
                    │   DISCOVER      │
                    └────────┬────────┘
                             ▼
                    ┌─────────────────┐
                    │   IDENTIFY      │
                    └────────┬────────┘
                             ▼
                    ┌─────────────────┐
                    │   AUTHORIZE     │
                    └────────┬────────┘
                             ▼
                    ┌─────────────────┐
                    │      SCAN       │
                    └────────┬────────┘
                             ▼
                    ┌─────────────────┐
                    │      TEST       │
                    └────────┬────────┘
                             ▼
                    ┌─────────────────┐
                    │      SCORE      │
                    └────────┬────────┘
                             ▼
                        PRODUCTION
                             │
                             ▼
                    ┌─────────────────┐
                    │     GUARD       │
                    └────────┬────────┘
                             ▼
                    ┌─────────────────┐
                    │    MONITOR      │
                    └────────┬────────┘
                             ▼
                    ┌─────────────────┐
                    │    DETECT       │
                    └────────┬────────┘
                             ▼
                    ┌─────────────────┐
                    │     DECIDE      │
                    └────────┬────────┘
                             ▼
                    ┌─────────────────┐
                    │     RESPOND     │
                    └────────┬────────┘
                             ▼
                    ┌─────────────────┐
                    │     REPORT      │
                    └────────┬────────┘
                             │
                             └──────► REASSESS
```

---

# 34. Final Vision Statement

**NG's Hachiman Agent** is an autonomous security layer for the AI-agent and MCP ecosystem.

It does not ask users to blindly trust an AI platform, MCP, or tool.

It establishes a controlled security boundary around them.

Before deployment, Hachiman evaluates security posture and production readiness.

During runtime, Hachiman continuously watches authorized AI activity, verifies every security-sensitive action, detects malicious or abnormal behavior, and automatically contains threats according to explicit policy.

The central philosophy is:

> **Nothing is trusted merely because it is connected. Nothing is allowed merely because an AI requested it. Every security-sensitive action must be authorized, evaluated, and accountable.**

## Hachiman

**SCAN → SCORE → AUTHORIZE → GUARD → DETECT → RESPOND → REPORT**


---

# FINAL ARCHITECTURE 2.0 — ADAPTIVE EXTERNAL SECURITY PERIMETER

## 1. Core Architectural Innovation

Hachiman's defining technology is the **Adaptive External Security Perimeter (AESP)**.

AESP allows Hachiman to protect software **without becoming part of that software**.

```text
                    PROTECTED APPLICATION
              ┌─────────────────────────────┐
              │ Business / AI / Enterprise  │
              │                             │
              │ Internal code               │
              │ Internal files              │
              │ Internal database           │
              │ Internal processes          │
              └──────────────┬──────────────┘
                             │
                    AUTHORIZED BOUNDARY
                             │
═════════════════════════════╪════════════════════════════
                             │
                     HACHIMAN AESP
              ┌──────────────▼──────────────┐
              │ Observe → Normalize         │
              │ Authorize → Analyze         │
              │ Decide → Enforce → Report   │
              └──────────────┬──────────────┘
                             │
                      Security action
```

Hachiman does not require source-code modifications, file modification, code injection, dependency replacement, database schema changes, or binary patching.

> **The protected application owns its application environment. Hachiman owns the security perimeter.**

---

## 2. Watchman Model

Hachiman behaves like a security watchman outside a building.

```text
                    PROTECTED BUILDING
             ┌─────────────────────────┐
             │                         │
             │     BUSINESS / AI       │
             │       SOFTWARE         │
             │                         │
             └─────────────────────────┘
                       ▲
                       │
                 doors / gates
                       │
                       ▼
                    HACHIMAN
                       👁
                security perimeter
                       │
               detects trespasser
                       │
                       ▼
               alert / block /
                 quarantine
```

Hachiman watches legitimate entry/exit boundaries rather than entering the application's internal execution space.

---

## 3. External-Only Runtime Contract

### Hachiman may

- observe authorized security-relevant events;
- inspect authorized metadata;
- evaluate authorized requests;
- enforce policies at boundaries it controls;
- block authorized security-sensitive actions;
- quarantine authorized integrations;
- revoke explicitly granted permissions;
- generate evidence and reports.

### Hachiman must not

- modify protected application files;
- inject code into protected processes;
- rewrite application databases;
- replace application libraries;
- silently change application configuration;
- bypass authentication;
- bypass platform isolation;
- inspect unrelated data;
- consume unlimited host resources.

---

## 4. Boundary-First Automatic Adaptation

Hachiman should not begin by trying to understand the internal implementation of a platform.

It first discovers the **authorized security boundary**.

```text
Target
  ↓
Authorization verification
  ↓
Boundary discovery
  │
  ├── MCP
  ├── API / gateway
  ├── Tool interface
  ├── IPC / service boundary
  ├── security-event interface
  └── platform-supported adapter
  ↓
Capability assessment
  ↓
Least-invasive protection mode
```

The adapter layer only translates the platform's legitimate interface into Hachiman's normalized security model.

If a platform exposes no authorized boundary, Hachiman must not bypass it.

---

## 5. Protection Tiers

### Tier 0 — No Authorized Boundary

Hachiman cannot legitimately observe/control the target and does not attempt to bypass it.

### Tier 1 — Observation

```text
Observe → Detect → Report
```

### Tier 2 — Decision

```text
Observe → Analyze → Allow / Review / Block
```

### Tier 3 — Enforcement

```text
Observe → Decide → Block / Restrict / Quarantine / Revoke
```

### Tier 4 — Enterprise Control

```text
Runtime Enforcement
+
Fleet Visibility
+
Central Policy
+
Incident Management
```

This makes compatibility measurable rather than claiming universal access.

---

## 6. Application Plane vs Security Plane

```text
APPLICATION PLANE
┌──────────────────────────────────────┐
│ AI / Business / Enterprise Software │
│                                      │
│ Internal logic                       │
│ Internal files                       │
│ Internal state                       │
└──────────────────┬───────────────────┘
                   │
              Authorized
               boundary
                   │
═══════════════════╪════════════════════════
                   │
SECURITY PLANE     │
┌──────────────────▼───────────────────┐
│              HACHIMAN               │
│                                     │
│ Boundary Layer                      │
│ MCP Gateway                         │
│ Security Agent                      │
│ Identity / Authorization             │
│ Policy / Risk / Trust               │
│ Detection / Decision                │
│ Response / Quarantine               │
│ Resource Governor                   │
│ Audit / Reporting                   │
└─────────────────────────────────────┘
```

Hachiman has independent configuration and security state.

---

## 7. Independent Runtime and Failure Isolation

Hachiman should run as an independently managed security runtime.

```text
Protected Application Process Space
                 │
                 X
                 │
Hachiman Security Runtime
```

If Hachiman restarts:

- the protected application's files remain untouched;
- application state remains application-owned;
- Hachiman reconstructs only its own security state;
- controlled boundaries follow their configured failure policy.

If the protected application restarts, Hachiman's security records remain independent.

---

## 8. Security Resource Governor

The new **Security Resource Governor (SRG)** prevents Hachiman from becoming a performance problem.

It continuously considers:

- Hachiman CPU;
- Hachiman memory;
- host CPU pressure;
- host memory pressure;
- event rate;
- queue depth;
- semantic-analysis workload;
- threat level.

```text
Host Telemetry
      │
      ▼
Security Resource Governor
      │
 ┌────┼──────────────────────┐
 ▼    ▼                      ▼
CPU  Memory              Threat Level
 │    │                      │
 └────┼──────────────────────┘
      ▼
Adaptive Security Budget
      │
      ▼
Analysis Depth
```

---

## 9. Continuous but Adaptive Operation

Hachiman is always running, but it does not always perform maximum-cost analysis.

### Sentinel Mode

Normal environment:

- lightweight observation;
- deterministic policies;
- metadata-first analysis;
- no unnecessary semantic calls.

### Watch Mode

Minor anomaly:

- increased sampling;
- targeted correlation;
- additional deterministic checks.

### Threat Mode

Suspicious behavior:

- richer evidence;
- deeper correlation;
- selective semantic analysis.

### Incident Mode

High-confidence threat:

- prioritize containment;
- preserve evidence;
- perform bounded deep analysis;
- create incident;
- alert according to policy.

After containment:

```text
Incident → Recovery → Watch → Sentinel
```

---

## 10. Resource Priority

When resources become constrained:

```text
1. Security-critical enforcement
2. Authorization
3. Threat detection
4. Incident evidence
5. Policy evaluation
6. Semantic analysis
7. Historical analytics
8. Non-critical reporting
```

Non-essential workloads are reduced before security-critical enforcement.

---

## 11. Bounded Runtime

Hachiman should use:

- bounded worker pools;
- bounded event queues;
- memory limits;
- backpressure;
- streaming processing;
- incremental analysis;
- cache eviction;
- asynchronous reporting;
- controlled concurrency.

It must avoid:

- unbounded queues;
- loading complete historical logs into memory;
- duplicating entire datasets;
- one worker per event;
- permanent full-context LLM analysis.

---

## 12. Metadata-First Security

Hachiman should prefer security metadata over raw content.

Preferred:

```text
tool = database.query
action = read
data_class = confidential
authorization = denied
destination = external
risk = high
```

rather than copying:

```text
entire database response
entire conversation
all historical logs
all MCP schemas
```

Content should only be inspected when an authorized policy or security test requires it.

This improves:

- privacy;
- CPU usage;
- memory usage;
- token usage;
- latency.

---

## 13. Token-Efficient Security Pipeline

```text
                 SECURITY EVENT
                       │
                       ▼
                Normalize Event
                       │
                       ▼
                 Authorization
                       │
                       ▼
                  Policy Check
                       │
                       ▼
                  Decision Cache
                 │            │
                HIT          MISS
                 │            │
                 ▼            ▼
              DECISION    Risk Analysis
                              │
                         ┌────┴────┐
                         ▼         ▼
                       LOW       UNCERTAIN
                         │         │
                         ▼         ▼
                     Decision   Compact Context
                                    │
                                    ▼
                              Semantic Analysis
                                    │
                                    ▼
                             Risk + Confidence
                                    │
                                    ▼
                                 Decision
```

The expensive path is entered only when necessary.

---

## 14. Security Context Compression

The semantic engine receives a compact security context rather than the entire conversation.

Example:

```json
{
  "agent": "research-agent",
  "tool": "database.query",
  "action": "read",
  "data_class": "confidential",
  "authorization": "denied",
  "destination": "external",
  "anomaly": true
}
```

This reduces:

- model tokens;
- latency;
- memory;
- privacy exposure.

---

## 15. Decision Cache

Equivalent security situations should not repeatedly require semantic analysis.

```text
Request
  ↓
Security Fingerprint
  ↓
Decision Cache
  │
  ├── HIT → reuse valid decision
  └── MISS → analyze
```

Cache validity should depend on relevant factors such as:

- policy version;
- authorization state;
- tool capability/version;
- trust state;
- security context.

---

## 16. Adaptive Security Decision

Hachiman makes security depth proportional to uncertainty.

```text
LOW RISK
  ↓
Deterministic

MEDIUM RISK
  ↓
Additional rules

HIGH RISK
  ↓
Context correlation

CRITICAL RISK
  ↓
Deep analysis + containment
```

This is a core token-efficiency and performance principle.

---

## 17. Runtime Decision Model

Every significant action may produce:

```text
Risk Score
Decision Confidence
Trust Score
Authorization
Policy
Decision
Evidence
```

Example:

```text
Risk:              91/100
Confidence:        97%
MCP Trust:         38/100
Authorization:     DENIED

Decision: BLOCK
```

Risk, confidence and trust are separate values.

---

## 18. Authorization as a Hard Gate

The decision order is:

```text
IDENTITY
   ↓
AUTHORIZATION
   ↓
POLICY
   ↓
SECURITY ANALYSIS
   ↓
DECISION
```

Trust cannot override authorization.

An AI model cannot authorize itself.

Hachiman cannot grant itself additional authority.

---

## 19. Automatic Containment

Authorized response actions include:

```text
BLOCK
RESTRICT
REQUIRE APPROVAL
REVOKE PERMISSION
QUARANTINE MCP
ISOLATE AGENT
ALERT
CREATE INCIDENT
```

Example:

```text
Suspicious MCP
     ↓
Risk 73
     ↓
Restricted

Behavior escalates
     ↓
Risk 94 / Confidence 98%
     ↓
BLOCK
     ↓
QUARANTINE
     ↓
REVOKE AUTHORIZED PERMISSION
     ↓
INCIDENT
```

Containment must occur at boundaries Hachiman is explicitly authorized to control.

---

## 20. Unknown MCP Lifecycle

```text
DISCOVERED
    ↓
UNKNOWN
    ↓
UNVERIFIED
    ↓
RESTRICTED
    ↓
AUTHORIZED ASSESSMENT
    ↓
SECURITY SCORE
    ↓
TRUST DECISION
```

Possible outcomes:

```text
SAFE       → authorize according to policy
RESTRICTED → limited capabilities
SUSPICIOUS → review
DANGEROUS  → quarantine
```

Unknown does not automatically mean malicious.

---

## 21. Pre-Deployment and Runtime Continuity

```text
PRE-DEPLOYMENT
      │
 Scan + Test
      │
Safety Score
      │
Security Baseline
      ▼
   DEPLOY
      │
      ▼
   RUNTIME
      │
Behavioral Drift
      │
      ▼
 Reassessment
      │
 ┌────┴────┐
 ▼         ▼
Stable   Changed
            │
            ▼
          Rescan
```

A production approval is a baseline, not a permanent guarantee.

---

## 22. Zero-Impact Verification

The hackathon must demonstrate measurable overhead.

### Baseline

Run the protected application without Hachiman.

Record:

```text
CPU
Memory
Latency
Throughput
Error rate
```

### Protected

Run the identical workload with Hachiman.

Record the same metrics.

### Security test

Trigger an authorized simulated attack and measure:

```text
Detection
Risk
Confidence
Decision
Containment
CPU
Memory
Latency
```

### Stress test

Increase application load and verify Hachiman reduces non-critical work instead of starving the application.

---

## 23. Security Protection Overhead — SPO

Introduce a dedicated benchmark:

# SPO — Security Protection Overhead

```text
SPO
├── CPU overhead
├── Memory overhead
├── P95 latency overhead
├── Throughput impact
└── Security workload
```

Example dashboard:

```text
SECURITY PROTECTION OVERHEAD

CPU overhead          +2.1%
Memory overhead       +1.8%
P95 latency           +4.3%
Throughput impact     -1.2%

Threat detection       96%
```

These are measured values for the workload, not universal promises.

---

## 24. Platform Adaptation

The adapter contract is:

```text
Platform Adapter
├── discover_boundary()
├── observe_event()
├── normalize_event()
├── request_authorization()
├── enforce_allowed_action()
└── collect_security_metadata()
```

Adapters translate platform-specific events into Hachiman's normalized model.

The security engines remain platform-independent.

Potential platform categories:

- MCP AI applications;
- cloud agents;
- local agents;
- desktop AI applications;
- CLI agents;
- coding agents;
- enterprise assistants;
- business software;
- custom AI systems;
- high-security software with an authorized boundary.

---

## 25. Hachiman MCP Gateway

```text
AI Platform
    │ MCP
    ▼
┌─────────────────────────────┐
│ HACHIMAN MCP GATEWAY        │
│ Authenticate               │
│ Authorize                  │
│ Normalize                  │
│ Policy                     │
│ Risk                       │
│ Enforce                    │
│ Audit                      │
└──────────────┬──────────────┘
               │
               ▼
        Downstream MCP
               │
        ┌──────┼──────┐
        ▼      ▼      ▼
      Tools  Data    APIs
```

Hachiman exposes only authorized capabilities.

---

## 26. Business Software Protection

```text
                 BUSINESS SOFTWARE
              ┌─────────────────────┐
              │ Core application    │
              │ Internal services   │
              │ Database            │
              │ Files               │
              └──────────┬──────────┘
                         │
                 Authorized boundary
                         │
                         ▼
                 ╔══════════════╗
                 ║   HACHIMAN   ║
                 ║              ║
                 ║ Watch        ║
                 ║ Detect       ║
                 ║ Authorize    ║
                 ║ Protect      ║
                 ║ Report       ║
                 ╚══════════════╝
```

The business application remains independent.

---

## 27. High-Security Deployment

```text
Sensitive Software
       │
       │ authorized boundary
       ▼
Hachiman Runtime
       │
       ├── strict authorization
       ├── metadata-first observation
       ├── deterministic policy
       ├── resource budget
       ├── isolated state
       ├── controlled enforcement
       └── auditable response
```

Semantic analysis can be disabled, localized or restricted according to the deployment policy.

---

## 28. Hackathon Differentiator

The project should be presented as more than an MCP scanner.

### Hachiman introduces:

**Adaptive External Security Perimeter (AESP)**

combined with:

- autonomous runtime defense;
- MCP security gateway;
- pre-deployment security assessment;
- dynamic trust;
- risk/confidence decisions;
- authorization-first enforcement;
- automatic containment;
- resource-aware security;
- token-efficient analysis;
- measurable Security Protection Overhead.

The novelty is the combination of **external isolation + adaptive security depth + autonomous enforcement + measurable low-overhead operation**.

---

## 29. Final End-to-End Architecture

```text
                         USER / ADMIN
                              │
                              ▼
                    ┌──────────────────┐
                    │ AUTHORIZATION    │
                    └────────┬─────────┘
                             ▼
                    ┌──────────────────┐
                    │ BOUNDARY         │
                    │ DISCOVERY        │
                    └────────┬─────────┘
                             ▼
                    ┌──────────────────┐
                    │ HACHIMAN AESP    │
                    │ External         │
                    │ Security         │
                    │ Perimeter        │
                    └────────┬─────────┘
                             │
             ┌───────────────┼────────────────┐
             ▼               ▼                ▼
        Observation      MCP Gateway      Resource
          Layer                           Governor
             │               │                │
             └───────────────┼────────────────┘
                             ▼
                    ┌──────────────────┐
                    │ SECURITY CORE    │
                    │ Identity         │
                    │ Authorization    │
                    │ Policy           │
                    │ Risk             │
                    │ Trust            │
                    │ Detection        │
                    │ Decision         │
                    └────────┬─────────┘
                             │
                    ┌────────┴─────────┐
                    │                  │
                  FAST               DEEP
                  PATH               PATH
                    │                  │
                    │           Compact context
                    │                  │
                    │           Semantic analysis
                    │                  │
                    └────────┬─────────┘
                             ▼
                       SECURITY DECISION
                             │
                  ┌──────────┼──────────┐
                  ▼          ▼          ▼
                ALLOW      REVIEW      BLOCK
                  │          │          │
                  │          │     CONTAINMENT
                  │          │          │
                  └──────────┼──────────┘
                             ▼
                    AUDIT / INCIDENT
                             │
                             ▼
                         REPORTING
                             │
                             ▼
                         REASSESSMENT
                             │
                             └──────→ CONTINUOUS GUARD
```

---

## 30. Final Product Principle

> **The protected software owns its application environment. Hachiman owns the security perimeter.**

> **Do not modify the building. Guard the boundary.**

> **Do not trust the visitor. Verify authorization.**

> **Do not inspect everything. Inspect what matters.**

> **Do not spend maximum resources continuously. Escalate when risk demands it.**

> **Do not only detect compromise. Contain it.**

> **Do not claim absolute security. Produce measurable evidence.**

# HACHIMAN

**SCAN → SCORE → AUTHORIZE → GUARD → DETECT → RESPOND → REPORT → REASSESS**
