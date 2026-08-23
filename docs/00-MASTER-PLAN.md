# HACHIMAN AGENT — MASTER EXECUTION PLAN (A → Z)

> Source of truth for planning. Derived from `NG's Hachiman Agent - Final Architecture.md`
> (Architecture v1 + FINAL ARCHITECTURE 2.0 — Adaptive External Security Perimeter).
>
> **One-line definition:** Hachiman is an authorized, external, autonomous security perimeter
> that **scans AI agents/MCPs before deployment** and **mediates, monitors, and contains
> their actions at runtime** — without ever modifying the protected software.

---

## 0. Plan map (read in order)

| Doc | Contents |
|---|---|
| `00-MASTER-PLAN.md` | Vision, principles, phases, milestones, versions, KPIs, demo script (this file) |
| `01-IMPLEMENTATION-ARCHITECTURE.md` | Tech stack, monorepo layout, 20-module specs, data model, storage schemas, API surface, Hachiman's own security |
| `02-WORKFLOWS.md` | 10 end-to-end workflow specs with sequences, decision tables, failure handling |
| `03-OPTIMIZATION.md` | Token-efficiency pipeline, decision cache, Security Resource Governor, performance budgets, bounded runtime |
| `04-TESTING-AND-BENCHMARKING.md` | Test pyramid, attack fixture corpus, golden-decision regressions, SPO benchmark harness, CI gates |
| `05-FEATURE-BACKLOG.md` | Prioritized (MoSCoW) feature backlog per phase with acceptance criteria, explicit non-goals |

---

## 1. What we are building

Two products sharing one security model (architecture §25 continuity):

### Product A — "Is this agent/MCP safe to deploy?" (Pre-Deployment)
1. **Discovery**: find MCPs/agents/tools reachable through authorized boundaries.
2. **Scanner**: capability inspection → attack-surface map → applicable-test selection →
   controlled security tests (prompt injection, tool poisoning, parameter safety, authz flaws…).
3. **Production Safety Score**: 0–100 across 11 dimensions + findings (C/H/M/L) +
   status verdict (`PRODUCTION READY` / `WITH RESTRICTIONS` / `NOT READY`).
4. **Report & remediation loop**: findings with evidence, fix guidance, retest, baseline handoff.

### Product B — "Is this action safe and authorized right now?" (Runtime)
1. **MCP Security Gateway**: sits between AI platform/app and downstream MCPs/tools;
   intercepts every tool request, normalizes it, and decides ALLOW / REVIEW / BLOCK.
2. **Autonomous Security Agent**: continuous monitoring, anomaly/behavior analysis,
   injection detection, data-leak prevention, automatic containment (quarantine/revoke/isolate),
   incident creation, reporting, and reassessment.
3. **Triple decision values** kept separate: Risk Score (0–100), Decision Confidence (0–100%),
   Trust Score (0–100).

### The differentiator (architecture 2.0 §28)
**AESP** — external isolation + **adaptive security depth** + autonomous enforcement +
**measurable low overhead (SPO)**. We present evidence, not claims.

---

## 2. Non-negotiable principles (enforced in code review)

1. **External-only**: never write into the protected app's files/processes/DB (2.0 §3 contract).
2. **Authorization first**: every Hachiman action requires an explicit grant; grants are revocable, TTL'd, audited.
3. **Model is not the security authority**: an AI can request, never approve, its own action.
4. **Fail closed** for security-critical decisions when authz cannot be verified.
5. **Deterministic first, AI when necessary**: LLM is an evidence producer, never the final decider.
6. **Separate the three values**: risk ≠ confidence ≠ trust; never collapse them into one number.
7. **Trust never overrides authorization.**
8. **Bounded runtime**: every queue/pool/cache has a size limit and backpressure policy.
9. **Metadata-first**: inspect content only when an authorized policy or test requires it.
10. **Everything audited**: every decision carries evidence + policy trace + explainable rationale.

---

## 3. Delivery phases → milestones

We compress the architecture's six phases into **7 milestones (M0–M6)**. Each milestone has an
exit demo; **M3 is the hackathon-shippable vertical slice**.

```
M0 Foundations ─► M1 Security Core ─► M2 MCP Gateway ─► M3 Scanner + Slice (DEMO)
                                                            │
                 ┌──────────────────────────────────────────┘
                 ▼
M4 Runtime Agent ─► M5 Token Efficiency & SRG ─► M6 Enterprise
```

| Milestone | Scope (architecture phase) | Exit criteria / demo |
|---|---|---|
| **M0 — Foundations** | repo, tooling, schemas | Monorepo builds; CI green; normalized `SecurityEvent` + storage up; `hachiman init/status` works |
| **M1 — Security Core** | Phase 1 | Identity/AuthZ/Policy/Risk/Decision/Audit engines pass unit + golden-decision suites; deterministic replay proven |
| **M2 — MCP Gateway** | Phase 2 | Real MCP client → Hachiman proxy → real downstream MCP; allow/review/block demonstrated; full audit trail |
| **M3 — Scanner + Slice** | Phase 3 (partial) + demo | `/hachiman scan <mcp> --production` produces a real Safety Score + PDF/MD report; malicious test MCP gets scored low and quarantined; **SPO baseline vs protected run** |
| **M4 — Runtime Agent** | Phase 4 | Continuous monitor; prompt-injection + data-exfil scenarios detected & auto-contained E2E; trust dynamics live; reassessment triggers rescan |
| **M5 — Efficiency & SRG** | Phase 5 + 2.0 §8–16 | ≥90% deterministic decisions; cache hit ≥70%; sentinel→incident mode transitions verified; SPO within budgets |
| **M6 — Enterprise** | Phase 6 + 2.0 Tier 4 | Multi-tenant isolation; central control plane; fleet dashboard; org policy propagation; incident management |

### Phase-to-milestone mapping (architecture §30)
- Phase 1 Core Security → M1 · Phase 2 MCP Gateway → M2 · Phase 3 Scanner → M3
- Phase 4 Runtime Agent → M4 · Phase 5 Token Efficiency → M5 · Phase 6 Enterprise → M6
- Cross-cutting: SPO benchmark starts at M2 and gates every milestone afterwards.

---

## 4. Version & release strategy

| Version | Content | Audience |
|---|---|---|
| `v0.1` (M3) | Gateway + scanner + CLI + report + SPO demo | Hackathon / first users, single-tenant local |
| `v0.2` (M4) | Runtime agent, containment, incidents, dashboard v1 | Early adopters ("protect one agent fleet") |
| `v0.3` (M5) | Efficiency hardening, SRG, modes, cache | Performance-sensitive deployments |
| `v0.4` (M6) | Multi-tenant control plane, fleet management | Enterprise pilots |
| `v1.0` | Stability, docs, policy library, certified adapters | GA |

Distribution: npm packages + Docker image + single-binary CLI (`hachiman`).
Enterprise control plane ships as a separate service (stateless API + Postgres) reusing core packages.

---

## 5. Success metrics (KPIs)

### Security effectiveness (measured on fixture corpus + live, never claimed)
- Detection rate on attack corpus ≥ **95%**; false-positive rate ≤ **2%**
- 0 "fail-open" incidents in chaos tests (fail-closed verified)
- Every BLOCK carries complete evidence chain (explainability = 100% by construction)

### Efficiency (architecture §17 + 2.0 §13–15)
- Deterministic-path decisions ≥ **90%** of all requests
- Decision-cache hit rate ≥ **70%** under replay-heavy workloads
- Tokens per security decision: median ≤ **0** (fast path), p95 ≤ **~1.5k** (escalated)
- LLM calls per request: median **0**, p99 ≤ **1**

### Performance / overhead (SPO, architecture 2.0 §22–23)
- Gateway fast-path added latency: p50 ≤ **5 ms**, p95 ≤ **25 ms**, p99 ≤ **75 ms**
- CPU overhead ≤ **5%**, memory overhead ≤ **10%** vs baseline workload
- Throughput impact ≥ **−2%** under normal load; SRG sheds non-critical load under stress

### Adoption (north-star)
- Time from `hachiman guard <mcp-config>` → first protected request < **10 minutes**
- Time from `hachiman scan` → production verdict + report < **15 minutes** per MCP
- 3 reference integrations (one coding agent, one business AI app, one custom MCP suite)

---

## 6. Workstreams & stakeholders

| Workstream | Owner role | Deliverables | Milestones |
|---|---|---|---|
| Core engines | Backend lead | identity, authz, policy, risk, trust, decision, audit | M0–M2, M5 |
| Gateway & adapters | Backend | MCP proxy, normalization, enforcement hooks | M2, M4, M6 |
| Scanner | Security lead | discovery, attack-surface mapper, test runner, scoring | M3 |
| Runtime defense | Backend/security | monitor, anomaly, response, quarantine, modes | M4–M5 |
| CLI + Dashboard | Frontend | `/hachiman`, reports, live dashboard | M2–M6 |
| Benchmarking | Platform | corpus, SPO harness, CI gates | M2 onward (standing) |
| Docs/GTM | Product | policy templates, integration guides, demo script | M3, M6 |

Solo-dev mode: serialize workstreams in milestone order; benchmarking stays automated from M2.

---

## 7. Immediate next actions (Week 1 — M0 checklist)

1. Scaffold monorepo (layout in `01-IMPLEMENTATION-ARCHITECTURE.md` §3) + CI (lint, test, typecheck).
2. Implement `@hachiman/core` types: `SecurityEvent`, `SecurityRequest`, `Decision`, `Finding`,
   `SafetyScore`, `TrustRecord`, `Grant`, `Incident` (schemas in doc 01 §5).
3. Implement storage layer (SQLite/WAL) + migration tooling; audit log = append-only table.
4. Implement event bus with bounded queues + drop/shed policies (doc 03 §6).
5. Build CLI skeleton: `hachiman init | status | config | version`, JSON + human output modes.
6. Create `fixtures/` seed: 5 benign MCP specs + 5 malicious MCP specs (doc 04 §3 corpus design).
7. Write first golden decisions (20 cases) to lock deterministic semantics (doc 04 §4).

---

## 8. Hackathon demo script (for v0.1 / M3)

Stage a "customer MCP ecosystem": one benign MCP (`notes`) and one malicious MCP (`sync-tool`
that exfiltrates data and obeys injected instructions).

1. **Onboard (2 min)** — `hachiman init && hachiman guard ./mcp-config.json`; show zero-change
   to the app (AESP watchman slide).
2. **Scan (3 min)** — `hachiman scan mcp:sync-tool --production`
   → score ~40 with HIGH findings (excessive DB access, unrestricted external HTTP);
   `notes` scores 92 + PRODUCTION READY.
3. **Live guard (3 min)** — chat with a protected agent: benign tool call → ALLOW (<5 ms shown);
   then trigger (a) an indirect prompt injection from a fetched web page, (b) an exfil attempt:
   `http.request` to unknown destination with confidential payload → Risk 94 / Confidence 97%
   → **BLOCK → QUARANTINE → INCIDENT** live on dashboard.
4. **Evidence (2 min)** — `hachiman report incident` → full report: findings, evidence,
   decision trace, remediation. Run retest after "fix" → score 91 → allow.
5. **Overhead proof (2 min)** — SPO panel: CPU +2.1%, P95 +4.3%, deterministic 93%, cache 71%.

---

## 9. Top risks & mitigations (full register in doc 05 §5)

| # | Risk | Mitigation |
|---|---|---|
| 1 | MCP spec churn breaks gateway | Pin SDK versions; conformance tests vs reference MCP servers in CI |
| 2 | False-positive blocks erode trust | REVIEW tier before BLOCK; per-tool allowlists; shadow mode (observe-only) first |
| 3 | Scanner tests cause side effects | Sandbox mode + dry-run capability classification; tests only touch scoped scratch resources |
| 4 | Semantic path cost explosion | SRG budgets + request coalescing + decision cache (doc 03) |
| 5 | Hachiman itself becomes an attack surface | Least-privilege grants, self-audit, signed config, no self-escalation (doc 01 §9) |
| 6 | Scope creep toward "AI platform" | Non-goals list in doc 05 §6 enforced at PR review |

---

## 10. Definition of Done (program-level)

Hachiman v1.0 is done when:
- All M0–M6 exit demos pass with reproducible scripts.
- SPO numbers published with methodology (measured values, not promises — architecture 2.0 §23).
- Fixture corpus ≥ 200 scenarios; CI regression gates on detection rate, FP rate, and overhead.
- Third-party-style red-team pass on the gateway itself with no fail-open findings.
- One external reference deployment running protected for ≥ 2 weeks with ≥99.9% decision availability.
