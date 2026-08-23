# 05 — FEATURE BACKLOG (PRIORITIZED) + NON-GOALS

> MoSCoW per milestone. Acceptance criteria are demo-able + test-able.
> Cross-reference: workflows in doc 02, optimizations in doc 03, test gates in doc 04.

---

## 1. M0 — Foundations

| # | Feature | Pri | Acceptance criteria |
|---|---|---|---|
| F0.1 | Monorepo + CI (lint/test/typecheck/build) | Must | green pipeline < 3 min |
| F0.2 | Canonical types (doc01 §5) + Zod schemas | Must | schema-fuzz passes |
| F0.3 | Storage layer SQLite/WAL + migrations + append-only audit | Must | chaos disk tests green |
| F0.4 | Bounded EventBus + shed ladder skeleton | Must | overload test asserts class order |
| F0.5 | CLI skeleton (init/status/config/version, `--json`) | Must | scripted demo |
| F0.6 | Config model + validation + operator keypair | Should | signed-config roundtrip |
| F0.7 | Fixture MCPs (5 benign, 5 malicious) + sinks | Must | spawn under harness |
| F0.8 | Prometheus `/metrics` + per-stage timers | Should | metrics visible in gateway |

## 2. M1 — Security Core (Phase 1)

| # | Feature | Pri | Acceptance criteria |
|---|---|---|---|
| F1.1 | Identity engine (registry, Ed25519, sessions) | Must | golden cases + rotation test |
| F1.2 | Authorization engine + Grant model + hard-gate semantics | Must | no-authz-no-allow property test |
| F1.3 | Policy engine + JSON rule DSL + compile→matcher tree + versions/hot-reload | Must | determinism property test; hot-reload invalidates cache |
| F1.4 | Data classifier (metadata-first; secrets/PII patterns incl. Indian formats) | Must | classifier unit suite ≥ 95% precision on labeled set |
| F1.5 | Injection heuristics + canary protocol | Must | injection fixtures detected |
| F1.6 | Risk engine (8 factors, weighted, evidence) | Must | corpus calibration bands |
| F1.7 | Trust engine state machine + EMA score | Must | WF-02 transition table unit-locked |
| F1.8 | Decision engine + decide tables + explainer/trace | Must | 100 golden decisions |
| F1.9 | Audit engine + evidence refs on every verdict | Must | invariant test (no orphan verdicts) |
| F1.10 | Policy packs: `default`, `strict` | Should | docs + CLI `policy validate` |

## 3. M2 — MCP Gateway (Phase 2)

| # | Feature | Pri | Acceptance criteria |
|---|---|---|---|
| F2.1 | MCP proxy (stdio + HTTP), wire-compat passthrough | Must | conformance vs SDK reference servers |
| F2.2 | Capability capture on `initialize`, registry sync on `tools/list` | Must | schema-drifter fixture flagged |
| F2.3 | Intercept `tools/call` → full WF-05 pipeline | Must | e2e component test |
| F2.4 | ALLOW/REVIEW/BLOCK effects (forward / approval queue / -32088 error) | Must | live demo with benign + malicious fixtures |
| F2.5 | Tool param validation from registry schemas | Must | param-smuggler blocked |
| F2.6 | Egress inspection hook (result metadata; optional content per policy) | Should | secret-in-response fixture |
| F2.7 | `hachiman guard|status|mcp list|audit --tail` | Must | CLI demo |
| F2.8 | Per-stage latency instrumentation + budget asserts | Must | budget table (doc03 §8) measured |
| F2.9 | Approval inbox (dashboard v0 + CLI) | Should | review approve/deny roundtrip |

## 4. M3 — Pre-Deployment Scanner + Slice (Phase 3, hackathon gate)

| # | Feature | Pri | Acceptance criteria |
|---|---|---|---|
| F3.1 | Boundary discovery + tier report | Must | WF-01 demo incl. Tier-0 report |
| F3.2 | Attack-surface mapper (capability→surface model) | Must | fixture surfaces golden-locked |
| F3.3 | Test-selection engine (applicability predicates) | Must | selection unit suite; zero irrelevant runs |
| F3.4 | AI suite: direct/indirect injection, manipulation, poisoning, excessive agency, memory contamination, unsafe chaining | Must | corpus categories 1–6 pass |
| F3.5 | MCP suite: authz, capability exposure, excessive perms, unsafe params, schema, impersonation, unexpected behavior, unauthorized chaining | Must | categories 7–13 |
| F3.6 | App suite (where applicable): SQLi, cmd-inj, path traversal, SSRF, file ops, output inj, deserialization, authn/z flaws, data/secret exposure | Should | categories 14–20 (per surface) |
| F3.7 | Sandboxed test runner (scratch dirs, localhost sinks, budgets, timeouts) | Must | sandbox denial test |
| F3.8 | Findings model + validation (reproduce ≥1×) + severity matrix | Must | no unvalidated findings property |
| F3.9 | Production Safety Score (11 dims) + status gates + remediation guidance | Must | scoring calibration locks |
| F3.10 | Reports: scan/production (MD/JSON/PDF) | Must | demo report for sync-tool |
| F3.11 | Baseline snapshot → runtime handoff | Must | WF-09 drift compare works |
| F3.12 | `hachiman scan/test/inspect/report production` | Must | CLI golden transcripts |
| F3.13 | SPO v1 (baseline vs protected + threat run) | Must | statement rendered (doc04 §6.2) |
| F3.14 | Shadow/observe-only mode for first-touch deployments | Should | Tier-1 demo |

## 5. M4 — Runtime Agent (Phase 4)

| # | Feature | Pri | Acceptance criteria |
|---|---|---|---|
| F4.1 | Behavior profiles (baselines; Markov-lite sequences; volume/destination stats, fixed-memory) | Must | drift fixture triggers WATCH |
| F4.2 | Anomaly detector → risk elevation events | Must | category 21 corpus pass |
| F4.3 | Attack-chain detector (multi-step correlation) | Must | category 22 corpus pass |
| F4.4 | Response engine + action ladder L1–L6 with grant checks | Must | ladder unit + e2e containment demo |
| F4.5 | Quarantine manager (enter/release requiring operator + rescan) | Must | WF-02/07 transitions locked |
| F4.6 | Incident lifecycle + timeline + dedupe + bundle evidence | Must | report incident demo |
| F4.7 | Trust runtime dynamics (penalties/rewards, floor on violation) | Must | WF-09 example trajectory reproducible |
| F4.8 | Reassessment triggers (capability diff, drift, policy bump) | Must | auto-rescan advisory + forced rescan on capability change |
| F4.9 | Notifications/webhooks (HMAC signed) | Should | webhook roundtrip test |
| F4.10 | Dashboard v1 (Environment/Security/Trust/live stream) | Should | demo page parity with doc00 §8 |

## 6. M5 — Token Efficiency & SRG (Phase 5 + 2.0 §8–16)

| # | Feature | Pri | Acceptance criteria |
|---|---|---|---|
| F5.1 | SemanticAnalyzer SPI + compact-context builder (≤800 tok in) | Must | evidence-only contract test |
| F5.2 | Semantic escalation gate (confidence floor, SRG slots, conservative fallback) | Must | WF-06 chaos test (provider timeout) |
| F5.3 | Decision cache + fingerprint + generation-token invalidation | Must | ≥70% hit on replay profile; poison attempts fail |
| F5.4 | Request coalescing (200ms window) | Should | call-count reduction measured |
| F5.5 | SRG telemetry loop + SecurityBudget + priority ladder enforcement | Must | stress test (doc04 §6.1.5) |
| F5.6 | Mode machine SENTINEL→WATCH→THREAT→INCIDENT→RECOVERY + hysteresis + audit | Must | mode transition e2e demo |
| F5.7 | Token/efficiency metrics + dashboard Performance page | Must | KPIs live |
| F5.8 | Token-regression CI gates | Must | doc04 §7 gates enforced |
| F5.9 | High-security deployment mode (semantic fully disabled) | Should | fixture pack + docs (2.0 §27) |

## 7. M6 — Enterprise (Phase 6 + 2.0 Tier 4)

| # | Feature | Pri | Acceptance criteria |
|---|---|---|---|
| F6.1 | Multi-tenant isolation (tenants on all entities/logs/incidents/reports) | Must | cross-tenant negative test suite |
| F6.2 | Control-plane service (Fastify + Postgres) + runtime mTLS channel | Must | fleet of 3 runtimes demo |
| F6.3 | Org policy packs: signed, versioned, atomic activation + cache invalidation | Must | WF-10 demo + forgery rejection |
| F6.4 | Fleet visibility (aggregated risk/trust/SPO) | Should | enterprise dashboard pages |
| F6.5 | Incident management (fleet-wide, quarantine broadcast) | Should | broadcast containment demo |
| F6.6 | Compliance exports (audit log export, evidence bundles, report packs) | Should | export schema + integrity hashes |
| F6.7 | RBAC for operators (owner/security-ops/auditor/viewer) | Must | matrix test |
| F6.8 | Local-stricter-wins conflict rule | Must | conflict fixture test |

## 8. Post-v1.0 candidates (explicitly NOT in v1)

Platform adapters beyond v1 set (cloud-agent vendor hooks, IDE agent hooks);
marketplace/policy-store; mobile approval app; ML-assisted anomaly baselines;
formal verification of policy interactions; managed SaaS control plane;
non-MCP tool protocols (function-calling direct interception).

---

## 9. Non-goals (architecture §28 — enforced at PR review)

Hachiman is **not**: a replacement for an AI model; a replacement for MCP; generic antivirus;
generic web scanner; a means to bypass AI-provider restrictions; an unauthorized pentest tool;
a system that trusts an LLM's verdict; a bundle of third-party security plugins.
Any PR that drifts into these areas is rejected.

---

## 10. Definition of Ready / Done (per feature)

**Ready:** mapped to a workflow step (doc 02) · fixture/corpus entry designed · acceptance
criteria written · dependency modules stable.
**Done:** code + unit + golden/corpus cases green · instrumented (metrics) · docs/CLI help
updated · SPO micro-run within budgets if hot-path touched · reviewed against principles
(doc00 §2).
