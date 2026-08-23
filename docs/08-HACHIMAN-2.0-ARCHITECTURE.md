# 08 — Hachiman 2.0 Architecture: Repository Audit & Universal Control-Plane Plan

> **Status:** AUDIT COMPLETE / PLAN APPROVAL PENDING — no 2.0 code exists yet.
> Everything marked **EXISTS** in this document maps to real code and tests in this repository.
> Everything marked **PLANNED** is design only. Nothing is claimed implemented unless it is.
>
> **Target principle:** *"AI can act. Hachiman decides whether it is allowed to act."*
> **Author:** Nidhish Guhan · **Applies to:** Hachiman Agent v0.2 (`main`, commit era 2026-08)

---

## 1. Complete repository audit (what exists today)

### 1.1 Composition root — `lib/hachiman.js`

`createNode(config)` assembles the whole runtime with **no await required**, returns a `node`:

| Member | Built from | Role |
|---|---|---|
| `storage` | `packages/core/src/storage.js` | SQLite WAL persistence, append-only audit |
| `bus` | `packages/core/src/bus.js` | EventBus with shed classes (`{shedClass, name}`) |
| `metrics` | `packages/gateway/src/metrics.js` | decision/latency/cache counters |
| `policyEngine` | `packages/engines/src/policy.js` | rule packs loaded from `policies/` |
| `identity` | `engines/src/identity.js` | session tokens, subjects |
| `authz` | `engines/src/authorization.js` | grants hard gate |
| `monitor` | `packages/runtime/src/monitor.js` | behavior signals + chains |
| `srg` | `packages/srg/src/srg.js` | modes SENTINEL→WATCH→THREAT→INCIDENT, budgets |
| `response` | `packages/runtime/src/response.js` | containment ladder L1–L6, quarantine, incidents |
| `gateway` | `packages/gateway/src/gateway.js` | the ONLY ingress today (MCP) |
| `scanner` | `packages/scanner/src/scanner.js` | pre-deployment discovery + tests + scoring |
| `semantic` | `engines/src/semantic.js` | **advisor only** (`LocalHeuristicAnalyzer`) |
| `canary` | `engines/src/injection.js` | injection canary |

Operator helpers: `allowAgent`, `allowMcp`, `status()`, `start()`/`stop()` (idempotent).

### 1.2 Storage schema — `packages/core/src/storage.js` (18 tables)

`kv, entities, sessions, grants, trust_records, tool_registry, policies, quarantine, incidents,
scans, decision_cache, metrics_rollups, engagements, pentest_findings, repair_contracts,
retest_results, audit_events`.

Prepared statements only; `audit_events` is append-only (DELETE rejected — enforced by test).
Offense tables added in v0.2: engagements / pentest_findings / repair_contracts / retest_results.

### 1.3 Security Decision Plane — `packages/engines/src/decision.js`

`evaluateRequest(deps, req)` — one deterministic pipeline, 11 stages:
`IDENTITY → AUTHORIZATION (hard gate) → TOOL REGISTRY → LEGITIMACY/SCHEMA → CLASSIFY →
INJECTION → POLICY (can force) → CACHE (decision_cache) → RISK → DECIDE (thresholds) →
FAILURE MODES (failsafes) → SEMANTIC (advisor) → AUDIT + emit`.

Output: `{decision: ALLOW|REVIEW|BLOCK, risk 0-100, confidence 0-100, trust 0-100, reasons[],
evidence[], path}` — risk/confidence/trust are **separate values, never conflated**.

Request shape today: `{id, ts, mcpId?, toolId?, params, destination?, authzContext?, identity?,
classification?, injection?, toolMeta?...}` — **mostly generic; MCP-flavored in 4 fields** (see §3).

### 1.4 Security Engines (all deterministic, all authoritative)

| Engine | File | Status |
|---|---|---|
| Identity (sessions) | `engines/identity.js` | EXISTS — register/resolve/verify; kinds operator/agent/service |
| Authorization (grants) | `engines/authorization.js` | EXISTS — `{subject, capability, resource, constraints, ttlMs, maxUses}` → ALLOW/DENY/CONDITIONAL |
| Policy rule packs | `engines/policy.js` | EXISTS — `when{}` predicates → force decision / riskFloor |
| Data classifier | `engines/classifier.js` | EXISTS — secrets/PII/confidential detection on params |
| Injection detector | `engines/injection.js` | EXISTS — deterministic indicators + canary |
| Risk scorer | `engines/risk.js` | EXISTS — tool risk + classification + destination + injection + trust |
| Semantic analyzer | `engines/semantic.js` | EXISTS — **advisor only**; output validated, never authoritative |
| Trust model | `engines/trust.js` | EXISTS — UNKNOWN→TRUSTED/RESTRICTED/HIGH_RISK/QUARANTINED, EMA feedback |

Policies: `default`, `high-security`, `strict` (`policies/*.hachiman.json`), rule shape
`{id, when{}, then{decision?, riskFloor?, reason}}`.

### 1.5 Gateway + Discovery + Runtime + SRG

* **Gateway** (`packages/gateway/`): `McpGateway` owns HTTP + stdio MCP clients, serves
  `/mcp/<server>`, plus `stdio-bridge.js` (universal: exposes protected MCPs to any MCP host),
  `normalize.js`, `metrics.js`.
* **Scanner** (`packages/scanner/`): `surface.js` (capability discovery), `tests.js` (controlled
  test catalog: injection relay, injection→egress chains, excessive agency, bulk exfiltration,
  unrestricted egress, param smuggling, tool impersonation, forged auth, capability drift, SQLi
  surface, path traversal, secret exposure), `scoring.js` (11-dimension Production Safety Score
  + `PRODUCTION_READY[_WITH_RESTRICTIONS]` / `NOT_PRODUCTION_READY` gates), drift re-scan loop.
* **Runtime** (`packages/runtime/`): `monitor.js` (per-subject windows; signals: `rate-burst`,
  `novel-destination`, `repeated-authz-failure`, `injection`; chain detection), `response.js`
  (containment ladder 1–6: review→throttle→restrict→flag→suspend→quarantine; incident timelines).
* **SRG** (`packages/srg/`): global posture modes + resource budgets
  (`analysisDepth`, `semanticConcurrency`, `cacheTtlScale`); reacts to threatLevel / bus events.

### 1.6 Offensive skill, reporting, dashboard, benchmark, CLI

* **Offense** (`packages/offense/`, 11 modules): engagement ROE (`engagement.js`), hypothesis
  lifecycle (`hypothesis.js`), planner (`planner.js`), controlled attack execution (`attack.js`),
  validation (`validation.js` — reproducible + controlled difference + safe proof), attack graph
  (`graph.js`), root-cause engine (`rootcause.js`), AI Repair Contracts (`repair.js`), verified
  retest (`retest.js` — VERIFIED/UNRESOLVED/REGRESSION), orchestrators (`recon.js`, `pentest.js`).
* **Reporting** (`packages/reporting/`): scan / incident / SPO / pentest reports (text + JSON).
* **Dashboard** (`packages/dashboard/`): SSE live feed + REST + admin-gated mutations; Mission
  Control UI (KPI sparklines, perimeter, decision mix, efficiency/SPO, offensive panel, **Advisor
  fix-recommendation engine** `recommend.js`); endpoints incl. `/api/offense`, `/api/health`.
* **Benchmark** (`packages/benchmark/`): `runner.js`, `spo.js` (Security Protection Overhead),
  `offense-metrics.js`.
* **CLI** (`packages/cli/`, `bin/hachiman.js`): 26 commands — init, config, guard, scan, trust,
  threats, quarantine, agent, agents, audit, report, mcp, policy, dashboard, bridge, recon,
  pentest, findings, explain, fix, retest, chain, status, test, inspect, help.
* **Fixtures**: 12 MCP fixtures incl. adversarial (`sync-tool`, `schema-drifter`, `identity-spoof`,
  `param-smuggler`) and intentionally vulnerable lab targets (`vuln-notes`, `vuln-notes-fixed`),
  golden set, benign corpus, attack corpora (injection, exfiltration, authorization, chains).

### 1.7 Tests (the definition of "exists") — 81 passing

| Layer | Files | Counts |
|---|---|---|
| Unit | `core-runtime`, `engines`, `offense` | 43 |
| Golden | `golden.test.js` | 14 |
| Attack corpus | `corpus.test.js` | 4 |
| Property | `property.test.js` | 2 |
| E2E | `scan`, `guard`, `bridge`, `offensive-loop`, `dashboard` | 18 |

### 1.8 Security boundaries & invariants (EXISTS, must survive 2.0)

1. **The LLM is an advisor, never the authority** — semantic output cannot ALLOW/BLOCK.
2. **Authorization is a hard gate** — no grant ⇒ no capability; grants are human-issued.
3. **Trust promotion is operator-only** — scans inform; humans decide.
4. **Fail-closed** on verification failure for sensitive resources; quarantine is sticky.
5. **Audit is append-only** — deletion is rejected; forensics follow the log, never the model.
6. **Risk / confidence / trust are separate values**, never conflated.
7. **Offense requires written authorization** (engagement file; ROE enforced deterministically).
8. **Zero runtime dependencies**, Node ≥ 22.5, all OSes.

### 1.9 Extension points today

* `EventBus` channels (add channel = add surface without touching producers).
* `policy pack` rule conditions (new `when` predicates).
* `grants` capability/resource strings (already protocol-neutral).
* `fixtures/host.js` + corpus/golden pattern (add target ⇒ add test material).
* Dashboard `recommend.js` rule arrays (reason → fix).
* CLI command dispatch (additive `case`).

---

## 2. Reusable components (carry forward unchanged where possible)

| Component | 2.0 reuse |
|---|---|
| `EventBus` + shed classes | transport for **all** planes (decision, discovery, attack, forensics) |
| `Storage` + `audit_events` | forensics backbone; extend additively with 2.0 tables |
| `evaluateRequest(deps, req)` | the **universal decision core** — needs a resource-neutral seam (§4) |
| `AuthorizationEngine` grants | universal primitive: `api:read@/v1/users`, `k8s:exec@prod/*` fit today |
| `PolicyEngine` | policy plane for every adapter (new predicates only) |
| `trust.js` subject model | any subject id (`agent:`, `mcp:` → plus `svc:`, `app:`, `pipeline:`) |
| `ResponseEngine` ladder + incidents | containment plane, already keyed by subject string |
| `BehaviorMonitor` signals | generic per-subject; gains data-flow signals (§4.4) |
| SRG modes/budgets | global posture; budget axes generalized (§4.3) |
| Offense `graph.js`/`chainImpact` | embryo of the Security Knowledge Graph |
| Dashboard + `recommend.js` | Mission Control; rules extended as planes arrive |
| Corpus/golden/property harness | every 2.0 adapter ships with its own corpus |
| Installer/CI verification contract | unchanged; extended with adapter integrity probes |

---

## 3. Architectural conflicts (what blocks "universal" today)

* **C1 — MCP-flavored decision request.** `req.mcpId/toolId` and `tool_registry`-backed
  `toolMeta` are baked into `evaluateRequest` and `risk.js`. A web request, a k8s exec, or a
  CI artifact has no honest home in those fields.
* **C2 — Gateway is the only ingress.** `McpGateway` is hard-wired in composition; there is no
  adapter SPI, so an HTTP API or a container-runtime signal cannot reach the decision core.
* **C3 — Scanner is MCP-bound.** Surface discovery, test catalog and tool registry assume MCP
  semantics (`tools/list`). 11 scoring dimensions are conceptually generic but mechanically MCP.
* **C4 — SRG budgets are LLM-shaped.** `tokensPerDecision`, `semanticConcurrency` assume LLM
  advisory passes; non-LLM planes need resource-agnostic budget axes.
* **C5 — Offense executors assume MCP-shaped connections.** `executeProbe(eng, client, …)` speaks
  MCP `tools/call`; other target families need per-type executors inside the same ROE envelope.
* **C6 — Dashboard APIs are MCP-shaped.** `/api/mcps`, perimeter panel assume MCP servers.
* **C7 — Identity is session-local.** No federation: external principals (OIDC, service mesh,
  cloud IAM) cannot map into Hachiman subjects; sessions dominate identity.
* **C8 — Policy predicates are MCP/decision-centric.** No data-flow, infrastructure, or supply-chain
  predicates yet.
* **C9 — No plugin/extension registry.** Everything is a static import; adapters need a
  registration surface that stays deterministic (code, no LLM).

---

## 4. Missing abstractions (the minimum set for Hachiman 2.0)

### 4.1 Resource descriptor (`packages/planes/src/resource.js` — PLANNED)

One shape describes every protected target:

```js
{ type: 'mcp'|'api'|'app'|'desktop'|'mobile'|'game'|'cloud'|'k8s'|'container'|'db'|
        'ci'|'supply'|'data'|'identity'|'service',
  id: 'api:billing-service',
  attrs: { /* type-specific: route, namespace, table, image, pipeline stage… */ } }
```

Decision requests gain `subject / action / resource` as first-class fields; legacy
`mcpId/toolId` remain as sugar that maps to `{type:'mcp', …}` (C1 fix).

### 4.2 Adapter SPI + registry (`packages/adapters/` — PLANNED)

```js
{ id, resourceTypes, protocol,
  register(node),                       // deterministic; adds ingress + metadata provider
  toDecisionRequest(raw) }              // adapter is a translator, never an authority
```

`McpGateway` gets wrapped as the **first registered adapter** (`adapters/mcp/`) — existing
golden decisions must remain byte-identical for the same corpus (compat gate for C2).

### 4.3 Plane registry in composition (PLANNED)

`createNode` gains `planes: { decision, discovery, engines, adapters, response, forensics,
knowledge, intel, identity, srg, telemetry }` alongside today's members — **additive**, nothing
removed (C9 fix). SRG budgets grow axes: `{tokens, apiQps, scanConcurrency, probeRate}` (C4 fix).

### 4.4 Data-flow engine (PLANNED)

`flows` as first-class events: `(subject → resource → destination, classification, volume)`.
The classifier already tags params; a flow ledger turns tags into auditable lineage, feeds
BehaviorMonitor with `data-flow` signals, and gives policy new `when` predicates (C8 fix).

### 4.5 Identity federation seam (PLANNED)

`IdentityEngine` gains a **mapping + verification hook** layer: external principal →
Hachiman subject, verified by adapter-supplied attestation. Sessions remain authoritative for
gateway clients; federation never auto-grants anything (grants stay human-issued) (C7 fix).

### 4.6 Threat intelligence context (PLANNED)

An **advisory** intel provider feeds `risk.js` evidence (e.g., known-bad destinations). Same
rule as semantic: intelligence can raise risk and force REVIEW via policy — it can never be the
sole authority for ALLOW.

### 4.7 Security Knowledge Graph (PLANNED)

Generalize offense `graph.js` into node/link types: `subject|resource|finding|flow|incident|grant`,
edges: `auth-dependency|data-flow|privilege-transition|tool-capability|workflow|observed-attack`.
Manifest: persisted in new tables; rendered additively in Mission Control (C6 fix).

---

## 5. Phased implementation plan (minimum changes per phase)

| Phase | Scope | Non-goals |
|---|---|---|
| **P0 — audit + plan** (this document) | map, conflicts, abstractions, compat contract | no code |
| **P1 — core seams** | `resource.js` descriptor, adapter registry skeleton, new bus channels, `subject/action/resource` accepted by `evaluateRequest` with legacy mapping | no new behavior; all 81 tests green |
| **P2 — MCP behind adapter SPI** | wrap `McpGateway` as registered adapter; node.gateway stays working via adapter | golden corpus byte-identical |
| **P3 — universal decision input** | risk.js metadata provider becomes adapter-supplied (tool_registry fallback); policy predicates gain resource-type awareness | semantics frozen for MCP input |
| **P4 — adapters, one release each** | 1) HTTP/API reverse-proxy adapter (+corpus) 2) CLI/shell adapter 3) container/k8s admission stub 4) data-flow tap | families without an adapter stay **PLANNED** in docs |
| **P5 — knowledge + forensics** | attribution tables, forensics replay API, SRG axes, intel hook, identity federation seam | federation maps subjects only; never grants |
| **P6 — Mission Control 2.0** | `/api/resources`, `/api/planes`, knowledge-graph panel, per-adapter health, recommend rules extended | dashboard stays additive (old endpoints untouched) |
| **P7 — benchmark expansion** | per-adapter SPO, universal decision overhead bench, corpus growth rules | measured claims only |

### 5.1 Backward-compatibility contract (enforced per phase)

1. **All 26 CLI commands survive**; new commands are additive; flags only ever extend.
2. **All REST endpoints survive**; new ones are additive (`/api/resources`, …).
3. **All 18 storage tables survive**; new tables are additive; no column renames.
4. **Config keys survive**; `mcpServers.*` keeps working (mapped into resource descriptors).
5. **Golden test set is frozen per adapter** — same input ⇒ same verdict bytes.
6. **Invariants §1.8 are untouchable** — any phase that would weaken them is rejected in review.

### 5.2 Plane → module map (target state)

| 2.0 plane | Built from TODAY | Added in 2.0 |
|---|---|---|
| 1 Security Decision Plane | `engines/decision.js` | resource-neutral seam |
| 2 Discovery Plane | `scanner/*` | per-type discovery adapters |
| 3 Security Engines | `engines/*` | data-flow + intel predicates |
| 4 Adapter System | `gateway/*` (+bridge) | adapter SPI + registry + new adapters |
| 5 Attack Graph | `offense/graph.js` | generalized node/link model |
| 6 Identity Engine | `engines/identity.js` | federation seam |
| 7 Data-Flow Engine | `engines/classifier.js` + audit | flow ledger + signals |
| 8 Behavioral Engine | `runtime/monitor.js` | flow-aware signals |
| 9 Threat Intelligence | policy `riskFloor` | intel context provider (advisory) |
| 10 Response/Containment | `runtime/response.js` | per-adapter containment actions |
| 11 Forensics | `audit_events` + incidents | replay API, timelines |
| 12 Security Knowledge Graph | offense graph | attribution store + rendering |
| 13 Mission Control | `dashboard/*` + `recommend.js` | resource-plane views |
| 14 Testing/Benchmark | golden/corpus/property/SPO | per-adapter corpora + benches |

---

## 6. Honest scope statement

* **EXISTS now:** everything in §1 — the MCP/AI-agent security layer with offensive skill,
  proven by 81/81 tests, CI on Windows/macOS/Linux, and live demos.
* **PLANNED (this document defines the path, no code yet):** universal adapters (web apps, APIs,
  desktop, mobile, games, cloud, k8s, containers, databases, CI/CD, supply chain, identities,
  external services), the knowledge graph, intel, federation. Until a phase ships with tests,
  those families are **out of scope**, exactly as v0.2 was honest about offense families it did
  not implement.

*"AI can act. Hachiman decides whether it is allowed to act."* — in 2.0, that sentence stops
being about MCP tools only.
