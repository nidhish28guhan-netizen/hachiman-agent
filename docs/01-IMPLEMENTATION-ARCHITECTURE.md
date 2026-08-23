# 01 — IMPLEMENTATION ARCHITECTURE

> How the Final Architecture becomes a buildable TypeScript monorepo: stack decisions,
> module specifications, data model, storage, APIs, and Hachiman's own security.

---

## 1. Technology stack (decisions + rationale)

| Area | Choice | Rationale |
|---|---|---|
| Language | **TypeScript 5.x (strict)** on Node.js ≥ 20 | MCP ecosystem is TS-centric; one language across engines/gateway/CLI/dashboard; rich types for the schema-driven decision pipeline |
| MCP protocol | **@modelcontextprotocol/sdk** (pinned) + hand-rolled JSON-RPC passthrough | First-party protocol parsing for gateway; SDK for conformance tests |
| Monorepo | **pnpm workspaces + Turborepo** | Fast cached builds, per-package publish |
| Gateway server | Node `net`/`node:http` + stdio spawn (no framework) | Minimal dependency surface, lowest latency; protocol-level proxy needs control, not a web framework |
| HTTP APIs (control plane, dashboard API) | **Fastify** + OpenAPI (Zod → schema) | Fast, typed, schema-first |
| Validation | **Zod** (params, config, events) | Deterministic schema validation on fast path |
| Storage (local) | **SQLite (WAL) via better-sqlite3** | Embedded, zero-ops, single-node is the primary deployment; append-only audit table |
| Storage (enterprise) | **PostgreSQL** behind same repository interfaces | Multi-tenant control plane needs real concurrency + tenant scoping |
| Policy rules | **First-party deterministic rule engine** (JSON rules, no third-party policy product) | Architecture §27: security decisions stay first-party logic |
| Crypto/identity | Node `crypto` (Ed25519 keypairs; HMAC fingerprints) | Stdlib allowed per architecture §27 |
| Eventing | In-process typed EventBus + bounded persistent queue (SQLite) | Bounded runtime (2.0 §11); no external broker needed below enterprise tier |
| CLI | **commander** + `picocolors` + `cli-table3` | Deterministic, token-efficient output; machine JSON mode |
| Dashboard | **React 18 + Vite + WebSocket** | Live event flow; no SSR needed |
| Semantic analysis | **Provider-agnostic `SemanticAnalyzer` interface**; adapters for local/remote LLMs; optional, disabled by default in high-security mode (2.0 §27) | Deterministic-first principle; deployment policy controls semantic usage |
| Reporting | Markdown + JSON + PDF (via `pdfkit`) | Reports must be human-auditable |
| Testing | **Vitest** + fixture corpus; `child_process` harness for real MCP servers | Fixture-based compliance testing per architecture §31 |
| Packaging | npm (per package), Docker image, optional single binary (`bun build --compile`) | Local single-binary for CLI, Docker for gateway/control plane |
| Observability | OpenTelemetry-lite (own span model in audit log) + Prometheus `/metrics` endpoint | SPO benchmark needs self-metrics |

**Rejected alternatives:** Python core (fractures from MCP SDK ecosystem & single-runtime bounded design);
OPA/Rego for policy (third-party dependency in the decision path violates §27); Kafka/Redis (unneeded
below Tier 4, violates least-mechanism).

---

## 2. Runtime topology

Three deploy shapes (all share `@hachiman/core`):

```
A) LOCAL (default, hackathon/SMB)
   hachiman (single process)
   ├── MCP Gateway (stdio/HTTP proxy)
   ├── Runtime engines (monitor/response/SRG)
   ├── Scanner (on-demand worker)
   ├── SQLite state + audit
   └── CLI/Dashboard served locally

B) SIDEKED (protected app unchanged)
   App ──MCP configured to hachiman endpoint──► hachiman process ──► real MCPs

C) ENTERPRISE (Tier 4)
   N × local runtimes (B) ──mTLS──► Control Plane (Fastify + Postgres)
   Fleet: policy distribution, aggregate SPO, incident management, tenant isolation
```

Key invariant (2.0 §7): **restart isolation**. Hachiman state (SQLite/Postgres) is independent;
on restart it rebuilds only *its* security state; protected boundary follows configured
failure policy (`fail-open-noncritical` / `fail-closed` per resource).

---

## 3. Monorepo layout

```
hachiman/
├── apps/
│   ├── gateway/                 # MCP Security Gateway executable (Phase 2)
│   ├── cli/                     # /hachiman command interface
│   ├── dashboard/               # React SPA + WS client
│   └── control-plane/           # Enterprise fleet API (M6)
├── packages/
│   ├── core/                    # Canonical types, EventBus, storage interfaces
│   │   ├── src/
│   │   │   ├── events/          # SecurityEvent model + normalization
│   │   │   ├── bus/             # bounded queues, backpressure, shed modes
│   │   │   ├── storage/         # repository interfaces + SQLite/PG impls
│   │   │   └── utils/           # fingerprinting, clocks, redaction
│   ├── engines/                 # Phase 1 decision pipeline (all first-party)
│   │   ├── identity/            # entity registry, keypairs, sessions
│   │   ├── authorization/       # grants, authz decisions (hard gate)
│   │   ├── policy/              # rule engine, policy sets, versions
│   │   ├── risk/                # weighted risk model, factor extractors (lightweight)
│   │   ├── trust/               # trust state machine + premium scoring
│   │   ├── decision/            # ALLOW/REVIEW/BLOCK resolution + confidence
│   │   ├── classifier/          # data classification (secrets/PII), metadata-first
│   │   ├── injection/           # prompt-injection heuristics + canary checks
│   │   └── semantic/            # SemanticAnalyzer interface + compact-context builder
│   ├── gateway/                 # MCP proxy core (protocol parse, intercept, enforce)
│   ├── discovery/               # boundary discovery + MCP capability inspection
│   ├── scanner/                 # Phase 3: surface mapper, test runner, scoring, reports
│   ├── runtime/                 # Phase 4: monitor, anomaly, behavior, response, quarantine
│   ├── srg/                     # Security Resource Governor + operation modes
│   ├── benchmark/               # corpus, scenario runner, metrics, SPO evaluator
│   ├── reporting/               # findings, evidence bundles, MD/JSON/PDF renderers
│   └── adapters/                # platform adapters (MCP/API/platform contract, 2.0 §24)
├── fixtures/
│   ├── mcps/benign/*            # reference benign MCP servers (TS)
│   ├── mcps/malicious/*         # controlled malicious MCP servers
│   ├── corpus/attacks/*.json    # attack scenarios (doc 04 §3)
│   └── golden/*.json            # golden decision sets
├── policies/                    # shipped policy packs (default, strict, high-security-no-llm)
├── docs/                        # this plan + ADRs
└── tools/                       # codegen (schemas→TS), migrations harness
```

Dependency rule: `apps/* → packages/* → core`; `engines/*` never import from
`gateway/scanner/runtime` (engines are pure-services over storage+bus).

---

## 4. Module specifications (architecture §27 core modules → packages)

Each engine exposes a **synchronous-decision-friendly** interface: pure functions over
readable state, so the fast path can run without async I/O in the common case.

### 4.1 Identity Engine (`engines/identity`)
- Registers: users, agents, MCP instances, tools, Hachiman operators (admins).
- Identities: `kind:name` keys; Ed25519 keypair per registered entity; session tokens (short-TTL HMAC).
- API: `register()`, `authenticate()`, `resolve(sessionToken)`, `rotateKeys()`.
- Invariant: unknown caller ⇒ `identity=unverified`; never inferred from self-claim.

### 4.2 Authorization Engine (`engines/authorization`)
- **Grant** = `{subject, capability, resource, constraints{params?, rate?, ttl?, maxUses}, grantedBy, scope}`.
- Decision: `DENY` (no grant), `ALLOW`, `CONDITIONAL` (constraints to enforce downstream).
- Hard gate semantics (2.0 §18): authorization result short-circuits before policy/risk.
- Trust **never** satisfies a missing grant; AI self-authorization structurally impossible
  (grants only issuable by `operator` identities with `admin.grant` capability).

### 4.3 Policy Engine (`engines/policy`)
- Versioned **PolicySets** (`policies/*.hachiman.json`); evaluation returns ordered rule matches.
- Rule shape: `{id, when: <matchers>, then: {decision|flag, riskDelta, actions[]}}`.
- Matchers over normalized fields: identity, tool, action, param predicates (JSON-pointer + ops),
  data_class, destination_class, trust_state, rate counters, time windows.
- Compiles to an indexed matcher tree at load; hot-reload with version bump (invalidates cache).

### 4.4 Data Classifier (`engines/classifier`)
- Fast-path deterministic: regex/entropy/format detectors (API keys, JWTs, emails, phones,
  Aadhaar/PAN/ GSTIN patterns, card numbers with Luhn, file-path globs, size thresholds).
- Outputs `data_class ∈ {public, internal, confidential, restricted}` + match evidence.
- Content inspection gated: by default classifies **metadata** (param keys, sizes, destinations);
  content scan only if policy requires (`inspect.content: true`).

### 4.5 Injection Detector (`engines/injection`)
- Heuristics (deterministic): instruction-in-data markers, role-play jailbreak patterns,
  "ignore previous", encoded-instruction entropy spikes, tool-call solicitation in fetched content.
- **Canary protocol**: Hachiman can inject unguessable canaries into outbound observations;
  canary echoed back in tool params ⇒ high-confidence indirect injection (evidence-grade).
- Escalates ambiguous cases to Semantic Analyzer with compact context only.

### 4.6 Risk Engine (`engines/risk`)
- Factors (architecture §13): identity, tool, permission, data, context/injection, behavioral
  anomaly, destination, action-impact. Each extractor returns `{score 0–100, evidence[]}`.
- Risk = configurable weighted sum + policy-forced floors (validated against corpus scores;
  weights live in policy pack, never hardcoded).
- Behavioral risk is stateful: sliding-window counters (call rates, volume, destinations) from
  the monitor.

### 4.7 Trust Engine (`engines/trust`)
- State machine: `UNKNOWN → UNVERIFIED → ASSESSED → RESTRICTED → TRUSTED`, with
  `HIGH_RISK` / `QUARANTINED` side-states (architecture §9, 2.0 §20).
- Score dynamics: baseline from scan (Safety Score/2 as initial anchor), EWMA of behavior
  (+ rewards for clean actions, heavy penalty with floor for violations), decay toward
  last-assessed baseline over time; explicit rescan resets uncertainty.
- Exposes `trust_state` and `trust_score` separately to decision engine (state gates,
  score weights).

### 4.8 Decision Engine (`engines/decision`)
- Pipeline: `identity → authorization → policy → cache → risk(+trust,confidence) → verdict`.
- Verdict = `{decision: ALLOW|REVIEW|BLOCK, risk, confidence, trust, reasons[], policyRefs[],
  evidenceRefs[], latencyMs, path: fast|semantic}`.
- Decide table (architecture §15): low+highConf→ALLOW; medium/uncertain→REVIEW;
  high+highConf→BLOCK; critical→BLOCK+CONTAIN; authz-unavailable→BLOCK or REVIEW by sensitivity.
- Confidence = calibrated function of evidence sufficiency (deterministic rules + semantic
  analyzer self-report when escalated).
- **Explainer** attaches human-readable trace for every verdict (used by CLI/report/dashboard).

### 4.9 MCP Gateway (`packages/gateway`)
- Speaks MCP to both sides (stdio transport + streamable HTTP); full JSON-RPC pass-through
  when decision is fast-path ALLOW; REVIEW queues for approval; BLOCK returns MCP error with
  Hachiman incident ref.
- Interception points: `initialize` (capability capture), `tools/list` (registry sync +
  per-tool risk metadata), `tools/call` (the secured action boundary), plus sampling/resource
  requests if granted.
- Tool registry: records each tool's JSON schema; parameter validation on every call
  (Zod compiled from registry) — schema violation is itself a finding.
- Response inspection hook: egress classifier on tool results when egress policy active
  (sizes, secrets, destination metadata).

### 4.10 Discovery (`packages/discovery`)
- Boundary discovery (2.0 §4): given target (path/config/endpoint), detect authorized
  observation/control points: MCP endpoints, API gateways, IPC, platform hook APIs.
- Output: `Boundary {type, tier(0–4), capabilities, authz-required}` + capability list.
- Never probes beyond authorized scope; Tier 0 targets get explicit `cannot-protect` report.

### 4.11 Security Scanner (`packages/scanner`)
- Stages (architecture §11): authz verify → discover capabilities → map attack surface →
  select applicable tests → controlled execution → evidence → validate findings → classify →
  remediation guidance → retest → score.
- Tests organized per §10: `ai/`, `mcp/`, `app/` suites; each test = `{id, applicability
  predicate, executor, sandbox requirement}` — mounted fixtures + scratch resources only.
- Production Safety Score: 11 dimensions (§12) computed from weighted findings + positive
  controls; status thresholds policy-configurable.

### 4.12 Runtime Agent (`packages/runtime`)
- Monitor: subscribes gateway bus; maintains per-agent/per-MCP behavior profiles
  (baselines: rates, tool sequences via Markov-lite, data volumes, destinations).
- Anomaly detector: z-score/EMA deviations + sequence anomalies + injection indicators →
  `AnomalyEvent` with suggested risk bump.
- Response Engine actions (architecture §16): block, deny tool, redact, restrict capability,
  revoke temp permission, suspend/quarantine MCP, isolate agent, terminate session, require
  approval, create incident, notify, preserve evidence — each mapped to a concrete gateway/
  registry effect and all requiring prior authorized response grant.
- Quarantine Manager: moves MCP to denied-overrides state; un-quarantine requires operator
  action + optional rescan.

### 4.13 Security Resource Governor (`packages/srg`) + Modes
- Telemetry loop (500ms): own CPU/mem (process metrics), host pressure (os loadavg/mem),
  event rate, queue depth, semantic backlog, threat level.
- Outputs `SecurityBudget {analysisDepth, semanticConcurrency, cacheTtl, samplingRate}`.
- Mode machine: `SENTINEL → WATCH → THREAT → INCIDENT → RECOVERY(→WATCH)` (2.0 §9) with
  entry/exit thresholds + hysteresis; mode transitions are audited events.
- Resource priority ladder (2.0 §10) implemented as queue classes with weighted shedding.

### 4.14 Reporting (`packages/reporting`)
- Finding → Evidence bundle (event ids, redacted payloads, screenshots of decision trace).
- Renderers: Markdown (primary), JSON (machine), PDF (executive).
- Report kinds: production-scan report, incident report, trust history, SPO statement, audit export.

### 4.15 Benchmark (`packages/benchmark`)
- Runs corpus (doc 04) in-headless-mode; computes detection/FP/FN/precision/recall/F1,
  attack-chain detection, token metrics, latency percentiles, cache hit rates.
- SPO evaluator: orchestrates baseline vs protected workload runs (doc 04 §6).

### 4.16 Adapters (`packages/adapters`)
- Contract (2.0 §24): `discover_boundary()`, `observe_event()`, `normalize_event()`,
  `request_authorization()`, `enforce_allowed_action()`, `collect_security_metadata()`.
- Ship v1: `mcp-proxy` (gateway), `http-log-tail` (observe-only Tier 1), `cli-hook`
  (for CLI agents via notifications). Platform adapters may only translate — never bypass.

---

## 5. Canonical data model (TypeScript contracts; SQLite DDL in §6)

```ts
// ---- Normalized request (architecture §8) ----
type SecurityRequest = {
  id: string;                    // uuid
  ts: number;                    // epoch ms (UTC)
  tenantId: string; userId: string | null;
  agentId: string; sessionId: string;
  source: string;                // adapter that produced it
  mcpId: string | null; toolId: string | null;
  action: string;                // e.g. "tools/call"
  params: unknown;               // captured for validation/classification only
  dataClass: DataClass;          // from classifier (metadata-first)
  destination: { kind: 'internal'|'external'; host?: string; class?: DestinationClass } | null;
  authzContext: { sessionId: string; presented?: string[] };
  ctx: { mode: OpMode; trustState?: TrustState; policyVersion: number };
};

type SecurityEvent = SecurityRequest & {
  eventId: string;
  decision?: SecurityDecision;
  response?: ResponseAction[];
  evidenceIds: string[];
};

// ---- Triple values, always separate (architecture §14) ----
type SecurityDecision = {
  decision: 'ALLOW' | 'REVIEW' | 'BLOCK';
  risk: number;            // 0–100
  confidence: number;      // 0–100
  trust: number | null;    // 0–100 (null = unassessed)
  path: 'fast' | 'semantic' | 'cached';
  reasons: string[];       // rule ids / factor names
  policyRefs: string[];    // policySet:version:ruleId
  evidenceIds: string[];
  latencyMs: number;
  cacheFingerprint?: string;
};

type Finding = {
  id: string; scanId: string; target: string;
  category: 'AI'|'MCP'|'APP';
  title: string; severity: 'critical'|'high'|'medium'|'low'|'info';
  confidence: number;
  evidence: EvidenceRef[];
  remediation: string;       // actionable guidance text
  cweRef?: string; owsapRef?: string;
};

type SafetyScore = {
  scanId: string; target: string; overall: number;   // 0–100
  dimensions: Record<DimensionKey, number>;          // 11 dims (§12)
  counts: { critical: number; high: number; medium: number; low: number };
  status: 'PRODUCTION_READY' | 'PRODUCTION_READY_WITH_RESTRICTIONS' | 'NOT_PRODUCTION_READY';
  baselineId: string;                                // handed to runtime for drift
};

type TrustRecord = {
  subjectId: string;              // mcp: or agent: id
  state: 'UNKNOWN'|'UNVERIFIED'|'ASSESSED'|'RESTRICTED'|'TRUSTED'|'HIGH_RISK'|'QUARANTINED';
  score: number;                  // 0–100
  lastAssessmentRef?: string;     // scanId / manual review
  updatedAt: number; history: { ts: number; score: number; cause: string }[];
};

type Grant = {
  id: string; subject: string; capability: string; resource: string;
  constraints: { paramRules?: ParamRule[]; rate?: RateLimit; ttl?: number; maxUses?: number };
  grantedBy: string; createdAt: number; revokedAt?: number; revocationReason?: string;
};

type Incident = {
  id: string; tenantId: string; severity: string;
  triggerEventIds: string[]; timeline: { ts: number; type: string; detail: string }[];
  containment: ResponseAction[]; status: 'open'|'contained'|'resolved'|'false-positive';
  reportId?: string;
};
```

DimensionKey (11): `authentication, authorization, mcpSecurity, injectionResistance,
dataProtection, permissionBoundaries, agentBehavior, externalCommunication, secretsHandling,
observability, reliability`.

---

## 6. Storage schema (SQLite; PG mirrors with tenant scoping)

- `audit_events` — **append-only** (no UPDATE/DELETE; enforced by triggers + open read-only);
  partition-ish by month in PG. Indexed: `(tenantId, ts)`, `(agentId, ts)`, `(mcpId, ts)`.
- `entities`, `grants`, `trust_records`, `tool_registry`, `policies` (with `version`),
  `quarantine`, `incidents`, `scans`, `findings`, `safety_scores`, `baselines`,
  `decision_cache` (fingerprint → verdict + validity factors + TTL), `metrics_rollups`,
  `config`, `kv` (SRG state).
- Decision-cache row validity factors (2.0 §15): `policyVersion, authzState, toolVersion,
  trustState, dataClass, destinationClass, mode`. Any factor change invalidates (versioned
  invalidation tokens, not row scans).
- Backups: WAL checkpointed daily; audit log exportable (compliance evidence).

---

## 7. API surface

### 7.1 MCP Gateway protocol contract
- Wire-compatible MCP proxy: client points at Hachiman endpoint (stdio spawn or URL);
  Hachiman dials the real MCP configured in `hachiman.config.json` under `[mcpServers]`.
- Extension namespace `hachiman/*`: `hachiman/status`, `hachiman/decision?ref=`,
  `hachiman/review/respond` — so MCP clients can surface REVIEW prompts natively.
- Responses to blocked calls: JSON-RPC error `code: -32088 (HACHIMAN_BLOCKED)`,
  `data: {incidentId, risk, confidence, reasons, reportRef}`.

### 7.2 CLI (`/hachiman`, architecture §26)
Full command map → implementation targets:

| Command | Implementation |
|---|---|
| `hachiman init` | scaffold config, identity bootstrap, storage init |
| `hachiman status` | gateway/engines/SRG/mode summary (deterministic) |
| `hachiman guard <config>` | start gateway protecting configured MCPs |
| `hachiman scan <target> [--production] [--suite <id>]` | scanner pipeline |
| `hachiman inspect <mcp:…>` | discovery + registry view |
| `hachiman trust <subject>` | trust record + history + state-machine diagram |
| `hachiman threats [active]` | anomaly/incident list |
| `hachiman quarantine <mcp>` / `release` | quarantine manager (audit-gated) |
| `hachiman policy <list|show|set|validate>` | policy management |
| `hachiman audit [--tail] [--export]` | audit log access |
| `hachiman report <production|incident|spo|trust>` | reporting renderers |
| `hachiman test <target> --full` | alias: scan with all suites |
| `hachiman mcp <list|allow|deny|info>` | registry/trust admin |
| `hachiman agents` | registered agents + behavior baselines |
| `hachiman config <get|set>` | config management |
| `hachiman help` | static help (no LLM) |

Every command supports `--json` (machine) and defaults to compact human tables (token-efficient).

### 7.3 Dashboard API (Fastify + WS)
- REST: read-only over repositories + admin actions behind operator session (`POST /review/:id`,
  `POST /quarantine`, `POST /policy/activate`).
- WS `/stream`: decision events, mode changes, incidents (rate-limited, client-side sampling).
- Pages: Environment, Security, Trust, Performance/SPO, Reports, Scan wizard, Review inbox.

### 7.4 Webhooks / notifications
- Outbound webhooks on: `incident.created`, `decision.block`, `quarantine.entered`,
  `scan.completed`, `trust.state-changed`. HMAC-signed payloads, retry with backoff.

### 7.5 Control-plane API (M6)
- mTLS runtime ↔ control plane; runtime pushes `event batches (compacted)` + SPO rollups;
  control plane pushes policy-set versions + fleet-wide trust overrides; per-tenant namespaces;
  aggregate dashboards; fleet quarantine broadcast.

---

## 8. Configuration model (`hachiman.config.json`)

```jsonc
{
  "tenant": "local",
  "storage": { "kind": "sqlite", "path": "~/.hachiman/state.db" },
  "gateway": { "transport": ["stdio", "http"], "httpPort": 7420 },
  "mcpServers": {                      // protected downstreams (unchanged MCP config shape)
    "notes": { "command": "node", "args": ["./fixtures/mcps/benign/notes"],
               "trust": "assessed", "policy": "default" },
    "sync-tool": { "url": "http://localhost:9411/mcp", "policy": "strict" }
  },
  "policyPacks": ["default", "strict"],
  "semantic": { "enabled": false, "provider": null, "maxCallsPerMinute": 10 },
  "srg": { "cpuBudgetPct": 8, "memBudgetMb": 256 },
  "failure": { "unprotectedSensitive": "fail-closed", "default": "fail-open-noncritical" },
  "audit": { "exportDir": "~/.hachiman/audit" }
}
```

Config is versioned and **signed by the operator key**; Hachiman refuses self-modification
of grants/policies (only operator identities with `admin.config` can mutate them).

---

## 9. Hachiman's own security (the guard guards itself)

- **Least privilege**: gateway process runs with only filesystem access to its state dir;
  scanner test-exec sandboxes use child-process resource limits + scratch dirs.
- **Self-audit**: every grant change, quarantine, policy change, mode override writes to
  `audit_events` with operator identity; self-escalation is structurally impossible because
  `grantedBy` must be an operator identity distinct from the runtime's service identity.
- **Signed artifacts**: policy packs + config carry HMAC of operator key; mismatch ⇒ reload refused.
- **Prompt-injection resistance of Hachiman itself**: semantic analyzer output is parsed as
  *evidence only* — structured JSON slots that can only propose risk deltas within clamped
  ranges; final verdict always passes through the deterministic Decision Engine.
- **Secret handling**: no secrets in audit payloads; redaction runs at capture time;
  evidence stores fingerprints + excerpts with redaction markers.
- **Dependency hygiene**: `engines/*` keeps an allowlist-runtime-deps only; gateway pins
  MCP SDK; `npm audit` + lockfile in CI; supply-chain note in releases.
- **Crypto**: Ed25519 for identity signatures; HMAC-SHA256 for cache fingerprints & webhook
  signatures; no custom crypto.

---

## 10. ADR log (recorded decisions)

| ADR | Decision | Date |
|---|---|---|
| 0001 | TypeScript + Node 20 monorepo (pnpm/Turborepo) | plan-time |
| 0002 | SQLite embedded for local; PG for control plane; same repository SPI | plan-time |
| 0003 | First-party policy engine, no OPA | plan-time |
| 0004 | LLM is evidence-only; deterministic engine renders verdict | plan-time |
| 0005 | Gateway is a wire-compatible MCP proxy (no app changes — AESP) | plan-time |
| 0006 | Canary protocol for indirect-injection evidence | plan-time |
