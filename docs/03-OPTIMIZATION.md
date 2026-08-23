# 03 — OPTIMIZATION: TOKENS, LATENCY, RESOURCES

> Implements architecture §17 (Token-Efficient Security) and FINAL ARCHITECTURE 2.0 §8–16:
> Security Resource Governor, operation modes, metadata-first inspection, decision cache,
> adaptive depth, bounded runtime. Optimization is a **product requirement**, not a nice-to-have.

---

## 1. Design targets (from Master Plan KPIs)

| Metric | Target | How |
|---|---|---|
| Fast-path added latency | p50 < 5ms, p95 < 25ms | in-process pipeline, indexed matchers, zero I/O except cache |
| Deterministic decisions | ≥ 90% | fast-path rule coverage + cache |
| Cache hit rate | ≥ 70% (replay-heavy loads) | fingerprint + versioned invalidation |
| Tokens/decision | median 0, p95 ≤ ~1.5k | escalation only + compact context |
| LLM calls/request | median 0, p99 ≤ 1 | SRG slots + coalescing |
| CPU overhead (SPO) | ≤ 5% vs baseline | SRG budget + shedding |
| Memory overhead | ≤ 10% vs baseline | bounded pools, streaming, eviction |
| Throughput impact | ≥ −2% | backpressure before CPU starvation |

---

## 2. Two-path pipeline (architecture §17)

```
Request → [deterministic fast path] → clearly-safe? ─ YES → ALLOW (cache+)
                                         │ NO/uncertain
                                         ▼
                          [semantic deep path with compact context]
```

**Fast-path coverage checklist** (each = a low-cost deterministic stage, doc02 WF-05):
identity · authorization · allowlists · schema validation · parameter validation ·
known-pattern matching · data classification (metadata) · rate limits · policy rules ·
cached decisions. A request is "clearly safe" only when *all applicable* stages pass with
high evidence sufficiency — sufficiency itself is computed deterministically
(each factor contributes evidence weight; total weight ≥ confFloor ⇒ high confidence).

---

## 3. Semantic-path optimization stack (architecture §17 list, concrete designs)

| Technique | Design |
|---|---|
| **Context compression** | Compact-context builder emits only: identity refs, tool/action, data-class, destination-class, anomaly flags, last-5 behavior stats, matched rule ids. Hard cap: 800 tokens in / 400 tokens out requested. Never raw conversation. |
| **Structured security state** | Request carries pre-normalized fields; analyzer never re-parses freeform |
| **Decision caching** | §4 below |
| **Tool-risk metadata** | Per-tool static risk profile (from registry/scan) precomputed; runtime lookups are O(1) |
| **Policy precomputation** | Policy sets compiled to matcher trees + hot/cold rule partitioning at load time |
| **Risk-based escalation** | Escalate iff confidence < floor OR risk band = medium AND anomaly OR policy mandates |
| **Minimal model calls** | Request coalescing: similar escalated requests within 200ms window share one analysis (same fingerprint-class) |
| **Compact event representations** | Enum encoding for wire/storage (data_class, destination_class as int codes) |
| **Reusable security fingerprints** | §4 fingerprint reused across cache, coalescing, replay tests |

**Semantic output contract (evidence-only):**
```json
{ "risk_delta": 12, "range": [-15, 25],
  "indicators": [{"type": "injection", "evidence_hash": "…", "weight": 0.8}],
  "self_confidence": 0.74, "notes": "≤200 chars" }
```
Structurally validated; out-of-range values clamped; malformed ⇒ treated as "no evidence"
plus a quality alert. Analyzer can never output a verdict.

---

## 4. Decision cache (architecture 2.0 §15)

**Fingerprint** = HMAC over canonical tuple:
```
(policy_version, authz_state, tool_id, tool_version, action,
 param_pattern_hash, data_class, destination_class, trust_state, op_mode)
```
- `param_pattern_hash`: hash of param *shape + normalized value classes* (not raw values) —
  so `{amount: <money>, to: <internal>}` matches repeat calls with different concrete values.
- **Invalidation by tokens, not scans**: each dimension maintains a generation counter
  (`gen[policy_version]`, `gen[trustState(subj)]`, …); cache entry stores the generations it
  depended on; lookup = O(1) validity compare. State change bumps one counter.
- TTL policy: positive safety decisions ≤ 10 min (bounded staleness); TTL shortened under
  WATCH/THREAT modes by the SRG.
- Negative decisions (BLOCK) cached with same semantics but flagged for incident correlation.
- Eviction: LRU, bounded memory (default 50k entries), counters survive eviction.

---

## 5. Metadata-first inspection (architecture 2.0 §12)

Default lens = metadata: `tool, action, data_class, destination, sizes, authz`.
Content inspection (payload bytes) enabled only when a policy rule has `inspect.content: true`
or a security test requires it (scanner). Effects: privacy, CPU, memory, tokens, latency
all improve; documented in high-security deployment guide (2.0 §27: semantic can be fully
disabled — Hachiman remains functional on deterministic layers).

---

## 6. Bounded runtime & backpressure (architecture 2.0 §11)

| Resource | Bound | Overflow policy |
|---|---|---|
| Ingress queue (events) | 10k | backpressure to gateway accept loop (stop reading) |
| Fast-path worker pool | 8 (CPU-bound) | queue; then drop policy below |
| Semantic analysis slots | 2 concurrent | conservative-now + delayed re-eval queue |
| Decision cache | 50k entries | LRU eviction |
| Behavior windows | sliding N=15min, fixed-memory sketches (Count-Min + reservoir) | age-out |
| Audit writes | batched 100ms / 512 rows, WAL | block producers (audit never drops) |
| Reporting/analysis | async low-priority queue | shed first under pressure |
| Historical scans | streamed cursors, no full-table loads | — |

**Never:** unbounded queues, in-memory historical log loads, dataset duplication,
one-worker-per-event, permanent full-context LLM analysis (2.0 §11).

Drop/shed priority ladder when overloaded (2.0 §10 order, re-implemented as queue classes):
`[1 enforcement] [2 authorization] [3 threat detection] [4 incident evidence] [5 policy eval]
 [6 semantic analysis] [7 historical analytics] [8 non-critical reporting]` — class 8 sheds
first; classes 1–2 never shed; shedding events are audited + visible in dashboard.

---

## 7. Security Resource Governor (SRG) (2.0 §8–9)

**Telemetry (500ms tick):** own CPU/mem (process usage), host load (`os.loadavg`,
free mem), event rate (EWMA), queue depths, semantic backlog, threat level (from monitor).

**Budget output:**
```
SecurityBudget = {
  analysisDepth: 0..3        // how many optional stages (egress content, behavior correlation…)
  semanticConcurrency: 0..2  // 0 in INCIDENT mode pressure / high-security mode
  cacheTtlScale: 0.25..1     // shrink TTLs when threat rises
  samplingRate: 0.1..1       // observation sampling under pressure
}
```

**Mode machine (2.0 §9)** with hysteresis (entry threshold > exit threshold, min dwell 30s):

| Mode | Entry | Behavior |
|---|---|---|
| SENTINEL | default | metadata-first, deterministic, no semantic calls |
| WATCH | anomaly rate > θ₁ or threat_level ≥ 1 | target correlation, extra deterministic checks, sampling up |
| THREAT | active finding w/ risk ≥ 70 or canary/injection hit | richer evidence, selective semantic (budget slots) |
| INCIDENT | critical-block / containment running | containment priority, evidence preservation, bounded deep analysis, alerts |
| RECOVERY→WATCH→SENTINEL | after containment + clean window | graded down, audit each transition |

Mode transitions are SecurityEvents (dashboard shows live mode + reasons). Under host
pressure, SRG lowers `analysisDepth` + `semanticConcurrency` **before** touching enforcement
(2.0 §8: adaptive budget; §10: priority ladder).

---

## 8. Latency budget breakdown (fast path, target p50 total < 5ms)

| Stage | Budget |
|---|---|
| Normalize + parse | 0.5 ms |
| Identity + authz lookup (in-memory indexes) | 0.5 ms |
| Schema + param validation (compiled Zod) | 0.8 ms |
| Classifier (metadata) | 0.5 ms |
| Policy matcher tree | 0.7 ms |
| Cache lookup | 0.3 ms |
| Risk factors (precomputed + counters) | 0.7 ms |
| Audit enqueue (async, non-blocking) | 0.2 ms |
| Margin | 0.8 ms |

Measured per-stage timings exported as Prometheus histograms; SPO report includes this table.

---

## 9. Token-efficiency metrics (dashboard Performance page, §17 metrics)

- tokens/request (split fast/semantic), tokens/decision, tokens/correct-decision
  (correct = matches golden/review label)
- LLM calls/request distribution; cache-hit rate; fast-path %; security latency percentiles
- per-MCP and per-mode breakdowns (identify which traffic forces escalation)

Budget gate: CI benchmark fails if tokens/degrade > 20% vs previous release (doc 04 §7).

---

## 10. Optimization roadmap by milestone

| Milestone | Optimization work |
|---|---|
| M1 | Evidence-sufficiency model (confidence), compiled matchers |
| M2 | Per-stage instrumentation + budget table; benchmarks start |
| M3 | Decision cache + fingerprint; scan result → tool-risk metadata |
| M4 | Behavior sketches (fixed-memory); coalescing; egress sampling |
| M5 | Full SRG + modes + shedding ladder; cache invalidation tokens; compact-context v2; regression gates on token metrics |
| M6 | Fleet-wide cache insights (anonymousized miss patterns), distributed policy precomputation |
