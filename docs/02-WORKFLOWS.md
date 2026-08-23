# 02 — END-TO-END WORKFLOW SPECIFICATIONS

> Every workflow: actors, preconditions, sequence, decision tables, failure handling,
> outputs, and measured metrics. Guarantees are enforced by the engines in doc 01 §4.
>
> Global lifecycle (architecture §2 + §33):
> `DISCOVER → SCAN → TEST → SCORE → AUTHORIZE → DEPLOY → MONITOR → DETECT → DECIDE →
>  RESPOND → REPORT → REASSESS`

---

## WF-01 — Onboarding & identity bootstrap (`hachiman init` → `guard`)

**Actors:** Operator (human), Hachiman CLI/Gateway.
**Precondition:** protected app exposes an authorized boundary (MCP config, endpoint).

```
Operator                CLI                    Gateway/Engines
   │ hachiman init        │                          │
   ├─────────────────────►│ create config skeleton   │
   │                      │ generate operator keypair│
   │                      │ init storage + audit     │
   │◄─────────────────────┤ config ready             │
   │ hachiman guard cfg   │                          │
   ├─────────────────────►│ parse mcpServers         │
   │                      ├─────────────────────────►│ discover_boundary() each server
   │                      │                          │ capability list + tier
   │                      │                          │ register MCP identities (UNKNOWN)
   │                      │                          │ load policy packs (versioned)
   │                      │                          │ start gateway listeners
   │◄─────────────────────┤ protecting N MCPs (tier table)
```

**Rules:**
- Every discovered MCP starts at trust state `UNKNOWN`, tier = measured boundary capability
  (2.0 §5): Tier 0 targets are reported as `cannot-protect` and never silently skipped.
- Config/policy load failure ⇒ gateway refuses to start with explicit missing-requirements
  report (fail closed at bootstrap).
- Output artifacts: `tenant`, operator identity, MCP registry rows, boundary report.
- Metrics: onboarding time (KPI < 10 min), boundary tiers discovered.

---

## WF-02 — MCP admission & trust lifecycle

**Goal:** move an MCP from `UNKNOWN` to an authorized operating state.

```
UNKNOWN ──operator registers──► UNVERIFIED ──scan WF-03 passes──► ASSESSED
ASSESSED ──policy caps capability──► RESTRICTED ──operator `mcp allow` + stable ops──► TRUSTED
ANY ──violation/critical scan──► HIGH_RISK ──auto/manual──► QUARANTINED
QUARANTINED ──remediation + rescan WF-03 + operator release──► ASSESSED/RESTRICTED
```

| Trigger | From | To | Who | Audit |
|---|---|---|---|---|
| `hachiman mcp add` | — | UNKNOWN/UNVERIFIED | operator | grant row |
| scan score ≥ threshold | UNVERIFIED | ASSESSED | engine | scan ref |
| policy capability cap | ASSESSED | RESTRICTED | policy | policy ref |
| `hachiman mcp allow` (score OK) | ASSESSED/RESTRICTED | TRUSTED | operator | explicit consent |
| critical finding or runtime incident | any | HIGH_RISK→QUARANTINED | engine/operator | incident ref |
| remediation + pass rescan | QUARANTINED | ASSESSED | operator | rescan ref |

**Invariants:** trust never overrides authorization; state changes always produce a
`trust.state-changed` event; score and state are separate fields.

---

## WF-03 — Pre-deployment scan (full pipeline, architecture §10–12)

```
hachiman scan mcp:sync-tool --production
   │
   1. Authorization verify ── no scan grant? → ABORT (report why)
   2. Discover capabilities (tools/list, resources, prompts, transports)
   3. Attack-surface map: surface[tool] = {sideEffects, ioKinds, paramschema, egress, authzModel}
   4. Applicable-test selection (only tests whose applicability-predicate matches surface)
   5. Sandbox prep: scratch resources, canaries, rate caps, per-test timeout budgets
   6. Controlled tests (suites: ai/ mcp/ app/) — evidence per probe
   7. Validation: reproduce each potential finding ≥1× to drop noise
   8. Classification: severity per finding matrix (§below)
   9. Remediation guidance generation (template + surface specifics)
  10. Score: 11 dimensions + overall + status
  11. Report render (MD/JSON/PDF) + baseline snapshot for runtime
```

**Severity matrix:** `impact(reach × damage)` × `exploitability` → C/H/M/L; injection-to-exfil
chains force minimum `high`.

**Test-suite applicability (selection = zero irrelevant tests):**
- SQL/cmd-injection tests only if surface declares db/exec capabilities.
- SSRF/egress tests only if http/fetch capability present.
- Prompt-injection battery only if agent consumes external content.
- Excessive-permission analysis always (capability vs declared-need).

**Failure handling:** test crash ⇒ finding `info` + harness retry; timeout ⇒ test `inconclusive`
(reported, never silently passed); sandbox rejection ⇒ skip with note (never degrade to live run).

**Postconditions:** `SafetyScore` + `Baseline` stored; MCP trust moves per WF-02 table.

---

## WF-04 — Remediation & retest loop

```
report ──dev fixes MCP──► hachiman scan (same suites) ── diffs vs previous findings
   ├── resolved → mark fixed, update score/baseline
   ├── new findings → append with severity
   └── unchanged → carry over, count as repeated-risk
Score ≥ gate → `mcp allow` path (WF-02) ; else loop.
```

- Retest reuses the same canaries where possible to prevent coincidental passes.
- Score history kept (`scans.history`) for dashboard trend and enterprise evidence.

---

## WF-05 — Runtime fast path (the hot loop, architecture §8/§17, 2.0 §13)

**Budget:** p50 < 5 ms added latency. All steps in-process, no I/O except cache lookup.

```
downstream tools/call arrives at gateway
   │
   ▼ normalize → SecurityRequest (fields, sizes, param-shape hash)
   │
   ▼ 1) IDENTITY        validate session token           (fail: reject-unverified)
   ▼ 2) AUTHORIZATION   grant lookup(subject,tool,action) (hard gate §2.0.18)
   │      no grant ─► BLOCK (audit) ; conditional ─► constraints attached
   ▼ 3) LEGITIMACY      tool in registry? schema valid?   (mismatch: BLOCK+finding)
   ▼ 4) AUTHZ-CONSTRAINTS param rules / rate limits / TTL (exceed: BLOCK reason=constraint)
   ▼ 5) DATA CLASS      metadata-first classifier → dataClass
   ▼ 6) DESTINATION     internal/external classification
   ▼ 7) POLICY          rule match over normalized fields (indexed matcher tree)
   │      explicit rule verdict ─► decision (trace rule)
   ▼ 8) CACHE           fingerprint(policyV,authzState,toolV,trustState,dataClass,destClass,mode)
   │      HIT ─► reuse verdict (path=cached) → skip ahead to audit
   ▼ 9) RISK            factor extractors → weighted risk + evidence
   ▼ 10) DECIDE         table below → ALLOW/REVIEW/BLOCK + confidence
   │
   ├─ ALLOW   ─► forward call (attach constraints) ─► egress check on result (if policy)
   ├─ REVIEW  ─► enqueue approval request (dashboard/CLI) ; hold w/ timeout policy
   └─ BLOCK   ─► MCP error -32088 + incident ref ; trigger WF-07 if risk≥critical
   │
   ▼ audit event (append-only) + metrics + trust micro-update (EMA tick)
```

**Decide table (architecture §15, thresholds per policy pack):**

| condition | verdict | side effects |
|---|---|---|
| risk < lowTh ∧ conf ≥ highConf | ALLOW | cache positive |
| risk < medTh ∧ conf < highConf | REVIEW | approval queue |
| medTh ≤ risk < highTh | REVIEW or RESTRICT (policy) | notify |
| risk ≥ highTh ∧ conf ≥ highConf | BLOCK | incident low |
| risk ≥ critTh | BLOCK + CONTAIN | WF-07 |
| authz unavailable ∧ resource sensitive | BLOCK (fail-closed) | incident |
| authz unavailable ∧ resource non-sensitive | REVIEW | alert |

---

## WF-06 — Semantic escalation path (ambiguous/high-risk only)

```
WF-05 step 9/10 returned UNCERTAIN (conf < confFloor) OR policy mandates semantic for class
   │
   ▼ SRG budget check (semantic concurrency slot free? mode≥WATCH?)
   │      no slot ─► conservative decision now (REVIEW/BLOCK per sensitivity) + queued re-eval
   ▼ compact-context builder: metadata extract (never full conversation)
      {agent, tool, action, data_class, destination, anomaly flags, last-N behavior stats}
   ▼ SemanticAnalyzer.analyze(compactCtx) → {riskDelta∈[-15,+25], indicators[], selfConf}
   ▼ clamp + validate output structurally (evidence-only contract, doc01 §9)
   ▼ Decision Engine re-resolves with merged evidence → final verdict + confidence
   ▼ cache store (fingerprint now includes semantic-evidence hash)
```

**Guarantees:** semantic output can never directly ALLOW; it can only add evidence.
Median tokens/decision stays 0; escalation rate tracked as KPI.

---

## WF-07 — Threat response & automatic containment (architecture §16, §24)

```
TRIGGER: BLOCK w/ critical risk │ exfil pattern │ repeated authz failures │
         injection canary hit │ behavioral anomaly burst
   │
   ▼ Response Engine selects ladder by risk tier & grants:
   L1  redact/strip sensitive params
   L2  deny this tool call (BLOCK audited)
   L3  restrict capability set (tool-level deny-overrides, TTL)
   L4  revoke temporary permission / session
   L5  suspend MCP (new calls queued/denied; in-flight completes per policy)
   L6  QUARANTINE MCP (WF-02 state) + isolate agent session
   │
   ▼ incident created (severity, trigger events, containment timeline)
   ▼ evidence bundle preserved (append-only)
   ▼ notifications: dashboard + webhooks + operator channel per policy
   ▼ trust: subject penalty → HIGH_RISK/QUARANTINED ; mode escalates (SRG)
```

**Rules:** each ladder step requires prior standing grant (`response.level≤N`);
Hachiman cannot self-grant higher ladder. Every response is reversible only by operator.
Containment happens only at boundaries Hachiman is authorized to control (AESP contract).

---

## WF-08 — Incident lifecycle

```
open ──containment applied──► contained ──operator review──► resolved │ false-positive
                                   └── needs evidence ──► deep analysis (bounded, incident mode)
```
- Timeline entries: trigger, decisions, responses, mode changes, operator actions.
- `false-positive` outcome feeds back: policy rule tuning note + trust micro-restore.
- `hachiman report incident` renders full report (WF outputs: evidence, trace, remediation).

---

## WF-09 — Behavioral drift & reassessment (architecture §25, 2.0 §21)

```
runtime continuously compares behavior profile vs baseline (from WF-03):
   ├── stable (within envelope) → trust EMA rewards ; no action
   ├── capability changed (tools/list diff) → trust→ASSESSED? NO: AUTO-RESCAN required
   ├── behavior drift (distribution shift > threshold for W mins) → WATCH→THREAT, sample up
   └── policy/gov schema change → policy-pack version bump → cache invalidation → rescan advisory
Rescan outcomes update baseline; prior approval never treated as permanent (2.0 §21).
```

---

## WF-10 — Enterprise: policy distribution & fleet (M6)

```
control plane
   ├── org policy authoring → policy pack version vX (signed)
   ├── push vX to runtimes (mTLS) → each runtime validates signature, activates atomically,
   │     invalidates decision cache, emits audit
   ├── runtimes push: compacted event batches + SPO rollups + incident summaries
   └── fleet view: aggregated trust/risk/SPO; quarantine broadcast; per-tenant isolation
Conflict rule: runtime-local stricter policy always wins over org policy (fail-safe direction).
```

---

## Cross-workflow invariants (checked in integration tests)

1. No decision exists without audit row + evidence refs + policy trace.
2. No ALLOW path skips the authorization hard gate — even for TRUSTED subjects.
3. Semantic analyzer is never on the ALLOW-critical path without confidence floor.
4. Every containment action maps to ≥1 prior grant; revoke ⇒ immediate effect.
5. Fail-closed verified on: storage unavailable, policy load failure, authz service error.
6. WF-05 fast path never degrades to sync-LLM — SRG conservative fallback instead.
7. Restart test: kill gateway mid-incident → restart → state reconstructed, audit intact,
   boundary failure policy honored.
