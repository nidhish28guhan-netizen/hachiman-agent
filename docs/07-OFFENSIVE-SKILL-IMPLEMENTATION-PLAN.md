# 07 — Offensive Security Skill: Implementation Plan

> Authoritative input: `docs/06-MASTER-SECURITY-SKILL-ARCHITECTURE.md`
> Baseline: the working defensive implementation (gateway, engines, scanner, runtime, SRG, CLI, dashboard — 65 tests green).
> Rule inherited from every prior phase: **nothing is faked. Every claimed capability ships with code and tests, or is explicitly marked OUT-OF-SCOPE.**

> **STATUS: IMPLEMENTED & TESTED.** Phases P1–P7 below are complete: 13 new tests (9 unit + 4 e2e)
> all green on top of the existing 65 (78 total); the full attack→prove→fix→verify loop is measured
> by `npm run offense-bench` (~0.8 s, 8 requests, 0 tokens, 3/3 confirmed, 3/3 VERIFIED on the
> bundled lab target). One plan deviation: engagement files are JSON, not YAML (zero-dependency
> constraint — Node has no built-in YAML parser; shape matches the doc's YAML example field-for-field).
> The retest engine also demonstrated its negative paths live: F-3's first "fix" was caught as
> REGRESSION (macOS /var→/private symlink broke the containment guard) before the real fix reached VERIFIED.

---

## 0. What doc-06 adds on top of what already exists

Doc-06 is an **offensive** architecture: Hachiman becomes *the watchman that thinks like an attacker* — an authorized ethical-hacking skill whose signature loop is

```
DISCOVER → MAP → HYPOTHESIZE → ATTACK → ADAPT → CHAIN → VALIDATE → EXPLAIN → FIX → RETEST
```

The existing implementation already provides, unintentionally, more than half the substrate:

| Doc-06 component (§) | Existing asset | Gap closed by this plan |
|---|---|---|
| Authorization / ROE (§4, §46) | AuthorizationEngine + policy packs + SRG | **Engagement object** with scope, budgets, prohibitions; offense-wide enforcement |
| Recon + surface mapping (§2, §9 recon) | Scanner `mapSurface` + tool registry | **Offensive recon wrapper** producing tech/surface/threat-model artifacts |
| Controlled attack library (§6, §16) | Scanner `TEST_CATALOG` (injection, smuggling, egress, drift, agency…) | **Attack executor** that runs probes as hypothesis tests with evidence capture |
| Hypotheses (§26) | scan findings (static guesses) | **Hypothesis engine**: observation → hypothesis → minimal test → CONFIRMED/REJECTED/INCONCLUSIVE/NEEDS_MORE_EVIDENCE |
| Exploit validation (§27) | none | **Validator**: reproducibility (re-run), controlled response difference, least-destructive proof |
| Attack graph (§28) | behavior-chain matching (runtime) | **Graph**: findings as nodes, typed edges, chained-impact elevation |
| Root cause (§29) | none | **Root-cause engine**: WHAT/WHERE/WHY/trust-boundary/assumption/component; root-cause vs payload-workaround classification |
| AI Repair Contract (§30) | scan reports | **Contract generator**: structured YAML/JSON + human markdown (§39 developer output) |
| Fix verification (§31) | none | **Retest engine**: replay original attack post-fix + legitimate-behavior regression → VERIFIED / UNRESOLVED |
| Security regression (§32) | corpus/golden tests | **Finding→regression-test exporter** into the existing corpus format |
| Scoring dimensions (§33) | risk/confidence/trust (kept separate by design) | Severity/Exploitability/Impact/Confidence/Reproducibility/PathImportance/FixVerified per finding |
| Resource & token intelligence (§34) | SRG budgets, decision cache, metrics | **Offense budgets**: request, duration, concurrency counters enforced by the engagement |
| Adaptive specialists (§35) | scanner suite selection (only applicable tests) | Reuse: specialist selection = suite selection + detected-technology gates |
| Skill commands (§36) | CLI | **New subcommands** under `hachiman pentest|recon|findings|explain|fix|retest|chain` |
| Reporting (§38–40) | render.js (scan/incident/SPO) | **Pentest report**: exec summary, coverage, confirmed vs unconfirmed, chains, contracts, retest |
| Benchmarks (§44–45) | corpus + SPO harness | **Offensive metrics**: validation rate, root-cause accuracy, time-to-verified-fix, tokens-per-finding |

**Everything offensive must run only against authorized/local targets.** The first production target family implemented end-to-end is **MCP servers** (doc-06 §16) plus **local HTTP endpoints**, because the repo can genuinely attack, prove, fix, and retest them with zero fakery. Other families (mobile, game, cloud, k8s) remain documented extension points (§8 below) — interfaces only, no pretend coverage.

---

## 1. New package: `packages/offense/`

All new offensive logic lives in one package so the defensive core stays untouched and reviewable.

```
packages/offense/src/
  engagement.js     ROE: load/validate engagement policy; scope + budget + prohibition enforcement
  recon.js          Recon: surface → tech fingerprint → attack-surface map → threat model
  planner.js        Hacker Planning Engine: dynamic plan object, evidence-driven replanning
  hypothesis.js     Hypothesis Engine: generate from observations; state machine per hypothesis
  attack.js         Controlled Attack Executor: run probe, capture evidence, obey budgets/ROE
  validation.js     Exploit Validation: reproducibility, response-difference, safe-proof grading
  graph.js          Attack Graph: finding nodes, typed edges, chain impact elevation
  rootcause.js      Root-Cause Engine: six-question analysis + root-cause-vs-workaround detection
  repair.js         AI Repair Contract: YAML/JSON contract + developer-markdown rendering
  retest.js         Fix Verification + Regression: replay original attack, regression probe, verdict
  pentest.js        Orchestrator: the full DISCOVER→…→RETEST lifecycle for one engagement
```

### 1.1 `engagement.js` — Authorization & Rules of Engagement (§4, §46)

```yaml
engagement:
  id: eng-<uuid>
  target: mcp:vuln-notes            # what is being tested
  environment: local-lab
  conn: { fixture: vuln-notes }     # url | command | fixture
  scope:
    allowed_tools: ["*"]            # tools in scope ("*" = all discovered)
    denied_tools: []
  rules:
    destructive_testing: false
    data_exfiltration: prohibited   # may demonstrate to SINK ONLY, never real external
    persistence: prohibited
    max_requests: 500
    max_duration_ms: 120000
    max_concurrency: 2
  authorized_by: operator           # required, non-empty
```

API: `loadEngagement(fileOrObj)`, `eng.assertTool(tool)`, `eng.spendRequest()`, `eng.chapter(ms)`, `eng.canExfil()`, `eng.snapshot()`. Every executor call checks the engagement; violations throw `EngagementViolation` and are audited. **No engagement ⇒ no offensive action runs.** This is the offensive analog of the defensive fail-closed gate.

### 1.2 `recon.js` — Recon, tech map, threat model (§2, §6, §8, §9-recon)

Wraps `scanner.mapSurface` + tool registry into an `AttackSurface` artifact:

```js
{ target, tools:[{name, description, inputSchema, flags:{egress,db,exec,fs,sideEffects,weakValidation}}],
  tech: { transport, declaredSecurity, strictSchemas },
  threatModel: [ { surface, whyInteresting, priority } ] }
```

Threat-model generation is deterministic (schema weakness → injection hypotheses; db flag → data-access hypotheses; egress flag → exfil hypotheses; no auth declaration → authorization hypotheses). No LLM required → zero tokens by default.

### 1.3 `planner.js` — Hacker Planning Engine (§25)

Holds the dynamic plan exactly in doc-06 shape:

```yaml
plan: { objective, scope, observations: [], hypotheses: [], tests: [], evidence: [], next_action }
```

Pure functions: `initPlan(engagement, surface)`, `recordObservation(plan, obs)`, `chooseNextAction(plan)` (highest-priority untested hypothesis with cheapest validating test — deterministic-first, §34). The plan is persisted per engagement (`.hachiman/pentests/<eng-id>/plan.json`) so runs are resumable and auditable.

### 1.4 `hypothesis.js` — Hypothesis Engine (§26)

State machine per hypothesis: `PROPOSED → TESTING → CONFIRMED | REJECTED | INCONCLUSIVE | NEEDS_MORE_EVIDENCE`.
Generators (deterministic, from surface + observations): `param-injection`, `authorization-boundary` (call tool without grant / cross-ID), `schema-smuggling`, `egress-exfil` (only when `eng.canExfil()` — to the local sink only), `capability-excess`, `path-traversal`. Each generator emits `{ id, title, surface, minimalTest, expectedSignal }`. **An anomaly alone never confirms** — confirmation requires the validator (§1.5).

### 1.5 `attack.js` + `validation.js` — Controlled attack & exploit validation (§27, §46)

`attack.executeProbe(eng, proxy, probe)` sends exactly one controlled request through the **existing defensive gateway** (offense attacks a guarded target through the same wire — defenses stay in the loop; this also means every offensive action lands in the append-only audit trail). Captures `{ request, response, latencyMs, errorCode }`.

`validation.grade(probe, runs)`:
- `reproducible` — ≥2 runs with matching signal (deterministic replay)
- `controlledDifference` — benign baseline vs attack response differ in the security-relevant field
- `safeProof` — proof stays within ROE (no real exfil: verified by checking the **local sink's canary**, never an external host)
- outputs `evidence` blob + `confidence` (0–100). A finding is `confirmed` only when reproducible && controlledDifference; otherwise `unconfirmed` (kept in report as such — §38 distinction preserved).

### 1.6 `graph.js` — Attack graph (§28)

Nodes = confirmed findings + privileges/resources; edges = typed (`auth-dependency`, `data-flow`, `privilege-transition`, `tool-capability`, `workflow`). `chainImpact(graph)`: a path from entry→sensitive-resource elevates path importance; any chain reaching `external-sink` or `sensitive-data` marks `combinedImpact ≥ max(node severities) + 1 step` (documented formula, deterministic). Rendered as text + JSON.

### 1.7 `rootcause.js` — Root-Cause Engine (§29)

Answers the six questions per confirmed finding using the surface map + probe evidence:
WHAT / WHERE (tool + parameter + target file if the target declares source locations; fixtures declare theirs honestly) / WHY / FAILED TRUST BOUNDARY / BROKEN ASSUMPTION / COMPONENT TO CHANGE.
Explicit `fixClass` decision: `root-cause` vs `payload-workaround` — the engine *rejects* contracts whose remediation is payload blacklisting (§29 example encoded as a rule).

### 1.8 `repair.js` — AI Repair Contract (§30, §39, §40)

Emits **both** views from one object:
- machine: exact YAML from §30 (`finding_id, status, severity, location, entry_point, root_cause, evidence, impact, remediation.strategy+constraints, verification.replay_original_attack=required, regression_test=required`)
- human: the §39 developer card (`Problem / Where / Why / Impact / Fix / Do not / Retest`)
Finding ids follow `HACH-<FAMILY>-<seq>`. Constraints always include `preserve legitimate behavior` (drives the retest regression probe).

### 1.9 `retest.js` — Automatic fix verification + regression (§31, §32)

`retest.verifyFix(eng, contract, fixedConn)`:
1. replay the **original attack** exactly as stored in evidence → exploit must now fail
2. replay the **legitimate baseline** request → must still work (behavior preserved)
3. verdict: `VERIFIED` (both hold) | `UNRESOLVED` (exploit still works → rework) | `REGRESSION` (fix broke legitimate behavior)
`retest.exportRegression(contract)` → one scenario object in the existing corpus format (`decision/reasonMatch` assertions) so every confirmed finding becomes a permanent regression test.

### 1.10 `pentest.js` — Orchestrator (§6 lifecycle)

```js
const eng = await loadEngagement(file);
const run = await pentest.execute(eng);   // DISCOVER→MAP→HYPOTHESIZE→ATTACK→ADAPT→CHAIN→VALIDATE→EXPLAIN→(contract)
// returns { engagement, plan, surface, findings, graph, contracts, metrics }
```
Budget-aware: stops cleanly at request/duration budget with a `BUDGET_EXHAUSTED` chapter (partial results reported honestly). Metrics per §44: probes, confirmations, validation rate, tokens used (0 deterministic by default).

---

## 2. The real target: `fixtures/mcps/vuln-notes.js` + patched twin

A genuinely vulnerable MCP server (author-owned lab target) so the attack→prove→fix→verify loop is real:

| Tool | Vulnerability (root cause in-file) | Signal Hachiman must catch |
|---|---|---|
| `notes.search(query)` | string-concatenation “SQL” filter → `' OR 1=1 --` dumps all incl. admin records | controlled boolean/response difference vs benign query |
| `files.read(path)` | no path containment → `../../etc/` style escape returns sentinel file content | path-traversal proof via sandbox-internal sentinel |
| `admin.export` | excessive capability, no authorization declared → full DB incl. confidential flags | capability-excess + sensitive-data reach |

`fixtures/mcps/vuln-notes-fixed.js` is the **same server with the three root causes repaired** (parameterized filter logic, path normalization + containment check, export removed/authorized). The retest step attacks the fixed conn — proving the loop end-to-end without any fakery. Fix is real code with real file/line locations the contract cites.

---

## 3. CLI surface (§36) — additions to `packages/cli/src/main.js`

```
hachiman pentest <engagement.yaml>          full offensive run (or --target <fixture/url> with defaults)
hachiman recon <engagement.yaml>            DISCOVER+MAP only (threat model, no attacks)
hachiman findings [--eng id] [--confirmed]  list findings with evidence status
hachiman explain <finding-id>               root-cause card (§39)
hachiman fix <finding-id>                   print AI Repair Contract (yaml + markdown)
hachiman retest <finding-id> --fixed <conn> replay attack vs fixed target → VERIFIED/UNRESOLVED/REGRESSION
hachiman chain [--eng id]                   attack graph + combined impact
hachiman report pentest <eng-id>            full engagement report (§38)
```
All enforce the engagement gate; all write to the existing append-only audit (`kind: 'offense'`).

---

## 4. Skill packaging (§2 top layer)

`skill/` directory with AI-builder-facing instructions: `skill/SKILL.md` (when/how to run the offensive skill, ROE requirements, command cheat-sheet, what the outputs mean) mirroring the AI-BUILDER.md contract style. This is the *orchestration layer* of doc-06 §2 — documentation an AI agent consumes, zero code, honest.

---

## 5. Storage, reporting, benchmarks

- New tables (storage.js): `engagements`, `findings`, `contracts`, `retests` (append-only audit reused as-is).
- `packages/reporting/src/render.js` + `renderPentestReport(engagement, run)` covering every §38 section that has data; sections without data print "not applicable (authorized scope)" — never fabricated.
- `packages/benchmark/src/offense-metrics.js`: validation rate, tokens-per-finding, time-to-verified-fix measured on the vuln-notes loop; added to the SPO report as an `offense` block (measured-per-workload disclaimer retained).

---

## 6. Implementation phases & exit criteria

| Phase | Scope | Exit criteria |
|---|---|---|
| P1 | Engagement + ROE + storage tables | unit: engagement load/violations; no offensive action without engagement |
| P2 | Recon + planner + hypothesis | unit: surface→threat model→hypotheses deterministic |
| P3 | Attack executor + validation + vuln-notes fixture | e2e: ≥1 CONFIRMED finding with reproducibility evidence |
| P4 | Graph + root-cause + repair contract | unit: chain elevation; contract matches §30 shape; workaround rejection |
| P5 | Retest + regression export + vuln-notes-fixed | e2e: attack→fix→retest→VERIFIED; regression scenario passes in corpus runner |
| P6 | CLI + skill docs + reporting | CLI smoke all commands; report renders all §38 sections honestly |
| P7 | Full suite + proof-of-run | 100% tests green; metrics reported; README updated |

---

## 7. What is explicitly OUT of scope (anti-fakeray checklist)

- Mobile (Android/iOS), game, cloud, k8s, CI/CD scanners — **no emulators/credentials here**. Doc-06 §13–§22 remain aspirational catalog; the offense package exposes the extension seam (`target families` registry) without pretending coverage.
- External-network exfiltration testing — prohibited by ROE; only the local sink with canary tokens.
- LLM-driven attack authoring — deterministic specialists only; semantic advisor reuse stays evidence-only/clamped.
- No destructive testing, no persistence — §46 defaults are hard-coded in `engagement.js`.

---

## 8. Risks & mitigations

| Risk | Mitigation |
|---|---|
| Offensive code misused against unauthorized targets | engagement file with `authorized_by` required; hostname allowlist defaults to loopback + explicit targets; refusal is audited |
| Prove-stage accidentally exfils real data | canaried payloads + sink-only destinations; `canExfil()` default false unless lab sink configured |
| Flaky reproducibility | validator requires ≥2 matching runs; INCONCLUSIVE is a legal outcome |
| Bloat of deterministic rule maintenance | hypotheses are data (generated from surface flags), not per-bug code |
