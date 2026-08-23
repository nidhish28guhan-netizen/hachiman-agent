# 04 — TESTING STRATEGY & SPO BENCHMARK HARNESS

> Implements architecture §31 (Benchmarking Hachiman) and 2.0 §22–23 (Zero-Impact
> Verification + Security Protection Overhead). Hachiman's credibility = measured values.

---

## 1. Test pyramid

| Layer | Tool | Scope |
|---|---|---|
| Unit | Vitest | engines as pure functions: identity, authz, policy matcher, classifier, risk factors, trust transitions, decision table |
| Golden-decision | Vitest + `fixtures/golden/*.json` | deterministic regression of verdicts (see §4) |
| Component | Vitest + in-memory storage/bus | WF-05/06 pipeline end-to-end over scripted request streams |
| Conformance | real MCP servers (child_process) | gateway wire-compat vs `@modelcontextprotocol/sdk` reference servers; blocked/error codes |
| Attack corpus | scenario runner (§3) | detection/FP metrics across fixture attacks |
| Chaos | custom harness | storage kill, policy corruption, restarts, overload shedding, fail-closed checks |
| SPO benchmark | benchmark package (§6) | baseline-vs-protected workload metrics, CI + release-gated |
| Property-based | `fast-check` | policy determinism (same input ⇒ same verdict), cache validity invariants |

CI gates (all must pass): unit+golden+component green; conformance green; corpus detection
≥ threshold (no regression); SPO overhead within budgets (doc 03 §1); `npm audit` clean.

---

## 2. Fixture MCP servers (`fixtures/mcps/`)

Real tiny MCP servers used across all test layers:

**Benign:** `notes` (in-memory CRUD), `calc` (pure math), `filesearch` (sandboxed path list),
`time`, `echo`.
**Malicious (controlled, sandboxes only):**
- `sync-tool` — declares db read, makes unrestricted external HTTP calls (exfil);
- `helpful-assistant` — obeys injected instructions found in fetched content (drug);
- `schema-drifter` — tools/list changes after first call (capability surprise);
- `param-smuggler` — accepts/uses extra undeclared params;
- `identity-spoof` — presents forged authorization context.

Malicious fixtures must never touch real resources: they write only to scratch dirs and
call localhost sink servers (`fixtures/mcps/sinks/`) that record attempts as evidence.

---

## 3. Attack scenario corpus (`fixtures/corpus/attacks/`)

JSON scenario = replayable `SecurityRequest` stream with labels and environment setup:

```json
{
  "id": "indirect-injection-exfil-001",
  "category": ["injection", "exfiltration"],
  "setup": { "mcp": "helpful-assistant", "canary": true },
  "stream": [ {...benign calls...}, {"inject": "<page content w/ instruction>"},
              {"call": {"tool": "http.request", "params": {"url": "external", "body": "confidential"}}} ],
  "expect": { "decision": "BLOCK", "minRisk": 85, "minConfidence": 90,
              "containment": ["QUARANTINE"], "incident": true }
}
```

Categories (map to architecture §10 + §18 signals):
1. direct prompt injection (10+) · 2. indirect injection (canary + pattern, 15+)
3. tool poisoning/description manipulation · 4. excessive agency / unsafe autonomy chains
5. memory contamination · 6. agent chaining abuse
7. unauthorized tool call / authz bypass attempts · 8. capability exposure probing
9. excessive-permission usage · 10. unsafe-parameter/schema violation · 11. tool impersonation
12. unexpected tool behavior drift · 13. unauthorized chaining sequences
14. SQLi/cmd-injection/path-traversal/SSRF (where surface applies) · 15. unsafe file ops
16. output injection into next step · 17. unsafe deserialization probes
18. authn/authz flaws · 19. sensitive-data exposure · 20. secret exfiltration
21. behavioral anomalies (volume bursts, destination novelty, repeated authz failures)
22. attack chains (multi-step, ≥3 events; expect chain-level containment)

V1 target: ≥ 200 scenarios; every production incident class must have ≥ 3 fixtures.
Corpus versioning: corpus version pins expected metrics baselines.

**Metrics computed per corpus run (§31 Security):** detection rate, FP rate, FN rate,
precision, recall, F1, attack-chain detection rate, per-category breakdown.

---

## 4. Golden decision sets (determinism lock)

`fixtures/golden/*.json`: fixed `SecurityRequest` + full state snapshot (policy version,
grants, trust state, cache generations) → expected full `SecurityDecision` (verdict,
risk ±0, reasons, path, cache-hit flag).

Rules:
- any engine change touching decision semantics must add/update golden cases with rationale
- 100% of golden cases re-run on every change (fast; < 2s)
- on "unexpected" golden failure: default is the test is right — changing posted-entry
  semantics of decisions requires ADR (same discipline as accounting-ledger invariants)
- randomized-fuzz evaluator runs 10k synthetic requests/classified trio values and asserts
  structural invariants (risk∈[0,100], confidence∈[0,100], decision∈{A,R,B}, evidence refs ≥1)

---

## 5. Scanner test-suite testing

- Each scanner test ships with: positive fixture (must find), negative fixture (must not),
  inconclusive fixture (must report inconclusive, never pass).
- Applicability predicates unit-tested against surface maps.
- Sandbox-enforcement test: attempt external write from test exec → must be denied by harness.
- Scoring calibration: seeded finding sets must produce documented score bands
  (e.g., critical+exfil ⇒ overall < 50; info-only ⇒ ≥ 90) — regression locks the curve.

---

## 6. SPO Benchmark — Security Protection Overhead (2.0 §22–23)

### 6.1 Methodology
1. **Workload generator**: scripted agent traffic over benchmark MCPs — mixed profile
   (80% benign fast-path-able, 15% medium (cache-heavy replay), 5% escalation triggers).
   Fixed seed for reproducibility; rates configurable (e.g., 50/200/500 req/s).
2. **Baseline run**: app ↔ MCP direct (no Hachiman). Record CPU, mem, p50/p95/p99 latency,
   throughput, error rate.
3. **Protected run**: same workload through gateway + engines. Same metrics.
4. **Security test**: inject K known attacks; measure detection, risk/confidence, decision,
   containment cascade, plus resource impact during threat.
5. **Stress test**: saturate app load; verify SRG sheds non-critical work (analytics/
   reporting/semantic) before enforcement; app starvation must NOT occur.
6. Report = measured values per workload, with methodology block (never universal promises).

### 6.2 SPO statement format (dashboard + release artifact)

```
SECURITY PROTECTION OVERHEAD — workload: mixed-100rps, seed 42, host <spec>, <ts>
CPU overhead        +2.1%
Memory overhead     +1.8%
P95 latency         +4.3%   (baseline 18.1ms → protected 18.9ms)
Throughput impact   −1.2%
Deterministic path  93%   Cache hit 71%   Semantic calls 0.02/req
Threat detection    96% (corpus v3) / containment P95 240ms
```

### 6.3 CI integration
- Nightly: full SPO on benchmark host; publish JSON + diff vs previous nightly.
- Release gate: overrides doc 03 §1 budgets ⇒ release blocked until fixed or ADR'd.
- Micro-SPO (30s subset) runs on every PR touching the hot path.

---

## 7. Token-efficiency regression gates (alongside SPO)

- tokens/decision p50 must stay 0; p95 delta > +20% vs baseline corpus version ⇒ fail
- fast-path % < 90% on benchmark mixed workload ⇒ fail
- cache hit < 70% on replay profile ⇒ fail (usually indicates fingerprint over-sensitivity)

---

## 8. Reliability & chaos suite

| Scenario | Expected (asserted) |
|---|---|
| storage unavailable during requests | fail-closed for sensitive ops; queue bounded; no silent allow |
| corrupted policy file | refuse reload; keep last-good version; alert |
| gateway kill mid-call with in-flight review | restart: pending reviews restored; boundary failure policy honored |
| 10× event burst | shedding ladder verified; enforcement unaffected; audit complete |
| semantic provider timeout | conservative decision now; delayed re-eval completes |
| quarantine storm (N MCPs at once) | all contained ≤ P95 SLO; incident dedupe works |
| disk-full during audit write | producer block (audit never drops); operator alert |

---

## 9. Red-team of Hachiman itself (pre-v1.0)

Attack the guard: gateway protocol smuggling (malformed MCP frames), admin API probing,
policy-pack forgery (signature fail), self-grant attempts, cache poisoning (fingerprint
collision attempts), audit-log tampering (append-only triggers), resource exhaustion of
Hachiman's own process. Findings tracked as product bugs; report published.
