# HACHIMAN — Offensive Security Skill (AI-builder instructions)

> Layer 1 of the Master Security Skill Architecture: this is what an AI coding agent (Claude Code,
> Codex, Cursor, Hermes, DeepSeek Harness, Qoder, …) must know to **operate** Hachiman's offensive
> loop against an authorized target. Keep this file next to the repository.

## What this skill does

Hachiman is a watchman that thinks like an attacker. On an authorized target it runs:

```
DISCOVER → MAP → HYPOTHESIZE → ATTACK → ADAPT → CHAIN → VALIDATE → EXPLAIN → FIX → RETEST
```

Signature loop: **ATTACK → PROVE → UNDERSTAND → FIX → REATTACK → VERIFY.**

It is not a scanner that emits warnings. It produces **confirmed, reproduced findings**, an
**AI Repair Contract** per finding, and an **independent retest verdict** (`VERIFIED`,
`UNRESOLVED`, `REGRESSION`) for every fix.

## Non-negotiable rules of engagement (hard-coded)

1. **Authorization first.** Every run needs an engagement file with `authorized_by` set.
   No authorization → Hachiman refuses to run. This is enforced in code, not convention.
2. **Scope is a wall.** Tools outside `scope.allowed_tools` are never touched; violations abort
   the run and are audit-logged.
3. **No persistence. No real exfiltration. No destructive testing.** (doc-06 §46 defaults.)
   Exfil demonstrations are allowed only against the local canary sink when explicitly enabled.
4. **Budgets are enforced**: requests, duration, concurrency. Exhausting a budget stops the run
   and reports partial results honestly.

## Operating commands (run from the repository root)

```bash
# 1. Authorize + scope the target (write an engagement JSON — see examples/)
node bin/hachiman.js pentest examples/engagement.vuln-notes.json

# 2. Recon only (no attacks)
node bin/hachiman.js recon examples/engagement.vuln-notes.json

# 3. Inspect results
node bin/hachiman.js findings
node bin/hachiman.js explain <finding-id>       # root-cause developer card
node bin/hachiman.js fix <finding-id>           # AI Repair Contract (yaml + json)
node bin/hachiman.js chain --eng <engagement>   # attack graph + chained impact
node bin/hachiman.js report pentest <engagement>

# 4. After YOUR fix: prove it
node bin/hachiman.js retest <finding-id> --fixed <fixture|url>
```

`--json` on any command gives machine-readable output for automation.

## How an AI builder should consume a contract

Each contract (doc-06 §30) contains: `location` (file + marker), `entry_point` (tool + parameter),
`root_cause` (category + why), `remediation.strategy` with `constraints` and explicit `do_not`
(never blacklist the payload), and `verification` requirements. Treat it as an engineering task:
implement the strategy at the root cause, preserve the constraints, then run `retest` and respond
to the verdict:

- `VERIFIED` — done. The original attack fails and legitimate behavior works.
- `UNRESOLVED` — the exploit still works; your change missed the root cause. Rework.
- `REGRESSION` — the fix broke legitimate behavior; the retest proves it. Rework.

A code change alone never constitutes verification. Only a passing retest does.

## What this skill does NOT do (honest scope)

Implemented and proven end-to-end today: **MCP servers and local HTTP MCP endpoints** (recon,
hypothesis-driven attacks, exploit validation, attack graphs, root cause, contracts, retest,
regression export) on Windows/Linux/macOS. Documented extension points without implementation:
mobile, game clients, cloud, Kubernetes, CI/CD targets — the skill will not fake coverage there.

## Evidence and honesty contract

- A finding is `CONFIRMED` only when reproducible across repeated runs with a controlled response
  difference against a benign baseline. Everything else stays `unconfirmed` in reports.
- Every offensive action is written to the append-only audit trail (`kind: offense`).
- Reports print `not applicable (authorized scope)` for sections without data — never fabrications.
