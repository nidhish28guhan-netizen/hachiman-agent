# Hachiman Agent

> **Scan before deployment. Authorize before access. Monitor during execution.
> Contain when compromised. Report everything.**

Hachiman is an autonomous security layer for AI agents and the Model Context Protocol (MCP).
It sits between your agents and their MCP servers as a wire-compatible gateway, and it treats
**every** tool call as a security decision — never the model.

The LLM is deliberately **not** the security authority. Hachiman makes deterministic decisions from
structured evidence (authorization grants, data classification, destination, injection signals,
behavior, trust state) and uses semantic analysis only as an *advisor* whose output is validated,
clamped, and evidence-only.

Built with zero runtime dependencies: Node.js ≥ 22.5 (`node:sqlite`, `node:test`), pure ESM.
**Runs identically on Windows, Linux, and macOS** — see `AI-BUILDER.md` for the one-prompt
installation contract any AI coding agent can execute on any OS.

---

## Quick start

Hachiman is distributed **exclusively through this git repository** — it is not published on npm
or any package registry. Clone it and run everything from inside the clone:

```bash
git clone https://github.com/nidhish28guhan-netizen/hachiman-agent.git
cd hachiman-agent
```

All commands below assume your shell is inside the cloned `hachiman-agent` directory.

```bash
# Requirement: Node.js >= 22.5 (Hachiman uses node:sqlite and node:test)
node --version

# Universal installer: health check + config + engine self-test (any OS)
node scripts/install.js

# Full suite: unit + golden + corpus + property + e2e
npm test

# The A→Z story: scan → authorize → block → quarantine → report
npm run demo

# Security Protection Overhead benchmark (micro)
npm run spo

# CLI reference
node bin/hachiman.js help
```

> **Note:** comments above are on their own lines on purpose — in default zsh (macOS), a trailing
> `#` on the same line as a command is not treated as a comment. Copy commands line by line, or as
> whole blocks; never mix shell comments onto command lines.

* **No `npm install` step is required** — there are zero runtime dependencies.
* **The git repository is the single source of truth.** There is no downloaded/zip distribution to
  run; always operate from a clone of this repository so you have the exact, complete, tested tree
  (source, tests, fixtures, policy packs, and docs together).

---

## Hachiman inside AI builders (Claude, Codex, Hermes, OpenClaw & more)

Hachiman is designed to be installed and operated **from inside AI coding builders, on any OS**.
Every integration uses standard mechanisms only — a shell, MCP stdio, or MCP-over-HTTP. **No SDK,
no plugin, no platform fork is required.** Anything that can run a terminal command or speak MCP
can use Hachiman.

There are two roles an AI builder can play, and a single platform can play both:

| Role | Meaning | Mechanism |
|---|---|---|
| **Installer / operator** | The AI builder installs and runs Hachiman on your machine | It has terminal access → paste the one-prompt block from [`AI-BUILDER.md`](AI-BUILDER.md) |
| **Protected client** | The AI builder is the agent being secured; its tool calls pass through the Hachiman gateway | Register the **stdio bridge** or the **HTTP endpoint** in the platform's MCP config |

### Supported AI builders — organized compatibility matrix

| AI builder | Vendor | Windows | macOS | Linux | Installs Hachiman | Protected client |
|---|---|---|---|---|---|---|
| Claude Code | Anthropic | ✅ | ✅ | ✅ | ✅ (terminal) | ✅ MCP stdio/HTTP |
| Claude Desktop | Anthropic | ✅ | ✅ | ✅ | — | ✅ MCP stdio |
| Codex CLI | OpenAI | ✅ | ✅ | ✅ | ✅ (terminal) | ✅ MCP stdio/HTTP |
| Cursor | Anysphere | ✅ | ✅ | ✅ | ✅ (terminal) | ✅ MCP stdio/HTTP |
| Windsurf | Codeium | ✅ | ✅ | ✅ | ✅ (terminal) | ✅ MCP stdio/HTTP |
| GitHub Copilot / VS Code agent | GitHub / Microsoft | ✅ | ✅ | ✅ | ✅ (terminal) | ✅ MCP stdio/HTTP |
| Gemini CLI | Google | ✅ | ✅ | ✅ | ✅ (terminal) | ✅ MCP stdio/HTTP |
| Hermes | Nous Research | ✅ | ✅ | ✅ | ✅ (terminal) | ✅ MCP stdio/HTTP |
| OpenClaw | community | ✅ | ✅ | ✅ | ✅ (terminal) | ✅ MCP stdio/HTTP |
| DeepSeek Harness | DeepSeek | ✅ | ✅ | ✅ | ✅ (managed job) | ✅ MCP stdio/HTTP |
| Qoder | Alibaba | ✅ | ✅ | ✅ | ✅ (terminal) | ✅ MCP stdio/HTTP |
| Aider | community | ✅ | ✅ | ✅ | ✅ (terminal) | shell commands (no MCP) |
| Anything else speaking MCP | — | ✅ | ✅ | ✅ | ✅ if it has a shell | ✅ MCP stdio/HTTP |

*(Requirement everywhere: Node.js ≥ 22.5. MCP config file names and schemas evolve between
platform versions; when a platform's own docs differ, trust the platform docs — the bridge command
and env variables below never change.)*

### Step 0 — same start on every platform

```bash
git clone https://github.com/nidhish28guhan-netizen/hachiman-agent.git
cd hachiman-agent
node scripts/install.js
```

### Step 1 — let the AI builder install & verify it (paste one prompt)

Open your AI builder **in the cloned directory** (or tell it the path) and paste the one-prompt
block from [`AI-BUILDER.md`](AI-BUILDER.md) §1 verbatim. The builder checks Node, runs the
installer, boots the guard, and runs the full test suite — with machine-readable success criteria
(`RESULT: READY on <os>`, `HACHIMAN GUARD ACTIVE`, `# fail 0`). This is identical in Claude Code,
Codex CLI, Cursor, Windsurf, Copilot, Gemini CLI, Hermes, OpenClaw, DeepSeek Harness, Qoder, and
Aider — they all have terminal access.

### Step 2 — issue a session for the builder

Each builder (or each human+builder pair) gets its own scoped, expiring identity:

```bash
node bin/hachiman.js agent add claude-code --allow notes,search --ttl 24
```

That prints a `sessionToken` (`hsm_…`). Put it into the platform config of Step 3.

### Step 3 — wire the builder into the gateway (per-platform guides)

**Universal bridge block** (the JSON body is the same everywhere — only *where* it lives differs):

```json
"hachiman-notes": {
  "command": "node",
  "args": ["/full/path/to/hachiman-agent/bin/hachiman.js", "bridge", "notes"],
  "env": {
    "HACHIMAN_GATEWAY": "http://127.0.0.1:7420",
    "HACHIMAN_SESSION": "hsm_XXXXXXXXXXXX.XXXXXXXXXXXX"
  }
}
```

**Claude Desktop** — add the block inside `mcpServers` in `claude_desktop_config.json`
(macOS: `~/Library/Application Support/Claude/`, Windows: `%APPDATA%\Claude\`):

```json
{ "mcpServers": { "hachiman-notes": { "command": "node", "args": ["/full/path/to/hachiman-agent/bin/hachiman.js", "bridge", "notes"], "env": { "HACHIMAN_GATEWAY": "http://127.0.0.1:7420", "HACHIMAN_SESSION": "hsm_XXXXXXXXXXXX.XXXXXXXXXXXX" } } } }
```

**Claude Code** — from the repo directory:

```bash
claude mcp add hachiman-notes \
  --env HACHIMAN_GATEWAY=http://127.0.0.1:7420 \
  --env HACHIMAN_SESSION=hsm_XXXXXXXXXXXX.XXXXXXXXXXXX \
  -- node /full/path/to/hachiman-agent/bin/hachiman.js bridge notes
```

**Codex CLI** — `~/.codex/config.toml`:

```toml
[mcp_servers.hachiman_notes]
command = "node"
args = ["/full/path/to/hachiman-agent/bin/hachiman.js", "bridge", "notes"]

[mcp_servers.hachiman_notes.env]
HACHIMAN_GATEWAY = "http://127.0.0.1:7420"
HACHIMAN_SESSION = "hsm_XXXXXXXXXXXX.XXXXXXXXXXXX"
```

**Cursor** — Settings → MCP → Add server (or `.cursor/mcp.json` in your project), same JSON block.
**Windsurf** — Settings → Cascade → MCP servers, same block. **Gemini CLI** —
`~/.gemini/settings.json`, `mcpServers` key, same block. **GitHub Copilot / VS Code** —
`.vscode/mcp.json`:

```json
{
  "servers": {
    "hachiman-notes": {
      "type": "stdio",
      "command": "node",
      "args": ["/full/path/to/hachiman-agent/bin/hachiman.js", "bridge", "notes"],
      "env": {
        "HACHIMAN_GATEWAY": "http://127.0.0.1:7420",
        "HACHIMAN_SESSION": "hsm_XXXXXXXXXXXX.XXXXXXXXXXXX"
      }
    }
  }
}
```

**Hermes / OpenClaw / Qoder / DeepSeek Harness** — two options, both supported:

1. **HTTP endpoint** (when the platform supports MCP-over-HTTP): point it at
   `http://127.0.0.1:7420/mcp/<server>` and send the header
   `x-hachiman-session: hsm_XXXXXXXXXXXX.XXXXXXXXXXXX` with each request.
2. **Stdio bridge** (when the platform spawns MCP subprocesses): register the bridge block above
   in the platform's MCP config — exactly as for Claude/Cursor.

Full per-platform detail, live-tested examples, and the operator checklist:
`Hachiman-Agnent-Guide.md` §7–§10.

### Step 4 — verify from inside the builder

Ask the AI builder to call any tool through its new `hachiman-*` server and check:

* the tool executes (ALLOW) — Hachiman logged the decision,
* the dashboard (`http://127.0.0.1:7420/`, Mission Control) shows the decision with risk/confidence,
* `node bin/hachiman.js audit --tail 20` shows the append-only audit row.

If a call returns `-32088` (BLOCK) or `-32089` (REVIEW), that's Hachiman working: read the
`reasons` in the error, or open the dashboard **Advisor**, which maps each reason to its exact fix.

### Step 5 — (optional) offensive skill from inside the builder

If you own the target and have authorized it in writing, the same AI builder can run Hachiman's
authorized offensive security skill — the builder follows [`skill/SKILL.md`](skill/SKILL.md):
engagement file → `pentest` → findings → AI Repair Contracts → `retest` until `VERIFIED`.

---

## The two operating modes

### Pre-Deployment (`WF-03`)
`DISCOVER → SCAN → TEST → SCORE → AUTHORIZE → DEPLOY`

* **Scan** a candidate MCP before it is ever exposed to an agent. The scanner discovers the
  capability surface (egress, db, exec, filesystem, memory, auth model) then runs only the
  applicable controlled tests from the catalog: prompt-injection relay, indirect-injection→egress
  **chains**, excessive agency, bulk-export exfiltration, unrestricted egress, param smuggling,
  tool impersonation, forged-auth flaws, capability drift, SQLi surface, path traversal, secret
  exposure.
* **Score** it with an 11-dimension Production Safety Score (0–100) and a status gate:
  `PRODUCTION_READY`, `PRODUCTION_READY_WITH_RESTRICTIONS`, `NOT_PRODUCTION_READY`.
* **Authorize**: only an operator can promote a scanned MCP to `TRUSTED`, and only a human grant
  gives an agent any capability at all.

### Runtime (`WF-05/06`)
`MONITOR → DETECT → DECIDE → RESPOND → REPORT → REASSESS`

* Every `tools/call` through the gateway is normalized and evaluated by a fixed pipeline:
  `IDENTITY → AUTHORIZATION (hard gate) → LEGITIMACY → CLASSIFY → INJECTION → POLICY → CACHE → RISK → DECIDE → (SEMANTIC) → AUDIT`.
* Three values are kept **separate and never conflated**: `risk` (0–100), `confidence` (0–100%),
  `trust` (0–100).
* Fail-closed on verification failure for sensitive resources. Containment is sticky and
  append-only. Every decision is audited and explainable.

---

## Offensive skill (authorized targets only)

`docs/06-MASTER-SECURITY-SKILL-ARCHITECTURE.md` + `docs/07-OFFENSIVE-SKILL-IMPLEMENTATION-PLAN.md`

The watchman also thinks like an attacker. On an **authorized** target (engagement file with
`authorized_by`, scope, budgets — all enforced in code), Hachiman runs:

```
DISCOVER → MAP → HYPOTHESIZE → ATTACK → ADAPT → CHAIN → VALIDATE → EXPLAIN → FIX → RETEST
```

Measured on the bundled lab target (`npm run offense-bench`): full attack → prove → fix-verify
loop ~0.8 s, 8 requests, 0 tokens, 3/3 hypotheses confirmed reproducibly, 3/3 fixes `VERIFIED`
by replaying the original attacks against the repaired build. The loop also catches broken fixes:
a fix that still allows the exploit → `UNRESOLVED`; a fix that breaks legitimate behavior →
`REGRESSION` (both demonstrated in `test/e2e/offensive-loop.test.js`).

```bash
node bin/hachiman.js pentest examples/engagement.vuln-notes.json
node bin/hachiman.js findings | explain <id> | fix <id> | retest <id> --fixed vuln-notes-fixed
npm run offense-bench
```

Scope today: MCP servers / local HTTP MCP endpoints, all OSes. Mobile/game/cloud/k8s families are
documented extension points only — the skill never fakes coverage. Operator docs: `skill/SKILL.md`.

---

## Repository layout

```
bin/hachiman.js                 CLI entry
lib/hachiman.js                 Root composition: assemble storage+engines+gateway+runtime+SRG
policies/*.hachiman.json        Policy packs (default, high-security, strict) — hot-reload by version
packages/
  core/        storage (SQLite/WAL, append-only audit), EventBus (bounded, shed ladder), utils
  engines/     classifier, injection, identity (Ed25519+HMAC sessions), authorization (grants),
               policy, risk, trust, semantic (validated advisory), decision pipeline
  gateway/     MCP client (stdio/HTTP), normalize, metrics, the McpGateway itself
  runtime/     BehaviorMonitor, ResponseEngine (6-level containment ladder)
  srg/         Security Resource Governor (SENTINEL→WATCH→THREAT→INCIDENT→RECOVERY, budgets)
  scanner/     surface mapper, test catalog, scoring, Scanner
  reporting/   scan / incident / SPO statement renderers
  benchmark/   scenario runner + SPO harness
  cli/         `hachiman <command>`
  dashboard/   local HTTP server + zero-dep SPA (SSE live events)
fixtures/      benign + malicious fixture MCPs, sink, attack corpus, golden decision set
docs/          00 master plan → 05 feature backlog (the build plan this implements)
test/          unit, golden, corpus, property, e2e
```

---

## Security model at a glance

| Principle | Enforcement |
|---|---|
| **Authorization is a hard gate** | No grant ⇒ `DENY` → sensitive `BLOCK` / benign `REVIEW`. Trust never substitutes for a grant. |
| **Model is not the authority** | Semantic analyzer output is clamped, evidence-only, and can only *tighten* a decision, never loosen it. |
| **Distinct risk / confidence / trust** | Separately computed, separately reported; no single magic number decides alone. |
| **Fail closed** | Verification failure on sensitive resources → `BLOCK`. Ambiguous → `REVIEW`. |
| **Containment is sticky** | Quarantine overrides every later decision until an operator releases it (recovery = rescan → re-authorize). |
| **Audit is append-only** | `audit_events` has `BEFORE UPDATE/DELETE` triggers that `RAISE(ABORT)`. |
| **Policy as data, hot-reloaded** | Rule packs versioned; strictest matching decision wins; floors dominate deltas. |
| **Efficiency without weakening** | Decision cache keyed on *content signals* (injection + classification ride the fingerprint), SRG budgets, semantic slot concurrency. |

---

## CLI

```text
hachiman init
hachiman guard [--port N] [--once]          # protect configured MCPs (gateway + runtime + dashboard)
hachiman status
hachiman scan <target> --fixture <name> [--production] [--suite AI,MCP,APP]
hachiman mcp list | allow <mcp> | deny <mcp>
hachiman trust <subject>
hachiman threats | quarantine <mcp:subj> [--reason R] | quarantine release <mcp:subj>
hachiman audit [--tail N] | report scan <id> | report incident <id> | report production <target>
hachiman dashboard [--port N]
hachiman config get|set <dotted.key> [json]
```

`scan … --production` exits non-zero when the target is not `PRODUCTION_READY` (CI gate).

---

## Testing & benchmarks

```bash
npm run test:unit       # engines + core + srg
npm run test:golden     # locked deterministic decisions (regression guards)
npm run test:corpus     # attack corpus + benign baseline: detection ≥95%, FP ≤2%
npm run test:e2e        # scanner + guarded gateway end-to-end
npm run test:property   # fuzz determinism + structural invariants
npm run spo             # Security Protection Overhead statement
```

Reported on the micro SPO workload (this machine): threat prevention **100%** (all attacks stopped,
0 false positives), deterministic fast-path **100%**, semantic calls **0%**, P95 latency overhead on
the order of a couple of milliseconds over a loopback MCP. SPO statements are **measured per
workload** and never advertised as universal guarantees.

---

## Non-goals

Hachiman does not attempt to be a general-purpose LLM firewall, a prompt-rewriter, or a sandboxed
code executor. It governs **tool access and data movement** for agents speaking MCP, with
deterministic, explainable, auditable decisions. See `docs/05-FEATURE-BACKLOG.md` for the explicit
non-goals and the MoSCoW backlog.

---

## Design documents

The build plan this repository implements lives in `docs/`:

* `00-MASTER-PLAN.md` — vision, milestones, KPIs
* `01-IMPLEMENTATION-ARCHITECTURE.md` — module specs, data model, SQLite schema, API surface
* `02-WORKFLOWS.md` — WF-01…WF-10 sequences and decision tables
* `03-OPTIMIZATION.md` — token efficiency, SRG budgets, caching
* `04-TESTING-AND-BENCHMARKING.md` — test pyramid, attack corpus, SPO harness
* `05-FEATURE-BACKLOG.md` — MoSCoW backlog, non-goals
* `06-MASTER-SECURITY-SKILL-ARCHITECTURE.md` — offensive skill vision (authorized targets)
* `07-OFFENSIVE-SKILL-IMPLEMENTATION-PLAN.md` — what is built, module map, phases, honest non-goals

---

## License & credits

**Developer:** Nidhish Guhan
**License:** MIT — see [LICENSE](LICENSE). Copyright © 2026 Nidhish Guhan.

