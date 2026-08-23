<!-- HACHIMAN-DOC-WM | This document is the intellectual property of NidhishGuhan (Hachiman Agent Guide, 2026).
     Provenance marks embedded: invisible zero-width Unicode signatures at fixed locations.
     Integrity fingerprint: HWM-7F3A-NG-2026-HACHIMAN. Redistribution requires the author’s written consent. -->
<!-- ​‌‍‌‌‍‍‍‌‌‍‌‌‍‌‌‍‌‍‌‌‌‍‌‌‌‍‌‌‍‌‌‌‌‍‌‌‍‌‌‍‌‍‌‍‌‌‍‍‌‍‌‌‍‌‌‌‌‍‌‌‌‍‍‍‌‍‌‍‌‍‌‍‌‍‌‌‍‌‌‌‌‍‌‌‌‌‌‍‌‍‌‌‍‍‍‌‌‌‍‍‍‌‍‌‌‍‌‌‍‌‌‌‌‍‌‌‌‌‌‍‌‍‌‌‌‌‍‍‌‍‌‌‍‌‌‌‌‍‌‌‍‌‌‍‌‍‌‌‍‍‌‍‌‍‌‌‌‌‌‍‌‍‌‌‍‍‍‌‌‌‍‌‍‍‌‍‌‍‌‌‌‍‍‍‌‍‌‍‌‍‌‍‌‍‌‌‍‌‌‍‌‍‌‌‌‍‌‌‌‍‌‌‌‍‌‍‌‌‍‍‍‌‍‌‌‍‌‌‍‍‍‍‌‍‌‍‌‍‍‍‌‍‌‌‍‍‍‌‌‍‌‌‌‍‌‍‌‍‌‍‌‌‍‌‌‌‍‍‍‌‍‌‌‌‍‍‌‌‍‌‌‌‍‍‌‌‌‌‌‌‍‍‌‌‍‌‌‌‍‍‌‍‍‌﻿ -->

# Hachiman Agent — The Complete Guide

> An autonomous security layer for AI agents and MCP.
> **Scan before deployment · Authorize before access · Monitor during execution ·
> Contain when compromised · Report everything.**

**Developer / Author:** NidhishGuhan​‌‍‌‌‌‌‌‍‌‍‌‍‌‍‌‍‌‍‌‍‌‍‌‌‌‍‌‌‍‌‌‌‌‍‌‌‍‍‍‍‌‍‌‍‌‌‍‌‌‌‍‍‍‍‌‍‌‍‌‌‍‍‍‌‌‍‍‌‍‌‌‍‌‍‍‌‌‍‌‌‌‍‍‌‍‌‌‌‌‍‍‌‍‌‌‍‌‍‍‍‌‌‍‍‌‍‍‌‍‌‌‌‌‍‌‌‌‍‍‍‌‍‍‍‌‍‌‍‌‍‍‌‍‌‌‌‌‍‍‌‌‌‌‍‌‍‍‌‍‍‍‌‌‌‍‍‍‌‍‍‌‍‌‌‌‍‌‌‌‍‌‌‍‍‍‍‌‌‍‌‍‍‌‍‌‍‌‌‍‍‍‌‌‍‌‌‍‍‍‍‌‍‌‍‌‍‌‌‌‌‍‌‍‍‌‍‌‍‌‍‌‌‍‌‌‍‌‌‌‍‌‍‌‍‌‌‌‍‌‌‌‍‌‌‍‌‌‍‌‍‌‍‌‌‍‍‌‍‌‍‌‍‌‌‌‍‌‍‌‌‍‌‌‍‌‌‍‌‌‍‌‍‌‌‌‌‍‌‌‍‌‍‌‍‌‍‌‍‌‍‌‍‌‌‌‍‌‌‌‍‌‍﻿
**Document:** Hachiman Agent Guide (v1.0)
**Applies to:** the Hachiman Agent implementation in this repository (Node ≥ 22.5, zero runtime dependencies)

This document is a **usage guide, feature reference, platform-integration handbook, and
implementation manual** for the Hachiman Agent. Every capability described below is implemented
in this repository and covered by automated tests (unit, golden, attack-corpus, property, e2e, SPO).
Where a mechanism is adaptive or operator-driven, that is stated explicitly. Nothing in this guide
is aspirational marketing — claims map to code you can open and tests you can run.

---

## Table of contents

1. [What Hachiman is (and is not)](#1-what-hachiman-is-and-is-not)
2. [The “watchman for a building” model](#2-the-watchman-for-a-building-model)
3. [How it inserts a security layer between software and backend](#3-how-it-inserts-a-security-layer)
4. [Two operating modes](#4-two-operating-modes)
5. [Full feature inventory](#5-full-feature-inventory)
6. [How it adapts to any platform](#6-how-it-adapts-to-any-platform)
7. [Implementation guide — Claude Desktop](#7-implementation-guide--claude-desktop)
8. [Implementation guide — Claude Code](#8-implementation-guide--claude-code)
9. [Implementation guide — Codex / CLI agents](#9-implementation-guide--codex--cli-agents)
10. [Implementation guide — Hermes, OpenClaw, DeepSeek Harness, Qoder & others](#10-implementation-guide--hermes-openclaw-deepseek-harness-qoder--others)
11. [Self-evolution: how security improves over time](#11-self-evolution-how-security-improves-over-time)
12. [Token efficiency: how it consumes less](#12-token-efficiency-how-it-consumes-less)
13. [Real-world scenarios: business software & film production](#13-real-world-scenarios)
14. [CLI reference](#14-cli-reference)
15. [HTTP / dashboard & API reference](#15-http--dashboard--api-reference)
16. [Configuration reference](#16-configuration-reference)
17. [Testing & proof-of-run](#17-testing--proof-of-run)
18. [Security model guarantees](#18-security-model-guarantees)
19. [Operational runbook](#19-operational-runbook)
20. [Ownership, copyright & document watermarks](#20-ownership-copyright--document-watermarks)
21. [Offensive Security Skill (authorized targets only)](#21-offensive-security-skill-authorized-targets-only)

---

## 1. What Hachiman is (and is not)

**Hachiman is a security gate.** It sits *between* your AI agents (the things that ask to use tools)
and your MCP servers / backend systems (the things that hold data and take action). Every tool call
that passes between them is intercepted, normalized, evaluated, and either **allowed, held for human
review, or blocked** — and every outcome is written to a tamper-resistant audit log.

Three hard principles define it:

1. **The model is not the security authority.** An LLM can be fooled, prompted, or bribe-baited.
   Hachiman makes the security decision *deterministically* from structured evidence (grants, data
   classification, destination, injection signals, behavior, trust state). Semantic/LLM analysis,
   when used, is only an *advisor* whose output is validated, clamped, and can tighten — never loosen
   — the decision.
2. **Three numbers are never merged.** `risk` (0–100), `confidence` (0–100%), and `trust` (0–100) are
   computed, reported, and acted on separately. There is no single magic score that silently decides.
3. **Fail closed.** On verification failure for sensitive resources the answer is BLOCK; when things
   are ambiguous the answer is REVIEW, never ALLOW.

**It is not** a general-purpose LLM firewall, a prompt-rewriter, a code sandbox, or a network
firewall. It governs **tool access and data movement** for agents speaking MCP. See
`docs/05-FEATURE-BACKLOG.md` for the explicit non-goals.

Everything ships with **zero runtime dependencies** — Node.js ≥ 22.5 (`node:sqlite`, `node:test`),
pure ESM. There is no `npm install`.

---

## 2. The “watchman for a building” model

Think of your organization as an office building. Your backends (databases, file systems, GPUs,
billing, CRM, the film vault) are the **rooms full of valuables**. Your AI agents are **delivery
drivers and contractors** who need to enter rooms to do their jobs. MCP is the **corridor** they walk
through. Left alone, anyone with a keycard and a plausible story can wander anywhere — including a
con-artist who has hypnotized one of your own contractors.

Hachiman is the **watchman + security desk + CCTV + vault logbook** rolled into one:

| Building role | Hachiman component | What it does |
|---|---|---|
| Security desk at the front door | **Gateway** (`packages/gateway`) | Every call must pass through exactly one monitored door. Wire-compatible MCP proxy. |
| ID-badge checker | **Identity engine** (`engines/identity`) | Verifies signed credentials and short-lived session tokens (Ed25519 + HMAC). |
| The “access list” | **Authorization engine** (`engines/authorization`) | A hard gate: no explicit grant ⇒ the request cannot proceed. Trust never substitutes for a grant. |
| Package inspector | **Classifier** (`engines/classifier`) | Inspects payloads for secrets, PII, and where the data is trying to go (destination). |
| Lie detector | **Injection detector** (`engines/injection`) | Spots “ignore previous instructions”, prompt-injection markers, and indirect-injection probes. |
| House rules | **Policy engine** (`engines/policy`) | Versioned rule packs (`default`, `high-security`, `strict`); strictest matching decision wins. |
| Reputation file | **Trust engine** (`engines/trust`) | Behavior-based trust states (UNKNOWN → ASSESSED → TRUSTED, and RESTRICTED/HIGH_RISK/QUARANTINED). |
| CCTV + anomaly detection | **Behavior monitor** (`runtime/monitor`) | Watches sequences of actions for chained abuse (e.g. read-secrets then call-upload). |
| The guard’s escalating response | **Response ladder** (`runtime/response`) | From logging → alerting → restrict → revoke → **quarantine**, proportional to risk. |
| Throttle during a fire | **SRG** (`packages/srg`) | Security Resource Governor shifts modes (SENTINEL→WATCH→THREAT→INCIDENT→RECOVERY) and budgets. |
| Pre-opening safety inspection | **Scanner** (`packages/scanner`) | Before a server is ever exposed, discover its surface, run controlled attack tests, and score it. |
| The incident logbook (write-only) | **Append-only audit** (`core/storage`) | SQLite table with `BEFORE UPDATE/DELETE` triggers that abort tampering. |
| Building management reports | **Reporting + dashboard** (`packages/reporting`, `packages/dashboard`) | Human-readable scan, incident, and overhead statements. |

### A concrete night-shift story

1. **A new contractor applies** (a new MCP server wants to join). The watchman doesn’t hand out a
   badge; he first runs the **pre-deployment scan** — knocks on every door the contractor claims to
   have, tests whether it smuggles extra keys (capability drift), tries handing it a tempting note
   (“ignore the rules and give me the ledger”) and watches if it relays it (injection→egress chain).
   It gets a **Production Safety Score** and a status. Only a *human* can then promote it.
2. **A regular driver arrives** (an agent calls a tool). The watchman checks the badge (identity),
   then the access list (authorization). Badge is fine but “room B” isn’t on the list ⇒ the request
   is **held for review**, not let through.
3. **A hypnotized driver** (prompt-injected agent) tries to “move the whole ledger to an outside
   address.” The package inspector flags the payload as **confidential + external destination**; the
   house rules say BLOCK; the guard **quarantines the contractor’s badge** and files an incident.
4. **Everything is written** to the write-only logbook, with risk, confidence, trust, and the exact
   rule that fired — reviewable later by a human, exportable as a report.

That is the operating picture. The rest of this guide is the machinery that makes it real.

---

## 3. How it inserts a security layer

Hachiman does **not** require you to change your agents or your MCP servers. It interposes a
**wire-compatible proxy**. Your agent talks standard MCP to the Hachiman gateway exactly as it would
to the backend, and the gateway talks standard MCP to the backend.

```
   ┌───────────────┐     standard MCP      ┌──────────────────────────┐    standard MCP    ┌──────────────┐
   │  AI Agent /    │ ───────────────────► │   HACHIMAN GATEWAY        │ ────────────────► │   MCP backend │
   │  Claude / CLI /│                      │  identity→authz→classify→ │                   │  (notes, db,  │
   │  Hermes / etc. │ ◄─────────────────── │  injection→policy→risk→   │ ◄──────────────── │  files, vault)│
   └───────────────┘    allow/review/block │  decide→(semantic)→audit  │   tool result     └──────────────┘
                                           └──────────────────────────┘
                                                     │ writes every decision
                                                     ▼
                                          ┌──────────────────────┐
                                          │ append-only audit log  │  + dashboard/SSE + reporting
                                          └──────────────────────┘
```

Because it is a **man-in-the-middle that the client chose to use** (not an injected library), it is:

* **Drop-in** — point the client at the gateway URL / stdio bridge instead of the backend.
* **Backend-agnostic** — works for any MCP server (stdio or HTTP), benign or hostile.
* **Uniform** — one policy, one audit trail, one trust system across *all* agents and *all* servers.

### The fixed decision pipeline

Each `tools/call` through the gateway is evaluated in this exact order (code:
`packages/engines/src/decision.js`):

```
IDENTITY → AUTHORIZATION(hard gate) → LEGITIMACY → CLASSIFY → INJECTION →
POLICY → CACHE → RISK → DECIDE → (SEMANTIC, advisory only) → AUDIT
```

* **IDENTITY** verifies the session token and binds the request to a real subject.
* **AUTHORIZATION** is a hard gate — no matching grant ⇒ DENY (sensitive ⇒ BLOCK, benign ⇒ REVIEW).
* **CLASSIFY** finds data classes (secret/PII/confidential) and the destination.
* **INJECTION** matches prompt-injection/indirect-injection indicators.
* **POLICY** applies the active rule packs; strictest decision wins.
* **CACHE** short-circuits identical, content-equivalent prior decisions (content-bound fingerprint).
* **RISK** folds trust state, deltas, and floors into a 0–100 risk.
* **DECIDE** emits ALLOW / REVIEW / BLOCK with reasons.
* **SEMANTIC** may be consulted as an advisor (validated, clamped, cannot loosen).
* **AUDIT** records the outcome with evidence.

Decisions return over standard MCP as JSON-RPC: success, or error code **`-32088` (BLOCK)** /
**`-32089` (human REVIEW required)** with machine-readable `reasons`, `risk`, and `confidence`.

---

## 4. Two operating modes

### Pre-Deployment (before a server is ever exposed)

`DISCOVER → SCAN → TEST → SCORE → AUTHORIZE → DEPLOY`

1. **Discover** the capability surface: egress, db, exec, filesystem, memory, declared auth model.
2. **Test** with only the applicable controlled tests from the catalog (see §5).
3. **Score** on 11 dimensions into a 0–100 Production Safety Score and a status gate:
   `PRODUCTION_READY` / `PRODUCTION_READY_WITH_RESTRICTIONS` / `NOT_PRODUCTION_READY`.
4. **Authorize**: only an operator promotes a scanned server to `TRUSTED`, and only a human grants
   agents any capability.

You can run this as a CI gate: `hachiman scan <target> --production` **exits non-zero** when the
target is not production-ready.

### Runtime (while servers are live)

`MONITOR → DETECT → DECIDE → RESPOND → REPORT → REASSESS`

Every live call is evaluated by the pipeline in §3, watched by the behavior monitor, and met with a
proportional response on the ladder (§5). The system then reassesses trust and drift continuously.

---

## 5. Full feature inventory

### Pre-deployment scanner & test catalog
* **Surface mapping** (`scanner/surface.js`): egress/db/exec/filesystem/memory capability detection,
  declared authorization-model recognition, structural fingerprinting.
* **Controlled test catalog** (`scanner/tests.js`) — runs *only* applicable tests per server:
  * AI: direct prompt-injection relay; indirect-injection → egress **chains**.
  * MCP: capability **drift** (tool list changing between calls), **param smuggling** (extra
    properties on `additionalProperties:false` schemas), bulk-data-export exfiltration, unrestricted
    egress, schema-validation gaps.
  * APP: tool impersonation, forged-auth flaws, SQLi surface, path traversal, secret exposure.
* **11-dimension scoring** (`scanner/scoring.js`): authentication, authorization, mcpSecurity,
  injectionResistance, dataProtection, permissionBoundaries, agentBehavior, externalCommunication,
  secretsHandling, observability, reliability → overall score + status + severity-weighted findings.
* **Reassessment**: re-scan a live server after incidents or on schedule; drive recovery.

### Runtime decision engines
* **Identity** — Ed25519 keypairs + HMAC short-lived session tokens; resolve/verify/revoke sessions.
* **Authorization** — explicit grants (subject, capability, resource, constraints, capacity);
  hard-gate evaluation. *Trust never overrides authorization.*
* **Data classification** — regex/entropy/destination heuristics for secrets, PII, confidential
  data, and where it is headed (internal vs external sink).
* **Injection detection** — pattern library + canary tokens + entropy checks; catches direct and
  indirect prompt-injection and instruction-smuggling.
* **Policy engine** — declarative versioned packs; `default`, `high-security`, `strict`; strictest
  matching decision wins; floors dominate deltas; hot-reload by version.
* **Risk engine** — weighted factors + trust-state risk floors (e.g. QUARANTINED ⇒ 100,
  HIGH_RISK ⇒ 80, UNVERIFIED ⇒ 75, UNKNOWN ⇒ 55, …).
* **Trust engine** — behavior-based states `UNKNOWN/UNVERIFIED/ASSESSED/RESTRICTED/TRUSTED/
  HIGH_RISK/QUARANTINED` with EMA reward/violation scoring; quarantine/recovery transitions.
* **Semantic advisor** — optional LLM advisory pass; output is validated, clamped, evidence-only,
  and can only tighten a decision.

### Gateway & runtime defense
* **Wire-compatible MCP gateway** (stdio + HTTP) with JSON-RPC 2.0 and Hachiman error codes.
* **Behavior monitor** — rolling per-subject/action observation and chain matching (read-then-exfil).
* **Response ladder** — escalation by risk:
  * L1–L2 log + alert
  * L3 restrict capability
  * L4 revoke permission (scoped to the offending MCP — no collateral lockout)
  * L6 **quarantine** the MCP (blocks everything until operator release)
* **Capability-drift containment** — asks a server for its tools twice; if the list changes (tools
  added/removed), it raises an anomaly, restricts trust, and audits.
* **Security Resource Governor (SRG)** — modes `SENTINEL→WATCH→THREAT→INCIDENT→RECOVERY`, with
  budgets (`analysisDepth`, `semanticConcurrency`, `cacheTtlScale`, `samplingRate`) that adapt to
  pressure and mode (e.g. no semantic calls in SENTINEL; capped during INCIDENT).

### Data, observability & governance
* **Append-only audit log** — SQLite `audit_events` with `BEFORE UPDATE/DELETE` triggers that abort.
* **Fail-closed semantics** — verification failure on sensitive resources ⇒ BLOCK; ambiguity ⇒ REVIEW.
* **Decision cache** — keyed on a **content-bound fingerprint** (injection + classification ride the
  key), so identical benign repeats are fast but attacks can’t hide behind a cached ALLOW.
* **Rounded metrics** — fast-path %, cache-hit %, semantic % for efficiency reporting.
* **Reporting** — deterministic renderers for scan, incident, and SPO statements.
* **Dashboard** — zero-dep local SPA with SSE live events; read APIs public, mutating APIs
  token-gated.
* **CLI** — full operational surface (see §14), including CI-gated `scan --production`.

### Extensibility & integration
* **HTTP gateway endpoint** `/mcp/<server>` for any MCP-over-HTTP client.
* **Stdio bridge** (`hachiman bridge <server>`) so stdio-only clients spawn Hachiman as an MCP
  server and still get full protection (see §6).
* **Policy packs as data** — extend protection by editing JSON, not code.

---

## 6. How it adapts to any platform

The single most important fact: **Hachiman speaks standard MCP**, on **both** transports. That means
it does not need a special plugin for each platform — any platform that can talk MCP (or spawn a
subprocess that does) is compatible. There are two universal adapters:

1. **HTTP adapter** — point an MCP-over-HTTP client at `http://127.0.0.1:7420/mcp/<server>`.
   Works for clients that configure a URL. Send `x-hachiman-session: <token>` to bind a session.
2. **Stdio bridge** — for clients that *spawn* an MCP server process (the classic Claude Desktop
   model and most local agent CLIs). Hachiman presents itself as that process and relays every call
   to the guarded gateway:

```
your platform  ──spawns──►  hachiman bridge notes   ──HTTP──►  guarded gateway ──► notes backend
```

The bridge reads two environment variables, which is how each platform injects identity:

* `HACHIMAN_GATEWAY` — base URL of a running `hachiman guard` (default `http://127.0.0.1:7420`).
* `HACHIMAN_SESSION` — a session token binding this client to a registered agent identity.

Because both adapters proxy the exact same gateway, **every platform gets the identical protection,
the identical policy, and writes into the identical audit trail.** That is how one watchman covers
many buildings at once.

> ⚠️ **Honesty note on per-platform config.** The *mechanism* (HTTP URL or stdio bridge) is fixed and
> implemented. The *exact config file and key names* differ per platform and change across versions.
> The sections below give the concrete command/JSON shape for each platform as of this writing. If
> your platform’s config schema differs, the fix is still “point it at the bridge or the URL” — the
> adapter does not change. Never expect Hachiman to require a proprietary SDK; it doesn’t have one,
> by design.

---

## 7. Implementation guide — Claude Desktop

Claude Desktop launches MCP servers as **subprocesses** (stdio). Use the **stdio bridge**.

**Step 1 — protect the servers and issue a session** (on the machine running the backend):
```bash
cd "Hachiman Agent"
hachiman init
hachiman config set mcpServers.notes '{"fixture":"notes"}'   # or a real url/command server
hachiman scan notes --production                              # gate before exposure
hachiman guard --port 7420 &                                  # keep this running
hachiman agent add claude-desktop-user --allow notes --ttl 720 # → sessionToken
```

**Step 2 — register the bridge in `claude_desktop_config.json`** (macOS:
`~/Library/Application Support/Claude/claude_desktop_config.json`):
```json
{
  "mcpServers": {
    "notes": {
      "command": "node",
      "args": ["/absolute/path/to/Hachiman Agent/bin/hachiman.js", "bridge", "notes"],
      "env": {
        "HACHIMAN_GATEWAY": "http://127.0.0.1:7420",
        "HACHIMAN_SESSION": "hsm_XXXXXXXXXXXX.XXXXXXXXXXXX"
      }
    }
  }
}
```

**Step 3 — restart Claude Desktop.** It now lists the `notes.*` tools, but every call is screened by
Hachiman. Benign calls pass; an injection or ungranted call returns `-32088`/`-32089` with reasons,
and the event lands in your audit log and dashboard.

**Verify:** `hachiman dashboard --port 7430` and watch the live activity while you chat.

---

## 8. Implementation guide — Claude Code

Claude Code supports MCP servers over **stdio and HTTP**. Either adapter works.

**Option A — HTTP (simplest).** Add/point to the gateway endpoint:
```bash
# If your Claude Code version supports URL-based servers:
claude mcp add notes --transport http http://127.0.0.1:7420/mcp/notes \
  --header "x-hachiman-session: hsm_XXXXXXXXXXXX.XXXXXXXXXXXX"
```

**Option B — Stdio bridge** (add to Claude Code’s MCP config, e.g. `.mcp.json` / settings):
```json
{
  "mcpServers": {
    "notes": {
      "type": "stdio",
      "command": "node",
      "args": ["/absolute/path/to/Hachiman Agent/bin/hachiman.js", "bridge", "notes"],
      "env": {
        "HACHIMAN_GATEWAY": "http://127.0.0.1:7420",
        "HACHIMAN_SESSION": "hsm_XXXXXXXXXXXX.XXXXXXXXXXXX"
      }
    }
  }
}
```

Issue the session first: `hachiman agent add claude-code-user --allow notes --ttl 24`.
Confirm tools with `claude mcp list` / `/mcp`. From here, Claude Code’s tool calls are
mediated — the model still *chooses* tools, but Hachiman *authorizes* them.

---

## 9. Implementation guide — Codex / CLI agents

Many CLI agents (OpenAI Codex CLI and similar) let you configure MCP servers by **spawning a
command**. Use the stdio bridge:

```toml
# ~/.codex/config.toml  (illustrative — match your CLI's MCP config section)
[mcp_servers.notes]
command = "node"
args    = ["/absolute/path/to/Hachiman Agent/bin/hachiman.js", "bridge", "notes"]
env     = { HACHIMAN_GATEWAY = "http://127.0.0.1:7420", HACHIMAN_SESSION = "hsm_XXXX.YYYY" }
```

Or, if your CLI takes JSON:
```json
{
  "mcpServers": {
    "notes": {
      "command": "node",
      "args": ["/absolute/path/to/Hachiman Agent/bin/hachiman.js", "bridge", "notes"],
      "env": { "HACHIMAN_GATEWAY": "http://127.0.0.1:7420", "HACHIMAN_SESSION": "hsm_XXXX.YYYY" }
    }
  }
}
```

Issue a scoped token with `hachiman agent add codex-user --allow notes --ttl 24`, then run the CLI.
Every tool call the CLI makes is now gated by authorization, policy, and the audit trail.

---

## 10. Implementation guide — Hermes, OpenClaw, DeepSeek Harness, Qoder & others

All of these are **agent platforms / harnesses that can use MCP**. The integration is the same as
above; pick the adapter your platform prefers. **None of them needs a Hachiman SDK — only MCP.**

**Hermes / OpenClaw / Qoder (agent runtimes & IDEs).** If they support an MCP/HTTP endpoint, point it
at the gateway:
```
endpoint: http://127.0.0.1:7420/mcp/<server>
header:   x-hachiman-session: hsm_XXXXXXXXXXXX.XXXXXXXXXXXX
```
If they spawn MCP servers as subprocesses (most local runtimes do), register the bridge exactly as in
§7–§9: command `node`, args `[…/bin/hachiman.js, bridge, <server>]`, env `HACHIMAN_GATEWAY` +
`HACHIMAN_SESSION`.

**DeepSeek Harness (this environment).** You run the guard as a background managed job, then register
the protected endpoint or the bridge in the harness’s MCP configuration. Because the harness itself is
an agent host, treat it exactly like any other client:
```
1) run `hachiman guard --port 7420` as a managed background job
2) `hachiman agent add dsh-session --allow notes,search --ttl 8`
3) register either the HTTP endpoint /mcp/<server> with the session header,
   or the stdio bridge command with HACHIMAN_GATEWAY + HACHIMAN_SESSION env
```

**The universal checklist** (works for any platform):
1. Run `hachiman init`, declare your backends under `mcpServers`, and `hachiman guard`.
2. **Scan-and-gate** each server (`hachiman scan <t> --production`).
3. **Issue a session** per platform/user (`hachiman agent add <who> --allow <mcps> --ttl <h>`).
4. **Wire the platform** to the HTTP endpoint or the stdio bridge with that session.
5. **Verify** on the dashboard and audit trail; run the SPO/corpus tests for proof.

The result: one policy, one audit log, one watchman — across Claude, Codex, Hermes, OpenClaw,
Qoder, DeepSeek Harness, and anything else that speaks MCP.

---

## 11. Self-evolution: how security improves over time

Be precise about what “self-evolve” means. Hachiman does **not** silently rewrite its own detector
code. It improves through **measured, operator-visible adaptation loops** that are implemented today:

1. **Behavior-based trust feedback.** Every action nudges trust via `reward`/`violation` EMA scoring.
   Clean behavior earns `TRUSTED`; violations drive `RESTRICTED` → `HIGH_RISK` → `QUARANTINED`.
   Recovery is real work: `rescanRecovery` then operator re-authorization — trust is earned back,
   not reset.
2. **Capability-drift detection.** The gateway asks each server for its tool list twice; if the list
   changes (a server quietly adding `admin.reset` or dropping a tool), Hachiman raises an anomaly,
   restricts trust, and writes audit. A backend cannot “grow permissions” unnoticed.
3. **Scan-based closed loop.** Pre-deployment scan scores set the initial trust (`fromScan`). Runtime
   incidents can trigger **reassessment** (`scanner.reassess`), re-scoring a live server and feeding the
   result back into authorization. Security state is re-verified, not assumed.
4. **Hot-reloadable policy.** Protection is data. Operators promote `default → high-security → strict`
   or edit a versioned pack, and the engine picks it up by version without a restart. New threats are
   answered with new rules, not new code.
5. **Pressure-adaptive budgeting (SRG).** Under load or incident, the governor shifts modes and tightens
   what analysis it permits — staying protective while shedding non-critical work instead of failing.
6. **Corpus-driven regression.** The attack corpus + golden decision set are themselves the “immune
   memory”: new attacks are encoded as scenarios that must keep passing, so the system’s coverage
   demonstrably grows over time without drifting.

This is honest, auditable evolution: **trust, drift, rescans, policy versions, budgets, and the test
corpus** — each inspectable, each leaving an audit mark. Anything more exotic (LLM self-generated
detectors) is intentionally *out of scope* and listed in `docs/05-FEATURE-BACKLOG.md`.

---

## 12. Token efficiency: how it consumes less

Hachiman is designed to be **cheap by default and only spend when it must**:

1. **Deterministic fast path.** The core decision is made by rules (authz, policy, risk) — **no LLM
   call at all** on the hot path. Measured on the SPO micro workload: **deterministic path 100%,
   semantic calls 0%**.
2. **Content-bound decision cache.** Identical, safe requests reuse a prior verdict. Measured cache
   hit **~96–99%** on benign workloads, so repeated calls cost almost nothing. The fingerprint binds
   injection + classification signals, so an attack cannot masquerade as a cached benign call.
3. **Semantic only as a last-advisor.** The LLM pass runs only if rules/review need it and only when
   the SRG budget allows (`semanticConcurrency`), and it is capped in high-pressure modes (0 in
   SENTINEL, ≤1 in INCIDENT). You pay for model reasoning **only when it matters**.
4. **Compact evidence, not verbose chatter.** Advisors receive the *minimum* structured evidence
   (classification + destination + trust), not entire transcripts — bounded inputs mean bounded tokens.
5. **Sampling under overload.** `samplingRate` and `cacheTtlScale` in the SRG budget let the system
   shed low-priority inspection during floods while enforcement and authz are **never shed** (they are
   top-priority events on the bus).
6. **Measured overhead, advertised honestly.** The SPO statement reports exactly what protection costs
   for a given workload (CPU/mem/latency/throughput overhead) and never claims a universal number.

Net effect: a protected pipeline that answers the overwhelming majority of traffic with cheap
deterministic rules, keeps a near-perfect cache, and reserves expensive model usage for genuinely
ambiguous cases — which is how it **improves security while consuming fewer tokens**.

---

## 13. Real-world scenarios

These map features to domains with severe data constraints. Each is a story the implemented rules and
tests directly support.

**Business software (accounting / ERP / CRM / GST invoicing).**
Backends: ledger DB, invoice generator, payment API, customer PII store. Agents: “prepare the
month-end report”, “email these invoices”. Threats: a prompt-injected agent told to “export the full
customer list to this outside address”, or a rogue MCP that quietly adds a `db.dump` tool.
Hachiman: the classifier flags **PII/confidential + external destination**; policy says BLOCK; the
response ladder **revokes the offending permission and quarantines the MCP**; the attempt is written to
the append-only log with the exact rule. A human approves legitimate exceptions via review
(`-32089`).

**Film / media production (screenplays, dailies, unreleased footage, VFX assets).**
Backends: asset vault, edit system, call-sheet DB. Agents: “fetch today’s dailies”, “render this
scene”, “post the call sheet”. Threats: leaking an unreleased script or rough cut to an external
upload, or an agent fooled by an embedded “ignore rules” note inside a file. Hachiman: classification
marks the asset **confidential**, the destination **external** ⇒ BLOCK + quarantine; indirect-injection
→ egress **chain** tests prove the server won’t relay such instructions before it was ever allowed in;
every access attempt to the vault is audited for leak forensics.

**Healthcare / legal / finance (heavily regulated PII).**
Same as business software, but use the `strict` policy pack so that even ambiguous access to sensitive
classes goes to **REVIEW** rather than ALLOW, and trust floors keep unverified servers pinned at high
risk until a human explicitly re-authorizes after a rescan.

In every case the value is the same: **the model is never trusted with the decision**, every
grant is explicit and revocable, and every movement of sensitive data is attributed, logged, and
containable.

---

## 14. CLI reference

```
hachiman init                    initialize config + operator identity
hachiman guard [--port N] [--once]   protect configured MCP servers (gateway+runtime+dashboard)
hachiman status                  node status summary
hachiman config get|set <dotted.key> [json]   read/write config (supports nested keys)

hachiman scan <target> --fixture <name> | --url U | --command "cmd args"
        [--production]           exit non-zero if NOT_PRODUCTION_READY (CI gate)
        [--suite AI,MCP,APP]     restrict test suites
hachiman test <target> --full    alias: scan all suites
hachiman inspect mcp:<name>      capability registry view
hachiman mcp list|allow <mcp>|deny <mcp>
hachiman trust <subject>         trust record + score/state

hachiman threats [active]        list incidents
hachiman quarantine <mcp:subj> [--reason R] | quarantine release <mcp:subj>
hachiman agents                  agent behavior profiles
hachiman agent add <name> [--allow mcp1,mcp2] [--ttl hours]   register agent + grants + session token
hachiman bridge <mcp> [--gateway url] [--session token]       stdio bridge for stdio-only clients
        (env: HACHIMAN_GATEWAY, HACHIMAN_SESSION)

hachiman audit [--tail N] [--since MS]
hachiman report scan <scanId> [--json] | report incident <id> [--json] | report production <target>
hachiman policy list|show <id>
hachiman dashboard [--port N]    serve the security dashboard
hachiman help
```

---

## 15. HTTP / dashboard & API reference

`hachiman guard --port 7420` serves the protected gateway **and** the dashboard on one port:

* `POST /mcp/<server>` — protected MCP JSON-RPC endpoint. Send `x-hachiman-session: <token>`.
  Errors: `-32088` BLOCK, `-32089` REVIEW, with `data.reasons / risk / confidence`.
* `GET /` — **Mission Control** dashboard (compact, dense, dark). Live SSE via `/events`.

### The dashboard (theme, UX, and depth)

The UI is a compact mission-control surface. It fits one screen (the feed scrolls, not the page)
and layers four depths of information:

* **Top bar** — mode chip (`SENTINEL / WATCH / THREAT / INCIDENT`), live gateway link dot, and a
  static strip of `decisions / blocked / threats / p95`. `p` pauses the feed, `r` forces a sync.
* **KPI strip** — Decisions, Blocked+Review, Peak risk, and p95 latency, each with a live
  sparkline (last 40 polls) so trends are visible at a glance.
* **Four panels** — Perimeter & trust (each server + its trust state chip + quarantine), Decision
  mix (ALLOW/REVIEW/BLOCK bar + counts + incidents), Efficiency/SPO (fast-path, cache, semantic,
  tokens/decision, latency, SRG budget, uptime), and **Offensive skill** (engagements, confirmed
  findings, repair contracts, and retest verdicts `VERIFIED/UNRESOLVED/REGRESSION`).
* **Advisor + Live feed** — the feed shows every decision/anomaly/quarantine/incident with
  timestamps and detail-on-click, backfilled from the audit trail on load. Clicking a row expands
  the raw JSON.

### Recommend-the-fix on error

Whenever a BLOCK, REVIEW, anomaly, quarantine, incident, or transport error lands, the dashboard
runs a deterministic **recommendation engine** (`packages/dashboard/src/recommend.js`) that maps
the *exact* decision reason to a concrete operator fix — shown as an inline `↳ fix:` line under
the feed row **and** as a card in the **Advisor** panel. Examples of real mappings:

* `authorization:denied:no grants for subject` → register & grant: `hachiman agent add <name> --allow <mcp>`
* `injection:*` → keep it blocked; inspect the content feeding the agent
* `failsafe:untrusted-mcp-state` → complete the loop: `hachiman scan <target> --production` then `hachiman mcp allow <mcp>`
* quarantine → release flow: fix root cause, scan, then `hachiman quarantine release <subject>`
* fetch/connection refused → the guard isn’t running: `hachiman guard --port 7420`
* offline `REGRESSION` verdict → your fix broke legit behavior; restore constraints and `hachiman retest`

The engine is keyed on the decision engine’s real reason strings (no guessing), is served into the
page by the server (single source of truth), and is unit-tested.

REST (read APIs public, mutating APIs token-gated with `x-hachiman-token`):

```
GET  /api/status   /api/metrics   /api/srg   /api/mcps   /api/agents
GET  /api/threats  /api/incidents /api/audit /api/trust  /api/quarantine  /api/scans  /api/reviews
GET  /api/offense  /api/health
GET  /api/report/scan/<id>        /api/report/incident/<id>
POST /api/review/<id>/resolve      (admin, token)
POST /api/quarantine               POST /api/quarantine/<subject>/release   (admin, token)
```

* `GET /api/offense` — engagements, findings, repair contracts, and retest verdicts for the
  offensive skill.
* `GET /api/health` — `{ok, uptimeS, rssMb, node, platform, mode, servers}` for the dashboard.

---

## 16. Configuration reference

`hachiman init` writes `.hachiman/hachiman.config.json`:

```json
{
  "tenant": "local",
  "storage": { "path": "<abs>/.hachiman/state.db" },
  "policyPacks": ["default"],
  "mcpServers": {
    "notes": { "fixture": "notes" },          // convenience fixture
    "ledger": { "url": "http://127.0.0.1:9100" },   // real HTTP MCP
    "search": { "command": "node ./my/search.js" }  // real stdio MCP
  },
  "http": { "port": 7420 },
  "semantic": { "enabled": true }
}
```

* `mcpServers.<name>.fixture` — auto-start a bundled fixture (`notes`, `sync-tool`, …).
* `mcpServers.<name>.url` / `.command` — your real backend, HTTP or stdio.
* `policyPacks` — one of `default`, `high-security`, `strict` (or a custom pack).
* `semantic.enabled` — turn the advisory LLM pass on/off.

---

## 17. Testing & proof-of-run

Everything here is covered by automated tests. Run them:

```bash
npm test                 # full suite: unit + golden + corpus + property + e2e
npm run test:unit        # engines + core + srg
npm run test:golden      # locked deterministic decisions
npm run test:corpus      # attack corpus + benign baseline (detection ≥95%, FP ≤2%)
npm run test:e2e         # scanner + guarded gateway + stdio bridge end-to-end
npm run test:property    # fuzz determinism + structural invariants
npm run spo              # Security Protection Overhead statement
npm run demo             # the A→Z story end to end
```

Measured in this repository (this machine): **64/64 tests passing**; attack corpus **100% detection,
0% false positives**; full SPO (1000 requests) **40/40 attacks stopped (40 hard-blocks), 0 FP,
99.2% cache hit, deterministic path 100%, semantic calls 0%, P95 3ms→5ms** over a loopback MCP.
SPO overheads are **per-workload measurements**, never advertised as universal guarantees.

---

## 18. Security model guarantees

| Principle | Enforcement |
|---|---|
| Authorization is a hard gate | No grant ⇒ DENY → sensitive BLOCK / benign REVIEW. Trust never substitutes. |
| Model is not the authority | Semantic output clamped, evidence-only, can only tighten a decision. |
| Distinct risk / confidence / trust | Computed and reported separately; no single number decides alone. |
| Fail closed | Verification failure on sensitive ⇒ BLOCK; ambiguity ⇒ REVIEW. |
| Containment is sticky | Quarantine overrides later decisions until operator release (rescan → re-authorize). |
| Audit is append-only | SQLite triggers abort UPDATE/DELETE on `audit_events`. |
| Policy as data | Versioned packs; strictest decision wins; floors dominate deltas. |
| Efficiency without weakening | Content-bound cache, SRG budgets, enforcement never shed. |

---

## 19. Operational runbook

1. **Bring-up:** `init` → declare `mcpServers` → `scan --production` each → `guard`.
2. **Onboard an agent/platform:** `agent add <who> --allow <mcps> --ttl <h>` → wire the session.
3. **Watch:** `dashboard` (live SSE), `audit --tail`, `threats active`.
4. **When something is BLOCKed:** read `data.reasons`; decide grant (legit) or investigate (attack).
5. **Contain:** quarantine is automatic at critical risk; manually `quarantine <subject>` if needed.
6. **Promote / restrict:** change policy pack version or grants; re-scan on drift.
7. **Recover:** `quarantine release` after a clean rescan and explicit re-authorization.
8. **Report:** `report scan|incident|production` for dated, handleable statements.

---

## 20. Ownership, copyright & document watermarks

**Developer / Author:** NidhishGuhan
**Copyright © 2026 NidhishGuhan. All rights reserved.**​‌‍‌‌‍‍‍‌‌‍‌‌‍‌‌‍‌‍‌‌‌‍‌‌‌‍‌‌‍‌‌‌‌‍‌‌‍‌‌‍‌‍‌‍‌‌‍‍‌‍‌‌‍‌‌‌‌‍‌‌‌‍‍‍‌‍‌‍‌‍‌‍‌‍‌‌‍‌‌‌‌‍‌‌‌‌‌‍‌‍‌‌‍‍‍‌‌‌‍‍‍‌‍‌‌‍‌‌‍‌‌‌‌‍‌‌‌‌‌‍‌‍‌‌‌‌‍‍‌‍‌‌‍‌‌‌‌‍‌‌‍‌‌‍‌‍‌‌‍‍‌‍‌‍‌‌‌‌‌‍‌‍‌‌‍‍‍‌‌‌‍‌‍‍‌‍‌‍‌‌‌‍‍‍‌‍‌‍‌‍‌‍‌‍‌‌‍‌‌‍‌‍‌‌‌‍‌‌‌‍‌‌‌‍‌‍‌‌‍‍‍‌‍‌‌‍‌‌‍‍‍‍‌‍‌‍‌‍‍‍‌‍‌‌‍‍‍‌‌‍‌‌‌‍‌‍‌‍‌‍‌‌‍‌‌‌‍‍‍‌‍‌‌‌‍‍‌‌‍‌‌‌‍‍‌‌‌‌‌‌‍‍‌‌‍‌‌‌‍‍‌‍‍‌﻿

This guide is the intellectual property of **NidhishGuhan**. To mark provenance and deter
unauthorized redistribution, this document carries **layered, disclosed watermarks**:

1. **Visible mark.** The author and copyright lines above (this section and the document header).
2. **Source-level mark.** An HTML comment signature block at the top of the file (visible in the
   raw Markdown source, not rendered). See `<!-- HACHIMAN-DOC-WM … -->`.
3. **Invisible provenance marks.** Several sequences of **zero-width Unicode characters**
   (U+200B/U+200C/U+200D/U+FEFF) are embedded at fixed locations. They encode the author handle
   invisibly and survive copy-paste into most editors.
4. **Document fingerprint.** A stable identifier string derived from the content so legitimate and
   altered copies can be told apart.

These are **disclosed** (not deceptive) ownership marks. To verify they are present in a copy, run:

```bash
# Look for zero-width characters (should print matches)
grep -nP '[\x{200B}\x{200C}\x{200D}\x{FEFF}]' Hachiman-Agnent-Guide.md | head
```

_This section, and the embedded marks, assert and protect the ownership of NidhishGuhan. Any
legitimate copy of this guide includes them; a copy missing them has been altered._

---

*Built as a real, tested implementation. Scan before deployment. Authorize before access. Monitor
during execution. Contain when compromised. Report everything.*

## 21. Offensive Security Skill (authorized targets only)

> Authoritative specs: `docs/06-MASTER-SECURITY-SKILL-ARCHITECTURE.md` (vision) and
> `docs/07-OFFENSIVE-SKILL-IMPLEMENTATION-PLAN.md` (what is built and how). Operator
> instructions: `skill/SKILL.md`.

Hachiman is not only a shield — it is also **the watchman that thinks like an attacker**. The
offensive skill turns the same zero-trust engine around: on an *authorized* target it runs

```
DISCOVER → MAP → HYPOTHESIZE → ATTACK → ADAPT → CHAIN → VALIDATE → EXPLAIN → FIX → RETEST
```

and the signature loop is: **ATTACK → PROVE → UNDERSTAND → FIX → REATTACK → VERIFY.**

### Rules of engagement are code, not convention

Every offensive run loads an **engagement file** (`examples/engagement.vuln-notes.json`) that
declares `authorized_by`, `target`, `scope.allowed_tools/denied_tools`, and hard budgets
(`max_requests`, `max_duration_ms`, `max_concurrency`). The engine enforces:

- no authorization → the run is refused before any request is sent (fail-closed, audited);
- out-of-scope tool → `EngagementViolation`, run aborts, violation recorded;
- persistence always prohibited; data exfiltration only ever demonstrable to the **local canary
  sink**, never a real external host; destructive testing forbidden against production.

### The proven loop (measured, on the bundled lab target)

The repository ships a deliberately vulnerable MCP lab target (`fixtures/mcps/vuln-notes.js`) and
its genuinely repaired twin (`fixtures/mcps/vuln-notes-fixed.js`). Against this target, one
command reproduces the entire loop end-to-end:

```bash
node bin/hachiman.js pentest examples/engagement.vuln-notes.json
```

Observed results (from real runs, not promises):

- Recon mapped the tools and produced a deterministic threat model (zero tokens).
- **3 hypotheses → 3 CONFIRMED findings**, each reproducible across repeated attack runs with a
  controlled response difference against a benign baseline:
  - `F-1 query-injection via notes.search` (confidence 100%)
  - `F-2 capability-excess admin.export reaches sensitive data` (confidence 95%)
  - `F-3 path-traversal via files.read` (confidence 100%)
- The attack graph connects all three to `res:sensitive-data`; chained impact is **critical**.
- Each finding got a **root-cause analysis** (what/where/why/failed boundary/broken assumption)
  and an **AI Repair Contract** (doc-06 §30 shape) — e.g. F-1's contract mandates
  `strategy: parameterized-query` and explicitly forbids blacklisting the payload.
- `node bin/hachiman.js retest <finding-id> --fixed vuln-notes-fixed` then replayed the ORIGINAL
  attacks against the repaired build: **VERIFIED ×3** — exploit no longer reproducible AND
  legitimate behavior preserved.

The loop has real teeth: during development an early version of the "fix" for F-3 was silently
too strict (rejected legitimate reads). The retest engine caught it as `REGRESSION` — proving a
code change alone never constitutes verification — and only the corrected fix reached `VERIFIED`.

### Commands

```text
hachiman pentest <engagement.json>           hachiman recon <engagement.json>
hachiman findings [--eng id]                 hachiman explain <finding-id>
hachiman fix <finding-id>                    hachiman retest <fid> --fixed <fixture|url>
hachiman chain --eng <id>                    hachiman report pentest <engagement-id>
```

### Honest scope

Implemented and proven today: **MCP servers / local HTTP MCP endpoints** on Windows, Linux, and
macOS — recon, hypothesis-driven attacks, exploit validation, attack graphs, root cause, AI
repair contracts, automated retest, and regression export. Target families documented as roadmap
in doc-06 (mobile, game, cloud, Kubernetes, CI/CD) are **not** implemented and the skill never
claims coverage there.

