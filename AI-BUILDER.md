# AI-BUILDER.md — Install & adapt Hachiman Agent on ANY operating system

> **This file is written for AI coding agents** (Claude Code, Codex CLI, Cursor, DeepSeek Harness,
> Hermes, OpenClaw, Qoder, Aider, Windsurf, …) **and the humans who prompt them.**
> One prompt is enough. Everything here works on **Windows, Linux, macOS**, and any other OS where
> **Node.js ≥ 22.5** runs — there are **zero dependencies** to install (no `npm install` needed).

---

## 1. The one prompt you paste to your AI builder

Copy this block verbatim into any AI coding agent that has terminal access on the target machine:

```text
Install the Hachiman Agent (autonomous security layer for AI agents and MCP) from the current
repository and verify it on THIS operating system. Follow AI-BUILDER.md at the repo root strictly.
Steps:
1) Check Node.js version >= 22.5 (node --version). If missing, tell me exactly how to install the
   Node 22 LTS for this OS (nodejs.org package, winget on Windows, apt/dnf/pacman/brew on Linux/macOS).
2) Run the universal installer: node scripts/install.js
   It performs an OS health check, module integrity check, policy validation, config init, and an
   in-memory engine self-test. It must print "RESULT: READY on <os>".
3) If any check fails, fix ONLY what the installer's ✗ lines say, then re-run it. Do not modify
   the security behavior of packages/ to make checks pass.
4) Prove it runs: node bin/hachiman.js init && node bin/hachiman.js guard --once (must print
   HACHIMAN GUARD ACTIVE and a status object) — or if config has no mcpServers yet, add the bundled
   demo server first: node bin/hachiman.js config set mcpServers.notes '{"fixture":"notes"}'
5) Run the test suite: npm test — expect all tests passing and zero failures.
6) Report: OS, node version, installer result, guard result, test counts. Do not upload or push
   anything anywhere.
```

That’s it. The installer exits non-zero on failure, so an AI builder gets machine-readable success
criteria, not vibes.

---

## 2. Why this installs “easy and fine” everywhere

| Property | Consequence |
|---|---|
| **Zero runtime dependencies** | No package manager, no lockfile, no compile step. Copy the folder, run Node. |
| **Pure ESM + Node builtins** | `node:sqlite`, `node:http`, `node:crypto`, `node:child_process`, `node:test` — all shipped with Node itself. |
| **All paths via `path.join/resolve`** | Windows backslashes, Linux/macOS slashes — handled identically. No hardcoded `/usr` or `$HOME`. |
| **Spawn via `process.execPath`** | Never guesses where `node` lives (Windows PATH quirks don’t matter). |
| **Windows `.cmd` shim handling** | Stdio MCP client uses `shell:true` on win32 so npm-installed MCP servers work. |
| **Stdin/stdout JSON-RPC + HTTP** | Both transports are OS-neutral; the stdio bridge makes stdio-only platforms work anywhere. |
| **SQLite WAL in a local dir** | Works on NTFS, APFS, ext4, xfs, btrfs (avoid network shares for the state file). |
| **`node --test` with native globs** | Test discovery is done by Node itself — no bash, no shell globbing. |

**Requirement matrix (verified by design; CI enforces it):**

| OS | Node | Status |
|---|---|---|
| macOS (arm64/x64) | 22 LTS / 24 | ✅ developed + live-tested here (all suites, Hermes integration, computer-use) |
| Ubuntu/Debian, Fedora, Arch (x64/arm64) | 22 LTS / 24 | ✅ supported — identical code paths; CI matrix included (`.github/workflows/ci.yml`) |
| Windows 10/11 (x64/arm64), PowerShell, cmd, WSL2 | 22 LTS / 24 | ✅ supported — win32 spawn-shim fix + windowsHide; CI matrix included |
| FreeBSD/others with Node ≥ 22.5 | 22.5+ | ✅ should work — same pure-Node surface |

---

## 3. Manual install (if an AI builder isn’t available)

```bash
# Any OS — same commands:
node --version                       # must be >= 22.5
node scripts/install.js              # full setup + self-test   (add --check for read-only verification)
node bin/hachiman.js init            # already done by installer; idempotent
npm test                             # full suite (optional but recommended)
```

**Optional global command** (any OS, via npm’s bin shim):

```bash
npm install -g .                     # then `hachiman` is on PATH
hachiman help
```

**Per-OS notes**

* **Windows (PowerShell):** quote JSON config values: `node bin/hachiman.js config set mcpServers.notes '{\"fixture\":\"notes\"}'` or use cmd. WSL2 works identically to Linux.
* **Windows services:** run `hachiman guard` under Task Scheduler / NSSM / a WinSW wrapper if you need auto-start (Hachiman itself is just a Node process).
* **Linux:** run `hachiman guard` under systemd:

  ```ini
  [Unit]
  Description=Hachiman Agent MCP security gateway
  After=network.target
  [Service]
  ExecStart=/usr/bin/node /opt/hachiman/bin/hachiman.js guard --port 7420
  WorkingDirectory=/opt/hachiman
  Restart=on-failure
  [Install]
  WantedBy=multi-user.target
  ```
* **macOS:** `launchd` plist or simply keep it in a terminal; `brew install node@22` if needed.

---

## 4. Connect ANY AI platform (after install)

Same mechanism on every OS — register the **stdio bridge** (or HTTP endpoint) in the platform’s MCP
config (details + examples per platform: `Hachiman-Agnent-Guide.md` §7–§10):

```bash
node bin/hachiman.js agent add <who> --allow <mcp1,mcp2> --ttl 24   # → prints sessionToken
```

```json
{
  "command": "node",
  "args": ["<repo>/bin/hachiman.js", "bridge", "<server>"],
  "env": {
    "HACHIMAN_GATEWAY": "http://127.0.0.1:7420",
    "HACHIMAN_SESSION": "hsm_XXXXXXXXXXXX.XXXXXXXXXXXX"
  }
}
```

Works with: Claude Desktop, Claude Code, Codex CLI, Hermes, OpenClaw, Qoder, DeepSeek Harness, and
anything else speaking MCP stdio or HTTP.

---

## 5. Verification contract (what “installed correctly” means)

An installation is DONE only when all of these hold (the AI-builder prompt enforces them):

1. `node scripts/install.js --check` → exit 0 (✓ on every line)
2. `node bin/hachiman.js guard --once` → prints `HACHIMAN GUARD ACTIVE` + status JSON
3. `npm test` → `# fail 0`
4. (Optional) `node scripts/demo.js` → benign ALLOW, injection BLOCK, exfil BLOCK → quarantine, incident report

If an AI builder claims success without these four, it is lying. These commands are the truth.

---

## 6. Troubleshooting (AI-builder decision table)

| Symptom | Fix |
|---|---|
| `node:sqlite unavailable` / `ExperimentalWarning` fatal | Node too old → install Node 22 LTS+ (win: `winget install OpenJS.NodeJS.LTS`; deb: NodeSource setup 22.x; brew: `node@22`) |
| Port busy (`listen EADDRINUSE`) | change port: `node bin/hachiman.js config set http.port 7421` |
| Windows: MCP stdio server fails ENOENT | ensure command quoted; Hachiman already applies the `.cmd` shim fix — check your Node ≥ 22.5 |
| Tests fail on exotic filesystem (network share/Docker volume) | move `.hachiman/state.db` to a local disk (SQLite WAL needs real local FS semantics) |
| Permission denied writing `.hachiman/` | run from a directory the user owns; installer prints the exact path |

---

## 7. What the installer does (trust, but verify)

`scripts/install.js` — pure Node, no network calls, read-only except `.hachiman/` creation:

1. **Runtime requirements** — Node ≥ 22.5, `node:sqlite` write/read probe, fetch global.
2. **Module integrity** — imports all 11 core modules (storage, decision, gateway, bridge, runtime, srg, scanner, reporting, dashboard, cli, composition).
3. **Policy packs** — validates `default`, `high-security`, `strict` JSON packs.
4. **Config init** — creates `.hachiman/hachiman.config.json` if absent (never overwrites).
5. **Engine self-test** — in-memory: identity→session→verify, zero-trust default state, **fail-closed authorization gate** (ungranted caller must NOT get ALLOW), **append-only audit trigger** (DELETE must be rejected).

`--uninstall` removes only `.hachiman/` (runtime state). It never touches code, docs, or your platform configs.

---

## 8. If you are asked to security-test an authorized target (offensive skill)

Hachiman also ships an **offensive security skill** (doc-06: Master Security Skill Architecture).
If the user asks you to pentest/attack/security-audit an owned or sanctioned target, follow
`skill/SKILL.md`:

1. Write an engagement JSON (`authorized_by` is mandatory — Hachiman refuses otherwise).
2. `node bin/hachiman.js pentest <engagement.json>` → confirmed findings + AI Repair Contracts.
3. Apply each contract’s `remediation.strategy` at the stated `location` (never blacklist payloads).
4. `node bin/hachiman.js retest <finding-id> --fixed <conn>` and honor the verdict
   (`VERIFIED` / `UNRESOLVED` / `REGRESSION`). A code change alone never constitutes verification.

Stay inside the engagement scope and budgets; every offensive action is audit-logged.

---

*Keep this file with the repository. It is the contract between Hachiman and any AI builder, on any OS.*
