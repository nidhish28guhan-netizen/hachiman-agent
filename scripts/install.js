#!/usr/bin/env node
// scripts/install.js — zero-dependency, cross-platform installer for Hachiman Agent.
// Works identically on Windows, Linux, macOS (and other Node-capable OSes).
// No npm install needed; Node >= 22.5 is the only requirement (node:sqlite).
//
//   node scripts/install.js            full setup (check + init + self-test)
//   node scripts/install.js --check    read-only health check (exit 0 = ready)  ← use this to verify
//   node scripts/install.js --selftest additionally run an in-memory engine self-test
//   node scripts/install.js --uninstall remove local runtime state (.hachiman), keep code
import { existsSync, mkdirSync, rmSync, writeFileSync, readFileSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import os from 'node:os';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, '..');
const HACHIMAN_DIR = join(ROOT, '.hachiman');
const CONFIG_PATH = join(HACHIMAN_DIR, 'hachiman.config.json');

const argv = process.argv.slice(2);
const has = (f) => argv.includes(f);
let failures = 0;
const ok = (t) => console.log('  \u2713 ' + t);
const fail = (t) => { failures++; console.log('  \u2717 ' + t); };
const info = (t) => console.log('    ' + t);

console.log('HACHIMAN AGENT — universal installer');
console.log(`  host: ${process.platform} (${process.arch}) · node ${process.version} · ${os.type()} ${os.release()}`);
console.log(`  root: ${ROOT}\n`);

// ── 1. runtime requirements ────────────────────────────────────────────────
console.log('[1] runtime requirements');
{
  const major = Number(process.versions.node.split('.')[0]);
  const minor = Number(process.versions.node.split('.')[1]);
  if (major > 22 || (major === 22 && minor >= 5)) ok(`node >= 22.5 (found ${process.version}) — node:sqlite available`);
  else fail(`node >= 22.5 required (found ${process.version}). Install Node 22 LTS+ from nodejs.org, then re-run.`);
  try {
    const { DatabaseSync } = await import('node:sqlite');
    const db = new DatabaseSync(':memory:');
    db.exec('CREATE TABLE t(x)'); db.prepare('INSERT INTO t VALUES (?)').run(1);
    if (db.prepare('SELECT x FROM t').get().x === 1) ok('node:sqlite functional (in-memory write/read)');
    else fail('node:sqlite returned unexpected data');
    db.close();
  } catch (e) {
    fail('node:sqlite unavailable: ' + e.message + (major < 22 ? ' (Node too old)' : ''));
  }
  try {
    if (typeof fetch === 'function' && typeof globalThis.Response === 'function') ok('fetch global available');
    else fail('fetch global missing (Node too old)');
  } catch (e) { fail('fetch check failed: ' + e.message); }
}

// ── 2. module integrity ────────────────────────────────────────────────────
console.log('\n[2] module integrity (pure ESM import, zero dependencies)');
const modules = {
  core: '../packages/core/src/storage.js',
  engines: '../packages/engines/src/decision.js',
  gateway: '../packages/gateway/src/gateway.js',
  bridge: '../packages/gateway/src/stdio-bridge.js',
  runtime: '../packages/runtime/src/response.js',
  srg: '../packages/srg/src/srg.js',
  scanner: '../packages/scanner/src/scanner.js',
  offense: '../packages/offense/src/pentest.js',
  offenseEngagement: '../packages/offense/src/engagement.js',
  offenseRetest: '../packages/offense/src/retest.js',
  offenseBench: '../packages/benchmark/src/offense-metrics.js',
  reporting: '../packages/reporting/src/render.js',
  dashboard: '../packages/dashboard/src/server.js',
  cli: '../packages/cli/src/main.js',
  composition: '../lib/hachiman.js',
};
for (const [name, p] of Object.entries(modules)) {
  try { await import(new URL(p, import.meta.url).href); ok(name + ' imports cleanly'); }
  catch (e) { fail(name + ' failed to import: ' + e.message); }
}

// ── 3. policy packs ────────────────────────────────────────────────────────
console.log('\n[3] policy packs');
for (const pack of ['default', 'high-security', 'strict']) {
  const p = join(ROOT, 'policies', pack + '.hachiman.json');
  try { JSON.parse(readFileSync(p, 'utf8')); ok(`${pack}.hachiman.json valid JSON`); }
  catch (e) { fail(`${pack}.hachiman.json: ` + e.message); }
}

// ── 4. config init (skipped with --check) ──────────────────────────────────
console.log('\n[4] local config');
if (has('--check')) {
  info(existsSync(CONFIG_PATH) ? `config present: ${CONFIG_PATH}` : 'no config yet (run without --check to create it)');
} else if (has('--uninstall')) {
  try { rmSync(HACHIMAN_DIR, { recursive: true, force: true }); ok('removed local runtime state (.hachiman)'); }
  catch (e) { fail('uninstall: ' + e.message); }
} else {
  try {
    mkdirSync(HACHIMAN_DIR, { recursive: true });
    if (!existsSync(CONFIG_PATH)) {
      writeFileSync(CONFIG_PATH, JSON.stringify({
        tenant: 'local',
        storage: { path: join(HACHIMAN_DIR, 'state.db') },
        policyPacks: ['default'],
        mcpServers: {},
        http: { port: 7420 },
        semantic: { enabled: true },
      }, null, 2));
      ok('created ' + CONFIG_PATH);
    } else ok('config already present (left untouched)');
  } catch (e) { fail('config init: ' + e.message); }
}

// ── 5. engine self-test (in-memory, no network) ────────────────────────────
if (!has('--check') || has('--selftest')) {
  console.log('\n[5] in-memory engine self-test (proves the security core runs on this OS)');
  try {
    const { createNode } = await import(new URL('../lib/hachiman.js', import.meta.url).href);
    const { evaluateRequest } = await import(new URL('../packages/engines/src/decision.js', import.meta.url).href);
    const node = createNode({ tenant: 'install-selftest', storage: { path: ':memory:' }, policyPacks: ['default'] });
    // identity + grant pipeline
    if (!node.identity.get('agent:selftest')) node.identity.register('agent', 'selftest');
    node.allowAgent('selftest', 'demo-mcp');
    const token = node.identity.issueSession('agent:selftest', { ttlMs: 60_000 }).token;
    const resolved = node.identity.resolve(token);
    if (resolved.verified && resolved.subjectId === 'agent:selftest') ok('identity: register → session → verify');
    else fail('identity verification failed: ' + JSON.stringify(resolved));
    // trust engine
    const t = node.storage.q.trustGet.get('mcp:demo-mcp');
    ok(`trust engine: mcp:demo-mcp state=${t?.state || 'UNKNOWN'} (zero-trust default)`);
    // authorization hard gate via the decision pipeline (no server needed: authz denies before network).
    // engine deps mirror exactly what the gateway passes (policy set resolved per request = hot-reload).
    const d = node.deps;
    const engineDeps = {
      storage: d.storage, bus: d.bus, identity: d.identity, authz: d.authz,
      policy: d.policyEngine.resolvePolicySet(d.policyPackIds), policyEngine: d.policyEngine,
      toolLookup: (mcpId, tool) => d.storage.q.toolGet.get(mcpId, tool || ''),
      monitor: d.monitor, srg: d.srg, semantic: d.semantic, metrics: d.metrics,
      canary: d.canary, config: node.config, cacheEnabled: d.config?.cache?.enabled !== false,
    };
    const v = await evaluateRequest(engineDeps, {
      id: 'selftest-1', tenantId: 'install-selftest', agentId: 'agent:intruder', mcpId: 'demo-mcp',
      toolId: 'demo-mcp.do', action: 'demo', params: {}, sessionToken: null,
    });
    if (['BLOCK', 'REVIEW'].includes(v.decision)) ok(`authorization hard gate: ungranted caller → ${v.decision} (fail-closed)`);
    else fail('authorization gate unexpected: ' + v.decision);
    // append-only audit
    node.storage.audit({ kind: 'lifecycle', action: 'install-selftest', actor: 'installer' });
    let tamperProof = false;
    try { node.storage.db.prepare('DELETE FROM audit_events').run(); } catch { tamperProof = true; }
    if (tamperProof) ok('audit log: append-only trigger rejects DELETE');
    else { failures++; console.log('  \u2717 audit log: WARNING — DELETE was not rejected'); }
    await node.stop();
    ok('cleanup: in-memory node stopped');
  } catch (e) {
    fail('engine self-test error: ' + e.message);
  }
}

// ── result ─────────────────────────────────────────────────────────────────
console.log('\n' + '─'.repeat(60));
if (failures > 0) {
  console.log(`RESULT: NOT READY — ${failures} check(s) failed (see \u2717 above).`);
  process.exit(1);
}
if (has('--uninstall')) { console.log('RESULT: runtime state removed. Code and docs untouched.'); process.exit(0); }
console.log('RESULT: READY on ' + process.platform + ' — Hachiman core verified on this OS.');
console.log(`
Next steps (identical on Windows / Linux / macOS):
  1. protect your first MCP server (add it to the config, or use a bundled fixture):
       node bin/hachiman.js config set mcpServers.notes '{"fixture":"notes"}'
  2. scan before deployment (CI gate exits non-zero on failure):
       node bin/hachiman.js scan notes --production
  3. start the watchman (gateway + dashboard on one port):
       node bin/hachiman.js guard --port 7420
  4. onboard an agent / platform (Claude Desktop, Claude Code, Hermes, Codex, …):
       node bin/hachiman.js agent add my-agent --allow notes --ttl 24
     then register the stdio bridge in the platform's MCP config:
       command: node  args: ${'"<root>/bin/hachiman.js" bridge notes'}
       env: HACHIMAN_GATEWAY=http://127.0.0.1:7420, HACHIMAN_SESSION=<token>
  5. run the test suite / demo / overhead benchmark:
       npm test      npm run demo      npm run spo

Docs: README.md, Hachiman-Agnent-Guide.md, AI-BUILDER.md (one-prompt setup for AI builders).
`);
