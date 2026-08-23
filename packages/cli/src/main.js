// cli — the /hachiman command interface (deterministic, token-efficient, --json mode).
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { dirname } from 'node:path';
import { createNode } from '../../../lib/hachiman.js';
import { startFixture } from '../../../fixtures/host.js';
import { renderScanReport, renderIncidentReport, reportJson } from '../../reporting/src/render.js';
import { startHttpServer } from '../../dashboard/src/server.js';
import * as trust from '../../engines/src/trust.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, '..', '..', '..'); // packages/cli/src → project root
const CONFIG_PATH = join(ROOT, '.hachiman', 'hachiman.config.json');

const HELP = `
HACHIMAN — autonomous security layer for AI agents and MCP
Usage: hachiman <command> [args] [--json]

Core:
  init                          initialize config + identity
  guard [--port N] [--once]     protect configured MCP servers (gateway + runtime)
  status                        node status summary
  config get|set <k> [v]        read/write config

Pre-deployment:
  scan <target> [--url U | --fixture name | --command C args...] [--production] [--suite AI,MCP,APP]
  test <target> --full          alias: scan all suites
  inspect mcp:<name>            capability registry view
  mcp list|allow <mcp>|deny <mcp>
  trust <subject>               trust record + history

Runtime:
  threats [active]              list incidents
  quarantine <mcp:subject> [--reason R] | quarantine release <mcp:subject>
  agents                        agent behavior profiles
  agent add <name> [--allow mcp1,mcp2] [--ttl hours]   register agent + grants + session token
  bridge <mcp> [--gateway url] [--session token]       stdio bridge for stdio-only MCP clients

Offensive skill (authorized targets only — ROE enforced):
  pentest <engagement.json>     full loop: DISCOVER→MAP→HYPOTHESIZE→ATTACK→CHAIN→VALIDATE→EXPLAIN→FIX
  recon <engagement.json>       DISCOVER+MAP only (surface, tech, threat model)
  findings [--eng id]           list confirmed/unconfirmed findings
  explain <finding-id>          root-cause developer card
  fix <finding-id>              AI Repair Contract (yaml + json)
  retest <finding-id> --fixed <fixture|url>   replay original attack vs fixed build → VERIFIED/UNRESOLVED/REGRESSION
  chain --eng <id>              attack graph + chained impact
  report pentest <eng-id>       full engagement report

Reports & audit:
  audit [--tail N] [--since MS]
  report scan <scanId> [--json] | report incident <id> [--json] | report production <target>
  policy list|show <id>
  dashboard [--port N]          serve the security dashboard
  help
`.trim();

export async function main(argv) {
  const args = argv.slice(2);
  const json = args.includes('--json');
  const flag = (name, dflt = null) => { const i = args.indexOf('--' + name); return i >= 0 && i + 1 < args.length ? args[i + 1] : dflt; };
  const has = (name) => args.includes('--' + name);
  const cmd = args[0];

  const out = (v) => { if (json) console.log(JSON.stringify(v, null, 2)); else console.log(v); };
  const loadConfig = () => existsSync(CONFIG_PATH) ? JSON.parse(readFileSync(CONFIG_PATH, 'utf8')) : null;

  switch (cmd) {
    case 'help': case undefined: return out(HELP);

    case 'init': {
      mkdirSync(dirname(CONFIG_PATH), { recursive: true });
      if (!existsSync(CONFIG_PATH)) {
        writeFileSync(CONFIG_PATH, JSON.stringify({
          tenant: 'local',
          storage: { path: join(ROOT, '.hachiman', 'state.db') },
          policyPacks: ['default'],
          mcpServers: {},
          http: { port: 7420 },
          semantic: { enabled: true },
        }, null, 2));
      }
      const node = createNode(loadConfig());
      const op = node.identity.get('operator:local') || node.identity.register('operator', 'local', { role: 'owner' });
      await node.stop();
      return out(`initialized at ${CONFIG_PATH}\noperator identity: operator:local`);
    }

    case 'status': {
      const cfg = loadConfig();
      if (!cfg) return out('not initialized — run: hachiman init');
      const node = createNode(cfg);
      const st = node.status();
      await node.stop();
      return out(st);
    }

    case 'config': {
      const cfg = loadConfig() || {};
      const getPath = (obj, p) => p.split('.').reduce((o, k) => (o == null ? undefined : o[k]), obj);
      const setPath = (obj, p, v) => {
        const ks = p.split('.'); let cur = obj;
        for (let i = 0; i < ks.length - 1; i++) { if (typeof cur[ks[i]] !== 'object' || cur[ks[i]] == null) cur[ks[i]] = {}; cur = cur[ks[i]]; }
        cur[ks[ks.length - 1]] = v; return obj;
      };
      if (args[1] === 'get') return out(getPath(cfg, args[2] || ''));
      if (args[1] === 'set') {
        let v; try { v = JSON.parse(args[3]); } catch { v = args[3]; }
        setPath(cfg, args[2], v);
        mkdirSync(dirname(CONFIG_PATH), { recursive: true });
        writeFileSync(CONFIG_PATH, JSON.stringify(cfg, null, 2));
        return out(`set ${args[2]}`);
      }
      return out(cfg);
    }

    case 'guard': {
      const cfg = loadConfig();
      if (!cfg) return out('not initialized — run: hachiman init');
      const port = Number(flag('port', cfg.http?.port || 7420));
      // materialize {fixture: name} specs into live {url} endpoints
      const fixtures = [];
      for (const [name, spec] of Object.entries(cfg.mcpServers || {})) {
        if (spec?.fixture) {
          const fx = await startFixture(spec.fixture, { env: { SINK_URL: process.env.SINK_URL || '' } });
          fixtures.push(fx);
          cfg.mcpServers[name] = { url: fx.url };
        }
      }
      const node = await createNode(cfg).start();
      const http = await startHttpServer(node, { port, token: 'local-dev-token' });
      const servers = node.gateway.activeServers();
      out(`HACHIMAN GUARD ACTIVE`);
      out(`  tenant: ${node.config.tenant}`);
      for (const s of servers) out(`  protecting mcp:${s.name} → trust ${s.trust.state}/${Math.round(s.trust.score)} tools:[${s.tools.join(', ')}]`);
      out(`  gateway:  http://127.0.0.1:${http.port}/mcp/<server>`);
      out(`  dashboard: http://127.0.0.1:${http.port}/`);
      const shutdown = async () => { await node.stop(); http.stop(); for (const f of fixtures) f.stop(); };
      if (has('once')) { const st = node.status(); await shutdown(); return out(st); }
      await new Promise((r) => process.once('SIGINT', r));
      await shutdown();
      return out('guard stopped');
    }

    case 'scan': case 'test': {
      const target = args[1];
      if (!target) return out('usage: hachiman scan <target> [--url U | --fixture name]');
      const cfg = loadConfig() || {};
      const node = createNode({ ...cfg, storage: { path: join(ROOT, '.hachiman', 'state.db') } });
      let fixture = null;
      try {
        let conn;
        if (flag('url')) conn = { url: flag('url') };
        else if (flag('fixture')) {
          fixture = await startFixture(flag('fixture'), { env: { SINK_URL: process.env.SINK_URL || '' } });
          conn = { url: fixture.url };
        } else if (cfg.mcpServers?.[target]) {
          const spec = cfg.mcpServers[target];
          if (spec.url) conn = { url: spec.url };
          else { fixture = await startFixture(target, { file: join(ROOT, 'fixtures', 'mcps', target + '.js') }); conn = { url: fixture.url }; }
        } else return out(`no connection for '${target}' — pass --url, --fixture, or add it to config mcpServers`);
        const suites = flag('suite') ? flag('suite').split(',') : null;
        const res = await node.scanner.scan({ target, conn, suites, by: 'operator' });
        const md = renderScanReport({ target, surface: res.surface, findings: res.findings, score: res.score, durationMs: res.durationMs });
        if (flag('report') && typeof flag('report') === 'string') writeFileSync(flag('report'), md);
        if (has('production') && res.score.status !== 'PRODUCTION_READY') {
          if (!json) console.log(md);
          out(`\n✖ PRODUCTION GATE FAILED — ${target} is ${res.score.status} (score ${res.score.overall}/100, ${res.score.counts.critical} critical/${res.score.counts.high} high). Deployment denied.`);
          process.exitCode = 2; // cleanup happens in finally
          return;
        }
        if (json) return out({ scanId: res.scanId, score: res.score, findings: res.findings.length });
        console.log(md);
        return out(`\nscan ${res.scanId} stored · trust now ${trust.getTrust(node.storage, 'mcp:' + target).state}`);
      } finally {
        if (fixture) fixture.stop();
        await node.stop();
      }
    }

    case 'inspect': {
      const subject = args[1];
      const node = createNode(loadConfig() || {});
      const mcp = subject?.replace(/^mcp:/, '');
      const tools = node.storage.q.toolList.all(mcp || '');
      const t = trust.getTrust(node.storage, `mcp:${mcp}`);
      await node.stop();
      return out({ subject: `mcp:${mcp}`, trust: { state: t.state, score: Math.round(t.score) }, tools: tools.map((r) => ({ name: r.name, description: r.description, riskMeta: safeParse(r.riskMeta) })) });
    }

    case 'trust': {
      const subject = args[1];
      const node = createNode(loadConfig() || {});
      const rec = trust.getTrust(node.storage, subject.includes(':') ? subject : `mcp:${subject}`);
      await node.stop();
      return out(rec);
    }

    case 'threats': {
      const node = createNode(loadConfig() || {});
      const rows = node.storage.q.incList.all(50);
      const active = args[1] === 'active';
      await node.stop();
      return out(rows.filter((r) => !active || r.status === 'open').map((r) => ({ id: r.id, severity: r.severity, status: r.status, createdAt: new Date(r.createdAt).toISOString() })));
    }

    case 'quarantine': {
      const node = createNode(loadConfig() || {});
      try {
        if (args[1] === 'release') { const r = node.response.release(args[2], 'operator', {}); return out(r); }
        const subject = args[1].includes(':') ? args[1] : `mcp:${args[1]}`;
        node.response.quarantine(subject, flag('reason', 'manual quarantine via CLI'), {});
        return out(`quarantined ${subject}`);
      } finally { await node.stop(); }
    }

    case 'agents': {
      const node = createNode(loadConfig() || {});
      const snap = node.monitor.snapshot();
      const agents = node.identity.list('agent');
      await node.stop();
      return out({ registered: agents.map((a) => a.id), profiles: snap });
    }

    case 'audit': {
      const node = createNode(loadConfig() || {});
      const rows = node.storage.auditTail(Number(flag('tail', 30)), Number(flag('since', 0)));
      await node.stop();
      if (json) return out(rows);
      for (const r of rows) console.log(`${new Date(r.ts).toISOString()} ${r.kind.padEnd(12)} ${r.subject || '-'} ${r.tool || ''} → ${r.decision || ''} risk=${r.risk ?? '-'} (${(r.reasons || []).join(',')})`);
      return;
    }

    case 'report': {
      const kind = args[1];
      const node = createNode(loadConfig() || {});
      try {
        if (kind === 'scan') {
          const row = node.storage.q.scanGet.get(args[2]);
          if (!row) return out('scan not found');
          const score = safeParse(row.score); const findings = safeParse(row.findings) || [];
          return out(has('json') ? reportJson({ score, findings }) : renderScanReport({ target: row.target, findings, score }));
        }
        if (kind === 'incident') {
          const row = node.storage.q.incGet.get(args[2]);
          if (!row) return out('incident not found');
          const audit = node.storage.auditTail(60);
          return out(has('json') ? reportJson(row) : renderIncidentReport(row, audit));
        }
        if (kind === 'production') {
          const rows = node.storage.q.scanByTarget.all(args[2] || '');
          if (!rows.length) return out('no scans for target');
          const latest = rows[0];
          const score = safeParse(latest.score); const findings = safeParse(latest.findings) || [];
          return out(has('json') ? reportJson({ score, findings }) : renderScanReport({ target: latest.target, findings, score }));
        }
        if (kind === 'pentest') {
          const engId = args[2];
          if (!engId) return out('usage: hachiman report pentest <engagement-id>');
          const { renderPentestReport } = await import('../../reporting/src/render.js');
          const engRow = node.storage.engGetById(engId);
          if (!engRow) return out('engagement not found: ' + engId);
          const findings = node.storage.fndListByEngagement(engId);
          const retests = [];
          for (const f of findings) retests.push(...node.storage.retListByFinding(f.id).map((r) => ({ findingId: r.findingId, verdict: r.verdict, reason: r.reason })));
          const engagement = { id: engRow.id, target: engRow.target, environment: engRow.environment, authorized_by: engRow.authorizedBy, scope: engRow.scope, rules: engRow.rules };
          const run = { findings, contracts: node.storage.q.ctrList.all(engId).map((r) => JSON.parse(r.contract)), retests, metrics: findings.length ? { hypotheses: findings.length, validationRate: null, requests: null, durationMs: null, tokensUsed: 0, budgetExhausted: null } : {}, plan: { tests: [] }, surface: null };
          return out(renderPentestReport({ engagement, run, graphText: '' }));
        }
        return out('usage: hachiman report scan <id> | incident <id> | production <target> | pentest <engagement-id>');
      } finally { await node.stop(); }
    }

    case 'mcp': {
      const node = createNode(loadConfig() || {});
      try {
        if (args[1] === 'list') {
          const trusts = node.storage.db.prepare('SELECT subjectId,state,score FROM trust_records WHERE subjectId LIKE ?').all('mcp:%');
          return out(trusts.map((t) => ({ subject: t.subjectId, state: t.state, score: Math.round(t.score) })));
        }
        if (args[1] === 'allow') { const r = node.allowMcp(args[2]); return out(r); }
        if (args[1] === 'deny') { node.response.quarantine(`mcp:${args[2]}`, 'operator deny', {}); return out(`denied/quarantined mcp:${args[2]}`); }
        return out('usage: hachiman mcp list|allow <mcp>|deny <mcp>');
      } finally { await node.stop(); }
    }

    case 'policy': {
      const node = createNode(loadConfig() || {});
      try {
        if (args[1] === 'list') return out([...node.policyEngine.active.values()].map((p) => `${p.id}@${p.version}`));
        if (args[1] === 'show') return out(node.policyEngine.getPack(args[2]));
        return out('usage: hachiman policy list|show <id>');
      } finally { await node.stop(); }
    }

    case 'dashboard': {
      const cfg = loadConfig() || {};
      const node = await createNode(cfg).start();
      const http = await startHttpServer(node, { port: Number(flag('port', 7430)), token: 'local-dev-token' });
      out(`dashboard: http://127.0.0.1:${http.port}/  (Ctrl-C to stop)`);
      await new Promise((r) => process.once('SIGINT', r));
      await node.stop(); http.stop();
      return out('dashboard stopped');
    }

    case 'agent': {
      const verb = args[1]; const name = args[2];
      if (verb === 'add' && name) {
        const cfg = loadConfig() || {};
        const node = createNode({ ...cfg, storage: { path: join(ROOT, '.hachiman', 'state.db') } });
        try {
          const agentId = `agent:${name}`;
          if (!node.identity.get(agentId)) node.identity.register('agent', name);
          const allows = flag('allow') ? flag('allow').split(',').map((s) => s.trim()) : Object.keys(cfg.mcpServers || {});
          for (const m of allows) node.allowAgent(name, m);
          const ttlMs = Math.max(1, Number(flag('ttl', 24))) * 3600_000;
          const sess = node.identity.issueSession(agentId, { ttlMs });
          node.storage.audit({ kind: 'session', subject: agentId, action: 'session-issued', actor: 'operator', detail: { ttlMs, granted: allows } });
          console.log(JSON.stringify({ agentId, granted: allows, sessionToken: sess.token, ttlHours: Number(flag('ttl', 24)) }, null, 2));
          return;
        } finally { await node.stop(); }
      }
      return out('usage: hachiman agent add <name> [--allow mcp1,mcp2] [--ttl hours]');
    }

    case 'bridge': {
      const server = args[1];
      if (!server) return out('usage: hachiman bridge <mcp> [--gateway URL] [--session TOKEN]  (env: HACHIMAN_GATEWAY, HACHIMAN_SESSION)');
      const url = flag('gateway', process.env.HACHIMAN_GATEWAY || 'http://127.0.0.1:7420');
      const token = flag('session', process.env.HACHIMAN_SESSION || null);
      const { runBridge } = await import('../../gateway/src/stdio-bridge.js');
      console.error(`[hachiman-bridge] mcp:${server} → ${url}/mcp/${server}${token ? ' · session bound' : ' · no session (anonymous)'} (Ctrl-C to stop)`);
      runBridge({ gatewayUrl: url, server, sessionToken: token });
      await new Promise((r) => process.once('SIGINT', r));
      return out('bridge stopped');
    }

    // ── offensive skill (doc-06 §36) — authorized targets only ──────────────
    case 'recon': case 'pentest': {
      const file = args[1];
      if (!file) return out(`usage: hachiman ${cmd} <engagement.json>`);
      const { loadEngagement } = await import('../../offense/src/engagement.js');
      const eng = loadEngagement(resolve(file));
      const cfg = loadConfig() || {};
      const node = createNode({ ...cfg, storage: { path: join(ROOT, '.hachiman', 'state.db') } });
      eng.audit = (sub, action, detail) => node.storage.audit({ kind: 'offense', actor: eng.authorized_by, subject: eng.target, tool: sub, action, detail });
      try {
        if (cmd === 'recon') {
          const { runRecon } = await import('../../offense/src/recon.js');
          let conn = eng.conn; let fx = null;
          if (conn.fixture) { fx = await startFixture(conn.fixture); conn = { url: fx.url }; }
          try { const surface = await runRecon(conn); out(JSON.stringify(surface, null, 2)); }
          finally { if (fx) fx.stop(); }
          return;
        }
        const { execute, persistRun } = await import('../../offense/src/pentest.js');
        const { renderPentestReport } = await import('../../reporting/src/render.js');
        const run = await execute(eng, { onProgress: (s) => console.error(`[pentest] ${s}`) });
        persistRun(node.storage, eng, run);
        const report = renderPentestReport({ engagement: eng, run, graphText: run.graphText });
        if (json) out({ engagement: run.engagement, findings: run.findings.map(({ evidence, ...f }) => f), contracts: run.contracts, metrics: run.metrics, chain: run.chain, error: run.error });
        else out(report);
        return;
      } finally { await node.stop(); }
    }

    case 'findings': {
      const cfg = loadConfig() || {};
      const node = createNode({ ...cfg, storage: { path: join(ROOT, '.hachiman', 'state.db') } });
      try {
        const engId = flag('eng');
        const rows = engId ? node.storage.q.fndList.all(engId) : node.storage.db.prepare('SELECT * FROM pentest_findings ORDER BY createdAt DESC LIMIT 100').all();
        const items = rows.map((r) => ({ id: r.id, engagement: r.engagementId, title: r.title, status: r.status, severity: r.severity, confidence: r.confidence }));
        if (json) return out(items);
        if (!items.length) return out('no findings recorded yet — run: hachiman pentest <engagement.json>');
        for (const f of items) out(`[${f.status}] ${f.severity ? f.severity.toUpperCase() + ' ' : ''}${f.id} — ${f.title} (eng ${f.engagement}, conf ${f.confidence ?? 'n/a'}%)`);
        return;
      } finally { await node.stop(); }
    }

    case 'explain': {
      const id = args[1];
      if (!id) return out('usage: hachiman explain <finding-id>  (print the developer card)');
      const { analyze } = await import('../../offense/src/rootcause.js');
      const { renderDeveloperCard } = await import('../../offense/src/repair.js');
      const cfg = loadConfig() || {};
      const node = createNode({ ...cfg, storage: { path: join(ROOT, '.hachiman', 'state.db') } });
      try {
        const f = node.storage.fndGetById(id);
        if (!f) return out(`finding not found: ${id}`);
        const contract = node.storage.ctrGetByFinding(f.id);
        const rc = f.rootCause || analyze(f);
        if (contract) out(renderDeveloperCard(contract, rc));
        else out(JSON.stringify({ finding: f.title, rootCause: rc }, null, 2));
        return;
      } finally { await node.stop(); }
    }

    case 'fix': {
      const id = args[1];
      if (!id) return out('usage: hachiman fix <finding-id>  (print AI Repair Contract: yaml + json)');
      const cfg = loadConfig() || {};
      const node = createNode({ ...cfg, storage: { path: join(ROOT, '.hachiman', 'state.db') } });
      try {
        const c = node.storage.ctrGetByFinding(id);
        if (!c) return out(`no repair contract for ${id} — was the finding confirmed by a pentest run?`);
        const { renderContractYaml } = await import('../../offense/src/repair.js');
        out('# AI REPAIR CONTRACT — hand this to your AI builder\n');
        out(renderContractYaml(c));
        const { _yaml, ...machine } = c;
        out('\n# machine-readable (json)\n' + JSON.stringify(machine, null, 2));
        return;
      } finally { await node.stop(); }
    }

    case 'retest': {
      const id = args[1];
      const fixed = flag('fixed');
      if (!id || !fixed) return out('usage: hachiman retest <finding-id> --fixed <fixture|url>');
      const { loadEngagement } = await import('../../offense/src/engagement.js');
      const { verifyFix } = await import('../../offense/src/retest.js');
      let fixedConn = /^https?:/.test(fixed) ? { url: fixed } : { fixture: fixed.replace(/\.js$/, '') };
      let fxHandle = null;
      if (fixedConn.fixture) { fxHandle = await startFixture(fixedConn.fixture); fixedConn = { url: fxHandle.url }; }
      const cfg = loadConfig() || {};
      const node = createNode({ ...cfg, storage: { path: join(ROOT, '.hachiman', 'state.db') } });
      try {
        const c = node.storage.ctrGetByFinding(id);
        if (!c) return out(`no repair contract for ${id} — nothing to retest`);
        const eng = loadEngagement({ engagement: { target: 'fix-verification:' + id, conn: { url: fixedConn.url }, authorized_by: 'operator', rules: { max_requests: 50 } } });
        const result = await verifyFix(eng, c, fixedConn);
        node.storage.retSave(result);
        node.storage.audit({ kind: 'offense', actor: eng.authorized_by, subject: id, action: 'retest', decision: result.verdict, detail: { fixedTarget: result.fixedTarget, reason: result.reason } });
        out(`RETEST ${id}: ${result.verdict}`);
        out(`  ${result.reason}`);
        out(`  exploit still works: ${result.attackReplay.exploitStillWorks}`);
        if (result.baseline) out(`  legitimate behavior preserved: ${result.baseline.ok}`);
        if (!json) out('\nverdict semantics: VERIFIED = original attack fails AND legitimate behavior works. A code change alone never constitutes verification.');
        return;
      } finally { if (fxHandle) fxHandle.stop(); await node.stop(); }
    }

    case 'chain': {
      const engId = flag('eng');
      if (!engId) return out('usage: hachiman chain --eng <engagement-id>');
      const { buildGraph, chainImpact, renderGraph } = await import('../../offense/src/graph.js');
      const cfg = loadConfig() || {};
      const node = createNode({ ...cfg, storage: { path: join(ROOT, '.hachiman', 'state.db') } });
      try {
        const findings = node.storage.fndListByEngagement(engId).filter((f) => f.confirmed);
        if (!findings.length) return out(`no confirmed findings for engagement ${engId}`);
        const graph = buildGraph(findings);
        const impact = chainImpact(graph, findings);
        out(renderGraph(graph, impact));
        return;
      } finally { await node.stop(); }
    }

    default: return out(`unknown command: ${cmd}\n\n${HELP}`);
  }
}

function safeParse(s) { if (s == null) return null; try { return JSON.parse(s); } catch { return null; } }
