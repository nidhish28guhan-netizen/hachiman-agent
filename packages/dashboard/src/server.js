// dashboard/server — HTTP edge: /mcp/<server> JSON-RPC + REST API + SSE + static UI.
import http from 'node:http';
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import * as trust from '../../engines/src/trust.js';
import { renderScanReport, renderIncidentReport, renderSpoStatement, reportJson } from '../../reporting/src/render.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const BOOT_AT = Date.now();

/** Read the UI and inject the fix-recommendation engine (single source of truth). */
async function buildIndexHtml() {
  const [html, recommendSrc] = await Promise.all([
    readFile(join(HERE, 'index.html'), 'utf8'),
    readFile(join(HERE, 'recommend.js'), 'utf8'),
  ]);
  const plain = recommendSrc.replace(/^export /gm, '');
  return html.replace('/*__RECOMMEND__*/', plain);
}

export function startHttpServer(node, { port = 7420, token = 'local-dev-token' } = {}) {
  const subs = new Map(); // SSE clients
  let indexHtmlPromise = null; // cached after first build
  const getIndexHtml = () => (indexHtmlPromise ||= buildIndexHtml());
  const bridge = (evt, channel) => broadcast(channel, evt);
  node.bus.on('decisions', bridge, { shedClass: 8, name: 'sse.decisions' });
  node.bus.on('anomaly', bridge, { shedClass: 8, name: 'sse.anomaly' });
  node.bus.on('incident', bridge, { shedClass: 8, name: 'sse.incident' });
  node.bus.on('quarantine', bridge, { shedClass: 8, name: 'sse.quarantine' });
  node.bus.on('srg', bridge, { shedClass: 8, name: 'sse.srg' });

  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, 'http://x');
    try {
      // ---- MCP wire endpoint ----
      const mcpMatch = url.pathname.match(/^\/mcp\/([^/]+)$/);
      if (mcpMatch && req.method === 'POST') {
        const body = await readBody(req, 2_000_000);
        const rpc = JSON.parse(body);
        const sessionMeta = parseSession(req);
        const out = await node.gateway.processJsonRpc(mcpMatch[1], rpc, sessionMeta);
        return sendJson(res, 200, out);
      }

      if (url.pathname === '/events') {
        res.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-cache', connection: 'keep-alive' });
        res.write(`event: hello\ndata: ${JSON.stringify({ mode: node.srg.mode })}\n\n`);
        const id = Symbol('sse');
        subs.set(id, res);
        req.on('close', () => subs.delete(id));
        return;
      }

      if (url.pathname === '/' || url.pathname === '/index.html') {
        return sendHtml(res, await getIndexHtml());
      }

      // ---- REST API ----
      if (url.pathname.startsWith('/api/')) return handleApi(node, req, res, url, token);

      sendJson(res, 404, { error: 'not found' });
    } catch (e) {
      sendJson(res, 500, { error: String(e.message) });
    }
  });

  function broadcast(channel, evt) {
    const data = `event: ${channel}\ndata: ${JSON.stringify(sanitize(evt)).slice(0, 8000)}\n\n`;
    for (const [, res] of subs) { try { res.write(data); } catch {} }
  }

  return new Promise((resolve) => {
    server.listen(port, '127.0.0.1', () => resolve({ server, port: server.address().port, stop: () => { for (const [, r] of subs) try { r.end(); } catch {}; server.close(); } }));
  });
}

async function handleApi(node, req, res, url, token) {
  const p = url.pathname;
  const method = req.method;
  const authed = req.headers['x-hachiman-token'] === token || url.searchParams.get('token') === token;

  const GET = method === 'GET';
  if (GET && p === '/api/status') return sendJson(res, 200, sanitize(node.status()));
  if (GET && p === '/api/metrics') return sendJson(res, 200, node.metrics.snapshot());
  if (GET && p === '/api/srg') return sendJson(res, 200, node.srg.snapshot());
  if (GET && p === '/api/mcps') return sendJson(res, 200, sanitize(node.gateway.activeServers()));
  if (GET && p === '/api/agents') return sendJson(res, 200, sanitize(node.monitor.snapshot()));
  if (GET && p === '/api/threats') {
    const inc = node.storage.q.incList.all(50).map(rowToIncident);
    return sendJson(res, 200, sanitize(inc));
  }
  if (GET && p === '/api/incidents') {
    const inc = node.storage.q.incList.all(Number(url.searchParams.get('limit') || 20)).map(rowToIncident);
    return sendJson(res, 200, sanitize(inc));
  }
  if (GET && p.startsWith('/api/audit')) {
    const rows = node.storage.auditTail(Number(url.searchParams.get('limit') || 100));
    return sendJson(res, 200, sanitize(rows));
  }
  if (GET && p === '/api/trust') {
    const subjects = [...node.gateway.serverMeta.keys()].flatMap((s) => [`mcp:${s}`]);
    return sendJson(res, 200, subjects.map((s) => sanitize(trust.getTrust(node.storage, s))));
  }
  if (GET && p === '/api/quarantine') return sendJson(res, 200, sanitize(node.storage.q.quarList.all()));
  if (GET && p === '/api/scans') {
    const target = url.searchParams.get('target');
    const rows = target ? node.storage.q.scanByTarget.all(target) : [];
    return sendJson(res, 200, rows.map((r) => ({ id: r.id, target: r.target, status: r.status, score: safeParse(r.score), createdAt: r.createdAt })));
  }
  if (GET && p.startsWith('/api/report/scan/')) {
    const scanId = p.split('/').pop();
    const row = node.storage.q.scanGet.get(scanId);
    if (!row) return sendJson(res, 404, { error: 'scan not found' });
    const score = safeParse(row.score); const findings = safeParse(row.findings) || [];
    if (url.searchParams.get('format') === 'json') return sendJson(res, 200, { scanId, score, findings });
    return sendText(res, 200, renderScanReport({ target: row.target, surface: null, findings, score }));
  }
  if (GET && p.startsWith('/api/report/incident/')) {
    const id = p.split('/').pop();
    const row = node.storage.q.incGet.get(id);
    if (!row) return sendJson(res, 404, { error: 'incident not found' });
    const audit = node.storage.auditTail(50);
    if (url.searchParams.get('format') === 'json') return sendJson(res, 200, rowToIncident(row));
    return sendText(res, 200, renderIncidentReport(rowToIncident(row), audit));
  }
  if (GET && p === '/api/reviews') return sendJson(res, 200, sanitize([...node.gateway.reviews.values()].map(({ req, ...r }) => r)));

  // ---- offensive skill aggregates (read-only) ----
  if (GET && p === '/api/offense') {
    const st = node.storage;
    const engagements = st.q.engList.all(10).map((r) => ({ id: r.id, target: r.target, environment: r.environment, status: r.status, createdAt: r.createdAt }));
    const allFindings = st.db.prepare('SELECT * FROM pentest_findings ORDER BY createdAt DESC LIMIT 50').all()
      .map((r) => ({ id: r.id, engagementId: r.engagementId, title: r.title, status: r.status, severity: r.severity, confidence: r.confidence, createdAt: r.createdAt }));
    const contracts = st.db.prepare('SELECT findingId, engagementId, createdAt FROM repair_contracts ORDER BY createdAt DESC LIMIT 50').all();
    const retests = st.db.prepare('SELECT findingId, verdict, fixTarget, reason, ts FROM retest_results ORDER BY ts DESC LIMIT 50').all();
    return sendJson(res, 200, sanitize({ engagements, findings: allFindings, contracts, retests }));
  }

  // ---- dashboard health ----
  if (GET && p === '/api/health') {
    return sendJson(res, 200, {
      ok: true,
      uptimeS: Math.round((Date.now() - BOOT_AT) / 1000),
      rssMb: Math.round(process.memoryUsage().rss / 1048576),
      node: process.version,
      platform: process.platform,
      mode: node.srg.mode,
      servers: [...node.gateway.serverMeta.keys()],
    });
  }

  // ---- admin (token-gated) ----
  if (!authed && !GET) return sendJson(res, 403, { error: 'missing or bad X-Hachiman-Token' });
  if (method === 'POST' && p.startsWith('/api/review/') && p.endsWith('/resolve')) {
    const reviewId = p.split('/')[3];
    const body = safeParse(await readBody(req, 100_000)) || {};
    return sendJson(res, 200, node.gateway.resolveReview(reviewId, !!body.approve, body.by || 'operator'));
  }
  if (method === 'POST' && p === '/api/quarantine') {
    const body = safeParse(await readBody(req, 100_000)) || {};
    if (!body.subject) return sendJson(res, 400, { error: 'subject required' });
    node.response.quarantine(body.subject, body.reason || 'manual quarantine', { risk: 100 });
    return sendJson(res, 200, { ok: true });
  }
  if (method === 'POST' && p.startsWith('/api/quarantine/') && p.endsWith('/release')) {
    const subject = decodeURIComponent(p.split('/')[3]);
    return sendJson(res, 200, node.response.release(subject, 'operator', { rescanPassed: true }));
  }
  if (method === 'POST' && p === '/api/mcp-allow') {
    const body = safeParse(await readBody(req, 100_000)) || {};
    return sendJson(res, 200, node.allowMcp(body.mcp));
  }
  if (method === 'POST' && p === '/api/report/save') {
    const body = safeParse(await readBody(req, 5_000_000)) || {};
    const dir = body.dir || join(node.root, '.hachiman', 'reports');
    await mkdir(dir, { recursive: true });
    const file = join(dir, body.name || `report-${Date.now()}.md`);
    await writeFile(file, body.content || '');
    return sendJson(res, 200, { file });
  }
  sendJson(res, 404, { error: 'api not found' });
}

function parseSession(req) {
  const t = req.headers['x-hachiman-session'];
  const agent = req.headers['x-hachiman-agent'];
  return t ? { sessionToken: t, agentId: agent || undefined } : (agent ? { agentId: agent, sessionToken: null } : {});
}
function readBody(req, max) {
  return new Promise((resolve, reject) => {
    let s = '';
    req.on('data', (c) => { s += c; if (s.length > max) { reject(new Error('body too large')); req.destroy(); } });
    req.on('end', () => resolve(s));
    req.on('error', reject);
  });
}
function sendJson(res, code, obj) { res.writeHead(code, { 'content-type': 'application/json' }); res.end(JSON.stringify(obj)); }
function sendText(res, code, text) { res.writeHead(code, { 'content-type': 'text/plain; charset=utf-8' }); res.end(text); }
function sendHtml(res, html) { res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' }); res.end(html); }
function safeParse(s) { if (s == null) return null; try { return JSON.parse(s); } catch { return null; } }
function rowToIncident(r) { return { id: r.id, tenantId: r.tenantId, severity: r.severity, status: r.status, triggerEvent: r.triggerEvent, timeline: r.timeline, containment: r.containment, createdAt: r.createdAt, updatedAt: r.updatedAt }; }
/** Strip functions/large blobs before shipping over JSON/SSE. */
function sanitize(v) {
  if (v == null || typeof v !== 'object') return v;
  const s = JSON.stringify(v, (k, val) => (typeof val === 'function' ? undefined : val));
  return JSON.parse(s);
}
