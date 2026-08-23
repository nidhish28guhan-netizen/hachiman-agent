// adapters/http — the HTTP/API reverse-proxy adapter (Hachiman 2.0, P4).
// Puts the decision plane in front of a REST/HTTP service. Every call becomes
// a universal decision request: method → capability verb, path → resource scope,
// body/query → classified params, headers → destination/identity context.
// Decision authority stays in evaluateRequest; this adapter only translates.
import { uuid, nowMs } from '../../core/src/utils.js';
import { evaluateRequest } from '../../engines/src/decision.js';

export function makeApiAdapter(node, { id = 'api', routes = {} } = {}) {
  return {
    id,
    protocol: 'http-reverse-proxy',
    resourceTypes: ['api'],
    description: 'HTTP/REST reverse-proxy guard: method→capability, path→resource scope.',
    /** routes table: 'GET /health' → risk meta {'METHOD /path': {sideEffectRisk, egressCapable}} */
    metadata(resource) {
      const m = resource?.attrs?.method, p = resource?.attrs?.path;
      const row = routes[`${(m || '').toUpperCase()} ${p}`] || routes[`${(m || '').toUpperCase()} *`];
      return row || null;
    },
    toDecisionRequest({ service, method, path, body, sessionToken, headers = {} }) {
      const params = (body && typeof body === 'object' && !Array.isArray(body)) ? body : (body != null ? { body } : {});
      return {
        id: uuid(), ts: nowMs(),
        subject: undefined,
        agentId: undefined,
        resource: { type: 'api', id: service, attrs: { method: String(method || '').toUpperCase(), path: path || '/' } },
        action: String(method || 'REQUEST').toUpperCase(),
        params,
        authzContext: { sessionToken: sessionToken || headers['x-hachiman-session'] || null },
        ctx: { adapterId: id },
        adapterId: id,
        headers: sanitizeHeaders(headers),
      };
    },
  };
}

function sanitizeHeaders(h) {
  const out = {};
  for (const [k, v] of Object.entries(h || {})) out[k.toLowerCase()] = String(v).slice(0, 200);
  return out;
}

/**
 * Pure guard function (test target: no sockets required).
 * Returns { status, json } where status: 200 forwarded proxied response info,
 * 403 BLOCK, 202 REVIEW required, 502 downstream error.
 */
export async function guardApiCall(node, adapter, call, { forward } = {}) {
  const req = adapter.toDecisionRequest(call);
  const deps = node.engineDepsFor(adapter.id);
  const verdict = await evaluateRequest(deps, req);

  if (verdict.decision === 'BLOCK') {
    return { status: 403, verdict, json: { hachiman: 'blocked', requestId: req.id, risk: verdict.risk, confidence: verdict.confidence, reasons: verdict.reasons } };
  }
  if (verdict.decision === 'REVIEW') {
    return { status: 202, verdict, json: { hachiman: 'review-required', requestId: req.id, risk: verdict.risk, reasons: verdict.reasons } };
  }
  // ALLOW → forward (if a forwarder is provided)
  if (typeof forward === 'function') {
    try {
      const res = await forward(call);
      return { status: res.status ?? 200, verdict, json: res.body, proxied: true };
    } catch (e) {
      return { status: 502, verdict, json: { hachiman: 'downstream-error', error: String(e.message).slice(0, 160) } };
    }
  }
  return { status: 200, verdict, json: { hachiman: 'allowed', requestId: req.id }, allowed: true };
}

/**
 * createApiGuard(node, adapter, {target}) → standard (req,res) handler that can
 * be mounted on any node:http server: it guards /api-guard/<service>/<path...>.
 */
export function createApiGuard(node, adapter, { target } = {}) {
  return async function guardHandler(req, res) {
    const url = new URL(req.url, 'http://x');
    const m = url.pathname.match(/^\/api-guard\/([^/]+)(\/.*)?$/);
    if (!m) { res.writeHead(404, { 'content-type': 'application/json' }); return res.end(JSON.stringify({ error: 'use /api-guard/<service>/<path>' })); }
    const service = m[1], path = m[2] || '/';
    let body = null;
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      const chunks = [];
      for await (const c of req) { chunks.push(c); if (chunks.join('').length > 2_000_000) break; }
      const raw = Buffer.concat(chunks).toString('utf8');
      body = raw ? safeJson(raw) : null;
      if (raw && body === null && raw.length) body = { raw: raw.slice(0, 4000) };
    }
    const call = { service, method: req.method, path, body, headers: req.headers || {} };
    const out = await guardApiCall(node, adapter, call, {
      forward: target ? async (c) => {
        const r = await fetch(`${target}${c.path}`, {
          method: c.method,
          headers: { 'content-type': 'application/json' },
          body: c.body != null ? JSON.stringify(c.body) : undefined,
        });
        const text = await r.text();
        return { status: r.status, body: safeJson(text) ?? text };
      } : undefined,
    });
    res.writeHead(out.status, { 'content-type': 'application/json', 'x-hachiman-decision': out.verdict.decision, 'x-hachiman-risk': String(out.verdict.risk) });
    res.end(JSON.stringify(out.json ?? {}));
  };
}

function safeJson(s) { try { return JSON.parse(s); } catch { return null; } }
