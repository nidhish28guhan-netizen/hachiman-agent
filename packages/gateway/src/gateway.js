// gateway/gateway — the MCP Security Gateway: intercepts, evaluates, enforces.
// Wire-compatible MCP pass-through: clients point at Hachiman; downstream config unchanged (AESP).
import { createMcpClient } from './mcp-client.js';
import { normalizeToolCall } from './normalize.js';
import { evaluateRequest } from '../../engines/src/decision.js';
import * as trust from '../../engines/src/trust.js';
import { uuid, nowMs } from '../../core/src/utils.js';

export const RPC_BLOCKED = -32088;      // HACHIMAN_BLOCKED
export const RPC_REVIEW = -32089;       // HACHIMAN_REVIEW_REQUIRED

export class McpGateway {
  /**
   * deps: { config, storage, bus, policyEngine, policyPackIds, identity, authz,
   *         monitor, srg, semantic, metrics, canary }
   */
  constructor(deps) {
    this.deps = deps;
    this.config = deps.config;
    this.clients = new Map();      // serverName -> client
    this.serverMeta = new Map();   // serverName -> {capabilities, initialized}
    this.reviews = new Map();      // reviewId -> pending review info
    this.decisionById = new Map(); // requestId -> last verdict (for explanation lookups)
    this.evaluated = 0;
  }

  policySet() { return this.deps.policyEngine.resolvePolicySet(this.deps.policyPackIds); }

  engineDeps() {
    const d = this.deps;
    return {
      storage: d.storage, bus: d.bus, identity: d.identity, authz: d.authz,
      policy: this.policySet(), policyEngine: d.policyEngine,
      toolLookup: (mcpId, tool) => d.storage.q.toolGet.get(mcpId, tool || ''),
      monitor: d.monitor, srg: d.srg, semantic: d.semantic, metrics: d.metrics,
      canary: d.canary, config: this.config, cacheEnabled: d.config?.cache?.enabled !== false,
    };
  }

  /** Connect to all configured downstream MCP servers. */
  async start() {
    for (const [name, spec] of Object.entries(this.config.mcpServers || {})) {
      const client = createMcpClient(spec);
      if (client.start) client.start();
      this.clients.set(name, client);
      this.serverMeta.set(name, { capabilities: null, initialized: false, spec });
      trust.registerSubject(this.deps.storage, `mcp:${name}`);
      try { await this._captureCapabilities(name, spec); } catch {}
    }
    return this;
  }

  async _captureCapabilities(name, spec) {
    const client = this.clients.get(name);
    const initResult = await client.request('initialize', {
      protocolVersion: '2025-06-18',
      capabilities: {},
      clientInfo: { name: 'hachiman-gateway', version: '0.1.0' },
    });
    const meta = this.serverMeta.get(name);
    meta.capabilities = initResult?.capabilities || {};
    meta.initialized = true;
    client.notify?.('notifications/initialized', {});
    await this.syncToolRegistry(name);
    this.deps.storage.audit({ kind: 'gateway', action: 'initialize', subject: `mcp:${name}`, detail: { capabilities: Object.keys(meta.capabilities) } });
    return initResult;
  }

  /** Registry sync on tools/list (+ capability-drift detection). */
  async syncToolRegistry(name) {
    const client = this.clients.get(name);
    const list = await client.request('tools/list', {});
    const tools = list?.tools || [];
    const known = this.deps.storage.q.toolList.all(name).map((r) => r.name);
    const seen = new Set();
    for (const t of tools) {
      seen.add(t.name);
      const prev = this.deps.storage.q.toolGet.get(name, t.name);
      const riskMeta = t._hachimanRiskMeta || (prev ? JSON.parse(prev.riskMeta || '{}') : inferRiskMeta(t));
      this.deps.storage.q.toolUp.run(
        `${name}:${t.name}`, name, t.name, t.description || '',
        JSON.stringify(t.inputSchema || {}), JSON.stringify(riskMeta),
        String(t._hachimanToolVersion || prev?.toolVersion || '1'), nowMs());
    }
    // capability-surprise detection: BOTH new and vanished tools are drift (schema-drifter fixture)
    const gone = known.filter((k) => !seen.has(k));
    const added = tools.map((t) => t.name).filter((n) => known.length && !known.includes(n));
    if (known.length && (gone.length || added.length)) {
      this.deps.bus.publish('anomaly', { type: 'capability-drift', mcpId: name, toolsAdded: added, toolsGone: gone, ts: nowMs() }, { shedClass: 3 });
      trust.restrict(this.deps.storage, `mcp:${name}`, 'capability-drift:' + [...added.map((a) => '+' + a), ...gone.map((g) => '-' + g)].join(','));
      this.deps.storage.audit({ kind: 'drift', subject: `mcp:${name}`, action: 'capability-drift-detected', actor: 'hachiman:gateway', detail: { added, gone } });
    }
    return tools;
  }

  /**
   * Main entry: process one JSON-RPC request aimed at a protected server.
   * Returns the JSON-RPC response object (result or error).
   */
  async processJsonRpc(serverName, rpc, sessionMeta = {}) {
    const client = this.clients.get(serverName);
    if (!client) return jsonRpcError(rpc.id, -32601, `hachiman: unknown protected server '${serverName}'`);

    if (rpc.method === 'initialize') {
      try { const result = await client.request('initialize', rpc.params || {}); return jsonRpcOk(rpc.id, result); }
      catch (e) { return jsonRpcError(rpc.id, -32000, String(e.message)); }
    }
    if (rpc.method === 'tools/list') {
      try {
        const result = await client.request('tools/list', {});
        await this.syncToolRegistry(serverName);
        return jsonRpcOk(rpc.id, result);
      } catch (e) { return jsonRpcError(rpc.id, -32000, String(e.message)); }
    }
    if (rpc.method !== 'tools/call') {
      // pass-through for resources/prompts etc, audited
      try { const result = await client.request(rpc.method, rpc.params || {}); return jsonRpcOk(rpc.id, result); }
      catch (e) { return jsonRpcError(rpc.id, -32000, String(e.message)); }
    }

    // ---- secured action boundary: tools/call ----
    const req = normalizeToolCall({ serverName, rpc, tenantId: this.config.tenant || 'local', sessionMeta, source: 'gateway' });
    const reqWithBehavior = this.deps.monitor ? { ...req, behavior: this.deps.monitor.getBehavior(req.agentId, req.toolId) } : req;
    const verdict = await evaluateRequest(this.engineDeps(), reqWithBehavior);
    this.decisionById.set(req.id, verdict);
    this.evaluated++;

    if (verdict.decision === 'BLOCK') {
      const incidentRef = verdict.containmentHint ? this._createBlockIncident(req, verdict) : null;
      this.deps.bus.publish('enforcement', { type: 'block', req, verdict, incidentRef, ts: nowMs() }, { shedClass: 1 });
      return jsonRpcError(rpc.id, RPC_BLOCKED, 'HACHIMAN: request blocked by security policy', {
        requestId: req.id, incidentId: incidentRef, risk: verdict.risk, confidence: verdict.confidence,
        trust: verdict.trust, reasons: verdict.reasons, reportRef: `/api/decisions/${req.id}`,
      });
    }
    if (verdict.decision === 'REVIEW') {
      const reviewId = uuid();
      this.reviews.set(reviewId, { req, verdict, serverName, createdAt: nowMs(), status: 'pending' });
      this.deps.bus.publish('review', { reviewId, req, verdict, ts: nowMs() }, { shedClass: 2 });
      return jsonRpcError(rpc.id, RPC_REVIEW, 'HACHIMAN: human review required', { reviewId, requestId: req.id, risk: verdict.risk, reasons: verdict.reasons });
    }

    // ALLOW → forward
    try {
      const result = await client.request('tools/call', rpc.params || {});
      this.deps.bus.publish('gateway', { type: 'forwarded', reqId: req.id, tool: req.toolId, ts: nowMs() }, { shedClass: 7 });
      return jsonRpcOk(rpc.id, result);
    } catch (e) {
      return jsonRpcError(rpc.id, -32000, `downstream error: ${e.message}`);
    }
  }

  resolveReview(reviewId, approve, by = 'operator') {
    const r = this.reviews.get(reviewId);
    if (!r) return { error: 'unknown review' };
    r.status = approve ? 'approved' : 'denied';
    r.resolvedBy = by; r.resolvedAt = nowMs();
    this.deps.storage.audit({ kind: 'review', subject: `mcp:${r.serverName}`, tool: r.req.toolId, decision: approve ? 'ALLOW' : 'BLOCK', actor: by, detail: { reviewId } });
    const { req, ...rest } = r;
    return { reviewId, status: r.status, requestId: req.id };
  }

  _createBlockIncident(req, verdict) {
    const id = uuid();
    const severity = verdict.risk >= 90 ? 'critical' : verdict.risk >= 75 ? 'high' : 'medium';
    this.deps.storage.q.incUp.run(id, req.tenantId || 'local', severity, 'open', req.id,
      JSON.stringify([{ ts: nowMs(), type: 'blocked', detail: { tool: req.toolId, risk: verdict.risk, confidence: verdict.confidence, reasons: verdict.reasons } }]),
      JSON.stringify([verdict.containmentHint || 'L2-deny']), null, nowMs(), nowMs());
    this.deps.bus.publish('incident', { id, severity, req, verdict, ts: nowMs() }, { shedClass: 4 });
    return id;
  }

  activeServers() {
    return [...this.serverMeta.entries()].map(([name, meta]) => ({
      name, initialized: meta.initialized, capabilities: meta.capabilities,
      trust: trust.getTrust(this.deps.storage, `mcp:${name}`),
      tools: this.deps.storage.q.toolList.all(name).map((t) => t.name),
    }));
  }

  async stop() { for (const [, c] of this.clients) try { c.stop?.(); } catch {} }
}

export function inferRiskMeta(tool) {
  const name = (tool.name || '').toLowerCase();
  const desc = (tool.description || '').toLowerCase();
  const s = name + ' ' + desc;
  const schema = tool.inputSchema || {};
  const propNames = Object.keys(schema.properties || {}).map((k) => k.toLowerCase());
  const egressCapable = propNames.some((k) => ['url', 'uri', 'host', 'endpoint', 'webhook', 'dest', 'destination'].includes(k))
    || /http|fetch|request|send|post|webhook/.test(s);
  const sideEffectRisk =
    /(delete|drop|exec|shell|write|create|update|insert|send|post|transfer|remove|rm)/.test(s) ? 35
    : /(read|get|list|query|calc|time|echo|search|describe)/.test(s) ? 0 : 15;
  return { egressCapable, sideEffectRisk, excessivePermissions: false };
}

export const jsonRpcOk = (id, result) => ({ jsonrpc: '2.0', id, result });
export const jsonRpcError = (id, code, message, data) => ({ jsonrpc: '2.0', id, error: { code, message, ...(data ? { data } : {}) } });
