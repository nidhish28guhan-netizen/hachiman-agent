// runtime/response — authorized response actions ladder + containment + incident timeline.
// Every ladder step requires a standing response grant (response.maxLadder in policy pack).
import { nowMs, uuid } from '../../core/src/utils.js';
import * as trust from '../../engines/src/trust.js';

export const LADDER = {
  1: 'redact', 2: 'deny-tool-call', 3: 'restrict-capability', 4: 'revoke-permission',
  5: 'suspend-mcp', 6: 'quarantine-mcp',
};

export class ResponseEngine {
  /** deps: { storage, bus, policyEngine, policyPackIds, authz, identity, srg } */
  constructor(deps) {
    this.deps = deps; this.actions = [];
    this.bus.on('decisions', (evt) => this.onDecision(evt), { shedClass: 1, name: 'response.onDecision' });
    this.bus.on('anomaly', (evt) => this.onAnomaly(evt), { shedClass: 3, name: 'response.onAnomaly' });
  }
  get bus() { return this.deps.bus; }
  get storage() { return this.deps.storage; }

  maxLadder() {
    const set = this.deps.policyEngine.resolvePolicySet(this.deps.policyPackIds);
    return set.response?.maxLadder ?? 4;
  }

  /** Respond to a BLOCK verdict: escalate containment ladder by risk. */
  onDecision(evt) {
    const { req, verdict } = evt;
    if (verdict.decision !== 'BLOCK') return;
    const subject = `mcp:${req.mcpId}`;
    const th = this.deps.policyEngine.resolvePolicySet(this.deps.policyPackIds).thresholds.risk;
    const max = this.maxLadder();

    let level;
    if (verdict.risk >= th.critical) level = 6;
    else if (verdict.risk >= th.high) level = Math.min(4, max);
    else level = Math.min(2, max);
    if (verdict.containmentHint === 'L6-quarantine') level = 6;

    this.apply(subject, level, req, verdict);
  }

  /** Escalate on correlated anomalies (chain detected). */
  onAnomaly(evt) {
    if (!evt.chain) return;
    const subject = `mcp:${evt.mcpId}`;
    if (!subject || subject === 'mcp:undefined') return;
    this.apply(subject, Math.min(5, this.maxLadder()), { mcpId: evt.mcpId, toolId: evt.toolId, tenantId: 'local' }, { risk: 80, confidence: 85, reasons: ['chain:' + evt.chain] }, 'anomaly-chain');
  }

  apply(subject, level, req, verdict, cause = 'block') {
    if (level > this.maxLadder()) level = this.maxLadder();
    const acts = [];
    const record = (name, detail) => {
      acts.push({ name, detail });
      this.actions.push({ ts: nowMs(), subject, name, detail, cause });
      if (this.actions.length > 500) this.actions.splice(0, this.actions.length - 500);
      this.storage.audit({ kind: 'response', subject, action: name, actor: 'hachiman:runtime', detail: { cause, level } });
    };

    if (level >= 3) {
      trust.restrict(this.storage, subject, `response:L3:${cause}`);
      record('restrict-capability', { level: 3 });
    }
    if (level >= 4) {
      // Revoke only grants scoped to the OFFENDING MCP (or wildcard grants).
      // Never revoke a victim agent's grants for benign MCPs (collateral lockout).
      const all = req?.agentId ? this.storage.q.grantActive.all(req.agentId) : [];
      const offending = all.filter((g) => g.resource === req?.mcpId || g.resource === '*');
      for (const g of offending.slice(0, 3)) this.deps.authz.revoke(g.id, 'hachiman:response', cause);
      record('revoke-permission', { level: 4, revoked: offending.length });
    }
    if (level >= 6) {
      this.quarantine(subject, `risk=${verdict.risk} confidence=${verdict.confidence} cause=${cause}`, verdict);
      record('quarantine-mcp', { level: 6, reason: cause });
      this._escalateIncident(subject, req, verdict);
    }
    this.bus.publish('gateway', { type: 'responded', subject, acts, ts: nowMs() }, { shedClass: 1 });
    return acts;
  }

  quarantine(subject, reason, verdict) {
    this.storage.q.quarUp.run(subject, reason, nowMs(), 'hachiman:response', JSON.stringify({ risk: verdict?.risk, confidence: verdict?.confidence }));
    trust.quarantine(this.storage, subject, 'response-engine');
    this.bus.publish('quarantine', { subject, reason, ts: nowMs() }, { shedClass: 1 });
  }

  release(subject, operatorId, { rescanPassed } = {}) {
    const q = this.storage.q.quarGet.get(subject);
    if (!q) return { error: 'not quarantined' };
    this.storage.q.quarDel.run(subject);
    // Recovery: lift QUARANTINED to a conservative RESTRICTED (operator can re-allow → TRUSTED).
    try { trust.releaseFromQuarantine(this.storage, subject, `released-by:${operatorId}`); } catch {}
    this.storage.audit({ kind: 'quarantine-release', subject, actor: operatorId, detail: { rescanPassed: !!rescanPassed, durationMs: nowMs() - q.enteredAt } });
    this.bus.publish('quarantine', { subject, released: true, by: operatorId, ts: nowMs() }, { shedClass: 2 });
    return { ok: true };
  }

  _escalateIncident(subject, req, verdict) {
    // append containment timeline to the newest open incident for this subject;
    // if no incident exists yet (e.g. direct evaluation, no gateway), create one.
    const incs = this.storage.q.incList.all(5);
    const open = incs.find((i) => i.status === 'open');
    const sev = verdict?.risk >= 90 ? 'critical' : verdict?.risk >= 75 ? 'high' : 'medium';
    const entry = { ts: nowMs(), type: 'containment', detail: { action: 'quarantine', subject, risk: verdict?.risk, confidence: verdict?.confidence } };
    if (open) {
      let tl = []; try { tl = JSON.parse(open.timeline || '[]'); } catch {}
      tl.push(entry);
      this.storage.q.incUp.run(open.id, open.tenantId, sev, 'contained', open.triggerEvent, JSON.stringify(tl),
        JSON.stringify(['L6-quarantine']), open.reportId, open.createdAt, nowMs());
      return open.id;
    }
    const id = uuid();
    const trigger = { ts: nowMs(), tenantId: req?.tenantId || 'local', agentId: req?.agentId, sessionId: req?.sessionId,
      mcpId: req?.mcpId, toolId: req?.toolId, action: req?.action };
    this.storage.q.incUp.run(id, req?.tenantId || 'local', sev, 'contained', JSON.stringify(trigger),
      JSON.stringify([entry]), JSON.stringify(['L6-quarantine']), null, nowMs(), nowMs());
    this.storage.audit({ kind: 'incident-created', subject, actor: 'hachiman:response', decision: 'BLOCK', risk: verdict?.risk, detail: { trigger } });
    return id;
  }

  recent(n = 50) { return this.actions.slice(-n); }
}
