// engines/policy — first-party deterministic rule engine over normalized fields.
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';

export class PolicyEngine {
  constructor() { this.packs = new Map(); this.active = new Map(); }

  loadPackFromFile(path) {
    const body = JSON.parse(readFileSync(path, 'utf8'));
    this.loadPack(body);
    return body;
  }
  loadPack(body) {
    if (!body.id || body.version == null) throw new Error('policy: pack requires id+version');
    this.packs.set(packKey(body.id, body.version), body);
    const cur = this.active.get(body.id);
    if (!cur || body.version >= cur.version) this.active.set(body.id, body);
    return body;
  }
  getPack(id) { return this.active.get(id) || null; }
  packVersion(id) { const p = this.active.get(id); return p ? p.version : 0; }

  /** Merge multiple active packs (later wins on rule id conflict). */
  resolvePolicySet(packIds) {
    const merged = {
      id: packIds.join('+'), rules: [], thresholds: null, riskWeights: {},
      cache: {}, response: {}, classify: { inspectContent: false }, semantic: { enabled: true },
      versions: {},
    };
    const seen = new Set();
    for (const id of packIds) {
      const p = this.getPack(id);
      if (!p) continue;
      merged.versions[id] = p.version;
      merged.thresholds = merged.thresholds || p.thresholds;
      Object.assign(merged.riskWeights, p.riskWeights || {});
      Object.assign(merged.cache, p.cache || {});
      Object.assign(merged.response, p.response || {});
      if (p.classify?.inspectContent) merged.classify.inspectContent = true;
      if (p.semantic && p.semantic.enabled === false) merged.semantic.enabled = false;
      for (const r of p.rules || []) if (!seen.has(r.id)) { seen.add(r.id); merged.rules.push({ ...r, _pack: id }); }
    }
    merged.thresholds ||= { risk: { low: 25, medium: 55, high: 75, critical: 90 }, confidenceFloor: 80 };
    return merged;
  }

  /** Evaluate rules against a normalized request context. Returns matched flags + forced decisions.
   *  Fail-safe: when multiple rules decide, the STRICTEST wins (BLOCK > REVIEW > ALLOW). */
  evaluate(policySet, reqCtx) {
    const hits = [];
    const rank = { BLOCK: 3, REVIEW: 2, ALLOW: 1 };
    let forced = null, riskFloor = null, riskDelta = 0;
    const flags = {};
    for (const rule of policySet.rules) {
      if (!this._match(rule.when, reqCtx)) continue;
      hits.push({ ruleId: rule.id, pack: rule._pack });
      const then = rule.then || {};
      if (then.riskDelta) riskDelta += then.riskDelta;
      if (then.riskFloor != null) riskFloor = riskFloor == null ? then.riskFloor : Math.max(riskFloor, then.riskFloor);
      flags[rule.id] = true;
      if (then.decision) {
        const cand = { decision: then.decision, ruleId: rule.id, pack: rule._pack, reason: then.reason };
        if (!forced || (rank[then.decision] || 0) > (rank[forced.decision] || 0)) forced = cand;
      }
    }
    return { hits, forced, riskFloor, riskDelta, flags };
  }

  _match(when, ctx) {
    if (!when) return false;
    for (const [k, expect] of Object.entries(when)) {
      if (!matchPred(k, expect, ctx)) return false;
    }
    return true;
  }
}

function matchPred(key, expect, ctx) {
  switch (key) {
    case 'toolUnknown': return (!!ctx.toolUnknown) === !!expect;
    case 'destinationClass': return ctx.destinationClass === expect;
    case 'destinationKnown': return (!!ctx.destinationKnown) === !!expect;
    case 'dataClassIn': return Array.isArray(expect) && expect.includes(ctx.dataClass);
    case 'injectionIndicator': return (!!ctx.injectionIndicator) === !!expect;
    case 'action': return ctx.action === expect;
    case 'tool': return ctx.tool === expect;
    case 'mcp': return ctx.mcp === expect;
    case 'agent': return ctx.agent === expect;
    case 'paramHas': return ctx.paramHas?.includes(expect);
    case 'identityVerified': return (!!ctx.identityVerified) === !!expect;
    case 'anomaly': return (!!ctx.anomaly) === !!expect;
    case 'mode': return ctx.mode === expect;
    default: {
      const v = ctx[key];
      if (Array.isArray(expect)) return expect.includes(v);
      return v === expect;
    }
  }
}
function packKey(id, version) { return `${id}@${version}`; }

export function loadPolicyDir(engine, dir) {
  const files = readdirSync(dir).filter((f) => f.endsWith('.hachiman.json'));
  const loaded = [];
  for (const f of files) { loaded.push(engine.loadPackFromFile(join(dir, f))); }
  return loaded;
}
