// engines/authorization — grants as hard gate. Trust never substitutes for a grant.
import { uuid, nowMs } from '../../core/src/utils.js';

export class AuthorizationEngine {
  constructor(storage) { this.storage = storage; this.windows = new Map(); }

  /** Issue a grant. Only operators with admin.grant may call (enforced by caller). */
  grant({ subject, capability, resource = '*', constraints = {}, grantedBy, ttlMs = null, maxUses = null}) {
    if (!grantedBy) throw new Error('authorization: grantedBy required (no self-grant)');
    const id = uuid();
    this.storage.q.grantIns.run(id, subject, capability, resource,
      JSON.stringify({ ...constraints, ttlMs, maxUses, issuedAt: nowMs(), uses: 0 }), grantedBy, nowMs());
    return id;
  }
  revoke(grantId, by, reason) { this.storage.q.grantRevoke.run(nowMs(), `${by}:${reason}`, grantId); }

  /**
   * Evaluate a capability request against active grants.
   * Returns {decision: ALLOW|DENY|CONDITIONAL, grant, constraints, reason}.
   */
  evaluate(subject, capability, resource = '*', params = {}) {
    const rows = this.storage.q.grantActive.all(subject);
    if (!rows.length) return { decision: 'DENY', grant: null, reason: 'no grants for subject' };
    for (const row of rows) {
      if (!matchCapability(row.capability, capability)) continue;
      if (!matchResource(row.resource, resource)) continue;
      const c = safeParse(row.constraints) || {};
      // TTL
      if (c.ttlMs && nowMs() > c.issuedAt + c.ttlMs) continue;
      // maxUses
      if (c.maxUses != null && (c.uses || 0) >= c.maxUses) continue;
      // param rules
      const verdict = evalParamRules(c.paramRules, params);
      if (verdict === 'DENY') continue;
      // rate limit
      if (c.rate && !this._rateOk(row.id, c.rate)) continue;
      // bump usage
      c.uses = (c.uses || 0) + 1;
      this.storage.q.grantUpd.run(JSON.stringify(c), row.id);
      return { decision: verdict === 'CONDITIONAL' ? 'CONDITIONAL' : 'ALLOW', grant: { id: row.id, capability: row.capability, resource: row.resource }, constraints: c, reason: 'grant matched' };
    }
    return { decision: 'DENY', grant: null, reason: 'no grant matched capability/resource/constraints' };
  }

  _rateOk(key, rate) {
    const now = nowMs(); const win = rate.windowMs || 60_000;
    let w = this.windows.get(key);
    if (!w) { w = { count: 0, start: now }; this.windows.set(key, w); }
    if (now - w.start > win) { w.count = 0; w.start = now; }
    w.count++;
    return w.count <= (rate.limit || 1);
  }

  activeFor(subject) { return this.storage.q.grantActive.all(subject); }
}

export function matchCapability(granted, requested) {
  if (granted === '*' || granted === requested) return true;
  if (granted.endsWith('.*')) return requested.startsWith(granted.slice(0, -1));
  return false;
}
export function matchResource(granted, requested) {
  if (granted === '*') return true;
  if (granted === requested) return true;
  if (granted.endsWith('*')) return requested.startsWith(granted.slice(0, -1));
  return false;
}

/** Evaluate param rules. Return ALLOW / CONDITIONAL / DENY. */
function evalParamRules(rules, params) {
  if (!rules || !rules.length) return 'ALLOW';
  let conditional = false;
  for (const rule of rules) {
    const val = getPath(params, rule.path);
    const match = applyCond(val, rule); // does the predicate fire?
    if (match) {
      if (rule.action === 'deny') return 'DENY';
      if (rule.action === 'review' || rule.action === 'require-review') conditional = true;
    }
  }
  return conditional ? 'CONDITIONAL' : 'ALLOW';
}
function applyCond(val, rule) {
  switch (rule.op) {
    case 'exists': return val !== undefined;
    case 'not-exists': return val === undefined;
    case 'eq': return val === rule.value;
    case 'neq': return val !== rule.value;
    case 'in': return Array.isArray(rule.value) && rule.value.includes(val);
    case 'match': return typeof val === 'string' && new RegExp(rule.value).test(val);
    case 'max-length': return typeof val === 'string' ? val.length <= rule.value : true;
    case 'lt': return Number(val) < rule.value;
    case 'gt': return Number(val) > rule.value;
    default: return true;
  }
}
function getPath(obj, path) {
  if (!path) return obj;
  let cur = obj;
  for (const seg of path.split('.')) {
    if (cur == null) return undefined;
    cur = cur[seg];
  }
  return cur;
}
function safeParse(s) { if (s == null) return null; try { return JSON.parse(s); } catch { return null; } }
