// offense/engagement — Authorization & Rules of Engagement (doc-06 §4, §46).
// No offensive action runs without a loaded, valid engagement. Violations throw
// EngagementViolation and are audited. This is the offensive fail-closed gate.
import { readFileSync } from 'node:fs';
import { uuid } from '../../core/src/utils.js';

export class EngagementViolation extends Error {
  constructor(rule, detail) { super(`ENGAGEMENT VIOLATION [${rule}]: ${detail}`); this.rule = rule; this.detail = detail; }
}

const DEFAULTS = {
  environment: 'local-lab',
  scope: { allowed_tools: ['*'], denied_tools: [] },
  rules: {
    destructive_testing: false,
    data_exfiltration: 'prohibited', // 'prohibited' | 'sink-only' (local canary sink only, never real external)
    persistence: 'prohibited',
    max_requests: 500,
    max_duration_ms: 120_000,
    max_concurrency: 2,
  },
};

export function loadEngagement(fileOrObj) {
  const raw = typeof fileOrObj === 'string' ? JSON.parse(readFileSync(fileOrObj, 'utf8')) : structuredClone(fileOrObj);
  const e = raw.engagement || raw;
  if (!e.target) throw new EngagementViolation('target', 'engagement.target is required');
  if (!e.conn || (!e.conn.url && !e.conn.fixture && !e.conn.command)) throw new EngagementViolation('conn', 'engagement.conn {url|fixture|command} is required');
  if (!e.authorized_by || String(e.authorized_by).trim() === '') throw new EngagementViolation('authorization', 'engagement.authorized_by is required (no authorization → no testing)');

  const eng = {
    id: e.id || 'eng-' + uuid(),
    target: e.target,
    environment: e.environment || DEFAULTS.environment,
    conn: e.conn,
    scope: { ...DEFAULTS.scope, ...(e.scope || {}) },
    rules: { ...DEFAULTS.rules, ...(e.rules || {}) },
    authorized_by: String(e.authorized_by).trim(),
    startedAt: null,
    counters: { requests: 0, ms: 0 },
    violations: [],
  };

  // §46 hard defaults: never overridable by an engagement file
  if (eng.rules.persistence !== 'prohibited') throw new EngagementViolation('persistence', 'persistence is always prohibited');
  if (!['prohibited', 'sink-only'].includes(eng.rules.data_exfiltration)) throw new EngagementViolation('data_exfiltration', "data_exfiltration must be 'prohibited' or 'sink-only'");
  if (eng.rules.destructive_testing === true && eng.environment === 'production') throw new EngagementViolation('destructive', 'destructive testing against production is never permitted');
  return eng;
}

export const engagementApi = {
  /** Tool-in-scope gate. Throws EngagementViolation when outside scope. */
  assertTool(eng, tool) {
    const denied = eng.scope.denied_tools || [];
    if (denied.includes(tool) || denied.includes('*')) throw record(eng, 'scope', `tool ${tool} is denied by scope`);
    const allowed = eng.scope.allowed_tools || [];
    if (allowed.includes('*') || allowed.includes(tool)) return true;
    throw record(eng, 'scope', `tool ${tool} is not in allowed scope`);
  },
  /** Request budget. Throws when exhausted. */
  spendRequest(eng) {
    eng.counters.requests++;
    if (eng.counters.requests > eng.rules.max_requests) throw record(eng, 'request-budget', `request budget ${eng.rules.max_requests} exhausted`);
    return eng.counters.requests;
  },
  /** Duration budget. Throws when elapsed. */
  chapter(eng, ms) {
    eng.counters.ms += ms;
    if (eng.startedAt && Date.now() - eng.startedAt > eng.rules.max_duration_ms) throw record(eng, 'duration-budget', `duration budget ${eng.rules.max_duration_ms}ms exceeded`);
  },
  /** Exfil demonstrations allowed only against the canary sink, and only when ROE permits. */
  canExfil(eng) { return eng.rules.data_exfiltration === 'sink-only'; },
  snapshot(eng) {
    return { id: eng.id, target: eng.target, environment: eng.environment, authorized_by: eng.authorized_by, counters: { ...eng.counters }, limits: { ...eng.rules }, violations: eng.violations.length };
  },
};

function record(eng, rule, detail) {
  const v = new EngagementViolation(rule, detail);
  eng.violations.push({ rule, detail, ts: Date.now() });
  return v;
}
