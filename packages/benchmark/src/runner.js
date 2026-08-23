// benchmark/runner — replay scenarios through the live decision pipeline.
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { evaluateRequest } from '../../engines/src/decision.js';
import { nowMs, uuid } from '../../core/src/utils.js';
import * as trust from '../../engines/src/trust.js';

export function loadCorpus(dir) {
  const out = [];
  for (const f of readdirSync(dir).filter((x) => x.endsWith('.json')).sort()) {
    const data = JSON.parse(readFileSync(join(dir, f), 'utf8'));
    for (const sc of Array.isArray(data) ? data : [data]) out.push({ ...sc, _file: f });
  }
  return out;
}

/** Expand each scenario into `variants` parameterized replays. */
export function expandScenarios(scenarios, variants = 3) {
  const out = [];
  for (const sc of scenarios) {
    for (let v = 0; v < variants; v++) {
      out.push({ ...sc, _variant: v, sessionId: `${sc.id}-v${v}-` + uuid().slice(0, 8) });
    }
  }
  return out;
}

function buildDeps(node) {
  const d = node.deps;
  return {
    storage: d.storage, bus: d.bus, identity: d.identity, authz: d.authz,
    policy: d.policyEngine.resolvePolicySet(d.policyPackIds), policyEngine: d.policyEngine,
    toolLookup: (mcpId, tool) => d.storage.q.toolGet.get(mcpId, tool || ''),
    monitor: d.monitor, srg: d.srg, semantic: d.semantic, metrics: d.metrics,
    canary: d.canary, config: d.config, cacheEnabled: false, // corpus: no caching (fresh evidence per scenario)
  };
}

function applySetup(node, setup = {}) {
  for (const g of setup.grants || []) {
    node.storage.q.entUpsert.run(g.subject, g.subject.split(':')[0], g.subject.split(':')[1] || g.subject, null, '{}', nowMs(), nowMs());
    node.authz.grant({ ...g, grantedBy: 'operator:test' });
  }
  for (const [subject, t] of Object.entries(setup.trust || {})) {
    trust.registerSubject(node.storage, subject);
    node.storage.q.trustUp.run(subject, t.state, t.score, t.lastAssessmentRef || null, nowMs(), JSON.stringify([]));
  }
  for (const t of setup.tools || []) {
    node.storage.q.toolUp.run(`${t.mcpId}:${t.name}`, t.mcpId, t.name, t.description || '',
      JSON.stringify(t.inputSchema || {}), JSON.stringify(t.riskMeta || {}), t.toolVersion || '1', nowMs());
  }
  if (setup.quarantine) {
    for (const subject of [].concat(setup.quarantine)) {
      node.storage.q.quarUp.run(subject, 'setup', nowMs(), 'operator:test', '{}');
    }
  }
}

/** Run one scenario. Returns {scenarioId, results:[{req, verdict, pass, why}]}. */
export async function runScenario(node, scenario) {
  const deps = buildDeps(node);
  applySetup(node, scenario.setup);
  const results = [];
  for (let i = 0; i < (scenario.requests || []).length; i++) {
    const r = scenario.requests[i];
    const req = {
      id: uuid(), ts: nowMs(), tenantId: 'test',
      agentId: r.agentId || 'agent:anon', sessionId: scenario.sessionId || 's-' + i,
      mcpId: r.mcpId || null, toolId: r.toolId || null, action: r.action || 'tools/call',
      params: r.params || {}, authz: r.authz !== false,
      dataClassOverride: r.dataClassOverride || undefined,
      fetchedContent: r.fetchedContent,
    };
    const verdict = await evaluateRequest(deps, req);
    let pass = true; const why = [];
    const exp = r.expect || {};
    if (exp.decision && verdict.decision !== exp.decision) { pass = false; why.push(`decision ${verdict.decision} != ${exp.decision}`); }
    if (exp.minRisk != null && verdict.risk < exp.minRisk) { pass = false; why.push(`risk ${verdict.risk} < ${exp.minRisk}`); }
    if (exp.minConfidence != null && verdict.confidence < exp.minConfidence) { pass = false; why.push(`conf ${verdict.confidence} < ${exp.minConfidence}`); }
    if (exp.reasonMatch && !verdict.reasons.some((x) => x.includes(exp.reasonMatch))) { pass = false; why.push(`no reason ~${exp.reasonMatch}`); }
    if (exp.riskBand) { const [lo, hi] = exp.riskBand; if (verdict.risk < lo || verdict.risk > hi) { pass = false; why.push(`risk ${verdict.risk} outside [${lo},${hi}]`); } }
    if (exp.confBand) { const [lo, hi] = exp.confBand; if (verdict.confidence < lo || verdict.confidence > hi) { pass = false; why.push(`conf ${verdict.confidence} outside [${lo},${hi}]`); } }
    if (exp.reasonIn) { for (const needle of exp.reasonIn) if (!verdict.reasons.some((x) => x.includes(needle))) { pass = false; why.push(`missing reason ~${needle}`); } }
    if (exp.path && verdict.path !== exp.path) { pass = false; why.push(`path ${verdict.path} != ${exp.path}`); }
    results.push({ req, verdict, pass, why: why.join('; ') });
  }
  return { scenarioId: scenario.id, category: scenario.category, label: scenario.label || (scenario.expect?.attack ? 'attack' : 'benign'), results };
}

/** Aggregate metrics over run results (doc 04 §3). */
export function aggregate(runs) {
  let tp = 0, fn = 0, fp = 0, tn = 0;
  const perCategory = {};
  const failures = [];
  for (const run of runs) {
    const attack = run.label === 'attack';
    const allPass = run.results.every((r) => r.pass);
    perCategory[run.category] ||= { total: 0, pass: 0 };
    perCategory[run.category].total++;
    if (allPass) perCategory[run.category].pass++;
    if (attack) { if (allPass) tp++; else { fn++; failures.push(run); } }
    else { if (allPass) tn++; else { fp++; failures.push(run); } }
  }
  const precision = tp + fp ? tp / (tp + fp) : 1;
  const recall = tp + fn ? tp / (tp + fn) : 1;
  return {
    scenarios: runs.length, attacks: tp + fn, benign: tn + fp,
    detected: tp, missed: fn, falsePositives: fp,
    detectionPct: Math.round(recall * 1000) / 10,
    fpPct: Math.round((fp / Math.max(1, tn + fp)) * 1000) / 10,
    precision: Math.round(precision * 1000) / 1000, recall: Math.round(recall * 1000) / 1000,
    f1: Math.round((2 * precision * recall / Math.max(0.0001, precision + recall)) * 1000) / 1000,
    perCategory, failures: failures.slice(0, 10).map((f) => ({ id: f.scenarioId, why: f.results.map((r) => r.why).filter(Boolean) })),
  };
}
