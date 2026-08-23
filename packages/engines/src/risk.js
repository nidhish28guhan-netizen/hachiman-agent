// engines/risk — weighted multi-factor risk model with evidence.
import { clamp } from '../../core/src/utils.js';
import { classRank } from './classifier.js';

const DATA_CLASS_RISK = { public: 5, internal: 30, confidential: 72, restricted: 96 };
const DEST_RISK = { internal: 5, 'external-known': 35, external: 75 };

/**
 * Compute per-factor risk and a weighted sum. Factors per architecture doc §13.
 * Each factor returns {score:0-100, evidence:[...]}.
 */
export function computeRisk(req, ctx) {
  const w = ctx.policy?.riskWeights || {};
  const factors = {};
  const evidence = [];
  const ev = (k, v, note) => { factors[k] = { score: v }; evidence.push({ factor: k, score: v, note }); };

  // 1 identity
  const idRisk = req.identity?.verified ? 8 : 62;
  ev('identity', idRisk, req.identity?.verified ? 'verified identity' : 'unverified/unknown identity');

  // 2 tool legitimacy (from registry risk meta)
  const toolMeta = ctx.toolMeta || {};
  let toolRisk = 20;
  let toolNote = 'known tool';
  if (!ctx.toolKnown) { toolRisk = 78; toolNote = 'tool not in registry'; }
  else {
    toolRisk = clamp(20 + (toolMeta.sideEffectRisk || 0) + (toolMeta.egressCapable ? 15 : 0) + (toolMeta.excessivePermissions ? 25 : 0));
    toolNote = `registered tool (sideEffect=${toolMeta.sideEffectRisk || 0}, egress=${!!toolMeta.egressCapable})`;
  }
  ev('tool', toolRisk, toolNote);

  // 3 permission / authorization posture
  let permRisk = 15;
  let permNote = 'explicit grant present';
  if (!ctx.grant) { permRisk = 85; permNote = 'no matching grant'; }
  else if (ctx.grantConditional) { permRisk = 45; permNote = 'conditional grant'; }
  ev('permission', permRisk, permNote);

  // 4 data sensitivity
  const dc = req.dataClass || 'internal';
  ev('data', DATA_CLASS_RISK[dc] ?? 40, `data_class=${dc}${req.classifyMatches?.length ? ' matches:' + req.classifyMatches.join(',') : ''}`);

  // 5 context / injection
  const injScore = req.injection?.hit ? 92 : Math.round((req.injection?.score || 0) * 70);
  ev('context', injScore, req.injection?.hit ? 'injection indicator HIT' : (injScore ? `injection signals ${injScore}` : 'no injection signals'));

  // 6 behavioral anomaly
  const beh = ctx.behavior || {};
  const behScore = clamp(Math.round((beh.anomalyScore || 0) * 100));
  ev('behavior', behScore, `anomalyScore=${beh.anomalyScore || 0}`);

  // 7 destination
  const d = req.destination;
  let dRisk, dNote;
  if (!d || d.kind === 'internal') { dRisk = DEST_RISK.internal; dNote = 'internal/no egress'; }
  else if (d.kind === 'external' && d.known) { dRisk = DEST_RISK['external-known']; dNote = `external known host ${d.host}`; }
  else { dRisk = DEST_RISK.external; dNote = `external unknown host ${d.host}`; }
  ev('destination', dRisk, dNote);

  // 8 action impact
  const impact = impactScore(req);
  ev('impact', impact, `action=${req.action} tool=${req.toolId || '?'}`);

  // weighted sum
  let risk = 0;
  for (const [k, f] of Object.entries(factors)) risk += (w[k] ?? 0.1) * f.score;
  // apply policy floors/deltas collected during policy matching.
  // Order matters: deltas adjust, but a forced floor always dominates (strictness wins).
  if (ctx.riskDelta) risk += ctx.riskDelta;
  if (ctx.riskFloor != null) risk = Math.max(risk, ctx.riskFloor);

  // Trust gate (input to RISK, never a substitute for authorization):
  // unverified / low-trust subjects raise the risk floor so they can't ride a
  // cheap ALLOW. Distinct from the authz hard gate.
  const ts = ctx.trustState;
  if (ts === 'QUARANTINED') risk = Math.max(risk, 100);
  else if (ts === 'HIGH_RISK') risk = Math.max(risk, 80);
  else if (ts === 'UNVERIFIED') risk = Math.max(risk, 70);
  else if (ts === 'UNKNOWN') risk = Math.max(risk, 55);
  else if (ts === 'RESTRICTED') risk = Math.max(risk, 50);
  else if (ts === 'ASSESSED') risk = Math.max(risk, 30);
  // TRUSTED: no floor beyond computed risk.
  risk = clamp(Math.round(risk), 0, 100);

  return { risk, factors, evidence };
}

/** Infer action impact from action + tool semantics. */
export function impactScore(req) {
  const t = (req.toolId || '').toLowerCase();
  const a = (req.action || '').toLowerCase();
  const s = t + ' ' + a;
  if (/(delete|drop|truncate|rm|exec|shell|run_command|system)/.test(s)) return 85;
  if (/(write|create|update|insert|send|post|upload|transfer|http|fetch|request)/.test(s)) return 60;
  if (/(read|get|list|query|view|search|describe)/.test(s)) return 25;
  return 40;
}
