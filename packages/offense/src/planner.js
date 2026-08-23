// offense/planner — Hacker Planning Engine (doc-06 §25).
// Dynamic plan in the exact doc shape; evidence-driven, deterministic next-action choice.
import { generateHypotheses } from './hypothesis.js';

export function initPlan(engagement, attackSurface) {
  const hypotheses = generateHypotheses(attackSurface, engagement);
  return {
    objective: `determine whether an authorized boundary can be crossed on ${engagement.target}`,
    scope: engagement.target,
    observations: [],
    hypotheses,
    tests: [],
    evidence: [],
    next_action: pickNext(hypotheses),
  };
}

export function recordObservation(plan, obs) {
  plan.observations.push({ ts: Date.now(), ...obs });
  plan.next_action = pickNext(plan.hypotheses);
  return plan;
}

export function recordTest(plan, test) { plan.tests.push({ ts: Date.now(), ...test }); return plan; }

export function recordEvidence(plan, ev) { plan.evidence.push({ ts: Date.now(), ...ev }); return plan; }

/** Cheapest untested hypothesis first (deterministic-first, doc-06 §34). */
function pickNext(hypotheses) {
  const open = hypotheses.filter((h) => h.status === 'PROPOSED' || h.status === 'NEEDS_MORE_EVIDENCE');
  if (open.length === 0) return 'consolidate: validate, chain, explain';
  const h = open[0];
  return `test hypothesis ${h.id}: ${h.title}`;
}

export function nextHypotheses(plan) {
  return plan.hypotheses.filter((h) => h.status === 'PROPOSED' || h.status === 'NEEDS_MORE_EVIDENCE');
}
