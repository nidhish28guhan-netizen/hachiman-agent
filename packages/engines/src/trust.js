// engines/trust — dynamic trust state machine + premium scoring.
import { clamp, nowMs, ewma } from '../../core/src/utils.js';

export const TRUST_STATES = ['UNKNOWN', 'UNVERIFIED', 'ASSESSED', 'RESTRICTED', 'TRUSTED', 'HIGH_RISK', 'QUARANTINED'];

export function getTrust(storage, subjectId) {
  const row = storage.q.trustGet.get(subjectId);
  if (!row) return { subjectId, state: 'UNKNOWN', score: 50, history: [], updatedAt: 0 };
  let history = [];
  try { history = JSON.parse(row.history || '[]'); } catch {}
  return { subjectId, state: row.state, score: row.score, lastAssessmentRef: row.lastAssessmentRef, updatedAt: row.updatedAt, history };
}

function setTrust(storage, subjectId, state, score, cause, lastAssessmentRef) {
  const cur = getTrust(storage, subjectId);
  const history = cur.history.slice(-49);
  history.push({ ts: nowMs(), score: Math.round(score), cause });
  storage.q.trustUp.run(subjectId, state, Math.round(score), lastAssessmentRef ?? cur.lastAssessmentRef ?? null, nowMs(), JSON.stringify(history));
  return getTrust(storage, subjectId);
}

/** Register a new MCP/agent subject at UNKNOWN. */
export function registerSubject(storage, subjectId) {
  if (!storage.q.trustGet.get(subjectId)) setTrust(storage, subjectId, 'UNKNOWN', 50, 'registered');
}

/** Anchor trust from a scan result (WF-02: UNVERIFIED→ASSESSED). */
export function fromScan(storage, subjectId, safetyScore, scanId) {
  const anchored = clamp(Math.round(safetyScore.overall / 2) + 20, 10, 90);
  const state = safetyScore.overall >= 70 ? 'ASSESSED' : 'UNVERIFIED';
  return setTrust(storage, subjectId, state, anchored, `scan:${scanId}`, scanId);
}

/** Operator explicit consent: UNKNOWN/UNVERIFIED/ASSESSED/RESTRICTED → TRUSTED.
 *  The operator is the human authority; explicit consent anchors trust even pre-scan
 *  (the gateway's grant+policy gates still decide every request — trust never substitutes).
 *  QUARANTINED/HIGH_RISK subjects must go through recovery first (containment is sticky). */
export function operatorAllow(storage, subjectId, operatorId) {
  const t = getTrust(storage, subjectId);
  if (['QUARANTINED', 'HIGH_RISK'].includes(t.state)) return t; // recovery path required
  return setTrust(storage, subjectId, 'TRUSTED', Math.max(75, t.score), `operator-allow:${operatorId}`);
}

/** Policy capability cap. */
export function restrict(storage, subjectId, reason) {
  const t = getTrust(storage, subjectId);
  if (t.state === 'QUARANTINED') return t;
  return setTrust(storage, subjectId, 'RESTRICTED', Math.min(t.score, 60), reason);
}

/** Violation penalty (runtime): heavy penalty, floor at 5; escalate state on severity. */
export function violation(storage, subjectId, { critical = false } = {}, cause = 'violation') {
  const t = getTrust(storage, subjectId);
  const penalty = critical ? 55 : 30;
  const score = clamp(t.score - penalty, 5, 100);
  const state = critical || score < 30 ? 'HIGH_RISK' : (t.state === 'TRUSTED' ? 'RESTRICTED' : t.state);
  return setTrust(storage, subjectId, state, score, cause);
}

/** Clean-action reward: EMA toward 90. */
export function reward(storage, subjectId) {
  const t = getTrust(storage, subjectId);
  if (['QUARANTINED', 'HIGH_RISK'].includes(t.state)) return t;
  const score = clamp(ewma(t.score, 90, 0.02), 0, 100);
  return setTrust(storage, subjectId, t.state, score, 'stable-operation');
}

/** Containment: QUARANTINED (side-state). */
export function quarantine(storage, subjectId, cause) {
  const t = getTrust(storage, subjectId);
  return setTrust(storage, subjectId, 'QUARANTINED', clamp(Math.min(t.score, 20), 0, 100), cause);
}

/** Containment lift: QUARANTINED → RESTRICTED (conservative; operator re-allow → TRUSTED). */
export function releaseFromQuarantine(storage, subjectId, cause) {
  const t = getTrust(storage, subjectId);
  if (t.state !== 'QUARANTINED') return t;
  return setTrust(storage, subjectId, 'RESTRICTED', Math.max(40, Math.min(t.score, 50)), cause);
}

/** Post-remediation: rescan allowed recovery. */
export function rescanRecovery(storage, subjectId, safetyScore, scanId) {
  if (safetyScore.overall >= 70) return fromScan(storage, subjectId, safetyScore, scanId);
  return setTrust(storage, subjectId, 'RESTRICTED', Math.min(50, safetyScore.overall / 2), `rescan:${scanId}`, scanId);
}
