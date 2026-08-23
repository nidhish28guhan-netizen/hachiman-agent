// engines/decision — the central security decision pipeline (WF-05/WF-06).
// Order is fixed (2.0 §18): IDENTITY → AUTHORIZATION (hard gate) → LEGITIMACY →
// CLASSIFY → INJECTION → POLICY → CACHE → RISK → DECIDE → (SEMANTIC) → AUDIT.
import { nowMs, uuid, clamp, shapeHash, stableStringify, sha256hex } from '../../core/src/utils.js';
import { classify, detectDestination } from './classifier.js';
import { detectInjection } from './injection.js';
import { computeRisk } from './risk.js';
import * as trust from './trust.js';
import { validateSemanticOutput, buildCompactContext } from './semantic.js';
import { universalizeRequest, capabilityOf } from '../../planes/src/resource.js';

/**
 * deps: { storage, bus, policy:{policySet}, authz, toolLookup(mcpId,name)->row|null,
 *         monitor?, srg?, semantic?, canary?, metrics?, config? }
 */
export async function evaluateRequest(deps, req) {
  const t0 = Date.now();
  const policySet = deps.policy;
  const th = policySet.thresholds;
  const reasons = [], policyRefs = [], evidence = [];
  const emit = (f, note) => { reasons.push(f); if (note) evidence.push({ factor: f, note }); };
  const config = deps.config || {};

  req = { id: req.id || uuid(), ts: req.ts || nowMs(), ...req };

  // ---- 0) UNIVERSAL INPUT (2.0 seam) — legacy requests pass through untouched ----
  try {
    req = universalizeRequest(req);
  } catch (e) {
    // Fail-closed: a malformed resource descriptor never reaches the engines.
    return finalize(deps, req, {
      decision: 'BLOCK', risk: 60, confidence: 100, trust: null, path: 'fast',
      reasons: ['resource:invalid:' + String(e.message).slice(0, 48)],
      policyRefs: [], evidence: [{ factor: 'resource', note: String(e.message).slice(0, 120) }],
      latencyMs: Date.now() - t0,
    }, {});
  }
  const mcpSubject = req.mcpId ? `mcp:${req.mcpId}` : null;
  const gateSubject = req.resource?.key || mcpSubject;   // 2.0: non-MCP resources carry their own subject

  // ---- 1) IDENTITY ----
  let identity = { verified: false, subjectId: null, reason: 'no-check' };
  if (deps.identity && req.authzContext?.sessionToken) {
    identity = deps.identity.resolve(req.authzContext.sessionToken);
  } else if (req.identity) {
    identity = req.identity; // corpus/test pre-supplied identity
  }
  if (!identity.verified) emit('identity:unverified');
  // The VERIFIED subject drives authorization; an unverified request falls back to the
  // claimed agent id (which then fails the authz gate unless explicitly granted).
  const subjectId = (identity.verified && identity.subjectId) || req.agentId || req.mcpId || 'unknown';
  if (identity.verified && identity.subjectId && req.agentId !== identity.subjectId) {
    req = { ...req, agentId: identity.subjectId }; // audit/monitor attribute to the verified subject
  }

  // ---- 1b) QUARANTINE override (containment is sticky) ----
  if (gateSubject) {
    const q = deps.storage.q.quarGet.get(gateSubject);
    if (q) return finalize(deps, req, {
      decision: 'BLOCK', risk: 100, confidence: 100, trust: trustScoreOf(deps, gateSubject),
      path: 'fast', reasons: ['quarantine:active'], policyRefs: [], evidence: [{ factor: 'quarantine', note: q.reason }],
      latencyMs: Date.now() - t0, containmentHint: 'already-quarantined',
    }, { subjectId: gateSubject });
  }

  // ---- 2) AUTHORIZATION — hard gate ----
  let authz = { decision: 'ALLOW', grant: null, reason: 'authz disabled (test harness)' };
  if (deps.authz && req.authz !== false) {
    authz = deps.authz.evaluate(subjectId, capabilityOf(req), req.gateResource ?? req.mcpId ?? '*', req.params || {});
    if (authz.decision === 'DENY') {
      const sensitive = classifyMetaSensitivity(req);
      const decision = sensitive ? 'BLOCK' : 'REVIEW';
      emit('authorization:denied:' + authz.reason);
      return finalize(deps, req, {
        decision, risk: sensitive ? 70 : 45, confidence: 95, trust: trustScoreOf(deps, gateSubject),
        path: 'fast', reasons, policyRefs: [], evidence: [{ factor: 'authorization', note: authz.reason }],
        latencyMs: Date.now() - t0, authzDenied: true,
      }, { subjectId: gateSubject });
    }
  }

  // ---- 3) TOOL LEGITIMACY (registry, or adapter-supplied metadata for 2.0 planes) ----
  let toolRow = null, toolMeta = {}, knownViaAdapter = false;
  if (deps.toolLookup && req.mcpId != null) toolRow = deps.toolLookup(req.mcpId, req.toolId);
  if (toolRow) try { toolMeta = JSON.parse(toolRow.riskMeta || '{}'); } catch {}
  else if (deps.resourceMeta && req.resource) {
    try { const m = deps.resourceMeta(req.resource); if (m && typeof m === 'object') { toolMeta = m; knownViaAdapter = true; } } catch {}
  }
  const toolKnown = !!toolRow || knownViaAdapter;
  const schemaViolation = toolRow ? checkSchema(toolRow, req.params) : null;
  if (!toolKnown) emit('tool:unknown');
  if (schemaViolation) emit('tool:schema-violation:' + schemaViolation);

  // ---- 4/5) DATA CLASSIFICATION + DESTINATION ----
  const cls = classify(req, { inspectContent: !!policySet.classify?.inspectContent });
  req = { ...req, dataClass: cls.dataClass, classifyMatches: cls.matches };
  const destination = req.destination || detectDestination(req.params, {
    knownExternalHosts: config.knownExternalHosts || [], internalHosts: config.internalHosts || [],
  });
  req = { ...req, destination: destination || { kind: 'internal', known: true, class: 'internal' } };

  // ---- 6) INJECTION ----
  const injection = detectInjection(req, { canary: deps.canary || null });
  req = { ...req, injection };
  if (injection.hit) emit('injection:' + injection.indicators.map((i) => i.type).join('+'));

  // ---- 7) POLICY ----
  const reqCtx = {
    toolUnknown: !toolKnown,
    destinationClass: req.destination.class, destinationKnown: !!req.destination.known,
    dataClass: req.dataClass, injectionIndicator: injection.hit,
    action: req.action, tool: req.toolId, mcp: req.mcpId, agent: req.agentId,
    identityVerified: identity.verified, mode: req.ctx?.mode || 'SENTINEL',
    anomaly: (req.behavior?.anomalyScore || 0) > 0.5,
    // 2.0 policy predicates (additive; legacy requests carry nulls and match nothing new)
    resourceType: req.resource?.type || null, resourceKey: req.resource?.key || null,
    adapterId: req.ctx?.adapterId || null, subjectType: subjectId.includes(':') ? subjectId.split(':')[0] : null,
  };
  const pol = deps.policyEngine.evaluate(policySet, reqCtx);
  for (const h of pol.hits) policyRefs.push(`${h.pack}:${deps.policyEngine.packVersion(h.pack)}:${h.ruleId}`);

  // ---- 8) DECISION CACHE ----
  const trustRec = gateSubject ? trust.getTrust(deps.storage, gateSubject) : { state: 'UNKNOWN', score: 50 };
  const fingerprint = decisionFingerprint({
    policyVer: stableStringify(policySet.versions), authzState: authz.grant ? 'granted' : 'open',
    tool: req.toolId, toolVer: toolRow?.toolVersion || '0', action: req.action,
    paramHash: shapeHash(req.params || {}), dataClass: req.dataClass,
    dest: req.destination.class + ':' + (req.destination.known ? 'k' : 'u'),
    trustState: trustRec.state, mode: req.ctx?.mode || 'SENTINEL',
    // Content-signal binding: injection + classification outcomes MUST ride the fingerprint,
    // otherwise a cached ALLOW for a benign shape replays over an injected/sensitive payload.
    injHit: req.injection?.hit ? 1 : 0,
    classifySig: (req.classifyMatches || []).length ? sha256hex(stableStringify([...req.classifyMatches].sort())).slice(0, 8) : 'none',
    // 2.0: resource-scoped cache keys (conditional — legacy fingerprints untouched)
    ...(req.resource ? { res: req.resource.key } : {}),
  });
  if (deps.cacheEnabled !== false) {
    const hit = cacheLookup(deps.storage, fingerprint);
    if (hit) {
      return finalize(deps, req, { ...hit.verdict, path: 'cached', latencyMs: Date.now() - t0, cacheFingerprint: fingerprint },
        { subjectId: gateSubject, cacheHit: true });
    }
  }

  // ---- 9) RISK ----
  const riskCtx = {
    policy: policySet, toolMeta, toolKnown, grant: authz.grant, grantConditional: authz.decision === 'CONDITIONAL',
    behavior: req.behavior || (deps.monitor ? deps.monitor.getBehavior(subjectId, req.toolId) : {}),
    riskFloor: pol.riskFloor, riskDelta: pol.riskDelta,
    trustState: trustRec.state, trustScore: trustRec.score,
  };
  let { risk, evidence: riskEv } = computeRisk(req, riskCtx);
  evidence.push(...riskEv);
  if (schemaViolation) risk = riskAdj(risk, +30); // param smuggling / schema bypass is a real flaw

  // ---- 10) CONFIDENCE (evidence sufficiency) ----
  let confidence = 95;
  if (!toolKnown) confidence -= 12;
  if (injection.indicators.length && !injection.hit) confidence -= 15; // ambiguous
  if (req.destination.class === 'external' && !req.destination.known) confidence -= 8;
  if (risk >= th.risk.medium && risk < th.risk.high) confidence -= 8; // mid-band uncertainty
  confidence = clamp(Math.round(confidence), 0, 100);

  // ---- 11) DECIDE TABLE ----
  let decision = 'ALLOW';
  if (pol.forced && pol.forced.decision) {
    decision = pol.forced.decision;
    emit('policy:' + pol.forced.ruleId);
    confidence = Math.max(confidence, 92);
  } else if (risk >= th.risk.critical) {
    decision = 'BLOCK';
  } else if (risk >= th.risk.high) {
    decision = confidence >= th.confidenceFloor ? 'BLOCK' : 'REVIEW';
  } else if (risk >= th.risk.medium || confidence < th.confidenceFloor) {
    decision = 'REVIEW';
  } else if (risk < th.risk.low && confidence >= th.confidenceFloor) {
    decision = 'ALLOW';
  } else {
    decision = 'REVIEW';
  }
  if (authz.decision === 'CONDITIONAL') { decision = decision === 'ALLOW' ? 'REVIEW' : decision; emit('authz:conditional'); }
  if (schemaViolation) { decision = 'BLOCK'; } // param smuggling / schema bypass is an attack attempt

  // ---- FAIL-SAFE: computed risk / trust can only TIGHTEN a decision, never loosen it ----
  if (decision === 'ALLOW' && risk >= th.risk.high) { decision = 'REVIEW'; emit('failsafe:risk-high-over-allow'); }
  if (decision !== 'BLOCK' && risk >= th.risk.critical) { decision = 'BLOCK'; emit('failsafe:risk-critical'); }
  if (decision === 'ALLOW' && ['UNKNOWN', 'UNVERIFIED', 'HIGH_RISK', 'QUARANTINED'].includes(trustRec.state)) {
    decision = 'REVIEW'; emit('failsafe:untrusted-mcp-state');
  }

  // ---- 12) SEMANTIC ESCALATION (WF-06) — only when uncertain/ambiguous ----
  let semanticUsed = false;
  const needsSemantic = decision === 'REVIEW' && confidence < th.confidenceFloor
    && policySet.semantic?.enabled !== false && deps.semantic
    && (!deps.srg || deps.srg.allowSemantic());
  if (needsSemantic) {
    const compact = buildCompactContext(req, { behavior: riskCtx.behavior, matchedRules: pol.hits.map((h) => h.ruleId) });
    const raw = await deps.semantic.analyze(JSON.parse(compact));
    const out = validateSemanticOutput(raw);
    if (!out.invalid) {
      semanticUsed = true;
      risk = riskAdj(risk, out.risk_delta);
      evidence.push({ factor: 'semantic', note: `delta=${out.risk_delta} conf=${out.self_confidence}` });
      for (const ind of out.indicators) evidence.push({ factor: 'semantic:' + ind.type, note: String(ind.evidence || '').slice(0, 120) });
      confidence = clamp(Math.round(confidence + out.self_confidence * 15), 0, 100);
      // re-resolve after evidence merge (semantic can never directly ALLOW)
      if (risk >= th.risk.critical) decision = 'BLOCK';
      else if (risk >= th.risk.high && confidence >= th.confidenceFloor) decision = 'BLOCK';
      else if (risk >= th.risk.medium && confidence >= th.confidenceFloor) decision = decision === 'ALLOW' ? 'REVIEW' : decision;
    }
  }

  const verdict = {
    decision, risk: Math.round(risk), confidence, trust: trustScoreOf(deps, gateSubject),
    path: semanticUsed ? 'semantic' : 'fast',
    reasons, policyRefs, evidence, latencyMs: Date.now() - t0,
    cacheFingerprint: fingerprint,
  };
  if (risk >= th.risk.critical && decision === 'BLOCK') verdict.containmentHint = 'L6-quarantine';
  else if (risk >= th.risk.high && decision === 'BLOCK') verdict.containmentHint = 'L2-deny';

  cacheStore(deps.storage, fingerprint, verdict, policySet, decision === 'ALLOW');
  return finalize(deps, req, verdict, { subjectId: gateSubject, semanticUsed });
}

function riskAdj(risk, delta) { return clamp(Math.round(risk + delta), 0, 100); }

function finalize(deps, req, verdict, extra = {}) {
  // trust micro-update
  if (extra.subjectId && deps.storage) {
    if (verdict.decision === 'ALLOW') trust.reward(deps.storage, extra.subjectId);
    else if (verdict.decision === 'BLOCK' && verdict.risk >= 70) trust.violation(deps.storage, extra.subjectId, { critical: verdict.risk >= 90 }, 'runtime-block');
  }
  // audit (append-only, never drops)
  if (deps.storage) {
    deps.storage.audit({
      ts: req.ts, tenantId: req.tenantId || null, kind: 'decision',
      actor: req.agentId || null, subject: extra.subjectId || null,
      tool: req.toolId || null, action: req.action || null,
      decision: verdict.decision, risk: verdict.risk, confidence: verdict.confidence, trust: verdict.trust,
      path: verdict.path, reasons: verdict.reasons, policyRefs: verdict.policyRefs,
      evidence: (verdict.evidence || []).map((e) => ({ f: e.factor, n: String(e.note || '').slice(0, 160) })),
      detail: { requestId: req.id, cacheHit: !!extra.cacheHit, mcp: req.mcpId, destination: req.destination?.host || null, resource: req.resource?.key || undefined, adapter: req.ctx?.adapterId || undefined },
    });
  }
  // event bus + metrics
  const evt = { kind: 'decision', req: { ...req, params: undefined }, verdict, ts: nowMs() };
  if (deps.bus) deps.bus.publish('decisions', evt, { shedClass: 1 });
  if (deps.metrics) deps.metrics.recordDecision(verdict);
  return verdict;
}

export function trustScoreOf(deps, subjectId) {
  if (!subjectId || !deps.storage) return null;
  const t = trust.getTrust(deps.storage, subjectId);
  return t.updatedAt ? Math.round(t.score) : null;
}

export function decisionFingerprint(parts) {
  return sha256hex(stableStringify(parts));
}

function cacheLookup(storage, fingerprint) {
  const row = storage.q.cacheGet.get(fingerprint);
  if (!row) return null;
  if (nowMs() > row.createdAt + row.ttlMs) return null;
  try { return { verdict: JSON.parse(row.verdict) }; } catch { return null; }
}
function cacheStore(storage, fingerprint, verdict, policySet, positive) {
  const ttl = positive ? (policySet.cache?.positiveTtlMs || 600_000) : (policySet.cache?.negativeTtlMs || 300_000);
  storage.q.cachePut.run(fingerprint, JSON.stringify({ decision: verdict.decision, risk: verdict.risk, confidence: verdict.confidence, trust: verdict.trust, reasons: verdict.reasons, policyRefs: verdict.policyRefs, evidence: verdict.evidence, containmentHint: verdict.containmentHint }), nowMs(), ttl, JSON.stringify(policySet.versions));
}

function checkSchema(toolRow, params) {
  let schema = null;
  try { schema = JSON.parse(toolRow.inputSchema || 'null'); } catch { return null; }
  if (!schema || typeof schema !== 'object') return null;
  const p = params || {};
  if (typeof p !== 'object' || Array.isArray(p)) return 'params-not-object';
  for (const req of schema.required || []) if (!(req in p)) return `missing-required:${req}`;
  if (schema.additionalProperties === false) {
    const declared = new Set(Object.keys(schema.properties || {}));
    for (const k of Object.keys(p)) if (!declared.has(k)) return `unknown-param:${k}`;
  }
  return null;
}

/** Cheap sensitivity hint for authz-denied fail-closed decisions. */
function classifyMetaSensitivity(req) {
  const d = detectDestination(req.params || {}, {});
  return !!(d && d.kind === 'external');
}
