// planes/flow — the data-flow engine tap (Hachiman 2.0, P4d/P5).
// First-class flow events: (subject → resource → destination). Flows are
// audited append-only, published on the 'flows' bus channel, and checked by a
// deterministic containment rule — confidential/restricted data leaving to an
// external destination is blocked regardless of who asks. No LLM in the loop.

export const DATA_CLASS_SEVERITY = { public: 0, internal: 1, confidential: 2, restricted: 3 };

/**
 * Record and evaluate one data flow. Returns:
 *  { blocked:true,  reason, auditId } when containment applies
 *  { blocked:false, auditId } for allowed flows
 */
export function recordFlow(node, {
  subject, resource, destination, classification = 'internal',
  bytes = null, note = null,
} = {}) {
  if (!subject || !resource || !destination) throw new Error('flow:missing-fields');
  const sev = DATA_CLASS_SEVERITY[classification] ?? 1;
  const destExternal = destination.kind === 'external' ||
    (!destination.kind && !/^internal|^localhost|^127\.|^::1/.test(String(destination.host || destination)));
  const destKnown = !!destination.known;

  // Deterministic containment rule (2.0 §4.4): external egress of
  // confidential+ data is blocked; external egress of internal data with an
  // unknown destination is flagged for review.
  let blocked = false, reason = null;
  if (destExternal && sev >= 2) { blocked = true; reason = 'flow:confidential-external'; }
  else if (destExternal && !destKnown && sev >= 1 && classification !== 'public') { reason = 'flow:internal-unknown-destination'; }

  const auditId = node.storage.audit({
    kind: 'flow', subject, resource,
    action: 'data-flow', decision: blocked ? 'BLOCK' : (reason ? 'REVIEW' : 'ALLOW'),
    detail: { destination: destination.host || String(destination), classification, bytes, sev, blocked, reason, note: note || undefined },
  });
  if (node.bus) node.bus.publish('flows', {
    subject, resource, destination: destination.host || String(destination),
    classification, bytes, blocked, reason, ts: Date.now(),
  }, { shedClass: blocked ? 2 : 6 });
  if (blocked) {
    node.storage.audit({ kind: 'containment', subject, action: 'flow-blocked', detail: { reason, resource } });
  }
  return { blocked, reason, auditId };
}

/** Summarize recent flows for forensics/dashboards (pure read over audit). */
export function flowSummary(node, { limit = 100 } = {}) {
  const rows = node.storage.auditTail(limit).filter((r) => r.kind === 'flow');
  const byDecision = { ALLOW: 0, REVIEW: 0, BLOCK: 0 };
  const blockedFlows = [];
  for (const r of rows) {
    if (byDecision[r.decision] != null) byDecision[r.decision]++;
    if (r.decision === 'BLOCK') blockedFlows.push({ subject: r.subject, resource: r.resource, reason: r.detail?.reason });
  }
  return { total: rows.length, byDecision, blockedFlows };
}
