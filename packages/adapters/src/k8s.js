// adapters/k8s — Kubernetes admission-review stub adapter (Hachiman 2.0, P4).
// Translates an AdmissionReview request into a universal decision request and
// answers in AdmissionReview response shape. A webhook can only allow/deny, so
// Hachiman REVIEW maps to a deny + "human review required" status — fail-closed.
import { uuid, nowMs } from '../../core/src/utils.js';
import { evaluateRequest } from '../../engines/src/decision.js';

export const K8S_GUARD_PACK = {
  id: 'k8s-guard', version: 1,
  thresholds: { risk: { low: 25, medium: 55, high: 75, critical: 90 }, confidenceFloor: 80 },
  rules: [
    { id: 'k8s-privileged-container', when: { resourceType: 'k8s', paramHas: '"privileged":true' }, then: { decision: 'BLOCK', riskFloor: 95, reason: 'privileged container admission' } },
    { id: 'k8s-host-namespace', when: { resourceType: 'k8s', paramHas: '"hostNetwork":true' }, then: { decision: 'BLOCK', riskFloor: 90, reason: 'host network namespace sharing' } },
    { id: 'k8s-host-pid', when: { resourceType: 'k8s', paramHas: '"hostPID":true' }, then: { decision: 'BLOCK', riskFloor: 90, reason: 'host PID namespace sharing' } },
    { id: 'k8s-kube-system', when: { resourceType: 'k8s', paramHas: '"namespace":"kube-system"' }, then: { decision: 'REVIEW', riskFloor: 70, reason: 'write into kube-system requires sign-off' } },
    { id: 'k8s-cap-sys-admin', when: { resourceType: 'k8s', paramHas: 'SYS_ADMIN' }, then: { decision: 'BLOCK', riskFloor: 95, reason: 'SYS_ADMIN capability requested' } },
  ],
};

export function makeK8sAdapter(node, { id = 'k8s' } = {}) {
  if (!node.policyEngine.getPack('k8s-guard')) node.policyEngine.loadPack(K8S_GUARD_PACK);
  if (!node.config.policyPacks.includes('k8s-guard')) node.config.policyPacks.push('k8s-guard');
  return {
    id,
    protocol: 'k8s-admission-review',
    resourceTypes: ['k8s'],
    description: 'Kubernetes admission-review gate: pods/deployments/admission requests evaluated by the decision plane.',
    metadata() { return { sideEffectRisk: 25, egressCapable: false }; },
    /** Translate a Kubernetes AdmissionReview request object. */
    toDecisionRequest({ request = {}, sessionToken = null, subject = null }) {
      const namespace = request.namespace || 'default';
      const name = request.name || request.object?.metadata?.name || 'unnamed';
      const operation = String(request.operation || 'ADMIT').toUpperCase();
      return {
        id: uuid(), ts: nowMs(),
        subject: subject || undefined,
        // 2.0 convention: k8s resource id is the NAME; namespace rides in attrs so
        // universalizeRequest can build gateResource 'k8s:<ns>/<name>' exactly once.
        resource: { type: 'k8s', id: name, attrs: { operation, namespace, kind: request.kind?.kind || 'Object' } },
        action: operation,
        params: { namespace, spec: request.object?.spec ?? null, object: request.object ?? null },
        authzContext: { sessionToken },
        ctx: { adapterId: id },
        adapterId: id,
      };
    },
  };
}

/**
 * Evaluate one AdmissionReview. Returns an AdmissionReview RESPONSE object.
 * Allow ⇔ Hachiman ALLOW. REVIEW/BLOCK both deny (webhook limitation) with an
 * explicit status so operators can tell policy-deny from review-pending apart.
 */
export async function admissionReview(node, adapter, review, { subject = null } = {}) {
  const req = adapter.toDecisionRequest({ request: review?.request || {}, subject });
  const deps = node.engineDepsFor(adapter.id);
  const verdict = await evaluateRequest(deps, req);
  const allowed = verdict.decision === 'ALLOW';
  const status = {
    hachiman: true,
    decision: verdict.decision,
    risk: verdict.risk, confidence: verdict.confidence,
    reasons: verdict.reasons,
    requestId: req.id,
    message: allowed ? 'HACHIMAN: admitted'
      : verdict.decision === 'REVIEW' ? 'HACHIMAN: human review required (denied pending approval)'
      : 'HACHIMAN: denied by security policy',
  };
  return {
    apiVersion: 'admission.k8s.io/v1',
    kind: 'AdmissionReview',
    response: {
      uid: review?.request?.uid || req.id,
      allowed,
      status: { code: allowed ? 200 : verdict.decision === 'REVIEW' ? 202 : 403, message: status.message },
      auditAnnotations: { 'hachiman.dev/decision': verdict.decision, 'hachiman.dev/risk': String(verdict.risk) },
    },
    _hachiman: { verdict, requestId: req.id },
  };
}
