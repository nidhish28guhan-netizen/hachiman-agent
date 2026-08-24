// test/unit/k8s-flow.test.js — Hachiman 2.0 P4c/P4d: k8s admission stub + data-flow tap.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createNode } from '../../lib/hachiman.js';
import { makeK8sAdapter, admissionReview, K8S_GUARD_PACK } from '../../packages/adapters/src/k8s.js';
import { recordFlow, flowSummary } from '../../packages/planes/src/flow.js';
import * as trust from '../../packages/engines/src/trust.js';

async function k8sSetup(ns = 'apps', name = 'billing') {
  const node = createNode({ storage: { path: ':memory:' }, policyPacks: ['default'], srg: { enabled: false } });
  const adapter = makeK8sAdapter(node);
  node.adapters.register(adapter);
  await node.start();
  node.identity.register('agent', 'ci-bot');
  const { token } = node.identity.issueSession('agent:ci-bot');
  node.authz.grant({ subject: 'agent:ci-bot', capability: '*', resource: '*', grantedBy: 'test:operator' });
  trust.operatorAllow(node.storage, `k8s:${ns}/${name}`, 'test:operator');
  return { node, adapter, token };
}

const benignPod = {
  apiVersion: 'admission.k8s.io/v1', kind: 'AdmissionReview',
  request: {
    uid: 'req-1', operation: 'CREATE', namespace: 'apps', name: 'billing',
    kind: { kind: 'Pod' },
    object: { metadata: { name: 'billing' }, spec: { containers: [{ name: 'app', image: 'billing:v2' }] } },
  },
};

test('k8s adapter: benign pod admission is ALLOWed with grant + trust', async () => {
  const { node, adapter, token } = await k8sSetup();
  try {
    const out = await admissionReview(node, adapter, benignPod, { subject: 'agent:ci-bot' });
    assert.equal(out.response.allowed, true, JSON.stringify(out._hachiman.verdict.reasons));
    assert.equal(out.response.uid, 'req-1');
    assert.equal(out.kind, 'AdmissionReview');
  } finally { await node.stop(); }
});

test('k8s adapter: privileged container is force-BLOCKed', async () => {
  const { node, adapter, token } = await k8sSetup();
  try {
    const evil = JSON.parse(JSON.stringify(benignPod));
    evil.request.object.spec.containers[0].securityContext = { privileged: true };
    const out = await admissionReview(node, adapter, evil, { subject: 'agent:ci-bot' });
    assert.equal(out.response.allowed, false);
    assert.ok(out._hachiman.verdict.reasons.includes('policy:k8s-privileged-container'),
      out._hachiman.verdict.reasons.join(','));
    assert.equal(out.response.status.code, 403);
  } finally { await node.stop(); }
});

test('k8s adapter: hostNetwork/hostPID sharing is force-BLOCKed', async () => {
  const { node, adapter } = await k8sSetup();
  try {
    const hostNet = JSON.parse(JSON.stringify(benignPod));
    hostNet.request.object.spec.hostNetwork = true;
    const out = await admissionReview(node, adapter, hostNet, { subject: 'agent:ci-bot' });
    assert.equal(out.response.allowed, false);
    assert.ok(out._hachiman.verdict.reasons.includes('policy:k8s-host-namespace'), out._hachiman.verdict.reasons.join(','));

    const hostPid = JSON.parse(JSON.stringify(benignPod));
    hostPid.request.object.spec.hostPID = true;
    const out2 = await admissionReview(node, adapter, hostPid, { subject: 'agent:ci-bot' });
    assert.equal(out2.response.allowed, false);
  } finally { await node.stop(); }
});

test('k8s adapter: SYS_ADMIN capability is force-BLOCKed', async () => {
  const { node, adapter } = await k8sSetup();
  try {
    const cap = JSON.parse(JSON.stringify(benignPod));
    cap.request.object.spec.containers[0].securityContext = { capabilities: { add: ['SYS_ADMIN'] } };
    const out = await admissionReview(node, adapter, cap, { subject: 'agent:ci-bot' });
    assert.equal(out.response.allowed, false);
    assert.ok(out._hachiman.verdict.reasons.includes('policy:k8s-cap-sys-admin'), out._hachiman.verdict.reasons.join(','));
  } finally { await node.stop(); }
});

test('response plane universalized: BLOCK on a k8s plane quarantines the resource key and revokes its grants', async () => {
  const node = createNode({ storage: { path: ':memory:' }, policyPacks: ['default'], srg: { enabled: false } });
  const adapter = makeK8sAdapter(node);
  node.adapters.register(adapter);
  await node.start();
  try {
    node.identity.register('agent', 'ci-bot');
    node.authz.grant({ subject: 'agent:ci-bot', capability: 'k8s.CREATE', resource: 'k8s:apps/billing', grantedBy: 'test:operator' });
    node.authz.grant({ subject: 'agent:ci-bot', capability: 'api.GET', resource: 'api:reports', grantedBy: 'test:operator' }); // unrelated plane grant
    trust.operatorAllow(node.storage, 'k8s:apps/billing', 'test:operator');

    const evil = JSON.parse(JSON.stringify(benignPod));
    evil.request.object.spec.containers[0].securityContext = { privileged: true };
    const out = await admissionReview(node, adapter, evil, { subject: 'agent:ci-bot' });
    assert.equal(out.response.allowed, false);

    // containment ladder acts on the bus — give the subscriber a tick
    await new Promise((r) => setTimeout(r, 30));

    // the OFFENDING k8s resource grant is revoked; the unrelated api grant survives (no collateral lockout)
    const remaining = node.storage.q.grantActive.all('agent:ci-bot').map((g) => g.resource);
    assert.ok(!remaining.includes('k8s:apps/billing'), 'offending plane grant must be revoked, got ' + JSON.stringify(remaining));
    assert.ok(remaining.includes('api:reports'), 'unrelated plane grant must survive, got ' + JSON.stringify(remaining));

    // quarantine applies to the universal resource key, not 'mcp:undefined'
    const q = node.storage.q.quarGet.get('k8s:apps/billing');
    assert.ok(q, 'k8s resource key must be quarantined');
    assert.equal(node.storage.q.quarGet.get('mcp:undefined'), undefined);
  } finally { await node.stop(); }
});

test('k8s adapter: kube-system writes land in REVIEW (denied pending approval)', async () => {
  const { node, adapter, token } = await k8sSetup();
  try {
    const sys = JSON.parse(JSON.stringify(benignPod));
    sys.request.namespace = 'kube-system'; sys.request.name = 'coredns';
    node.authz.grant({ subject: 'agent:ci-bot', capability: '*', resource: '*', grantedBy: 'test:operator' });
    trust.operatorAllow(node.storage, 'k8s:kube-system/coredns', 'test:operator');
    const out = await admissionReview(node, adapter, sys, { subject: 'agent:ci-bot' });
    assert.equal(out.response.allowed, false);
    assert.equal(out.response.status.code, 202, 'REVIEW must surface as 202 review-pending');
  } finally { await node.stop(); }
});

test('k8s adapter: no grant → admission denied at the hard gate', async () => {
  const node = createNode({ storage: { path: ':memory:' }, policyPacks: ['default'], srg: { enabled: false } });
  const adapter = makeK8sAdapter(node);
  node.adapters.register(adapter);
  await node.start();
  try {
    const out = await admissionReview(node, adapter, benignPod, {});
    assert.equal(out.response.allowed, false);
    assert.ok(out._hachiman.verdict.reasons.some((r) => r.startsWith('authorization:denied') || r === 'identity:unverified'));
  } finally { await node.stop(); }
});

test('data-flow tap: confidential egress is blocked; internal flows pass', () => {
  const node = createNode({ storage: { path: ':memory:' }, policyPacks: ['default'], srg: { enabled: false } });
  const t1 = recordFlow(node, {
    subject: 'agent:etl', resource: 'db:ledger', classification: 'confidential', bytes: 450_000,
    destination: { host: 'analytics.evil.example', kind: 'external', known: false },
  });
  assert.equal(t1.blocked, true);
  assert.equal(t1.reason, 'flow:confidential-external');

  const t2 = recordFlow(node, {
    subject: 'agent:etl', resource: 'db:metrics', classification: 'internal',
    destination: { host: 'warehouse.internal', kind: 'internal', known: true },
  });
  assert.equal(t2.blocked, false);

  const t3 = recordFlow(node, {
    subject: 'agent:etl', resource: 'db:metrics', classification: 'internal',
    destination: { host: 'unknown.cloudsink.example', kind: 'external', known: false },
  });
  assert.equal(t3.blocked, false);
  assert.equal(t3.reason, 'flow:internal-unknown-destination');

  const s = flowSummary(node, { limit: 50 });
  assert.equal(s.total, 3);
  assert.equal(s.byDecision.BLOCK, 1);
  assert.equal(s.blockedFlows[0].reason, 'flow:confidential-external');
  // append-only trail
  const rows = node.storage.auditTail(20).filter((r) => r.kind === 'flow' || r.kind === 'containment');
  assert.ok(rows.length >= 4, 'flow + containment rows must be audited');
});

test('k8s-guard pack contract: documented rules are shipped', () => {
  const ids = K8S_GUARD_PACK.rules.map((r) => r.id);
  for (const expected of ['k8s-privileged-container', 'k8s-host-namespace', 'k8s-host-pid', 'k8s-kube-system', 'k8s-cap-sys-admin']) {
    assert.ok(ids.includes(expected), 'missing rule ' + expected);
  }
});
