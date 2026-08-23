// test/e2e/dashboard.test.js — mission-control UI + new API surface + fix-recommendation engine.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createNode } from '../../lib/hachiman.js';
import { startHttpServer } from '../../packages/dashboard/src/server.js';
import { recommendFix, RULE_COUNTS } from '../../packages/dashboard/src/recommend.js';

function base() {
  return createNode({ storage: { path: ':memory:' }, policyPacks: ['default'], srg: { enabled: false } });
}

test('dashboard: serves mission-control UI with recommend engine injected', async () => {
  const node = base();
  const http = await startHttpServer(node, { port: 0, token: 'ui-token' });
  try {
    const res = await fetch(`http://127.0.0.1:${http.port}/`);
    assert.equal(res.status, 200);
    const html = await res.text();
    // new compact mission-control identity
    assert.match(html, /MISSION CONTROL/);
    assert.match(html, /Advisor · recommended fixes/);
    assert.match(html, /Offensive skill/);
    // the recommendation engine must be inlined, not left as a placeholder
    assert.ok(!html.includes('/*__RECOMMEND__*/'), 'placeholder replaced');
    assert.match(html, /function recommendFix/);
    assert.match(html, /REASON_FIX/);
  } finally { await http.stop(); await node.stop(); }
});

test('dashboard: /api/health and /api/offense respond with honest data', async () => {
  const node = base();
  const http = await startHttpServer(node, { port: 0, token: 'ui-token' });
  try {
    const hp = await (await fetch(`http://127.0.0.1:${http.port}/api/health`)).json();
    assert.equal(hp.ok, true);
    assert.ok(typeof hp.uptimeS === 'number');
    assert.ok(Array.isArray(hp.servers));

    const off = await (await fetch(`http://127.0.0.1:${http.port}/api/offense`)).json();
    assert.ok(Array.isArray(off.engagements));
    assert.ok(Array.isArray(off.findings));
    assert.ok(Array.isArray(off.contracts));
    assert.ok(Array.isArray(off.retests));
  } finally { await http.stop(); await node.stop(); }
});

test('recommendation engine: real decision reasons map to concrete fixes', () => {
  assert.ok(RULE_COUNTS.reasons >= 10, 'has a substantive reason→fix rule set');
  const noGrant = recommendFix({ verdict: { decision: 'BLOCK', reasons: ['authorization:denied:no grants for subject'] } });
  assert.match(noGrant.fix, /hachiman agent add/);
  const inj = recommendFix({ verdict: { decision: 'BLOCK', reasons: ['injection:instruction-override+role'] } });
  assert.match(inj.fix, /blocked/i);
  const untrusted = recommendFix({ verdict: { decision: 'REVIEW', reasons: ['failsafe:untrusted-mcp-state'] } });
  assert.match(untrusted.fix, /scan/);
  const sys = recommendFix({ error: 'fetch failed ECONNREFUSED' });
  assert.match(sys.fix, /hachiman guard/);
  const regression = recommendFix({ verdict: 'REGRESSION' });
  assert.match(regression.fix, /retest/);
  // an unrecognized object yields no false recommendation
  assert.equal(recommendFix({}), null);
});
