// test/unit/core-runtime.test.js — storage (append-only audit), bus bounds, trust dynamics, SRG modes.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Storage } from '../../packages/core/src/storage.js';
import { EventBus, SHED } from '../../packages/core/src/bus.js';
import { shapeHash, stableStringify, RateWindow, percentile } from '../../packages/core/src/utils.js';
import * as trust from '../../packages/engines/src/trust.js';
import { SecurityResourceGovernor } from '../../packages/srg/src/srg.js';

test('storage: audit is append-only (update/delete rejected)', () => {
  const s = new Storage(':memory:');
  s.audit({ kind: 'decision', subject: 'mcp:x', decision: 'BLOCK', risk: 90 });
  assert.ok(s.auditCount() >= 1);
  assert.throws(() => s.db.exec('DELETE FROM audit_events'), /append-only/);
  assert.throws(() => s.db.exec('UPDATE audit_events SET risk=1'), /append-only/);
  assert.ok(s.auditCount() >= 1, 'rows survived rejected mutations');
  s.close();
});

test('storage: audit tail returns newest first', () => {
  const s = new Storage(':memory:');
  s.audit({ kind: 'a', detail: { n: 1 } });
  s.audit({ kind: 'b', detail: { n: 2 } });
  const rows = s.auditTail(10);
  assert.equal(rows[0].kind, 'b');
  assert.equal(rows[1].kind, 'a');
  s.close();
});

test('bus: delivers to subscribers and survives subscriber throw', () => {
  const bus = new EventBus();
  const seen = [];
  bus.on('x', (e) => seen.push(e.v));
  bus.on('x', () => { throw new Error('boom'); });
  bus.on('x', (e) => seen.push(e.v * 10));
  bus.publish('x', { v: 2 });
  assert.deepEqual(seen, [2, 20]);
});

test('bus: shed ladder drops low-priority subscribers under overload', () => {
  const bus = new EventBus({ maxDepth: 0 }); // force overloaded branch
  let critical = 0, sheddable = 0;
  bus.on('y', () => { critical++; }, { shedClasses: [SHED.ENFORCE] });
  bus.on('y', () => { sheddable++; }, { shedClasses: [SHED.REPORT] });
  bus.publish('y', {}, { shedClass: SHED.REPORT });
  assert.equal(critical, 1);
  assert.equal(sheddable, 0);
});

test('shapeHash: same shape different values → same hash', () => {
  const h1 = shapeHash({ a: 1, b: 'hello' });
  const h2 = shapeHash({ a: 2, b: 'world' });
  assert.equal(h1, h2);
  const h3 = shapeHash({ a: 1, b: 'hello', url: 'http://x.example/' });
  assert.notEqual(h1, h3);
});

test('stableStringify: key order independent', () => {
  assert.equal(stableStringify({ a: 1, b: 2 }), stableStringify({ b: 2, a: 1 }));
});

test('RateWindow: totals and eviction', () => {
  const w = new RateWindow(60_000, 1_000);
  const now = Date.now();
  w.add('k1', 1, now - 120_000); // outside window → evicted
  w.add('k1', 2, now);
  const t = w.totals(now);
  assert.equal(t.total, 2);
});

test('percentile: basic', () => {
  const arr = [...Array(100)].map((_, i) => i + 1);
  assert.equal(percentile(arr, 50), 51);
  assert.equal(percentile(arr, 95), 96);
});

test('trust lifecycle: UNKNOWN→scan→ASSESSED→allow→TRUSTED→violation→HIGH_RISK→quarantine', () => {
  const s = new Storage(':memory:');
  trust.registerSubject(s, 'mcp:t');
  assert.equal(trust.getTrust(s, 'mcp:t').state, 'UNKNOWN');

  trust.fromScan(s, 'mcp:t', { overall: 88 }, 'scan-1');
  assert.equal(trust.getTrust(s, 'mcp:t').state, 'ASSESSED');

  trust.operatorAllow(s, 'mcp:t', 'operator:local');
  assert.equal(trust.getTrust(s, 'mcp:t').state, 'TRUSTED');

  trust.violation(s, 'mcp:t', { critical: true }, 'critical-block');
  assert.equal(trust.getTrust(s, 'mcp:t').state, 'HIGH_RISK');

  trust.quarantine(s, 'mcp:t', 'contained');
  assert.equal(trust.getTrust(s, 'mcp:t').state, 'QUARANTINED');
  assert.ok(trust.getTrust(s, 'mcp:t').score <= 20);

  trust.rescanRecovery(s, 'mcp:t', { overall: 90 }, 'scan-2');
  assert.equal(trust.getTrust(s, 'mcp:t').state, 'ASSESSED');
  s.close();
});

test('trust: low scan keeps UNVERIFIED', () => {
  const s = new Storage(':memory:');
  trust.registerSubject(s, 'mcp:bad');
  trust.fromScan(s, 'mcp:bad', { overall: 30 }, 'scan-x');
  assert.equal(trust.getTrust(s, 'mcp:bad').state, 'UNVERIFIED');
  s.close();
});

test('srg: threat escalation drives mode transitions', () => {
  const bus = new EventBus();
  const s = new SecurityResourceGovernor({ bus, storage: null }, { tickMs: 5, minDwellMs: 0 });
  s.start();
  s.raiseThreat(2);
  s.tick();
  assert.equal(s.mode, 'THREAT');
  s.raiseThreat(3);
  s.tick();
  assert.equal(s.mode, 'INCIDENT');
  s.lowerThreat(0);
  s.tick();
  assert.ok(['RECOVERY', 'INCIDENT'].includes(s.mode));
  s.stop();
});

test('srg: sentinel mode disables semantic slots', () => {
  const bus = new EventBus();
  const s = new SecurityResourceGovernor({ bus, storage: null });
  s.mode = 'SENTINEL';
  s.budget = s._budget();
  assert.equal(s.budget.semanticConcurrency, 0);
  assert.equal(s.allowSemantic(), false);
});

test('srg: threat mode allows semantic slot', () => {
  const bus = new EventBus();
  const s = new SecurityResourceGovernor({ bus, storage: null });
  s.mode = 'THREAT'; s.budget = { analysisDepth: 3, semanticConcurrency: 2, cacheTtlScale: 1, samplingRate: 1 };
  assert.equal(s.allowSemantic(), true);
});
