// test/golden.test.js — golden-decision regression locks (determinism).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createNode } from '../lib/hachiman.js';
import { loadCorpus, runScenario } from '../packages/benchmark/src/runner.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const GOLDEN_DIR = join(HERE, '..', 'fixtures', 'golden');

const scenarios = loadCorpus(GOLDEN_DIR);

test(`golden suite loaded (${scenarios.length} scenarios)`, () => {
  assert.ok(scenarios.length >= 10, 'expected a substantive golden set');
});

for (const sc of scenarios) {
  test(`golden: ${sc.id}`, async () => {
    const node = createNode({ storage: { path: ':memory:' }, policyPacks: ['default'], srg: { enabled: false } });
    try {
      const run = await runScenario(node, sc);
      for (const r of run.results) {
        assert.ok(r.pass, `${sc.id} failed: ${r.why} | verdict=${JSON.stringify({ d: r.verdict.decision, risk: r.verdict.risk, conf: r.verdict.confidence, reasons: r.verdict.reasons })}`);
      }
    } finally { await node.stop(); }
  });
}

test('golden: identical request twice → identical deterministic verdict (no cache)', async () => {
  const node = createNode({ storage: { path: ':memory:' }, policyPacks: ['default'], srg: { enabled: false } });
  try {
    const sc = scenarios.find((s) => s.id === 'golden-block-exfil-001');
    const a = await runScenario(node, { ...sc, cacheEnabled: false });
    const node2 = createNode({ storage: { path: ':memory:' }, policyPacks: ['default'], srg: { enabled: false } });
    const b = await runScenario(node2, { ...sc, cacheEnabled: false });
    const va = a.results[0].verdict, vb = b.results[0].verdict;
    assert.equal(va.decision, vb.decision);
    assert.equal(va.risk, vb.risk);
    assert.equal(va.confidence, vb.confidence);
    await node2.stop();
  } finally { await node.stop(); }
});
