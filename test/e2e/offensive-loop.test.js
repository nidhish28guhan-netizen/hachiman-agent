// test/e2e/offensive-loop.test.js — the full authorized offensive lifecycle against the real
// vulnerable lab target, including fix verification (VERIFIED / UNRESOLVED negative paths),
// regression export, engagement persistence, and ROE refusal.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Storage } from '../../packages/core/src/storage.js';
import { loadEngagement, EngagementViolation } from '../../packages/offense/src/engagement.js';
import { execute, persistRun } from '../../packages/offense/src/pentest.js';
import { verifyFix, exportRegression } from '../../packages/offense/src/retest.js';
import { startFixture } from '../../fixtures/host.js';
import { renderPentestReport } from '../../packages/reporting/src/render.js';

test('offensive loop: attack → prove → chain → contract on vuln-notes (real target)', async () => {
  const eng = loadEngagement({
    engagement: {
      target: 'mcp:vuln-notes', environment: 'local-lab', authorized_by: 'unit-test',
      conn: { fixture: 'vuln-notes' }, rules: { max_requests: 60, max_duration_ms: 60000 },
    },
  });
  const run = await execute(eng);
  assert.equal(run.error, null, 'no orchestrator error: ' + JSON.stringify(run.error));

  // DISCOVER/MAP
  assert.ok(run.surface.tools.length >= 5, 'recon mapped tools');
  assert.ok(run.surface.threatModel.length >= 3, 'threat model generated');

  // HYPOTHESIZE + ATTACK + VALIDATE: three real vulnerabilities must confirm
  const titles = run.findings.filter((f) => f.confirmed).map((f) => f.title).join('\n');
  assert.ok(run.findings.filter((f) => f.confirmed).length >= 3, 'expected 3+ confirmed findings');
  assert.match(titles, /query-injection/);
  assert.match(titles, /capability-excess/);
  assert.match(titles, /path-traversal/);
  for (const f of run.findings.filter((f) => f.confirmed)) {
    assert.ok((f.evidence.runs.attacks.length) >= 2, 'confirmed finding is reproducible');
    assert.ok(f.confidence >= 90, 'confirmed confidence high: ' + f.confidence);
  }

  // CHAIN
  assert.ok(run.graph.nodes.some((n) => n.id === 'res:sensitive-data'));
  assert.equal(run.chain.combinedSeverity, 'critical', 'chained impact reaches critical');

  // EXPLAIN + FIX contracts (§30 shape)
  assert.equal(run.contracts.length, run.findings.filter((f) => f.confirmed).length);
  const inj = run.contracts.find((c) => c.entry_point.tool === 'notes.search');
  assert.equal(inj.remediation.strategy, 'parameterized-query', 'root-cause strategy, not payload blacklist');
  assert.equal(inj.location.marker, 'VULN_FILTER', 'contract cites the real source location');
  assert.equal(inj.verification.replay_original_attack, 'required');

  // metrics honest: deterministic pipeline, zero tokens
  assert.equal(run.metrics.tokensUsed, 0);
  assert.ok(run.metrics.requests > 0 && run.metrics.requests <= 60, 'budget respected');

  // persistence round trip
  const db = new Storage(':memory:');
  persistRun(db, eng, run);
  const engRow = db.engGetById(eng.id);
  assert.equal(engRow.target, 'mcp:vuln-notes');
  const f1 = db.fndGetById('F-1');
  assert.ok(f1 && f1.confirmed, 'finding persisted');
  const c1 = db.ctrGetByFinding('F-1');
  assert.equal(c1.remediation.strategy, 'parameterized-query');
  assert.ok(!('_yaml' in c1), 'persisted contract is clean of render artifacts');

  // report renders with confirmed findings + verdict
  const report = renderPentestReport({ engagement: eng, run, graphText: run.graphText });
  assert.match(report, /3 confirmed finding/);
  assert.match(report, /INSECURE/);
  db.close();
});

test('fix verification: real fix VERIFIED; unfixed build UNRESOLVED; regression exported', async () => {
  const eng = loadEngagement({
    engagement: { target: 'mcp:vuln-notes', environment: 'local-lab', authorized_by: 'unit-test', conn: { fixture: 'vuln-notes' }, rules: { max_requests: 60 } },
  });
  const run = await execute(eng);
  const contracts = run.contracts;
  assert.ok(contracts.length >= 3);

  // negative path first: pretending the ORIGINAL vulnerable build is the "fix" → UNRESOLVED
  const orig = await startFixture('vuln-notes');
  const retestEng = () => loadEngagement({ engagement: { target: 'fix-verify', conn: { url: orig.url }, authorized_by: 'unit-test', rules: { max_requests: 20 } } });
  const bad = await verifyFix(retestEng(), contracts[0], { url: orig.url });
  assert.equal(bad.verdict, 'UNRESOLVED', 'original exploit still works → not verified');
  orig.stop();

  // positive path: the genuinely fixed build → VERIFIED for every finding
  const fixed = await startFixture('vuln-notes-fixed');
  const results = [];
  for (const c of contracts) {
    const e2 = loadEngagement({ engagement: { target: 'fix-verify', conn: { url: fixed.url }, authorized_by: 'unit-test', rules: { max_requests: 20 } } });
    results.push(await verifyFix(e2, c, { url: fixed.url }));
  }
  fixed.stop();
  for (const r of results) {
    assert.equal(r.verdict, 'VERIFIED', `${r.findingId}: ${r.reason}`);
    assert.equal(r.attackReplay.exploitStillWorks, false);
  }

  // regression export for every finding
  for (const c of contracts) {
    const reg = exportRegression(c);
    assert.equal(reg.id, `regression-${c.finding_id}`);
    assert.ok(reg.attack.mustNotReturn.length >= 1, 'regression knows the exploit markers');
  }
});

test('ROE: no authorization → engagement refused before any offensive work', () => {
  assert.throws(
    () => loadEngagement({ engagement: { target: 'mcp:anything', conn: { fixture: 'notes' }, rules: {} } }),
    (e) => e instanceof EngagementViolation && e.rule === 'authorization',
    'unauthorized target must be refused'
  );
});

test('ROE: out-of-scope tool aborts the probe', async () => {
  const { engagementApi } = await import('../../packages/offense/src/engagement.js');
  const eng = loadEngagement({
    engagement: { target: 'mcp:vuln-notes', conn: { fixture: 'vuln-notes' }, authorized_by: 'unit-test', scope: { allowed_tools: ['notes.list'], denied_tools: [] } },
  });
  assert.throws(() => engagementApi.assertTool(eng, 'admin.export'), EngagementViolation);
  assert.equal(eng.violations.at(-1).rule, 'scope');
});
