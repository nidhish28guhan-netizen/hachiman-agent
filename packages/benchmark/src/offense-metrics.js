// benchmark/offense-metrics — offensive effectiveness & efficiency (doc-06 §44).
// Measures the real loop on the bundled lab target: validation rate, confidence,
// requests per confirmed finding, and time-to-verified-fix. Measured values only.
import { loadEngagement } from '../../offense/src/engagement.js';
import { execute } from '../../offense/src/pentest.js';
import { verifyFix, exportRegression } from '../../offense/src/retest.js';
import { startFixture } from '../../../fixtures/host.js';

export async function runOffenseMetrics() {
  const t0 = Date.now();
  const eng = loadEngagement({
    engagement: {
      target: 'mcp:vuln-notes', environment: 'local-lab', authorized_by: 'benchmark',
      conn: { fixture: 'vuln-notes' }, rules: { max_requests: 60, max_duration_ms: 60000 },
    },
  });
  const run = await execute(eng);
  if (run.error) throw new Error('offense benchmark failed: ' + run.error.message);
  const attackMs = Date.now() - t0;

  // fix-verification leg (the reattack → verify half of the signature loop)
  const fixed = await startFixture('vuln-notes-fixed');
  const t1 = Date.now();
  const retests = [];
  for (const c of run.contracts) {
    const e2 = loadEngagement({ engagement: { target: 'fix-verify', conn: { url: fixed.url }, authorized_by: 'benchmark', rules: { max_requests: 20 } } });
    retests.push(await verifyFix(e2, c, { url: fixed.url }));
  }
  const verifyMs = Date.now() - t1;
  fixed.stop();

  const confirmed = run.findings.filter((f) => f.confirmed);
  const verified = retests.filter((r) => r.verdict === 'VERIFIED').length;
  return {
    workload: 'vuln-notes lab target (3 planted root causes)',
    measuredAt: new Date().toISOString(),
    engagementMs: attackMs,
    requests: eng.counters.requests,
    hypotheses: run.plan.hypotheses.length,
    confirmedFindings: confirmed.length,
    validationRate: +(confirmed.length / run.plan.hypotheses.length).toFixed(3),
    avgConfidencePct: Math.round(confirmed.reduce((s, f) => s + f.confidence, 0) / Math.max(1, confirmed.length)),
    requestsPerConfirmedFinding: +(eng.counters.requests / Math.max(1, confirmed.length)).toFixed(2),
    tokensUsed: run.metrics.tokensUsed,
    retest: {
      verified, total: retests.length, verdicts: retests.map((r) => r.verdict),
      timeToVerifiedFixMs: verified === retests.length ? attackMs + verifyMs : null,
    },
    regressionScenarios: run.contracts.map((c) => exportRegression(c).id),
    disclaimer: 'Measured for this workload on this machine — not universal promises.',
  };
}

const isMain = process.argv[1] && import.meta.url.endsWith(process.argv[1].split('/').pop());
if (isMain) {
  runOffenseMetrics().then((m) => { console.log(JSON.stringify(m, null, 2)); process.exit(0); }).catch((e) => { console.error(e); process.exit(1); });
}
