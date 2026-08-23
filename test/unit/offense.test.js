// test/unit/offense.test.js — offensive skill engines: engagement/ROE, hypotheses, planner,
// validation, graph, root cause, repair contract, regression export.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { loadEngagement, engagementApi, EngagementViolation } from '../../packages/offense/src/engagement.js';
import { generateHypotheses, transition } from '../../packages/offense/src/hypothesis.js';
import { initPlan, recordObservation, nextHypotheses } from '../../packages/offense/src/planner.js';
import { grade } from '../../packages/offense/src/validation.js';
import { buildGraph, chainImpact, renderGraph } from '../../packages/offense/src/graph.js';
import { analyze, classifyProposedFix, recommendedFix } from '../../packages/offense/src/rootcause.js';
import { buildContract, renderContractYaml, renderDeveloperCard } from '../../packages/offense/src/repair.js';
import { exportRegression } from '../../packages/offense/src/retest.js';

const baseEng = {
  engagement: { target: 'mcp:t', conn: { fixture: 'notes' }, authorized_by: 'op', rules: { max_requests: 3, max_duration_ms: 60000 } },
};

test('engagement: missing authorization is refused (fail-closed)', () => {
  assert.throws(() => loadEngagement({ engagement: { target: 't', conn: { fixture: 'x' } } }), EngagementViolation);
  assert.throws(() => loadEngagement({ engagement: { target: 't', conn: { fixture: 'x' }, authorized_by: '  ' } }), EngagementViolation);
  assert.throws(() => loadEngagement({ engagement: { conn: { fixture: 'x' }, authorized_by: 'op' } }), EngagementViolation);
});

test('engagement: persistence can never be enabled; exfil is prohibited or sink-only', () => {
  assert.throws(() => loadEngagement({ engagement: { target: 't', conn: { fixture: 'x' }, authorized_by: 'op', rules: { persistence: 'allowed' } } }), EngagementViolation);
  const e = loadEngagement(baseEng);
  assert.equal(engagementApi.canExfil(e), false);
  const e2 = loadEngagement({ ...baseEng, engagement: { ...baseEng.engagement, rules: { data_exfiltration: 'sink-only' } } });
  assert.equal(engagementApi.canExfil(e2), true);
});

test('engagement: scope + budget gates throw and audit violations', () => {
  const e = loadEngagement({ ...baseEng, engagement: { ...baseEng.engagement, scope: { allowed_tools: ['a'], denied_tools: ['b'] } } });
  assert.equal(engagementApi.assertTool(e, 'a'), true);
  assert.throws(() => engagementApi.assertTool(e, 'b'), EngagementViolation);
  assert.throws(() => engagementApi.assertTool(e, 'z'), EngagementViolation);
  engagementApi.spendRequest(e); engagementApi.spendRequest(e); engagementApi.spendRequest(e);
  assert.throws(() => engagementApi.spendRequest(e), EngagementViolation);
  assert.equal(e.violations.length, 3); // 2 scope denials + 1 budget exhaustion
});

const surface = {
  target: 't',
  tools: [
    { name: 'notes.search', description: 'Search notes', params: ['query'], strictSchema: true, flags: { db: true } },
    { name: 'files.read', description: 'Read file', params: ['path'], strictSchema: true, flags: { filesystem: true, db: false } },
    { name: 'admin.export', description: 'Export db', params: [], strictSchema: true, flags: { db: true } },
  ],
  tech: {},
  threatModel: [
    { surface: 'notes.search (input)', threat: 'injection-via-parameter', priority: 1, why: 'w' },
    { surface: 'files.read (filesystem)', threat: 'path-traversal', priority: 2, why: 'w' },
    { surface: 'admin.export (db)', threat: 'data-access-abuse', priority: 1, why: 'w' },
  ],
};

test('hypothesis generation: one minimal validating test per threat, deduped, PROPOSED', () => {
  const hs = generateHypotheses(surface, loadEngagement(baseEng));
  const titles = hs.map((h) => h.title);
  assert.ok(titles.some((t) => t.includes('query-injection')));
  assert.ok(titles.some((t) => t.includes('path-traversal')));
  assert.ok(titles.some((t) => t.includes('capability-excess')));
  assert.equal(new Set(titles).size, titles.length, 'no duplicate hypotheses');
  for (const h of hs) {
    assert.equal(h.status, 'PROPOSED');
    assert.ok(h.probe.tool && h.probe.args, 'every hypothesis has a minimal test');
  }
  assert.throws(() => transition(hs[0], 'BOGUS'));
});

test('planner: objective/scope/plan shape + next action targets cheapest open hypothesis', () => {
  const eng = loadEngagement(baseEng);
  const plan = initPlan(eng, surface);
  assert.match(plan.objective, /authorized boundary/);
  assert.equal(plan.scope, 'mcp:t');
  assert.ok(plan.hypotheses.length >= 3);
  assert.match(plan.next_action, /^test hypothesis H-1/);
  recordObservation(plan, { kind: 'x', note: 'y' });
  assert.equal(plan.observations.length, 1);
  assert.equal(nextHypotheses(plan).length, plan.hypotheses.length);
});

test('validation: CONFIRMED requires reproducibility + controlled difference; anomaly alone rejects', () => {
  const h = { probe: { tool: 'notes.search', args: { query: 'x' }, baseline: { query: 'z' }, signal: 'boundary-escape' } };
  const atk = { text: '{"hits":[{"id":1,"confidential":true,"title":"board-minutes"}]}', latencyMs: 1 };
  const base = { text: '{"hits":[]}', latencyMs: 1 };
  const confirmed = grade(h, { attacks: [atk, atk], baselines: [base] });
  assert.equal(confirmed.grade, 'CONFIRMED');
  assert.ok(confirmed.confidence >= 90);
  const notRepro = grade(h, { attacks: [atk], baselines: [base] });
  assert.equal(notRepro.confirmed, false, 'single run cannot confirm');
  const noDiff = grade(h, { attacks: [{ ...atk, text: base.text }, { ...atk, text: base.text }], baselines: [base] });
  assert.equal(noDiff.grade, 'REJECTED');
  const errOnly = grade(h, { attacks: [{ error: { code: -1, message: 'x' } }], baselines: [] });
  assert.equal(errOnly.grade, 'INCONCLUSIVE');
});

test('attack graph: nodes, typed edges, and chained-impact elevation', () => {
  const findings = [
    { id: 'F-1', title: 'inj', severity: 'high', status: 'CONFIRMED', info: { noAuth: true, reachesSensitive: true } },
    { id: 'F-2', title: 'capx', severity: 'critical', status: 'CONFIRMED', info: { noAuth: true, reachesSensitive: true, enables: 'F-3' } },
    { id: 'F-3', title: 'trav', severity: 'high', status: 'CONFIRMED', info: { noAuth: true, reachesSensitive: true } },
  ];
  const g = buildGraph(findings);
  assert.ok(g.nodes.some((n) => n.id === 'entry'));
  assert.ok(g.nodes.some((n) => n.id === 'res:sensitive-data'));
  assert.ok(g.edges.some((e) => e.kind === 'privilege-transition' && e.from === 'F-2' && e.to === 'F-3'));
  const impact = chainImpact(g, findings);
  assert.equal(impact.combinedSeverity, 'critical');
  assert.ok(impact.paths.length >= 3);
  const txt = renderGraph(g, impact);
  assert.match(txt, /ATTACK GRAPH/);
});

test('root cause: six questions answered; payload blacklisting rejected as a fix', () => {
  const finding = { id: 'F-1', title: 'query-injection via notes.search:query', probe: { tool: 'notes.search', args: { query: 'x' } }, evidence: { signal: 'boundary-escape' } };
  const rc = analyze(finding, { labSourceMap: { 'notes.search': { file: 'f.js', marker: 'M', component: 'c' } } });
  assert.ok(rc.what && rc.where && rc.why && rc.failedTrustBoundary && rc.brokenAssumption && rc.componentToChange, 'all six answers present');
  assert.equal(rc.category, 'unsafe-query-construction');
  assert.equal(rc.where.location.marker, 'M');
  assert.equal(recommendedFix(rc).strategy, 'parameterized-query');
  const weak = classifyProposedFix(rc, 'blacklist the observed injection string');
  assert.equal(weak.accepted, false);
  assert.equal(weak.fixClass, 'payload-workaround');
  const strong = classifyProposedFix(rc, 'use parameterized queries at the sink');
  assert.equal(strong.accepted, true);
});

test('AI Repair Contract: §30 shape + no-payload-blacklist constraint + yaml/dev-card render', () => {
  const finding = { id: 'F-1', status: 'CONFIRMED', severity: 'high', confidence: 100, title: 'query-injection via notes.search:query', probe: { tool: 'notes.search', args: { query: "' OR 1=1 --" }, baseline: { query: 'zzz' } }, evidence: { runs: { attacks: [{}, {}] } }, impacts: ['unauthorized read'] };
  const rc = analyze(finding);
  const c = buildContract(finding, rc, { engagementId: 'eng-1' });
  for (const k of ['finding_id', 'status', 'severity', 'location', 'entry_point', 'root_cause', 'evidence', 'impact', 'remediation', 'verification', 'replay']) assert.ok(k in c, 'contract has ' + k);
  assert.equal(c.verification.replay_original_attack, 'required');
  assert.equal(c.verification.regression_test, 'required');
  assert.ok(c.remediation.do_not.some((d) => /blacklist/i.test(d)));
  assert.equal(c.remediation.strategy, 'parameterized-query');
  assert.match(renderContractYaml(c), /finding_id: F-1[\s\S]*hach_id: HACH-SQL/);
  const card = renderDeveloperCard(c, rc);
  assert.match(card, /HIGH — F-1/);
  assert.match(card, /Do not:/);
  const reg = exportRegression(c);
  assert.equal(reg.id, 'regression-F-1');
  assert.deepEqual(reg.attack.args, { query: "' OR 1=1 --" });
  assert.ok(reg.attack.mustNotReturn.length >= 1);
  assert.ok(reg.legitimate.mustSucceed === true);
});
