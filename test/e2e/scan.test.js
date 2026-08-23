// test/e2e/scan.test.js — pre-deployment scanner against real fixture MCPs.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createNode } from '../../lib/hachiman.js';
import { startFixture, startSink } from '../../fixtures/host.js';
import { renderScanReport } from '../../packages/reporting/src/render.js';

test('scan: benign notes → PRODUCTION READY, high score', async () => {
  const fixture = await startFixture('notes');
  const node = createNode({ storage: { path: ':memory:' }, policyPacks: ['default'], srg: { enabled: false } });
  try {
    const res = await node.scanner.scan({ target: 'notes', conn: { url: fixture.url }, by: 'operator' });
    assert.ok(res.score, 'score produced');
    assert.ok(res.score.overall >= 85, `notes overall ${res.score.overall}`);
    assert.equal(res.score.status, 'PRODUCTION_READY');
    assert.equal(res.score.counts.critical, 0);
    const trustRow = node.storage.q.trustGet.get('mcp:notes');
    assert.equal(trustRow.state, 'ASSESSED');
  } finally { await node.stop(); fixture.stop(); }
});

test('scan: malicious sync-tool → low score, NOT PRODUCTION READY, exfil finding', async () => {
  const sink = await startSink();
  const fixture = await startFixture('sync-tool', { env: { SINK_URL: sink.url } });
  const node = createNode({ storage: { path: ':memory:' }, policyPacks: ['default'], srg: { enabled: false } });
  try {
    const res = await node.scanner.scan({ target: 'sync-tool', conn: { url: fixture.url }, by: 'operator' });
    assert.ok(res.score.overall < 70, `sync-tool overall ${res.score.overall}`);
    assert.notEqual(res.score.status, 'PRODUCTION_READY');
    const titles = res.findings.map((f) => f.title).join('\n');
    assert.ok(res.findings.some((f) => f.severity === 'high' && /unrestricted external http/i.test(f.title)), 'exfil behavior detected:\n' + titles);
    assert.ok(res.findings.some((f) => /excessive database access/i.test(f.title)), 'bulk db export flagged');
    // evidence: the sink actually received the canary
    const hits = await sink.hits();
    assert.ok(hits.length >= 1, 'sink recorded exfil attempt');
  } finally { await node.stop(); fixture.stop(); sink.stop(); }
});

test('scan: helpful-assistant → indirect-injection chain CRITICAL', async () => {
  const sink = await startSink();
  const fixture = await startFixture('helpful-assistant', { env: { SINK_URL: sink.url } });
  const node = createNode({ storage: { path: ':memory:' }, policyPacks: ['default'], srg: { enabled: false } });
  try {
    const res = await node.scanner.scan({ target: 'helpful-assistant', conn: { url: fixture.url }, by: 'operator' });
    const chain = res.findings.find((f) => /injection.*chain|chain/i.test(f.title) && f.severity === 'critical');
    assert.ok(chain, 'chain finding present: ' + res.findings.map((f) => f.title).join(' | '));
    assert.notEqual(res.score.status, 'PRODUCTION_READY');
  } finally { await node.stop(); fixture.stop(); sink.stop(); }
});

test('scan: param-smuggler → honors undeclared params detected', async () => {
  const sink = await startSink();
  const fixture = await startFixture('param-smuggler', { env: { SINK_URL: sink.url } });
  const node = createNode({ storage: { path: ':memory:' }, policyPacks: ['default'], srg: { enabled: false } });
  try {
    const res = await node.scanner.scan({ target: 'param-smuggler', conn: { url: fixture.url }, by: 'operator' });
    assert.ok(res.findings.some((f) => /undeclared|smuggl/i.test(f.title)), 'param smuggling flagged');
  } finally { await node.stop(); fixture.stop(); sink.stop(); }
});

test('scan: schema-drifter → capability drift detected', async () => {
  const fixture = await startFixture('schema-drifter');
  const node = createNode({ storage: { path: ':memory:' }, policyPacks: ['default'], srg: { enabled: false } });
  try {
    const res = await node.scanner.scan({ target: 'schema-drifter', conn: { url: fixture.url }, by: 'operator' });
    assert.ok(res.findings.some((f) => /drift|surface changed/i.test(f.title)), 'drift flagged: ' + res.findings.map((f) => f.title).join(' | '));
  } finally { await node.stop(); fixture.stop(); }
});

test('scan: identity-spoof → impersonation CRITICAL + secret exposure', async () => {
  const fixture = await startFixture('identity-spoof');
  const node = createNode({ storage: { path: ':memory:' }, policyPacks: ['default'], srg: { enabled: false } });
  try {
    const res = await node.scanner.scan({ target: 'identity-spoof', conn: { url: fixture.url }, by: 'operator' });
    const titles = res.findings.map((f) => f.title).join('\n');
    assert.ok(res.findings.some((f) => /impersonation/i.test(f.title) && f.severity === 'critical'), 'impersonation critical:\n' + titles);
    assert.ok(res.findings.some((f) => /secret|auth/i.test(f.title)), 'auth flaw/secret exposure flagged');
    assert.equal(res.score.counts.critical >= 1, true);
    const md = renderScanReport({ target: 'identity-spoof', surface: res.surface, findings: res.findings, score: res.score });
    assert.ok(md.includes('PRODUCTION SAFETY REPORT'));
  } finally { await node.stop(); fixture.stop(); }
});

test('scan: unauthorized scanner subject is refused (authorization-first)', async () => {
  const fixture = await startFixture('notes');
  const node = createNode({ storage: { path: ':memory:' }, policyPacks: ['default'], srg: { enabled: false } });
  try {
    const res = await node.scanner.scan({ target: 'notes', conn: { url: fixture.url }, by: 'agent:not-allowed' });
    assert.equal(res.aborted, 'authorization denied');
  } finally { await node.stop(); fixture.stop(); }
});
