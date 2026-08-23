// scanner/scanner — pre-deployment scan pipeline (WF-03): discover → map → select → test → score.
import { uuid, nowMs, sha256hex } from '../../core/src/utils.js';
import { HttpMcpClient } from '../../gateway/src/mcp-client.js';
import { mapSurface, selectTests } from './surface.js';
import { TEST_CATALOG } from './tests.js';
import { computeSafetyScore, surfaceHash } from './scoring.js';
import * as trust from '../../engines/src/trust.js';
import { startSink } from '../../../fixtures/host.js';

export class Scanner {
  /** deps: { storage, authz, canary?, bus? } */
  constructor(deps) { this.deps = deps; }

  /**
   * Scan a target. `conn` = {url} or {command,args} (MCP transport).
   * opts: { suites?, sinkUrl?, by? }
   * Returns {scanId, surface, findings, score}.
   */
  async scan({ target, conn, suites = null, sinkUrl = null, by = 'operator' }) {
    const scanId = uuid();
    const t0 = nowMs();

    // 1) authorization verification — scanner must hold a scan grant or be invoked by operator
    const authzOk = by === 'operator' ||
      (this.deps.authz && this.deps.authz.evaluate(by, 'scanner.run', target).decision !== 'DENY');
    if (!authzOk) {
      this._record(scanId, target, 'aborted-unauthorized', [], null);
      return { scanId, aborted: 'authorization denied', surface: null, findings: [], score: null };
    }

    const client = conn.url ? new HttpMcpClient(conn.url) : null;
    if (!client) throw new Error('scanner: url transport required for scan');

    // sink for exfil evidence
    let sink = null;
    if (!sinkUrl) { sink = await startSink(); sinkUrl = sink.url; }
    const canary = 'CANARY-' + sha256hex(scanId).slice(0, 8).toUpperCase();

    let surface = null, findings = [], testsRun = [];
    const probes = { allCallsSucceeded: true, descriptionsComplete: true };
    try {
      // 2) discover capabilities
      const initResult = await client.request('initialize', {
        protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'hachiman-scanner', version: '0.1.0' },
      });
      let tools = (await client.request('tools/list', {})).tools || [];
      surface = mapSurface({ name: target, initResult, tools });
      for (const tl of tools) if (!tl.description) probes.descriptionsComplete = false;

      // 3) select applicable tests only
      const catalog = suites ? TEST_CATALOG.filter((t) => suites.includes(t.category)) : TEST_CATALOG;
      const applicable = selectTests(surface, catalog);

      // 4-8) controlled tests + evidence + validation
      const ctx = {
        surface, sinkUrl, canary,
        call: async (name, args) => {
          try { return { result: await client.request('tools/call', { name, arguments: args }) }; }
          catch (e) { probes.allCallsSucceeded = false; return { error: e.message }; }
        },
        listTools: async () => (await client.request('tools/list', {})).tools || [],
        sinkHits: async () => sink ? sink.hits() : await readSinkHits(sinkUrl),
        sinkReset: async () => sink ? sink.reset() : await resetSink(sinkUrl),
      };
      for (const test of applicable) {
        testsRun.push(test.id);
        try {
          const out = await test.run(ctx);
          for (const f of out) {
            f.id = uuid(); f.scanId = scanId; f.target = target; f.testId = test.id; f.ts = nowMs();
            findings.push(f);
          }
        } catch (e) {
          findings.push({ id: uuid(), scanId, target, category: test.category, title: `test ${test.id} errored: ${e.message}`, severity: 'info', confidence: 100, evidence: [String(e.stack || e).slice(0, 200)], remediation: 'Inspect harness/environment; inconclusive tests are never counted as pass.', testId: test.id, ts: nowMs() });
        }
      }
    } finally {
      if (sink) sink.stop();
    }

    // 9) classify + 10) score
    findings = dedupe(findings);
    const score = computeSafetyScore({ scanId, target, findings, surface, testsRun, probes });

    // 11) persist + baseline
    this._record(scanId, target, 'completed', findings, score);

    // 12) trust handoff
    if (this.deps.storage) trust.fromScan(this.deps.storage, `mcp:${target}`, score, scanId);

    this.deps.bus?.publish('scan', { scanId, target, status: 'completed', score, durationMs: nowMs() - t0 }, { shedClass: 4 });
    return { scanId, surface, findings, score, durationMs: nowMs() - t0 };
  }

  _record(scanId, target, status, findings, score) {
    if (!this.deps.storage) return;
    this.deps.storage.q.scanIns.run(scanId, target, 'all', status,
      JSON.stringify(findings), score ? JSON.stringify(score) : null, score?.baselineId || null, nowMs());
    if (score) {
      this.deps.storage.kvSet(`baseline:${target}`, score.baseline);
      this.deps.storage.audit({ kind: 'scan', subject: `mcp:${target}`, action: 'scan-completed', actor: 'hachiman:scanner', risk: score.overall == null ? null : (100 - score.overall), detail: { scanId, status: score.status, overall: score.overall, findings: findings.length } });
    }
  }

  /** Reassess against baseline (WF-09 drift). */
  async reassess({ target, conn }) {
    const baseline = this.deps.storage?.kvGet(`baseline:${target}`);
    const res = await this.scan({ target, conn, by: 'operator' });
    const drift = !baseline || surfaceHash(res.surface) !== baseline.toolHash || Math.abs(res.score.overall - baseline.overall) > 15;
    return { ...res, drift, baseline };
  }
}

function dedupe(findings) {
  const seen = new Set(); const out = [];
  for (const f of findings) {
    const key = f.testId + '::' + f.title + '::' + f.severity;
    if (seen.has(key)) continue; seen.add(key); out.push(f);
  }
  return out;
}
async function readSinkHits(sinkUrl) { try { return (await (await fetch(sinkUrl + '/hits')).json()).hits || []; } catch { return []; } }
async function resetSink(sinkUrl) { try { await fetch(sinkUrl + '/reset', { method: 'POST' }); } catch {} }
