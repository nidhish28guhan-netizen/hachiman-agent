// gateway/metrics — self-instrumentation for SPO + dashboard performance page.
import { nowMs } from '../../core/src/utils.js';

export class Metrics {
  constructor() { this.reset(); }
  reset() {
    this.startedAt = nowMs();
    this.decisions = 0;
    this.byDecision = { ALLOW: 0, REVIEW: 0, BLOCK: 0 };
    this.byPath = { fast: 0, semantic: 0, cached: 0 };
    this.cacheHits = 0;
    this.semanticCalls = 0;
    this.tokens = { in: 0, out: 0 };
    this.latencies = new Float64Array(4096); this.latN = 0;
    this.stageTimings = {};
  }
  recordDecision(verdict) {
    this.decisions++;
    this.byDecision[verdict.decision] = (this.byDecision[verdict.decision] || 0) + 1;
    this.byPath[verdict.path] = (this.byPath[verdict.path] || 0) + 1;
    if (verdict.path === 'cached') this.cacheHits++;
    if (verdict.path === 'semantic') this.semanticCalls++;
    this.latencies[this.latN++ % 4096] = verdict.latencyMs ?? 0;
  }
  addTokens(tin, tout) { this.tokens.in += tin || 0; this.tokens.out += tout || 0; }
  stage(name, ms) { (this.stageTimings[name] ||= []).push(ms); }
  snapshot() {
    const arr = Array.from(this.latencies.slice(0, Math.min(this.latN, 4096))).sort((a, b) => a - b);
    const pct = (p) => arr.length ? arr[Math.min(arr.length - 1, Math.floor((p / 100) * arr.length))] : 0;
    const fastPathPct = this.decisions ? Math.round(((this.byPath.fast || 0) + (this.byPath.cached || 0)) / this.decisions * 1000) / 10 : 0;
    return {
      decisions: this.decisions,
      byDecision: { ...this.byDecision },
      byPath: { ...this.byPath },
      fastPathPct,
      cacheHitPct: this.decisions ? Math.round((this.byPath.cached || 0) / this.decisions * 1000) / 10 : 0,
      semanticCalls: this.semanticCalls,
      semanticPct: this.decisions ? Math.round((this.semanticCalls / this.decisions) * 1000) / 10 : 0,
      tokens: { ...this.tokens },
      tokensPerDecision: this.decisions ? Math.round(((this.tokens.in + this.tokens.out) / this.decisions) * 100) / 100 : 0,
      latency: { p50: pct(50), p95: pct(95), p99: pct(99), max: arr.length ? arr[arr.length - 1] : 0 },
      uptimeMs: nowMs() - this.startedAt,
    };
  }
}
