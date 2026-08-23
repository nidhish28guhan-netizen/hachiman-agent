// runtime/monitor — behavior profiles, anomaly detection, attack-chain correlation.
// Fixed-memory sketches only (doc 03 §6): windows + tiny sequence trackers.
import { RateWindow, nowMs, EwmaStat } from '../../core/src/utils.js';

const NOVEL_DEST_BASELINE = {}; // per-deployment known-destinations are learned

export class BehaviorMonitor {
  constructor(storage, bus, { windowMs = 15 * 60_000 } = {}) {
    this.storage = storage; this.bus = bus;
    this.profiles = new Map(); // agentId -> profile
    this.windowMs = windowMs;
    this.recentBlocks = []; // for chain detection
    this.chainPatterns = [
      { name: 'read-then-exfil', seq: [/^tools\/call$/, /read|get|query|list/, /send|post|http|request|transfer/] },
      { name: 'repeated-authz-failure', seq: ['authz-denied', 'authz-denied', 'authz-denied'] },
      { name: 'injection-then-action', seq: ['injection', /\.+/] },
    ];
    if (bus) this._subscribe();
  }

  _subscribe() {
    this.bus.on('decisions', (evt) => this.observe(evt), { shedClass: 3, name: 'monitor.observe' });
  }

  /** Update profile from a decision event. Returns profile (for tests). */
  observe(evt) {
    const { req, verdict } = evt;
    const agentId = req.agentId || req.mcpId || 'unknown';
    const p = this._profile(agentId);
    const ts = evt.ts || nowMs();

    p.calls.add([req.mcpId, req.toolId], 1, ts);
    p.lastTools.push(`${req.mcpId}/${req.toolId}`);
    if (p.lastTools.length > 24) p.lastTools.splice(0, p.lastTools.length - 24);
    if (verdict.decision === 'BLOCK') {
      this.recentBlocks.push({ ts, mcpId: req.mcpId, toolId: req.toolId, risk: verdict.risk, reasons: verdict.reasons });
      if (this.recentBlocks.length > 100) this.recentBlocks.splice(0, this.recentBlocks.length - 100);
    }
    if (req.destination?.host) {
      const n = p.destinations.get(req.destination.host) || 0;
      p.destinations.set(req.destination.host, n + 1);
      if (p.destinations.size > 200) {
        const first = p.destinations.keys().next().value; p.destinations.delete(first);
      }
    }

    // anomaly signals
    const signals = [];
    const rate = p.calls.totals(ts);
    const perMin = rate.total / Math.max(1, this.windowMs / 60_000);
    p.rateStat.add(perMin);
    if (perMin > Math.max(12, p.rateStat.get() * 3)) signals.push({ type: 'rate-burst', v: perMin });

    if (req.destination?.host && !p.seenDest.has(req.destination.host)) {
      p.seenDest.add(req.destination.host);
      if (p.seenDest.size > 3) signals.push({ type: 'novel-destination', v: req.destination.host });
    }
    if (verdict.reasons?.some((r) => r.startsWith('authorization:denied'))) {
      p.authzFailures++;
      if (p.authzFailures >= 3) signals.push({ type: 'repeated-authz-failure', v: p.authzFailures });
    } else p.authzFailures = Math.max(0, p.authzFailures - 1);
    if (verdict.reasons?.some((r) => r.startsWith('injection'))) signals.push({ type: 'injection', v: 1 });

    if (signals.length) this._emitAnomaly(agentId, signals, evt);
    return p;
  }

  _emitAnomaly(agentId, signals, evt) {
    const score = Math.min(1, signals.reduce((a, s) => a + weight(s.type), 0));
    const chain = this._matchChain(agentId);
    this.bus.publish('anomaly', {
      type: 'behavior-anomaly', agentId, signals, score, chain, ts: nowMs(),
      mcpId: evt.req.mcpId, toolId: evt.req.toolId, requestId: evt.req.id,
    }, { shedClass: 3 });
  }

  _matchChain(agentId) {
    const recent = this.recentBlocks.slice(-6);
    if (recent.length >= 2) {
      const reasonsFlat = recent.flatMap((b) => b.reasons || []);
      if (reasonsFlat.some((r) => r.startsWith('injection')) && recent.length >= 2) return 'injection-then-action';
      const toolStr = recent.map((b) => b.toolId || '').join(' ');
      if (/(read|get|query)/.test(toolStr) && /(send|post|http|request|transfer)/.test(toolStr)) return 'read-then-exfil';
    }
    return null;
  }

  _profile(agentId) {
    let p = this.profiles.get(agentId);
    if (!p) {
      p = {
        agentId, calls: new RateWindow(this.windowMs), lastTools: [], destinations: new Map(),
        seenDest: new Set(), authzFailures: 0, rateStat: new EwmaStat(0.2), anomalyScore: 0,
      };
      this.profiles.set(agentId, p);
    }
    return p;
  }

  /** Behavior snapshot for risk context (doc 02 WF-05 step 9). */
  getBehavior(agentId, toolId) {
    const p = this._profile(agentId);
    const totals = p.calls.totals();
    const toolShare = totals.byKey.get(toolId) ? (totals.byKey.get(toolId) / Math.max(1, totals.total)) : 0;
    return {
      anomalyScore: Math.round((p.anomalyScore + (recentBlockBurst(this.recentBlocks) ? 0.3 : 0)) * 100) / 100,
      callsPerWindow: totals.total,
      toolShare: Math.round(toolShare * 100) / 100,
      distinctDestinations: p.destinations.size,
    };
  }

  setAnomalyScore(agentId, score) { const p = this._profile(agentId); p.anomalyScore = Math.max(p.anomalyScore, score); }
  decayAnomaly(agentId, factor = 0.5) { const p = this.profiles.get(agentId); if (p) p.anomalyScore *= factor; }

  snapshot() {
    return [...this.profiles.values()].map((p) => ({
      agentId: p.agentId, calls: p.calls.totals().total, anomalyScore: Math.round(p.anomalyScore * 100) / 100,
      destinations: p.destinations.size, recentTools: p.lastTools.slice(-6),
    }));
  }
}

function weight(type) {
  switch (type) {
    case 'rate-burst': return 0.35;
    case 'novel-destination': return 0.3;
    case 'repeated-authz-failure': return 0.4;
    case 'injection': return 0.5;
    default: return 0.2;
  }
}
function recentBlockBurst(blocks, windowMs = 60_000, n = 3) {
  const now = nowMs();
  return blocks.filter((b) => now - b.ts < windowMs).length >= n;
}
