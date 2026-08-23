// srg — Security Resource Governor + operation modes (doc 03 §7, 2.0 §8–9).
import { nowMs, EwmaStat } from '../../core/src/utils.js';

export const MODES = ['SENTINEL', 'WATCH', 'THREAT', 'INCIDENT', 'RECOVERY'];

export class SecurityResourceGovernor {
  /** deps: { bus, storage, tickMs } */
  constructor(deps, { tickMs = 500, minDwellMs = 50 } = {}) {
    this.deps = deps; this.bus = deps.bus; this.storage = deps.storage;
    this.tickMs = tickMs; this.minDwellMs = minDwellMs;
    this.mode = 'SENTINEL';
    this.modeSince = nowMs();
    this.threatLevel = 0;              // 0..3
    this.eventRate = new EwmaStat(0.3); // events/sec EMA
    this.queueDepth = 0;
    this.semanticBacklog = 0;
    this.lastCpu = process.cpuUsage();
    this.lastTick = nowMs();
    this.cpuPct = 0; this.memMb = 0;
    this.budget = this._budget();
    this.history = [];                  // mode transitions (bounded)
    this.timer = null;
    this.lastEventTs = nowMs();
    this.eventsSeen = 0;
    if (this.bus) this.bus.on('decisions', () => { this.eventsSeen++; this.lastEventTs = nowMs(); }, { shedClass: 8, name: 'srg.count' });
  }

  start() {
    if (this.timer) return this;
    this.timer = setInterval(() => this.tick(), this.tickMs);
    this.timer.unref?.();
    return this;
  }
  stop() { if (this.timer) clearInterval(this.timer); this.timer = null; }

  /** Raise threat level (0..3) from detections. */
  raiseThreat(level) { this.threatLevel = Math.max(this.threatLevel, level); }
  lowerThreat(level = 0) { this.threatLevel = Math.min(this.threatLevel, level); }

  tick() {
    const now = nowMs();
    const dt = Math.max(1, now - this.lastTick); this.lastTick = now;
    const cpu = process.cpuUsage(this.lastCpu); this.lastCpu = process.cpuUsage();
    this.cpuPct = Math.min(100, Math.round(((cpu.user + cpu.system) / 1000) / dt * 100));
    this.memMb = Math.round(process.memoryUsage.rss() / 1048576);
    const rate = (this.eventsSeen / (dt / 1000)); this.eventsSeen = 0;
    this.eventRate.add(rate);
    this.queueDepth = this.bus?.stats?.depth || 0;

    // decay semantic backlog
    this.semanticBacklog = Math.max(0, this.semanticBacklog - 1);

    const target = this._targetMode();
    if (target !== this.mode && now - this.modeSince >= this.minDwellMs) this._transition(target);
    this.budget = this._budget();
  }

  _targetMode() {
    const rate = this.eventRate.get();
    // Entry thresholds with hysteresis: entering is easier than leaving (dwell enforced elsewhere)
    if (this.threatLevel >= 3) return 'INCIDENT';
    if (this.threatLevel >= 2) return 'THREAT';
    if (this.threatLevel >= 1 || rate > 200 || this.queueDepth > 1000) return 'WATCH';
    if (this.mode === 'INCIDENT' || this.mode === 'THREAT') return 'RECOVERY';
    if (this.mode === 'RECOVERY' && rate <= 50) return 'SENTINEL';
    if (this.mode === 'WATCH' && rate <= 50 && this.queueDepth < 100) return 'SENTINEL';
    return this.mode === 'SENTINEL' ? 'SENTINEL' : this.mode;
  }

  _transition(to) {
    const from = this.mode; this.mode = to; this.modeSince = nowMs();
    if (to === 'SENTINEL' || to === 'WATCH') this.lowerThreat(0);
    if (to === 'RECOVERY' && from === 'INCIDENT') this.lowerThreat(1);
    this.history.push({ from, to, ts: nowMs(), threat: this.threatLevel });
    if (this.history.length > 200) this.history.splice(0, this.history.length - 200);
    this.storage?.audit({ kind: 'mode-change', action: `${from}->${to}`, actor: 'hachiman:srg', detail: { threatLevel: this.threatLevel, rate: Math.round(this.eventRate.get()), queueDepth: this.queueDepth } });
    this.bus?.publish('srg', { mode: to, from, ts: nowMs(), budget: this._budget() }, { shedClass: 4 });
  }

  _budget() {
    const pressure = Math.max(0, Math.min(1, (this.cpuPct / 90) * 0.5 + (this.memMb / 512) * 0.2 + (this.queueDepth / 5000) * 0.3));
    let analysisDepth = 3, semanticConcurrency = 2, cacheTtlScale = 1, samplingRate = 1;
    if (pressure > 0.8) { analysisDepth = 0; semanticConcurrency = 0; cacheTtlScale = 0.25; samplingRate = 0.1; }
    else if (pressure > 0.6) { analysisDepth = 1; semanticConcurrency = 1; cacheTtlScale = 0.5; samplingRate = 0.5; }
    else if (pressure > 0.4) { analysisDepth = 2; cacheTtlScale = 0.75; }
    if (this.mode === 'INCIDENT') { semanticConcurrency = Math.min(semanticConcurrency, 1); }
    if (this.mode === 'SENTINEL') { semanticConcurrency = 0; }
    return { analysisDepth, semanticConcurrency, cacheTtlScale, samplingRate };
  }

  /** Gate semantic escalation: only when budget allows a slot. */
  allowSemantic() {
    if ((this.budget?.semanticConcurrency ?? 0) <= 0) return false;
    this.semanticBacklog++;
    return true;
  }

  snapshot() {
    return {
      mode: this.mode, modeSince: this.modeSince, threatLevel: this.threatLevel,
      cpuPct: this.cpuPct, memMb: this.memMb, eventRate: Math.round(this.eventRate.get() * 10) / 10,
      queueDepth: this.queueDepth, semanticBacklog: this.semanticBacklog,
      budget: this.budget, lastTransitions: this.history.slice(-5),
    };
  }
}
