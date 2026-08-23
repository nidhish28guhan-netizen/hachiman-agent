// @hachiman/core — bounded event bus with backpressure + shed ladder.
// Implements doc 03 §6 (bounded runtime) and doc 02 invariants.
import { nowMs } from './utils.js';

/**
 * Shed classes (doc 03 §6 / 2.0 §10). Lower number = more critical = shed last.
 * 1 enforcement, 2 authorization, 3 threat-detect, 4 incident-evidence,
 * 5 policy-eval, 6 semantic, 7 historical-analytics, 8 non-critical reporting.
 */
export const SHED = { ENFORCE: 1, AUTHZ: 2, THREAT: 3, EVIDENCE: 4, POLICY: 5, SEMANTIC: 6, ANALYTICS: 7, REPORT: 8 };

/**
 * A synchronous, bounded publish/subscribe bus. Subscribers are invoked inline.
 * Backpressure: if a subscriber's in-flight depth exceeds `maxDepth`, events for
 * that subscriber are shed according to class priority (higher class number drops first).
 */
export class EventBus {
  constructor({ maxDepth = 10_000 } = {}) {
    this.maxDepth = maxDepth;
    this.subs = new Map(); // channel -> [{fn, classes:Set, name}]
    this.stats = { published: 0, delivered: 0, shed: [], depth: 0 };
    this._depth = 0;
    this._lastShed = new Map(); // key -> ts (dedupe shed notifications)
  }

  on(channel, fn, opts = {}) {
    if (!this.subs.has(channel)) this.subs.set(channel, []);
    const rec = { fn, classes: new Set(opts.shedClasses || [SHED.REPORT]), name: opts.name || fn.name || 'anon' };
    this.subs.get(channel).push(rec);
    return () => this._off(channel, rec);
  }
  _off(channel, rec) {
    const list = this.subs.get(channel); if (!list) return;
    const i = list.indexOf(rec); if (i >= 0) list.splice(i, 1);
  }

  /** Decide if this subscriber should shed given class under pressure.
   *  Ladder (doc 03 §6): classes 1–2 (enforce/authz) NEVER shed; the rest shed
   *  when their criticality is at/under the event's shed class under overload. */
  _shouldShed(rec, shedClass) {
    if (!rec.classes.size) return false;
    const min = Math.min(...rec.classes);
    if (min <= 2) return false;          // enforcement & authorization never shed
    return min >= shedClass;             // shed non-critical subscribers under pressure
  }

  publish(channel, evt, { shedClass = SHED.ENFORCE } = {}) {
    this.stats.published++;
    const list = this.subs.get(channel);
    if (!list || !list.length) return;
    this._depth++; this.stats.depth = Math.max(this.stats.depth, this._depth);
    const overloaded = this._depth > this.maxDepth;
    try {
      for (const rec of list) {
        if (overloaded && this._shouldShed(rec, shedClass)) {
          this.stats.shed.push({ channel, sub: rec.name, shedClass, ts: nowMs() });
          if (this.stats.shed.length > 1000) this.stats.shed.splice(0, this.stats.shed.length - 1000);
          continue;
        }
        try { rec.fn(evt, channel); this.stats.delivered++; }
        catch (err) {
          // Never let one subscriber kill the bus. Record + continue.
          this._emitError(channel, rec, err);
        }
      }
    } finally { this._depth--; this.stats.depth = Math.max(0, this._depth); }
  }

  _emitError(channel, rec, err) {
    const key = channel + ':' + rec.name;
    const ts = nowMs();
    if ((this._lastShed.get(key) || 0) > ts - 1000) return; // debounce
    this._lastShed.set(key, ts);
    if (this.onBusError) { try { this.onBusError({ channel, sub: rec.name, message: String(err?.message || err) }); } catch {} }
  }

  snapshot() {
    return { published: this.stats.published, delivered: this.stats.delivered, shedCount: this.stats.shed.length, maxDepth: this.stats.depth };
  }
}
