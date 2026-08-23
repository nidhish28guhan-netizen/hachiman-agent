// @hachiman/core — shared utilities. Pure stdlib, zero deps.
import { createHash, createHmac, randomUUID } from 'node:crypto';

export const uuid = () => randomUUID();
export const nowMs = () => Date.now();

export const clamp = (v, lo = 0, hi = 100) => Math.max(lo, Math.min(hi, v));

export const sha256hex = (s) => createHash('sha256').update(s).digest('hex');

export const hmacHex = (key, s) => createHmac('sha256', key).update(s).digest('hex');

/** Deterministic stable stringify (sorted keys). */
export function stableStringify(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(stableStringify).join(',') + ']';
  const keys = Object.keys(value).sort();
  return '{' + keys.map((k) => JSON.stringify(k) + ':' + stableStringify(value[k])).join(',') + '}';
}

/** EWMA step. alpha in (0,1]. */
export const ewma = (prev, next, alpha = 0.3) => prev == null ? next : prev + alpha * (next - prev);

/** Sliding-window counter with fixed-memory decay (per-minute buckets). */
export class RateWindow {
  constructor(windowMs = 15 * 60_000, bucketMs = 60_000) {
    this.windowMs = windowMs; this.bucketMs = bucketMs; this.buckets = new Map();
  }
  add(key, n = 1, ts = nowMs()) {
    const b = Math.floor(ts / this.bucketMs);
    let e = this.buckets.get(b);
    if (!e) { e = { total: 0, byKey: new Map() }; this.buckets.set(b, e); }
    e.total += n;
    for (const k of Array.isArray(key) ? key : [key]) e.byKey.set(k, (e.byKey.get(k) || 0) + n);
    this._evict(ts);
  }
  _evict(ts) {
    const cutoff = Math.floor((ts - this.windowMs) / this.bucketMs);
    for (const b of this.buckets.keys()) if (b < cutoff) this.buckets.delete(b);
  }
  totals(ts = nowMs()) {
    this._evict(ts);
    let total = 0; const byKey = new Map();
    for (const e of this.buckets.values()) {
      total += e.total;
      for (const [k, v] of e.byKey) byKey.set(k, (byKey.get(k) || 0) + v);
    }
    return { total, byKey };
  }
}

/** Basic redaction: mask likely secrets, keep shape markers. */
export function redactValue(str, maxLen = 400) {
  if (typeof str !== 'string') str = String(str);
  const masked = str
    .replace(/\b(sk-[A-Za-z0-9]{8,})\b/g, (m) => m.slice(0, 6) + '…REDACTED')
    .replace(/\b(AKIA[A-Z0-9]{12,})\b/g, (m) => m.slice(0, 6) + '…REDACTED')
    .replace(/\b(ghp_[A-Za-z0-9]{20,})\b/g, (m) => m.slice(0, 6) + '…REDACTED')
    .replace(/\b([A-Za-z0-9._%+-]+)@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b/g, '$1@…REDACTED');
  if (masked.length > maxLen) return masked.slice(0, maxLen) + `…[+${masked.length - maxLen} bytes truncated]`;
  return masked;
}

/** Extract a compact excerpt of content for evidence (bounded). */
export const excerpt = (s, n = 200) => (typeof s === 'string' ? s.slice(0, n) : String(s).slice(0, n));

export class EwmaStat {
  constructor(alpha = 0.3) { this.alpha = alpha; this.value = null; }
  add(x) { this.value = ewma(this.value, x, this.alpha); return this.value; }
  get() { return this.value ?? 0; }
}

/**
 * Param pattern hash: hash of param shape + value classes (not raw values),
 * so repeat calls with different concrete values share cache entries (doc 03 §4).
 */
export function shapeHash(params) {
  return sha256hex(stableStringify(describeShape(params))).slice(0, 16);
}
function describeShape(v, depth = 0) {
  if (depth > 8) return '!deep';
  if (v == null) return 'null';
  if (Array.isArray(v)) return ['array', ...v.slice(0, 8).map((x) => describeShape(x, depth + 1))];
  if (typeof v === 'string') {
    if (/^[a-z]+:\/\//i.test(v)) return 'string:url';
    if (v.length > 512) return 'string:long';
    if (entropy(v) > 4.5 && v.length > 32) return 'string:highentropy';
    return 'string';
  }
  if (typeof v === 'number') return Number.isInteger(v) ? 'int' : 'float';
  if (typeof v === 'boolean') return 'bool';
  if (typeof v === 'object') {
    const out = {};
    for (const k of Object.keys(v).sort()) out[k] = describeShape(v[k], depth + 1);
    return out;
  }
  return typeof v;
}
function entropy(s) {
  const f = new Map();
  for (const c of s) f.set(c, (f.get(c) || 0) + 1);
  let e = 0;
  for (const c of f.values()) { const p = c / s.length; e -= p * Math.log2(p); }
  return e;
}

/** Percentile helper (array must be sorted ascending). */
export function percentile(sortedArr, p) {
  if (!sortedArr.length) return 0;
  const idx = Math.min(sortedArr.length - 1, Math.floor((p / 100) * sortedArr.length));
  return sortedArr[idx];
}
