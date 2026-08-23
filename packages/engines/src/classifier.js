// engines/classifier — metadata-first data classification.
// Classes: public < internal < confidential < restricted.
import { sha256hex } from '../../core/src/utils.js';

export const DATA_CLASSES = ['public', 'internal', 'confidential', 'restricted'];
export const classRank = (c) => DATA_CLASSES.indexOf(c);

const SECRET_PATTERNS = [
  { name: 'openai-key', re: /\bsk-[A-Za-z0-9_-]{16,}\b/ },
  { name: 'aws-key', re: /\bAKIA[0-9A-Z]{16}\b/ },
  { name: 'github-token', re: /\bgh[pousr]_[A-Za-z0-9]{20,}\b/ },
  { name: 'slack-token', re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/ },
  { name: 'private-key-block', re: /-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----/ },
  { name: 'jwt', re: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{6,}\b/ },
];
const PII_PATTERNS = [
  { name: 'email', re: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/ },
  { name: 'pan', re: /\b[A-Z]{5}[0-9]{4}[A-Z]\b/ },
  { name: 'aadhaar', re: /\b[2-9][0-9]{3}[\s-]?[0-9]{4}[\s-]?[0-9]{4}\b/ },
  { name: 'gstin', re: /\b[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z][A-Z0-9][A-Z][A-Z0-9]\b/ },
  { name: 'phone', re: /(?:\+91[\s-]?)?[6-9][0-9]{9}\b/ },
];

/** Luhn check for likely card numbers. */
export function luhnOk(digits) {
  let sum = 0, dbl = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits.charCodeAt(i) - 48;
    if (d < 0 || d > 9) return false;
    if (dbl) { d *= 2; if (d > 9) d -= 9; }
    sum += d; dbl = !dbl;
  }
  return sum % 10 === 0;
}
const CARD_RE = /\b(?:\d[ -]?){13,19}\b/g;

/** Shannon entropy of a string (bits/char). */
export function entropy(s) {
  if (!s) return 0;
  const f = new Map();
  for (const c of s) f.set(c, (f.get(c) || 0) + 1);
  let e = 0;
  for (const c of f.values()) { const p = c / s.length; e -= p * Math.log2(p); }
  return e;
}

/** Detect egress indicators inside params; returns destination descriptor or null. */
export function detectDestination(obj, { knownExternalHosts = [], internalHosts = [] } = {}, depth = 0) {
  if (depth > 6 || obj == null) return null;
  const EGRESS_KEYS = ['url', 'uri', 'host', 'hostname', 'endpoint', 'webhook', 'dest', 'destination', 'server', 'domain'];
  if (typeof obj === 'object') {
    for (const [k, v] of Object.entries(obj)) {
      const lk = k.toLowerCase();
      if (EGRESS_KEYS.includes(lk) && typeof v === 'string' && v.length > 3) {
        const host = extractHost(v);
        const known = knownExternalHosts.includes(host) || internalHosts.includes(host);
        return { kind: internalHosts.includes(host) ? 'internal' : 'external', host, known, class: internalHosts.includes(host) ? 'internal' : 'external' };
      }
      if (typeof v === 'object') {
        const r = detectDestination(v, { knownExternalHosts, internalHosts }, depth + 1);
        if (r) return r;
      }
    }
  }
  return null;
}
export function extractHost(s) {
  try { if (/^[a-z]+:\/\//i.test(s)) return new URL(s).host; } catch {}
  const m = String(s).match(/^([A-Za-z0-9.-]+)(?::\d+)?(\/|$)/);
  return m ? m[1] : String(s).slice(0, 64);
}

/** Classify metadata (and optionally content). Returns {dataClass, matches, sizes}. */
export function classify(req, { inspectContent = false } = {}) {
  const matches = [];
  const sizes = { paramBytes: 0 };
  const bump = (name) => matches.push(name);

  const scanString = (s) => {
    const bounded = s.length > 4000 ? s.slice(0, 4000) : s;
    for (const p of SECRET_PATTERNS) if (p.re.test(bounded)) bump('secret:' + p.name);
    for (const p of PII_PATTERNS) if (p.re.test(bounded)) bump('pii:' + p.name);
    const cards = bounded.match(CARD_RE) || [];
    for (const c of cards) if (luhnOk(c.replace(/[\s-]/g, ''))) bump('pii:card');
  };

  // Param values are ALWAYS scanned for secret/PII patterns (deterministic fast-path check).
  // `inspectContent` additionally opts into deeper content analysis (fetchedContent).
  walk(req.params, (v) => { sizes.paramBytes += String(v).length; if (typeof v === 'string') scanString(v); });
  if (inspectContent && typeof req.fetchedContent === 'string') scanString(req.fetchedContent);
  // metadata-only heuristics: large payloads & high-entropy values imply sensitivity risk
  if (sizes.paramBytes > 4096) bump('meta:large-payload');
  let hiEnt = 0;
  walk(req.params, (v) => { if (typeof v === 'string' && v.length > 24 && entropy(v) > 4.2) hiEnt++; });
  if (hiEnt > 0) bump('meta:high-entropy');

  const hasSecret = matches.some((m) => m.startsWith('secret:'));
  const hasCard = matches.includes('pii:card');
  const hasPii = matches.some((m) => m.startsWith('pii:'));
  let dataClass = 'internal';
  if (hasSecret || hasCard) dataClass = 'restricted';
  else if (hasPii) dataClass = 'confidential';
  else if (matches.includes('meta:large-payload') || matches.includes('meta:high-entropy')) dataClass = 'internal';
  if (req.dataClassOverride) dataClass = req.dataClassOverride; // corpus/test hook
  return { dataClass, matches, sizes, fingerprint: sha256hex(JSON.stringify(matches)) };
}

function walk(v, fn, depth = 0) {
  if (depth > 8) return;
  if (v == null) return;
  if (typeof v === 'string' || typeof v === 'number') { fn(v); return; }
  if (Array.isArray(v)) { for (const x of v) walk(x, fn, depth + 1); return; }
  if (typeof v === 'object') for (const x of Object.values(v)) walk(x, fn, depth + 1);
}
