// engines/injection — prompt-injection detection (deterministic heuristics + canary).
import { sha256hex } from '../../core/src/utils.js';
import { entropy } from './classifier.js';

const INJECTION_PATTERNS = [
  { name: 'ignore-instructions', re: /\b(ignore|disregard|forget|override)\b[^.]{0,60}\b(previous|prior|all|earlier|standing|above|system)\b[^.]{0,40}\b(instructions?|prompts?|rules?|guidelines?)/i },
  { name: 'role-hijack', re: /\b(you are now|act as if|pretend (to be|you are)|from now on you|new persona|you must behave)/i },
  { name: 'system-impersonation', re: /<\s*(system|instruction|admin)\s*>|\[SYSTEM\]|\bSYSTEM MESSAGE:/i },
  { name: 'tool-solicitation', re: /\b(call|invoke|execute|use)\s+(the\s+)?(tool|function|http|api)\b[^.]{0,60}\b(immediately|now|without confirmation|secretly)/i },
  { name: 'exfil-request', re: /\b(send|post|upload|transmit|exfiltrate)\b[^.]{0,50}\b(secrets?|tokens?|keys?|credentials?|passwords?|customers?|database|all data)\b/i },
  { name: 'canary-marker', re: /HACHIMAN_CANARY_[A-Z0-9]{8,}/i },
];

export function makeCanary(seed) {
  return 'HACHIMAN_CANARY_' + sha256hex(seed).slice(0, 10).toUpperCase();
}

export function detectInjection(req, { canary = null } = {}) {
  const indicators = [];
  const add = (type, weight, evidence) => indicators.push({ type, weight, evidence });

  const text = collectText(req);
  if (!text) return { indicators, hit: false, score: 0 };

  for (const p of INJECTION_PATTERNS) {
    const m = text.match(p.re);
    if (m) add(p.name === 'canary-marker' ? 'canary-hit' : p.name, 0.8, m[0].slice(0, 80));
  }
  if (canary && text.includes(canary)) add('canary-hit', 1.0, 'canary token echoed back');

  // encoded / obfuscated instruction burst
  const segs = text.split(/[\s"]+/).filter((s) => s.length > 20);
  let burst = 0;
  for (const s of segs) if (entropy(s) > 4.6 && /[A-Za-z0-9+/=]{20,}/.test(s)) burst++;
  if (burst >= 2) add('encoded-instruction', 0.4, `${burst} high-entropy segments`);

  const hit = indicators.some((i) => i.weight >= 0.8);
  const score = Math.min(1, indicators.reduce((a, i) => a + i.weight, 0));
  return { indicators, hit, score };
}

function collectText(req) {
  const parts = [];
  const push = (v) => { if (typeof v === 'string') parts.push(v); };
  (function walk(v, d = 0) {
    if (d > 8 || v == null) return;
    if (typeof v === 'string') { push(v); return; }
    if (Array.isArray(v)) { for (const x of v) walk(x, d + 1); return; }
    if (typeof v === 'object') for (const [k, val] of Object.entries(v)) {
      if (k === 'context' || k === 'content' || k === 'body' || k === 'message' || k === 'text' || k === 'input' || k === 'data' || typeof val === 'object') walk(val, d + 1);
      else if (typeof val === 'string') push(val);
    }
  })(req.params);
  if (typeof req.fetchedContent === 'string') parts.push(req.fetchedContent);
  return parts.join(' \n ');
}
