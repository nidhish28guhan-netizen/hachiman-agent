// engines/semantic — SemanticAnalyzer SPI + evidence-only local heuristic analyzer.
// Contract (doc 01 §9): analyzer output is EVIDENCE ONLY. It can never emit a verdict.
import { clamp } from '../../core/src/utils.js';

export const SEMANTIC_SCHEMA = { riskDeltaRange: [-15, 25], maxIn: 800, maxOut: 400 };

/** Clamp + structurally validate analyzer output. Malformed ⇒ {risk_delta:0, invalid:true}. */
export function validateSemanticOutput(out) {
  if (!out || typeof out !== 'object') return { risk_delta: 0, indicators: [], self_confidence: 0, invalid: true };
  const rd = typeof out.risk_delta === 'number' ? clamp(out.risk_delta, SEMANTIC_SCHEMA.riskDeltaRange[0], SEMANTIC_SCHEMA.riskDeltaRange[1]) : 0;
  const indicators = Array.isArray(out.indicators) ? out.indicators.filter((i) => i && typeof i.type === 'string').slice(0, 10) : [];
  const sc = typeof out.self_confidence === 'number' ? clamp(out.self_confidence, 0, 1) : 0;
  return { risk_delta: rd, indicators, self_confidence: sc, invalid: false };
}

/**
 * Build the compact security context (doc 03 §3). Hard cap ~800 tokens:
 * metadata extract only, never raw conversation.
 */
export function buildCompactContext(req, extra = {}) {
  const ctx = {
    agent: req.agentId || null,
    tool: req.toolId || null,
    action: req.action || null,
    data_class: req.dataClass || null,
    destination: req.destination ? { kind: req.destination.kind, known: !!req.destination.known, host: req.destination.host || null } : null,
    injection_indicators: (req.injection?.indicators || []).map((i) => `${i.type}:${i.weight}`),
    behavior: extra.behavior || null,
    matched_rules: extra.matchedRules || [],
  };
  const s = JSON.stringify(ctx);
  return s.length > 3200 ? s.slice(0, 3200) : s;
}

/**
 * Local deterministic heuristic analyzer (default provider). A real deployment
 * plugs an LLM behind the same interface with semantic.enabled gated by policy/SRG.
 */
export class LocalHeuristicAnalyzer {
  get name() { return 'local-heuristic'; }
  get tokensPerCall() { return 0; } // no remote tokens: rule-based
  async analyze(compactCtx) {
    const indicators = [];
    let delta = 0;
    const d = compactCtx.destination;
    if (d && d.kind === 'external' && !d.known) {
      if (['confidential', 'restricted'].includes(compactCtx.data_class)) {
        delta += 18; indicators.push({ type: 'exfil-pattern', evidence: 'confidential→unknown-external', weight: 0.9 });
      } else {
        delta += 6; indicators.push({ type: 'egress-novel', evidence: 'unknown external destination', weight: 0.4 });
      }
    }
    if ((compactCtx.injection_indicators || []).length) {
      delta += 10; indicators.push({ type: 'injection-corroborated', evidence: compactCtx.injection_indicators.join(','), weight: 0.7 });
    }
    const b = compactCtx.behavior;
    if (b && b.anomalyScore > 0.5) { delta += 8; indicators.push({ type: 'behavior-anomaly', evidence: `score=${b.anomalyScore}`, weight: 0.6 }); }
    return { risk_delta: clamp(delta, -15, 25), indicators, self_confidence: clamp(0.5 + indicators.length * 0.15, 0, 0.95), notes: 'heuristic' };
  }
}
