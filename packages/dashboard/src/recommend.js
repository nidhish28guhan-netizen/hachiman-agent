// dashboard/recommend — deterministic "what to do about this" engine.
// Maps real Hachiman decision reasons / anomalies / errors to concrete operator fixes.
// Every recommendation cites the exact CLI command or state that resolves it.
// No LLM, no guessing: rules keyed on the decision engine's actual reason strings.

const REASON_FIX = [
  { match: /^identity:unverified/, title: 'Caller identity not verified',
    fix: 'The request carried no valid session. Register the agent and use its token: `hachiman agent add <name> --allow <mcp>` → put the printed sessionToken in the client env (HACHIMAN_SESSION).' },
  { match: /^authorization:denied:no grants for subject/, title: 'Subject has no grants at all',
    fix: 'This identity was never authorized. Grant it: `hachiman agent add <name> --allow <mcp>`, or allow the server itself: `hachiman mcp allow <mcp>`.' },
  { match: /^authorization:denied:/, title: 'No matching grant (capability/resource/constraints)',
    fix: 'A grant exists but does not cover this tool or its constraints. Extend the grant (`hachiman agent add <name> --allow <mcp1,mcp2> --ttl h`) or narrow the call to a granted capability.' },
  { match: /^tool:unknown/, title: 'Tool not in the registry',
    fix: 'The MCP declared a tool Hachiman has not registered (capability drift). Re-scan before allowing: `hachiman scan <target> --full`. If the tool is legitimate, re-allow the server: `hachiman mcp allow <mcp>`.' },
  { match: /^tool:schema-violation/, title: 'Arguments violate the declared schema',
    fix: 'Fix the caller to match the tool inputSchema (extra/typed-wrong properties). If the schema changed upstream, re-scan the server to refresh the registry: `hachiman scan <target>`.' },
  { match: /^injection:/, title: 'Prompt-injection indicators detected',
    fix: 'Keep it blocked. Inspect the source content feeding this agent (fetched pages, documents, tool outputs). If this is a false positive on trusted input, review the policy pack: `hachiman policy show default`.' },
  { match: /^policy:/, title: 'Force rule in the active policy pack',
    fix: 'A policy pack rule forced this verdict. Inspect and, if intended, adjust: `hachiman policy list` / `hachiman policy show <pack>`.' },
  { match: /^authz:conditional/, title: 'Conditional authorization needs human sign-off',
    fix: 'The grant matched with conditions (e.g., budget). Approve/deny in the review queue: POST /api/review/<id>/resolve with X-Hachiman-Token.' },
  { match: /^failsafe:risk-critical/, title: 'Failsafe: risk above critical threshold',
    fix: 'Risk exceeded the critical floor even though lower gates passed. Investigate the request content first — do not simply raise thresholds. Check `hachiman threats` for the incident and the audit trail.' },
  { match: /^failsafe:risk-high-over-allow/, title: 'Failsafe: high risk on an otherwise-ALLOW',
    fix: 'Demoted to REVIEW by the risk failsafe. Resolve the pending review, or reduce the risky parameter content before retrying.' },
  { match: /^failsafe:untrusted-mcp-state/, title: 'MCP trust state is not TRUSTED',
    fix: 'The server is UNKNOWN/UNVERIFIED/RESTRICTED. Complete the loop: `hachiman scan <target> --production` then `hachiman mcp allow <mcp>` to move it to TRUSTED.' },
  { match: /^risk-floor:/, title: 'Risk floor raised by policy weights',
    fix: 'A policy risk floor dominated the decision. Review the weights in the active pack (`hachiman policy show <pack>`) and the flagged tool metadata.' },
];

const EVENT_FIX = {
  BLOCK: { title: 'Request blocked', base: 'Read the reason list on the row; the primary rule maps to a fix above. Repeated blocks from one subject → check `hachiman agents` for behavior chains.' },
  REVIEW: { title: 'Pending human review', base: 'Decide it: POST /api/review/<id>/resolve {"approve":true|false} with the X-Hachiman-Token header, or wait for the operator. Reviews never auto-approve.' },
  anomaly: { title: 'Behavior anomaly on an agent', base: 'Watch the chain: injection-then-action or burst patterns indicate a compromised session. Revoke it: re-issue a fresh session (`hachiman agent add`) and let the old one expire (--ttl), or quarantine the source MCP.' },
  quarantine: { title: 'Subject quarantined (sticky)', base: 'Quarantine blocks everything until deliberate release. Fix the root cause, then: `hachiman scan <target> --production` → `hachiman quarantine release <subject>` → re-authorize: `hachiman mcp allow <mcp>`.' },
  incident: { title: 'Incident opened', base: 'Containment is active. Pull the report: `hachiman report incident <id>`. Follow the timeline steps before releasing anything.' },
};

const OFFENSE_FIX = {
  UNRESOLVED: { title: 'Retest: exploit still works', base: 'Your fix missed the root cause. Re-open the contract: `hachiman fix <finding-id>` and implement `remediation.strategy` at `location` — do not blacklist the payload. Then retest.' },
  REGRESSION: { title: 'Retest: legitimate behavior broken', base: 'The fix violates the contract constraints (preserve legitimate behavior). Restore baseline behavior, keep the root-cause fix, then: `hachiman retest <finding-id> --fixed <conn>`.' },
  VERIFIED: { title: 'Fix verified', base: 'Original attack fails and legit behavior works. Ship it. The finding was exported as a regression scenario — keep it in future test runs.' },
};

/** System/transport errors (fetch failures, SSE loss, 5xx, fixture spawn errors). */
const SYSTEM_FIX = [
  { match: /Failed to fetch|network|ECONNREFUSED|fetch failed/i, title: 'Cannot reach the Hachiman gateway',
    fix: 'The guard is not running on this port. Start it: `hachiman guard --port 7420` (or the port this dashboard expects). If it crashed, rerun and read stderr.' },
  { match: /missing or bad X-Hachiman-Token|403/i, title: 'Admin action rejected (403)',
    fix: 'Send the header `X-Hachiman-Token: <token>` — the token guard was started with (default in dev: local-dev-token).' },
  { match: /not found|404/i, title: 'Unknown endpoint or object',
    fix: 'Check the id/spelling; list what exists first: `hachiman findings`, `hachiman threats`, or GET /api/status for server names.' },
  { match: /did not become ready|ENOENT|spawn/i, title: 'MCP server failed to start',
    fix: 'The downstream MCP process died or is not installed. Verify the command/path in .hachiman/hachiman.config.json; on Windows npm-installed servers need their .cmd shim (Hachiman applies `shell:true` for you when it spawns them).' },
  { match: /body too large|413/i, title: 'Request body rejected',
    fix: 'Shrink the payload below the 2MB wire limit.' },
  { match: /timeout/i, title: 'Downstream MCP timed out',
    fix: 'The protected server is too slow or hung. Check its process health; the decision stays fail-closed until it recovers.' },
];

/**
 * Main entry: classify any dashboard observation and return a recommendation.
 * Returns { kind, title, fix, severity: 'info'|'warn'|'bad' } or null if nothing actionable.
 */
export function recommendFix(evt) {
  if (evt == null || typeof evt !== 'object') return null;

  // decision events: { verdict: {decision, reasons[]}, req }
  const v = evt.verdict;
  if (v && v.decision) {
    const reasons = v.reasons || [];
    for (const r of reasons) {
      const rule = REASON_FIX.find((x) => x.match.test(r));
      if (rule) return { kind: 'decision', reason: r, title: rule.title, fix: rule.fix, severity: v.decision === 'BLOCK' ? 'bad' : 'warn' };
    }
    return { kind: 'decision', reason: reasons[0] || null, title: EVENT_FIX[v.decision]?.title || v.decision, fix: EVENT_FIX[v.decision]?.base || 'Inspect the audit trail: `hachiman audit --tail 50`.', severity: v.decision === 'ALLOW' ? 'info' : 'warn' };
  }

  // offense retest results
  if (evt.verdict && OFFENSE_FIX[evt.verdict]) {
    const o = OFFENSE_FIX[evt.verdict];
    return { kind: 'offense', title: o.title, fix: o.base, severity: evt.verdict === 'VERIFIED' ? 'info' : 'bad' };
  }

  // SSE channel events
  for (const ch of ['anomaly', 'quarantine', 'incident']) {
    if (evt._channel === ch || evt.kind === ch || (ch === 'anomaly' && evt.agentId && evt.score != null)) {
      const o = EVENT_FIX[ch];
      return { kind: ch, title: o.title, fix: o.base, severity: ch === 'anomaly' ? 'warn' : 'bad' };
    }
  }

  // errors: { error: 'message' } or thrown message strings
  const msg = evt.error || evt.message || '';
  if (msg) {
    const rule = SYSTEM_FIX.find((x) => x.match.test(String(msg)));
    if (rule) return { kind: 'system', title: rule.title, fix: rule.fix, severity: 'bad' };
    return { kind: 'system', title: 'Error surfaced', fix: 'Check the guard logs and `hachiman audit --tail 50`. If reproducible, file it with the exact reason list.', severity: 'warn' };
  }
  return null;
}

export const RULE_COUNTS = { reasons: REASON_FIX.length, events: Object.keys(EVENT_FIX).length, offense: Object.keys(OFFENSE_FIX).length, system: SYSTEM_FIX.length };
