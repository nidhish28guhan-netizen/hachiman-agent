// offense/attack — Controlled Attack Executor (doc-06 §6, §27, §34, §46).
// Runs exactly one controlled probe per call, through a live MCP connection,
// obeying the engagement budget + scope. All probe traffic is captured as evidence.
import { engagementApi as engApi, EngagementViolation } from './engagement.js';
import { nowMs } from '../../core/src/utils.js';

/** Execute one probe (or its benign baseline) against the target. */
export async function executeProbe(eng, client, { tool, args }, canary) {
  engApi.assertTool(eng, tool);
  engApi.spendRequest(eng);
  const t0 = nowMs();
  let result = null, error = null;
  try {
    const res = await client.request('tools/call', { name: tool, arguments: args });
    result = res;
  } catch (e) {
    error = { code: e.code, message: String(e.message) };
  }
  const ms = nowMs() - t0;
  engApi.chapter(eng, ms);
  const text = extractText(result);
  const run = { ts: nowMs(), tool, args, latencyMs: ms, error, text };
  if (canary && text && text.includes(canary)) run.canarySeen = true;
  return run;
}

/**
 * Run a hypothesis's validating test: attack run(s) + optional benign baseline,
 * so the validator can compute a controlled response difference.
 */
export async function runValidatingTest(eng, client, hypothesis, { reps = 2, canary } = {}) {
  const runs = { attacks: [], baselines: [] };
  for (let i = 0; i < reps; i++) {
    runs.attacks.push(await executeProbe(eng, client, { tool: hypothesis.probe.tool, args: hypothesis.probe.args }, canary));
  }
  if (hypothesis.probe.baseline) {
    runs.baselines.push(await executeProbe(eng, client, { tool: hypothesis.probe.tool, args: hypothesis.probe.baseline }));
  }
  return runs;
}

export function extractText(result) {
  if (!result) return '';
  if (typeof result === 'string') return result;
  if (Array.isArray(result.content)) return result.content.map((c) => c.text || '').join('\n');
  return JSON.stringify(result);
}

export { EngagementViolation };
