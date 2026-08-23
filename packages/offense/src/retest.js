// offense/retest — Automatic Fix Verification + Security Regression (doc-06 §31, §32).
// 1) replay the ORIGINAL attack exactly → must now fail. 2) replay the LEGITIMATE
// baseline → must still work. Only then is a fix VERIFIED. A code change alone
// never constitutes verification.
import { executeProbe } from './attack.js';
import { createMcpClient } from '../../gateway/src/mcp-client.js';
import { extractText } from './attack.js';

export async function verifyFix(eng, contract, fixedConn) {
  const client = createMcpClient(fixedConn);
  if (typeof client.start === 'function') await client.start();
  try {
    const rec = contract.replay || {};
    const attackRun = await executeProbe(eng, client, { tool: rec.tool, args: rec.originalArgs });
    const attackText = extractText(attackRun);
    const markerStillPresent = (rec.successMarkers || []).some((m) => attackText.includes(m));

    let baselineOk = true, baselineRun = null;
    if (rec.legitimateArgs) {
      baselineRun = await executeProbe(eng, client, { tool: rec.tool, args: rec.legitimateArgs });
      const bt = extractText(baselineRun);
      baselineOk = !baselineRun.error && bt.length > 0 && !/outside public boundary/i.test(bt);
    }

    let verdict, reason;
    if (markerStillPresent) { verdict = 'UNRESOLVED'; reason = 'original exploit still succeeds on the fixed build — rework required'; }
    else if (!baselineOk) { verdict = 'REGRESSION'; reason = 'fix broke legitimate behavior'; }
    else { verdict = 'VERIFIED'; reason = 'original attack no longer reproducible AND legitimate behavior preserved'; }

    return {
      findingId: contract.finding_id,
      verdict, reason,
      fixedTarget: fixedConn.fixture || fixedConn.url || 'unknown',
      attackReplay: { args: rec.originalArgs, exploitStillWorks: markerStillPresent, markerSeen: markerStillPresent },
      baseline: rec.legitimateArgs ? { args: rec.legitimateArgs, ok: baselineOk } : null,
      ts: Date.now(),
    };
  } finally {
    await Promise.resolve(typeof client.stop === 'function' ? client.stop() : undefined).catch(() => {});
  }
}

/** Export one confirmed finding as a permanent regression scenario (corpus-compatible shape). */
export function exportRegression(contract) {
  const rec = contract.replay || {};
  return {
    id: `regression-${contract.finding_id}`,
    description: `security regression: ${contract.finding_id} must stay fixed`,
    tool: rec.tool,
    attack: { args: rec.originalArgs, mustNotReturn: rec.successMarkers || [] },
    legitimate: rec.legitimateArgs ? { args: rec.legitimateArgs, mustSucceed: true } : null,
  };
}
