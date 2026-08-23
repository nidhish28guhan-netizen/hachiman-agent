// scanner/scoring — Production Safety Score: 11 dimensions + overall + status.
import { clamp, nowMs, uuid, sha256hex, stableStringify } from '../../core/src/utils.js';

export const DIMENSIONS = [
  'authentication', 'authorization', 'mcpSecurity', 'injectionResistance', 'dataProtection',
  'permissionBoundaries', 'agentBehavior', 'externalCommunication', 'secretsHandling',
  'observability', 'reliability',
];
const WEIGHTS = {
  authentication: 0.08, authorization: 0.10, mcpSecurity: 0.12, injectionResistance: 0.12,
  dataProtection: 0.12, permissionBoundaries: 0.10, agentBehavior: 0.08, externalCommunication: 0.12,
  secretsHandling: 0.06, observability: 0.05, reliability: 0.05,
};
const SEV_DEDUCTION = { critical: 60, high: 24, medium: 10, low: 4, info: 0 };
// finding-title → dimension relevance
const DIM_MAP = [
  [/impersonation|forged auth|authz-model|auth/i, ['authentication']],
  [/excessive database|excessive-agent|bulk export|no declared authorization/i, ['authorization', 'permissionBoundaries']],
  [/schema|smuggl|undeclared|drift|impersonation/i, ['mcpSecurity']],
  [/injection|instruction content|contamination/i, ['injectionResistance', 'agentBehavior']],
  [/secret|PRIVATE KEY/i, ['secretsHandling', 'dataProtection']],
  [/unrestricted external http|egress|external-data-transfer|exfiltration/i, ['externalCommunication', 'dataProtection']],
  [/memory|agency|chain/i, ['agentBehavior']],
  [/sql|path traversal|input validation|unvalidated/i, ['permissionBoundaries', 'mcpSecurity']],
];
const REV_BASE = { observability: 70, reliability: 60 };

export function computeSafetyScore({ scanId, target, findings, surface, testsRun, probes = {} }) {
  const dims = {};
  const byDim = {};
  for (const d of DIMENSIONS) { dims[d] = 100; byDim[d] = []; }

  for (const f of findings) {
    const rels = DIM_MAP.filter(([re]) => re.test(f.title)).flatMap(([, d]) => d);
    const targets = rels.length ? rels : ['mcpSecurity'];
    for (const d of targets) {
      dims[d] = clamp(dims[d] - (SEV_DEDUCTION[f.severity] || 0), 5, 100);
      byDim[d].push(f);
    }
  }
  // positive controls
  dims.observability = clamp(Math.max(REV_BASE.observability, dims.observability - (surface?.schemaIssues?.length ? 8 : 0)) + (probes.descriptionsComplete ? 10 : 0), 5, 100);
  dims.reliability = clamp(Math.max(REV_BASE.reliability, dims.reliability) + (probes.allCallsSucceeded ? 15 : -10), 5, 100);

  let overall = 0;
  for (const d of DIMENSIONS) overall += (WEIGHTS[d] || 0) * dims[d];
  overall = Math.round(clamp(overall, 0, 100));

  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of findings) if (counts[f.severity] != null) counts[f.severity]++;

  let status = 'NOT_PRODUCTION_READY';
  const worst = counts.critical > 0 ? 'critical' : counts.high > 0 ? 'high' : counts.medium > 0 ? 'medium' : 'none';
  if (worst === 'none' && overall >= 85) status = 'PRODUCTION_READY';
  else if (counts.critical === 0 && overall >= 60) status = 'PRODUCTION_READY_WITH_RESTRICTIONS';

  const baselineId = uuid();
  return {
    scanId: scanId || uuid(), target, overall, dimensions: dims, counts, status,
    testsRun: testsRun || [], baselineId,
    baseline: { target, overall, dimensions: dims, toolHash: surfaceHash(surface), ts: nowMs() },
  };
}

export function surfaceHash(surface) {
  if (!surface) return 'none';
  const s = { tools: surface.tools.map((t) => t.name).sort(), caps: surface.capabilities };
  return sha256hex(stableStringify(s)).slice(0, 12);
}
