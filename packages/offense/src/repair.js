// offense/repair — AI Repair Contract (doc-06 §30, §39, §40).
// Hachiman's signature output: a direct engineering task for the AI builder,
// rendered as structured YAML/JSON AND as the §39 developer card.
import { recommendedFix } from './rootcause.js';

let contractSeq = 0;

export function buildContract(finding, rootCause, { engagementId } = {}) {
  const tool = rootCause.where.tool;
  const param = rootCause.where.parameter;
  const originalArgs = finding.probe ? finding.probe.args : {};
  const legitimateArgs = finding.probe && finding.probe.baseline ? finding.probe.baseline : null;
  const markers = markersFor(rootCause.category);

  const contract = {
    finding_id: finding.id,
    hach_id: 'HACH-' + ({'unsafe-query-construction':'SQL','missing-path-containment':'PATH','excessive-capability':'CAPX','unrestricted-egress':'EGR'}[rootCause.category] || 'GEN') + '-' + String(++contractSeq).padStart(4,'0'),
    engagement: engagementId || null,
    status: finding.status === 'CONFIRMED' ? 'confirmed' : 'unconfirmed',
    severity: finding.severity,
    location: rootCause.where.location || { file: null, component: rootCause.componentToChange },
    entry_point: { tool, parameter: param },
    root_cause: { category: rootCause.category, description: rootCause.why },
    evidence: {
      reproducible: (finding.evidence?.runs?.attacks?.length || 0) >= 2,
      validation: finding.status === 'CONFIRMED' ? 'confirmed' : 'unconfirmed',
      confidence: finding.confidence,
    },
    impact: finding.impacts || [rootCause.why],
    remediation: {
      strategy: recommendedFix(rootCause).strategy,
      description: recommendedFix(rootCause).description,
      constraints: ['preserve authentication', 'preserve response schema', 'preserve legitimate behavior'],
      do_not: ['blacklist the observed payload', 'filter specific attack strings'],
    },
    verification: { replay_original_attack: 'required', regression_test: 'required' },
    // machine-readable replay instructions for the retest engine
    replay: { tool, originalArgs, legitimateArgs, successMarkers: markers },
  };
  contractSeq++;
  return contract;
}

function markersFor(category) {
  // markers that indicate "the exploit still works" when retesting
  if (category === 'unsafe-query-construction') return ['confidential":true', "confidential:\\s*true", 'board-minutes', 'salaries'];
  if (category === 'missing-path-containment') return ['HACH-TRAVERSAL-SENTINEL'];
  if (category === 'excessive-capability') return ['confidential":true', 'board-minutes', 'salaries'];
  return [];
}

/** Structured YAML rendering (doc-06 §30 exact shape). */
export function renderContractYaml(c) {
  const lines = [];
  lines.push(`finding_id: ${c.finding_id}`);
  if (c.hach_id) lines.push(`hach_id: ${c.hach_id}`);
  lines.push(`status: ${c.status}`);
  lines.push(`severity: ${c.severity}`);
  lines.push('location:');
  lines.push(`  file: ${c.location.file || 'unknown'}`);
  if (c.location.marker) lines.push(`  marker: ${c.location.marker}`);
  lines.push(`  component: ${c.location.component || ''}`);
  lines.push('entry_point:');
  lines.push(`  tool: ${c.entry_point.tool}`);
  lines.push(`  parameter: ${c.entry_point.parameter || ''}`);
  lines.push('root_cause:');
  lines.push(`  category: ${c.root_cause.category}`);
  lines.push(`  description: ${c.root_cause.description}`);
  lines.push('evidence:');
  lines.push(`  reproducible: ${c.evidence.reproducible}`);
  lines.push(`  validation: ${c.evidence.validation}`);
  lines.push(`  confidence: ${c.evidence.confidence}%`);
  lines.push('impact:');
  for (const i of c.impact) lines.push(`  - ${i}`);
  lines.push('remediation:');
  lines.push(`  strategy: ${c.remediation.strategy}`);
  lines.push('  constraints:');
  for (const x of c.remediation.constraints) lines.push(`    - ${x}`);
  lines.push('  do_not:');
  for (const x of c.remediation.do_not) lines.push(`    - ${x}`);
  lines.push('verification:');
  lines.push(`  replay_original_attack: ${c.verification.replay_original_attack}`);
  lines.push(`  regression_test: ${c.verification.regression_test}`);
  return lines.join('\n');
}

/** Developer card (doc-06 §39). */
export function renderDeveloperCard(c, rootCause) {
  const where = c.location.file ? `${c.location.file}${c.location.marker ? ` (marker ${c.location.marker})` : ''}` : c.entry_point.tool;
  return [
    `${String(c.severity).toUpperCase()} — ${c.finding_id}${c.hach_id ? ' (' + c.hach_id + ')' : ''}`,
    '',
    'Problem:',
    `  ${c.root_cause.description}`,
    '',
    'Where:',
    `  ${where} — ${c.entry_point.tool}()${c.entry_point.parameter ? `, parameter "${c.entry_point.parameter}"` : ''}`,
    '',
    'Why:',
    `  ${rootCause?.brokenAssumption || c.root_cause.description}`,
    '',
    'Impact:',
    c.impact.map((i) => `  - ${i}`).join('\n'),
    '',
    'Fix:',
    `  ${c.remediation.description}`,
    '',
    'Do not:',
    `  ${c.remediation.do_not.join('; ')}`,
    '',
    'Retest:',
    '  Hachiman will replay the original test after the fix.',
  ].join('\n');
}
