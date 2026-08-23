// offense/rootcause — Root-Cause Engine (doc-06 §29).
// Answers the six questions per confirmed finding and classifies the correct fix
// as root-cause vs payload-workaround (blacklisting the observed payload is REJECTED).
const CATEGORIES = {
  'boundary-escape': { query: 'unsafe-query-construction', traversal: 'missing-path-containment' },
  'sensitive-data-reach': { default: 'excessive-capability' },
  'exfil-to-sink': { default: 'unrestricted-egress' },
};

const ROOT_CAUSE_FIXES = {
  'unsafe-query-construction': { strategy: 'parameterized-query', description: 'treat the parameter as data only; never concatenate it into a constructed filter/query' },
  'missing-path-containment': { strategy: 'path-containment-guard', description: 'normalize then verify the resolved path stays inside the intended directory boundary (including symlink real-path)' },
  'excessive-capability': { strategy: 'capability-removal-or-authorization', description: 'remove the over-privileged tool, or place it behind explicit authorization + audit' },
  'unrestricted-egress': { strategy: 'egress-allowlist', description: 'restrict outbound destinations to an allowlist; reject everything else' },
};

/** Build the root-cause answer set for one confirmed finding. */
export function analyze(finding, { labSourceMap } = {}) {
  const signal = finding.evidence?.signal || finding.signal || 'boundary-escape';
  const tool = (finding.probe && finding.probe.tool) || finding.tool || 'unknown';
  const param = finding.probe ? Object.keys(finding.probe.args || {})[0] : null;

  let category;
  if (signal === 'boundary-escape') {
    category = finding.title.includes('traversal') ? 'missing-path-containment' : 'unsafe-query-construction';
  } else {
    category = (CATEGORIES[signal] && (CATEGORIES[signal].default)) || 'unvalidated-input';
  }

  const src = labSourceMap && labSourceMap[tool];
  return {
    findingId: finding.id,
    what: finding.title,
    where: { tool, parameter: param || null, location: src ? { file: src.file, marker: src.marker, component: src.component } : null },
    why: describeWhy(category),
    failedTrustBoundary: boundary(category),
    brokenAssumption: assumption(category),
    componentToChange: src ? src.component : `${tool} handler`,
    category,
    fixClass: 'root-cause',
  };
}

function describeWhy(c) {
  return {
    'unsafe-query-construction': 'user-controlled input is concatenated into a constructed filter, so input is treated as control syntax',
    'missing-path-containment': 'path input is resolved without a containment check, so ../ escapes the intended directory',
    'excessive-capability': 'a tool exists with broader reach than its legitimate purpose and no authorization gate',
    'unrestricted-egress': 'the tool can send data to arbitrary destinations with no allowlist',
  }[c] || 'input reaches a security-sensitive sink without validation';
}

function boundary(c) {
  return {
    'unsafe-query-construction': 'data-vs-control boundary between user input and query syntax',
    'missing-path-containment': 'filesystem boundary (public/ area) between API-visible files and the rest of the sandbox',
    'excessive-capability': 'authorization boundary between caller capabilities and tool reach',
    'unrestricted-egress': 'network boundary between internal data and external destinations',
  }[c] || 'input validation boundary';
}

function assumption(c) {
  return {
    'unsafe-query-construction': '"callers will only send literal search terms, not query syntax"',
    'missing-path-containment': '"callers will only request files inside the public area"',
    'excessive-capability': '"this convenience tool will only be used by trusted operators"',
    'unrestricted-egress': '"the destination a caller supplies is safe"',
  }[c] || 'an unstated developer assumption about caller behavior';
}

/** A proposed fix is rejected when it targets the payload, not the defect (doc-06 §29 example). */
export function classifyProposedFix(rc, proposedFixText) {
  const t = String(proposedFixText || '').toLowerCase();
  const workaround = /blacklist|blocklist|reject the string|filter out the payload|ban the input|block this specific/i.test(t);
  return workaround
    ? { accepted: false, fixClass: 'payload-workaround', reason: 'fix targets the observed payload instead of the root cause (' + rc.category + ')' }
    : { accepted: true, fixClass: 'root-cause', reason: 'fix addresses the defect, not the payload' };
}

export function recommendedFix(rc) {
  return ROOT_CAUSE_FIXES[rc.category] || { strategy: 'validate-at-the-sink', description: 'validate/coerce input at the security-sensitive sink' };
}
