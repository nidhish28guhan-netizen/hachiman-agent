// offense/graph — Attack Graph (doc-06 §28).
// Findings become connected nodes; typed edges; chained impact can exceed individual severities.
const SEV_ORDER = ['low', 'medium', 'high', 'critical'];

export function buildGraph(findings) {
  const nodes = [];
  const edges = [];
  const node = (id, kind, label, meta = {}) => { nodes.push({ id, kind, label, ...meta }); return id; };

  const entryId = node('entry', 'entry', 'caller (authorized lab session)', {});
  const sensitiveId = node('res:sensitive-data', 'resource', 'sensitive records (confidential notes, secrets)');
  const externalId = node('res:external-sink', 'resource', 'local evidence sink (ROE-only exfil demo)');

  for (const f of findings) {
    const fid = node(f.id, 'finding', f.title, { severity: f.severity, status: f.status });
    const info = f.info || {};
    const entryEdge = info.authBypass || info.noAuth ? 'auth-dependency' : 'workflow';
    edges.push({ from: entryId, to: fid, kind: entryEdge, why: 'reachable via authorized lab session' });
    if (info.reachesSensitive) edges.push({ from: fid, to: sensitiveId, kind: 'data-flow', why: 'response crosses into confidential records' });
    if (info.exfilToSink) edges.push({ from: fid, to: externalId, kind: 'data-flow', why: 'demonstrated movement toward a sink (canary)' });
    if (info.enables && findings.some((g) => g.id === info.enables)) {
      edges.push({ from: fid, to: info.enables, kind: 'privilege-transition', why: info.enablesWhy || 'obtained capability enables next step' });
    }
  }
  return { nodes, edges };
}

/**
 * Chain impact (deterministic, documented formula):
 * any path entry→…→sensitive-data or entry→…→external-sink elevates importance:
 * combinedSeverity = max(node severities on path) elevated by path length ≥ 2.
 */
export function chainImpact(graph, findings) {
  const sevRank = (s) => Math.max(0, SEV_ORDER.indexOf(s));
  const byId = Object.fromEntries(findings.map((f) => [f.id, f]));
  const terminals = new Set(['res:sensitive-data', 'res:external-sink']);
  const paths = [];

  // simple DFS from entry over edges (graphs are small by construction)
  const adj = {};
  for (const e of graph.edges) (adj[e.from] = adj[e.from] || []).push(e);
  const walk = (id, path) => {
    if (terminals.has(id)) { paths.push([...path, id]); return; }
    for (const e of adj[id] || []) {
      if ([...path, id].includes(e.to)) continue;
      walk(e.to, [...path, id]);
    }
  };
  walk('entry', []);

  let maxSeverity = null, worstPath = null;
  for (const p of paths) {
    const sevs = p.filter((id) => byId[id]).map((id) => sevRank(byId[id].severity));
    if (sevs.length === 0) continue;
    let combined = Math.max(...sevs);
    if (p.length >= 3) combined = Math.min(SEV_ORDER.length - 1, combined + 1); // chained path elevation
    if (maxSeverity === null || combined > sevRank(maxSeverity)) {
      maxSeverity = SEV_ORDER[combined]; worstPath = p;
    }
  }
  return { paths, combinedSeverity: maxSeverity, longestPath: worstPath, chained: (worstPath || []).length >= 3 };
}

export function renderGraph(graph, impact) {
  const lines = ['# ATTACK GRAPH', '', '## Nodes'];
  for (const n of graph.nodes) lines.push(`- [${n.kind}] ${n.id} — ${n.label}${n.severity ? ` (severity ${n.severity})` : ''}`);
  lines.push('', '## Edges');
  for (const e of graph.edges) lines.push(`- ${e.from} →(${e.kind})→ ${e.to}  // ${e.why}`);
  lines.push('', '## Chained impact');
  for (const p of impact.paths) lines.push('- ' + p.join(' → '));
  lines.push(`- combined severity: ${impact.combinedSeverity || 'none'}${impact.chained ? ' (elevated by chain length)' : ''}`);
  return lines.join('\n');
}
