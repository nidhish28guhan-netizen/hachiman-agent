// adapters/mcp — the MCP adapter (Hachiman 2.0, P2).
// Wraps the existing McpGateway as the first registered adapter WITHOUT changing
// its behavior: gateway internals keep calling normalizeToolCall directly and
// golden verdicts stay identical. This module is the translator + metadata seam
// that other planes are grafted next to.
import { normalizeToolCall } from '../../gateway/src/normalize.js';

export function makeMcpAdapter(node) {
  return {
    id: 'mcp',
    protocol: 'mcp-jsonrpc',
    resourceTypes: ['mcp'],
    description: 'Model Context Protocol gateway (HTTP pass-through + stdio bridge) — the original Hachiman ingress.',
    ingress: node.gateway,

    /** Translate a raw MCP JSON-RPC tools/call into a universal decision request. */
    toDecisionRequest({ serverName, rpc, sessionMeta = {}, tenantId = 'local' }) {
      const req = normalizeToolCall({ serverName, rpc, tenantId, sessionMeta, source: 'adapter:mcp' });
      return {
        ...req,
        resource: { type: 'mcp', id: serverName, attrs: { tool: req.toolId } },
        adapterId: 'mcp',
      };
    },

    /** Adapter-supplied risk metadata (decision-engine resourceMeta seam). */
    metadata(resource) {
      const tool = resource?.attrs?.tool || null;
      const row = node.storage.q.toolGet.get(resource.id, tool || '');
      if (!row && tool) return null;
      const target = row || node.storage.q.toolList.all(resource.id)[0];
      if (!target) return null;
      try { return JSON.parse(target.riskMeta || '{}'); } catch { return null; }
    },
  };
}
