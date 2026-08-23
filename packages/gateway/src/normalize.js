// gateway/normalize — turn a raw MCP request into a normalized SecurityRequest.
import { uuid, nowMs } from '../../core/src/utils.js';

export function normalizeToolCall({ serverName, rpc, tenantId, sessionMeta = {}, source = 'gateway' }) {
  const params = rpc.params || {};
  return {
    id: uuid(),
    ts: nowMs(),
    tenantId,
    userId: sessionMeta.userId || null,
    agentId: sessionMeta.agentId || `agent:${serverName}`,
    sessionId: sessionMeta.sessionId || 'anon',
    source,
    mcpId: serverName,
    toolId: params.name || null,
    action: 'tools/call',
    params: params.arguments || {},
    rpcId: rpc.id,
    authzContext: { sessionToken: sessionMeta.sessionToken || null },
  };
}

export function normalizeInitialize({ serverName, rpc, tenantId, source = 'gateway' }) {
  return {
    id: uuid(), ts: nowMs(), tenantId, source,
    mcpId: serverName, toolId: null, action: 'initialize',
    params: rpc.params || {}, agentId: `agent:${serverName}`, sessionId: 'anon',
  };
}
