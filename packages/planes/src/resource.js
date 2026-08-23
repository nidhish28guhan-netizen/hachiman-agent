// planes/resource — universal resource descriptor (Hachiman 2.0, P1).
// One shape describes every protected target: MCP tools, API routes, shells,
// k8s objects, containers, databases, CI pipelines, data flows, identities.
// Deterministic + pure: no IO, no LLM. The decision core stays authoritative.

export const RESOURCE_TYPES = [
  'mcp', 'api', 'app', 'desktop', 'mobile', 'game', 'cloud', 'k8s', 'container',
  'db', 'ci', 'supply', 'data', 'identity', 'service', 'shell',
];

export function resourceKey(type, id) {
  if (!RESOURCE_TYPES.includes(type)) throw new Error('resource:type-invalid:' + type);
  if (!id || typeof id !== 'string') throw new Error('resource:id-invalid');
  return `${type}:${id}`;
}

export function describeResource(type, id, attrs = {}) {
  return { type, id, key: resourceKey(type, id), attrs: attrs || {} };
}

export function parseResourceKey(key) {
  const i = String(key || '').indexOf(':');
  if (i <= 0) throw new Error('resource:key-invalid:' + key);
  const type = key.slice(0, i), id = key.slice(i + 1);
  if (!RESOURCE_TYPES.includes(type)) throw new Error('resource:type-invalid:' + type);
  return { type, id, key, attrs: {} };
}

/**
 * Normalize a universal decision request WITHOUT touching legacy requests.
 * Accepts req.resource as an object {type,id,attrs} or a string key "type:id".
 * Sets: resource.key, adapter-friendly toolId/capability/gateResource,
 * ctx.resourceType/adapterId. Legacy fields (mcpId/toolId) win when present —
 * existing corpora keep byte-identical behavior.
 */
export function universalizeRequest(req) {
  if (!req || typeof req !== 'object' || req.resource == null) return req;
  let res = typeof req.resource === 'string' ? parseResourceKey(req.resource) : { ...req.resource };
  if (!RESOURCE_TYPES.includes(res.type)) throw new Error('resource:type-invalid:' + res.type);
  if (!res.id) throw new Error('resource:id-invalid');
  res.attrs = res.attrs || {};
  res.key = resourceKey(res.type, res.id);

  const out = { ...req, resource: res };
  if (res.type === 'mcp') {
    if (!out.mcpId) out.mcpId = res.id;
    if (!out.toolId) out.toolId = res.attrs.tool || (out.action && out.action !== 'tools/call' ? out.action : undefined);
  } else if (res.type === 'api') {
    if (!out.toolId) out.toolId = `api.${String(out.action || 'REQUEST').toUpperCase()}`;
    if (!out.capability) out.capability = `api.${String(out.action || 'REQUEST').toUpperCase()}`;
  } else if (res.type === 'shell') {
    if (!out.toolId) out.toolId = 'shell.exec';
    if (!out.capability) out.capability = 'shell.exec';
  } else if (res.type === 'k8s') {
    if (!out.toolId) out.toolId = `k8s.${res.attrs.operation || 'admit'}`;
    if (!out.capability) out.capability = `k8s.${res.attrs.operation || 'admit'}`;
  }
  if (!out.capability && res.type !== 'mcp') out.capability = `${res.type}.${out.action || 'act'}`;
  // Capability is the BARE VERB; fine-grained scope rides the RESOURCE field
  // (wildcard-capable: 'api:billing:*', 'k8s:prod/*'), never the capability.
  if (out.gateResource == null) {
    if (res.type === 'mcp') out.gateResource = res.id;
    else if (res.type === 'api') out.gateResource = `api:${res.id}${res.attrs.path ? ':' + res.attrs.path : ''}`;
    else if (res.type === 'k8s') out.gateResource = `k8s:${res.attrs.namespace || 'default'}/${res.id}`;
    else out.gateResource = res.key;
  }
  if (!out.agentId && req.subject) out.agentId = req.subject;
  out.ctx = { ...(out.ctx || {}), resourceType: res.type, adapterId: req.adapterId || out.ctx?.adapterId };
  return out;
}

/** Default capability string for a request (authorization hard gate input). */
export function capabilityOf(req) {
  return req.capability || `tool.${req.toolId || '*'}`;
}
