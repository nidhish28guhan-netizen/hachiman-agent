// scanner/surface — capability discovery + attack-surface mapping.
import { inferRiskMeta } from '../../gateway/src/gateway.js';

/** Build an attack-surface model from initialize + tools/list results. */
export function mapSurface({ name, initResult, tools }) {
  const surface = {
    target: name,
    protocol: initResult?.protocolVersion || 'unknown',
    serverInfo: initResult?.serverInfo || {},
    claimedName: initResult?.serverInfo?.name || name,
    impersonationRisk: (initResult?.serverInfo?.name && initResult.serverInfo.name !== name),
    tools: [],
    capabilities: {
      egress: false, db: false, exec: false, filesystem: false, memory: false,
      authModel: 'none declared', sideEffects: false,
    },
    schemaIssues: [],
  };

  for (const t of tools) {
    const meta = t._hachimanRiskMeta || inferRiskMeta(t);
    const schema = t.inputSchema || {};
    const props = schema.properties || {};
    const propNames = Object.keys(props);
    const toolSurface = {
      name: t.name,
      description: t.description || '',
      meta,
      paramNames: propNames,
      declaresAdditionalProperties: 'additionalProperties' in schema,
      strictAdditional: schema.additionalProperties === false, // explicitly forbids unknown params
      hasAuthParam: propNames.some((p) => /^_?auth|token|credential/i.test(p)),
      acceptsFreeformBody: propNames.some((p) => /body|payload|content|data/i.test(p)),
      egressParam: propNames.find((p) => /^(url|uri|host|endpoint|webhook|dest|destination)$/i.test(p)),
    };
    if (toolSurface.egressParam) surface.capabilities.egress = true;
    if (/db|query|sql|database|export/.test(t.name + ' ' + (t.description || ''))) surface.capabilities.db = true;
    if (/exec|shell|command|system|run/.test(t.name + ' ' + (t.description || ''))) surface.capabilities.exec = true;
    if (/file|path|directory/.test(t.name)) surface.capabilities.filesystem = true;
    if (/memory|remember|store/.test(t.name + ' ' + (t.description || ''))) surface.capabilities.memory = true;
    if (meta.sideEffectRisk > 0) surface.capabilities.sideEffects = true;
    // schema hygiene
    if (!toolSurface.declaresAdditionalProperties) surface.schemaIssues.push(`${t.name}: additionalProperties undeclared (accepts unknown params)`);
    if (!Object.keys(props).length && !/no.?arg/i.test(t.description || '')) surface.schemaIssues.push(`${t.name}: empty input schema`);
    surface.tools.push(toolSurface);
  }

  // Servers may self-declare a security model at initialize (extension field).
  const sec = initResult?.security || initResult?.capabilities?.security;
  if (surface.capabilities.egress || surface.capabilities.db || surface.capabilities.sideEffects) {
    surface.capabilities.authModel = sec?.authorizationModel
      ? `declared: ${sec.authorizationModel}${sec.sideEffectPolicy ? ` (${sec.sideEffectPolicy})` : ''}`
      : 'unverified: no declared authorization model';
  }
  surface.capabilities.declaredSecurity = sec || null;
  return surface;
}

/** Select applicable test ids given the surface (zero irrelevant tests). */
export function selectTests(surface, catalog) {
  return catalog.filter((t) => t.applicable(surface));
}
