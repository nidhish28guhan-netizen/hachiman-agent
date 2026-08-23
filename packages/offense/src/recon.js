// offense/recon — DISCOVER + MAP: surface → tech fingerprint → attack-surface map → threat model (doc-06 §2, §6, §8).
// Deterministic — zero tokens. Wraps the existing scanner surface mapper.
import { mapSurface } from '../../scanner/src/surface.js';
import { createMcpClient } from '../../gateway/src/mcp-client.js';

const WEAK_FLAGS = {
  egress: { threat: 'sensitive-data-exfiltration', why: 'tool can reach external/network destinations', priority: 1 },
  db: { threat: 'data-access-abuse', why: 'tool touches a data store; injection or over-read possible', priority: 1 },
  exec: { threat: 'command-execution', why: 'tool executes commands; injection → RCE path', priority: 1 },
  filesystem: { threat: 'path-traversal', why: 'tool reads/writes paths; boundary may be escapable', priority: 2 },
  sideEffects: { threat: 'unauthorized-state-change', why: 'tool mutates state; authorization model matters', priority: 2 },
};

export async function runRecon(conn) {
  const client = createMcpClient(conn);
  if (typeof client.start === 'function') await client.start();
  try {
    const init = await client.request('initialize', { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'hachiman-recon', version: '1.0' } });
    const list = await client.request('tools/list', {});
    const surface = mapSurface({ name: 'recon-target', tools: list.tools || [], initResult: init });
    const tech = {
      transport: conn.url ? 'http' : 'stdio',
      serverInfo: init.serverInfo || null,
      declaredSecurity: init.security || init.capabilities?.security || null,
      labAnnotations: init.security?.sourceMap || null,
      strictSchemas: (list.tools || []).every((t) => t.inputSchema?.additionalProperties === false),
    };
    const attackSurface = {
      target: surface.name,
      tools: (list.tools || []).map((t) => ({
        name: t.name,
        description: t.description || '',
        params: Object.keys(t.inputSchema?.properties || {}),
        strictSchema: t.inputSchema?.additionalProperties === false,
        flags: {
          egress: /http|url|fetch|send|request|forward|webhook|email/i.test(t.name + ' ' + (t.description || '')),
          db: /db|query|sql|export|import|database|select/i.test(t.name + ' ' + (t.description || '')),
          exec: /exec|run|shell|command|eval/i.test(t.name + ' ' + (t.description || '')),
          filesystem: /file|path|read|write|upload|download/i.test(t.name + ' ' + (t.description || '')),
          sideEffects: (surface.sideEffects || []).some((s) => s.includes(t.name)) || /create|update|delete|send|post|export/i.test(t.name),
        },
      })),
      tech,
      threatModel: [],
    };

    // deterministic threat model: flags + schema weakness + auth-model absence → hypotheses worth pursuing
    for (const tool of attackSurface.tools) {
      for (const [flag, t] of Object.entries(WEAK_FLAGS)) {
        if (tool.flags[flag]) attackSurface.threatModel.push({ surface: `${tool.name} (${flag})`, ...t });
      }
      if (!tool.strictSchema) attackSurface.threatModel.push({ surface: `${tool.name} (schema)`, threat: 'parameter-smuggling', why: 'additionalProperties not locked', priority: 3 });
      if (tool.params.some((p) => /query|q|search|input|text|body|name/i.test(p)) && /search|query|filter/i.test(tool.name)) {
        attackSurface.threatModel.push({ surface: `${tool.name} (input)`, threat: 'injection-via-parameter', why: 'free-form search/query parameter on a data tool', priority: 1 });
      }
    }
    const envSec = tech.declaredSecurity;
    if (!envSec || envSec.authorizationModel === 'none declared' || envSec.authorizationModel === undefined) {
      attackSurface.threatModel.push({ surface: '* (server)', threat: 'authorization-excess', why: 'no authorization model declared; privileged-looking tools may be callable by anyone', priority: 1 });
    }
    attackSurface.threatModel.sort((a, b) => a.priority - b.priority);
    return attackSurface;
  } finally {
    await Promise.resolve(typeof client.stop === 'function' ? client.stop() : undefined).catch(() => {});
  }
}
