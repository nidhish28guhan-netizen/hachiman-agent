// lib/hachiman — root composition: assemble storage + engines + gateway + runtime + srg.
import { mkdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Storage } from '../packages/core/src/storage.js';
import { EventBus } from '../packages/core/src/bus.js';
import { uuid, nowMs } from '../packages/core/src/utils.js';
import { IdentityEngine } from '../packages/engines/src/identity.js';
import { AuthorizationEngine } from '../packages/engines/src/authorization.js';
import { PolicyEngine, loadPolicyDir } from '../packages/engines/src/policy.js';
import { LocalHeuristicAnalyzer } from '../packages/engines/src/semantic.js';
import { makeCanary } from '../packages/engines/src/injection.js';
import { McpGateway } from '../packages/gateway/src/gateway.js';
import { Metrics } from '../packages/gateway/src/metrics.js';
import { BehaviorMonitor } from '../packages/runtime/src/monitor.js';
import { ResponseEngine } from '../packages/runtime/src/response.js';
import { SecurityResourceGovernor } from '../packages/srg/src/srg.js';
import { Scanner } from '../packages/scanner/src/scanner.js';
import * as trust from '../packages/engines/src/trust.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, '..');

export const DEFAULT_CONFIG = {
  tenant: 'local',
  storage: { path: ':memory:' },
  policies: join(ROOT, 'policies'),
  policyPacks: ['default'],
  mcpServers: {},
  knownExternalHosts: [],
  internalHosts: [],
  semantic: { enabled: true },
  cache: { enabled: true },
  srg: { enabled: true },
  http: { port: 7420 },
};

/** Create an unbuilt node. Call start() to connect to MCPs and start SRG. */
export function createNode(userConfig = {}, { policiesDir } = {}) {
  const config = { ...DEFAULT_CONFIG, ...userConfig };
  const storagePath = config.storage?.path === ':memory:' ? ':memory:' : config.storage?.path || join(ROOT, '.hachiman', 'state.db');
  if (storagePath !== ':memory:') mkdirSync(dirname(storagePath), { recursive: true });

  const storage = new Storage(storagePath);
  const bus = new EventBus();
  const metrics = new Metrics();

  const policyEngine = new PolicyEngine();
  loadPolicyDir(policyEngine, policiesDir || config.policies);
  if (!config.policyPacks?.length) config.policyPacks = ['default'];
  for (const id of config.policyPacks) if (!policyEngine.getPack(id)) throw new Error(`policy pack '${id}' not found`);

  const identity = new IdentityEngine(storage);
  const authz = new AuthorizationEngine(storage);
  const monitor = new BehaviorMonitor(storage, bus);
  const srg = new SecurityResourceGovernor({ bus, storage });
  const canary = makeCanary(config.tenant + ':v1');
  const semantic = config.semantic?.enabled === false ? null : new LocalHeuristicAnalyzer();

  const deps = {
    config, storage, bus, metrics, policyEngine, policyPackIds: config.policyPacks,
    identity, authz, monitor, srg, semantic, canary,
  };
  const response = new ResponseEngine(deps);
  const gateway = new McpGateway(deps);
  const scanner = new Scanner(deps);

  const node = {
    config, root: ROOT,
    storage, bus, metrics, policyEngine, identity, authz, monitor, srg, response,
    gateway, scanner, semantic, canary, deps,

    async start() {
      await gateway.start();
      seedBaselineIdentity(node);
      if (config.srg?.enabled !== false) srg.start();
      storage.audit({ kind: 'lifecycle', action: 'node-started', actor: 'operator', detail: { servers: Object.keys(config.mcpServers || {}), policyPacks: config.policyPacks } });
      return node;
    },

    async stop() {
      if (node._stopped) return; node._stopped = true;
      try { srg.stop(); } catch {}
      try { await gateway.stop(); } catch {}
      try { storage.audit({ kind: 'lifecycle', action: 'node-stopped', actor: 'operator' }); } catch {}
      try { storage.close(); } catch {}
    },

    /** Operator helper: register agent identity + grant tool access to an mcp. */
    allowAgent(agentName, mcpName, { grantedBy = 'operator:local' } = {}) {
      const agentId = `agent:${agentName}`;
      if (!identity.get(agentId)) identity.register('agent', agentName);
      trust.registerSubject(storage, agentId);
      const grantId = authz.grant({ subject: agentId, capability: 'tool.*', resource: mcpName, grantedBy });
      storage.audit({ kind: 'grant', subject: agentId, action: 'tool.*@' + mcpName, actor: grantedBy, detail: { grantId } });
      return { agentId, grantId };
    },

    /** Operator trust decision for an MCP (WF-02). */
    allowMcp(mcpName, { grantedBy = 'operator:local' } = {}) {
      const rec = trust.operatorAllow(storage, `mcp:${mcpName}`, grantedBy);
      storage.audit({ kind: 'trust', subject: `mcp:${mcpName}`, action: 'operator-allow', actor: grantedBy, detail: { state: rec.state, score: rec.score } });
      return rec;
    },

    status() {
      return {
        version: '0.1.0',
        tenant: config.tenant,
        servers: gateway.clients ? [...gateway.clients.keys()] : [],
        mode: srg.mode, threatLevel: srg.threatLevel,
        policyPacks: config.policyPacks.map((id) => `${id}@${policyEngine.packVersion(id)}`),
        auditEvents: storage.auditCount(),
        metrics: metrics.snapshot(),
        trust: [...gateway.serverMeta?.keys() || []].map((s) => trust.getTrust(storage, `mcp:${s}`)),
      };
    },
  };
  return node;
}

/** Seed: operator identity + per-server agent identity with grants (baseline usability). */
function seedBaselineIdentity(node) {
  const { identity, authz, config, storage } = node;
  if (!identity.get('operator:local')) identity.register('operator', 'local', { role: 'owner' });
  if (!identity.get('agent:default')) identity.register('agent', 'default', { note: 'default protected agent' });
  trust.registerSubject(storage, 'agent:default');
  const active = storage.q.grantActive.all('agent:default');
  for (const [name] of Object.entries(config.mcpServers || {})) {
    if (!active.some((g) => g.resource === name && g.capability === 'tool.*')) {
      authz.grant({ subject: 'agent:default', capability: 'tool.*', resource: name, grantedBy: 'operator:local' });
    }
  }
}

export { uuid, nowMs };
