// adapters/shell — the CLI/shell command guard adapter (Hachiman 2.0, P4).
// Gates shell command execution for AI builders and automation. The adapter
// ships its own deterministic policy pack ("shell-guard"): known-lethal
// patterns are force-BLOCKed, risky patterns are force-REVIEWed — all
// first-party code, no LLM involved. Decisions still come from evaluateRequest.
import { uuid, nowMs } from '../../core/src/utils.js';
import { evaluateRequest } from '../../engines/src/decision.js';

export const SHELL_GUARD_PACK = {
  id: 'shell-guard', version: 1,
  thresholds: { risk: { low: 25, medium: 55, high: 75, critical: 90 }, confidenceFloor: 80 },
  rules: [
    { id: 'shell-rm-rf-root', when: { resourceType: 'shell', paramHas: 'rm -rf /' }, then: { decision: 'BLOCK', riskFloor: 98, reason: 'destructive filesystem wipe' } },
    { id: 'shell-pipe-to-shell', when: { resourceType: 'shell', paramHas: '| sh' }, then: { decision: 'BLOCK', riskFloor: 95, reason: 'remote code piped to shell' } },
    { id: 'shell-pipe-to-bash', when: { resourceType: 'shell', paramHas: '| bash' }, then: { decision: 'BLOCK', riskFloor: 95, reason: 'remote code piped to shell' } },
    { id: 'shell-chmod-world', when: { resourceType: 'shell', paramHas: 'chmod -R 777' }, then: { decision: 'BLOCK', riskFloor: 90, reason: 'world-writable permission sweep' } },
    { id: 'shell-sudo', when: { resourceType: 'shell', paramHas: 'sudo ' }, then: { decision: 'REVIEW', riskFloor: 72, reason: 'privilege escalation requires human sign-off' } },
    { id: 'shell-egress-curl', when: { resourceType: 'shell', paramHas: 'curl ' }, then: { decision: 'REVIEW', riskFloor: 55, reason: 'network egress via curl' } },
    { id: 'shell-egress-wget', when: { resourceType: 'shell', paramHas: 'wget ' }, then: { decision: 'REVIEW', riskFloor: 55, reason: 'network egress via wget' } },
    { id: 'shell-dd-wipe', when: { resourceType: 'shell', paramHas: 'dd if=' }, then: { decision: 'REVIEW', riskFloor: 70, reason: 'raw device write' } },
    { id: 'shell-env-dump', when: { resourceType: 'shell', paramHas: 'env |' }, then: { decision: 'REVIEW', riskFloor: 60, reason: 'environment exfiltration attempt' } },
  ],
};

export function makeShellAdapter(node, { id = 'shell', workstation = 'local', allowlist = [] } = {}) {
  if (!node.policyEngine.getPack('shell-guard')) node.policyEngine.loadPack(SHELL_GUARD_PACK);
  // The guard pack is part of the adapter contract — activate it with the adapter.
  if (!node.config.policyPacks.includes('shell-guard')) node.config.policyPacks.push('shell-guard');
  return {
    id,
    protocol: 'cli-command-guard',
    resourceTypes: ['shell'],
    description: 'CLI/shell command guard with deterministic shell-guard policy pack + optional allowlist.',
    /** Per-command risk metadata: allowlist entry beats the conservative default. */
    metadata(resource) {
      const cmd = String(resource?.attrs?.command || '');
      for (const entry of allowlist) {
        const rx = entry.pattern instanceof RegExp ? entry.pattern : new RegExp(entry.pattern);
        if (rx.test(cmd)) return { sideEffectRisk: entry.sideEffectRisk ?? 0, egressCapable: false, allowlisted: true };
      }
      return { sideEffectRisk: 30, egressCapable: true };
    },
    toDecisionRequest({ command, args = [], cwd = null, sessionToken = null, agentId = null }) {
      const line = [command, ...args].join(' ');
      return {
        id: uuid(), ts: nowMs(),
        agentId: agentId || undefined,
        resource: { type: 'shell', id: workstation, attrs: { command: command || '' } },
        action: 'exec',
        params: { command: command || '', args, cwd, line },
        authzContext: { sessionToken },
        ctx: { adapterId: id },
        adapterId: id,
      };
    },
  };
}

/**
 * Guard one shell command. Returns { allowed, verdict }.
 * blocked/reviewed commands are NEVER executed by caller contract: this adapter
 * does not spawn processes — enforcement stays with the integrating caller,
 * exactly like the MCP gateway refusing to forward.
 */
export async function guardShellCommand(node, adapter, call) {
  const req = adapter.toDecisionRequest(call);
  const deps = node.engineDepsFor(adapter.id);
  const verdict = await evaluateRequest(deps, req);
  return { allowed: verdict.decision === 'ALLOW', verdict, requestId: req.id };
}
