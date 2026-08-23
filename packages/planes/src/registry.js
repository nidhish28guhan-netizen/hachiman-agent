// planes/registry — adapter system (Hachiman 2.0, P1/P2).
// An adapter is a TRANSLATOR between one ingress protocol and the universal
// decision request. It never decides: evaluateRequest stays the authority.
// Registration is deterministic validation — no dynamic code, no LLM.

export function createAdapterRegistry() {
  const map = new Map();
  return {
    /** Register one adapter definition. Duplicate ids and bad shapes are rejected. */
    register(def) {
      if (!def || typeof def !== 'object') throw new Error('adapter:invalid-definition');
      if (!def.id || typeof def.id !== 'string') throw new Error('adapter:missing-id');
      if (map.has(def.id)) throw new Error('adapter:duplicate-id:' + def.id);
      if (map.size >= 64) throw new Error('adapter:registry-full');
      if (typeof def.protocol !== 'string') throw new Error('adapter:missing-protocol:' + def.id);
      if (!Array.isArray(def.resourceTypes) || !def.resourceTypes.length) throw new Error('adapter:missing-resourceTypes:' + def.id);
      if (typeof def.toDecisionRequest !== 'function') throw new Error('adapter:missing-toDecisionRequest:' + def.id);
      map.set(def.id, def);
      return def;
    },
    get(id) { return map.get(id) || null; },
    has(id) { return map.has(id); },
    list() { return [...map.values()].map(({ id, protocol, resourceTypes, description }) => ({ id, protocol, resourceTypes, description: description || '' })); },
    forResourceType(type) { return [...map.values()].filter((a) => a.resourceTypes.includes(type)); },
    size() { return map.size; },
  };
}
