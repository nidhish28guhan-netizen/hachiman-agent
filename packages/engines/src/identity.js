// engines/identity — entity registry, Ed25519 keypairs, HMAC session tokens.
import { generateKeyPairSync, createPublicKey, randomBytes, createHmac } from 'node:crypto';
import { uuid, nowMs } from '../../core/src/utils.js';

export class IdentityEngine {
  constructor(storage, { secret = null } = {}) {
    this.storage = storage;
    this.secret = secret || storage.kvGet('identity.secret') || randomBytes(32).toString('hex');
    if (!storage.kvGet('identity.secret')) storage.kvSet('identity.secret', this.secret);
  }

  register(kind, name, meta = {}) {
    const id = `${kind}:${name}`;
    const { publicKey, privateKey } = generateKeyPairSync('ed25519');
    const pub = publicKey.export({ format: 'der', type: 'spki' }).toString('base64');
    const priv = privateKey.export({ format: 'der', type: 'pkcs8' }).toString('base64');
    this.storage.q.entUpsert.run(id, kind, name, pub, JSON.stringify(meta), nowMs(), nowMs());
    return { id, kind, name, publicKey: pub, privateKey: priv };
  }

  get(id) {
    const row = this.storage.q.entGet.get(id);
    if (!row) return null;
    return { id: row.id, kind: row.kind, name: row.name, publicKey: row.publicKey, meta: row.meta ? JSON.parse(row.meta) : {} };
  }
  list(kind) { return this.storage.q.entList.all(kind).map((r) => ({ id: r.id, kind: r.kind, name: r.name })); }

  /** Issue a short-TTL session token for a registered subject. */
  issueSession(subjectId, { ttlMs = 60 * 60_000, meta = {} } = {}) {
    if (!this.get(subjectId)) throw new Error(`identity: subject ${subjectId} not registered`);
    const token = 'hsm_' + randomBytes(18).toString('base64url') + '.' + createHmac('sha256', this.secret).update(subjectId).digest('base64url').slice(0, 12);
    this.storage.q.sessPut.run(token, subjectId, nowMs(), ttlMs, JSON.stringify(meta));
    return { token, subjectId, expiresAt: nowMs() + ttlMs };
  }

  /** Resolve a session token → {verified, subjectId}. Unknown/expired ⇒ unverified. */
  resolve(token) {
    if (!token) return { verified: false, subjectId: null, reason: 'no-token' };
    const row = this.storage.q.sessGet.get(token);
    if (!row) return { verified: false, subjectId: null, reason: 'unknown-token' };
    if (nowMs() > row.createdAt + row.ttlMs) { this.storage.q.sessDel.run(token); return { verified: false, subjectId: row.subject, reason: 'expired' }; }
    return { verified: true, subjectId: row.subject };
  }

  revokeSession(token) { this.storage.q.sessDel.run(token); }
}
