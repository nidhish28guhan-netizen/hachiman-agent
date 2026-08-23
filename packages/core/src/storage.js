// @hachiman/core — storage layer (node:sqlite, WAL). Append-only audit table.
import { DatabaseSync } from 'node:sqlite';
import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { uuid, nowMs, stableStringify, sha256hex } from './utils.js';

const SCHEMA = `
CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS entities (
  id TEXT PRIMARY KEY, kind TEXT NOT NULL, name TEXT NOT NULL,
  publicKey TEXT, meta TEXT, createdAt INTEGER NOT NULL, updatedAt INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
  token TEXT PRIMARY KEY, subject TEXT NOT NULL, createdAt INTEGER NOT NULL,
  ttlMs INTEGER NOT NULL, meta TEXT
);
CREATE TABLE IF NOT EXISTS grants (
  id TEXT PRIMARY KEY, subject TEXT NOT NULL, capability TEXT NOT NULL, resource TEXT NOT NULL,
  constraints TEXT, grantedBy TEXT NOT NULL, createdAt INTEGER NOT NULL,
  revokedAt INTEGER, revocationReason TEXT
);
CREATE TABLE IF NOT EXISTS trust_records (
  subjectId TEXT PRIMARY KEY, state TEXT NOT NULL, score REAL NOT NULL,
  lastAssessmentRef TEXT, updatedAt INTEGER NOT NULL, history TEXT
);
CREATE TABLE IF NOT EXISTS tool_registry (
  id TEXT PRIMARY KEY, mcpId TEXT NOT NULL, name TEXT NOT NULL, description TEXT,
  inputSchema TEXT, riskMeta TEXT, toolVersion TEXT, updatedAt INTEGER NOT NULL,
  UNIQUE(mcpId, name)
);
CREATE TABLE IF NOT EXISTS policies (
  id TEXT NOT NULL, version INTEGER NOT NULL, body TEXT NOT NULL,
  activatedAt INTEGER, PRIMARY KEY(id, version)
);
CREATE TABLE IF NOT EXISTS quarantine (
  subjectId TEXT PRIMARY KEY, reason TEXT NOT NULL, enteredAt INTEGER NOT NULL,
  enteredBy TEXT NOT NULL, ladder TEXT
);
CREATE TABLE IF NOT EXISTS incidents (
  id TEXT PRIMARY KEY, tenantId TEXT NOT NULL, severity TEXT NOT NULL,
  status TEXT NOT NULL, triggerEvent TEXT, timeline TEXT, containment TEXT,
  reportId TEXT, createdAt INTEGER NOT NULL, updatedAt INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS scans (
  id TEXT PRIMARY KEY, target TEXT NOT NULL, suite TEXT, status TEXT NOT NULL,
  findings TEXT, score TEXT, baselineId TEXT, createdAt INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS decision_cache (
  fingerprint TEXT PRIMARY KEY, verdict TEXT NOT NULL, createdAt INTEGER NOT NULL,
  ttlMs INTEGER NOT NULL, gens TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS metrics_rollups (
  id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, labels TEXT,
  value REAL NOT NULL, ts INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS engagements (
  id TEXT PRIMARY KEY, target TEXT NOT NULL, environment TEXT, authorizedBy TEXT NOT NULL,
  conn TEXT, scope TEXT, rules TEXT, status TEXT NOT NULL, createdAt INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS pentest_findings (
  id TEXT PRIMARY KEY, engagementId TEXT NOT NULL, title TEXT NOT NULL, status TEXT NOT NULL,
  severity TEXT, confidence REAL, payload TEXT NOT NULL, createdAt INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS repair_contracts (
  findingId TEXT PRIMARY KEY, engagementId TEXT NOT NULL, contract TEXT NOT NULL, createdAt INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS retest_results (
  id INTEGER PRIMARY KEY AUTOINCREMENT, findingId TEXT NOT NULL, verdict TEXT NOT NULL,
  fixTarget TEXT, reason TEXT, ts INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_events (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  eventId TEXT NOT NULL, ts INTEGER NOT NULL, tenantId TEXT, kind TEXT NOT NULL,
  actor TEXT, subject TEXT, tool TEXT, action TEXT, decision TEXT,
  risk REAL, confidence REAL, trust REAL, path TEXT,
  reasons TEXT, policyRefs TEXT, evidence TEXT, detail TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_events(ts);
CREATE INDEX IF NOT EXISTS idx_audit_subject ON audit_events(subject);
CREATE INDEX IF NOT EXISTS idx_audit_tool ON audit_events(tool);
-- Append-only enforcement on the audit table.
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit_events BEGIN
  SELECT RAISE(ABORT, 'audit_events is append-only');
END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit_events BEGIN
  SELECT RAISE(ABORT, 'audit_events is append-only');
END;
`;

export class Storage {
  constructor(path) {
    if (path !== ':memory:') mkdirSync(dirname(path), { recursive: true });
    this.db = new DatabaseSync(path);
    this.db.exec('PRAGMA journal_mode = WAL');
    this.db.exec('PRAGMA synchronous = NORMAL');
    this.db.exec(SCHEMA);
    this._prep();
  }
  _prep() {
    this.q = {
      kvGet: this.db.prepare('SELECT v FROM kv WHERE k=?'),
      kvSet: this.db.prepare('INSERT INTO kv(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v'),
      entUpsert: this.db.prepare(`INSERT INTO entities(id,kind,name,publicKey,meta,createdAt,updatedAt)
        VALUES(?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name,publicKey=excluded.publicKey,
        meta=excluded.meta,updatedAt=excluded.updatedAt`),
      entGet: this.db.prepare('SELECT * FROM entities WHERE id=?'),
      entList: this.db.prepare('SELECT * FROM entities WHERE kind=?'),
      sessPut: this.db.prepare('INSERT OR REPLACE INTO sessions(token,subject,createdAt,ttlMs,meta) VALUES(?,?,?,?,?)'),
      sessGet: this.db.prepare('SELECT * FROM sessions WHERE token=?'),
      sessDel: this.db.prepare('DELETE FROM sessions WHERE token=?'),
      grantIns: this.db.prepare(`INSERT INTO grants(id,subject,capability,resource,constraints,grantedBy,createdAt)
        VALUES(?,?,?,?,?,?,?)`),
      grantUpd: this.db.prepare(`UPDATE grants SET constraints=? WHERE id=?`),
      grantActive: this.db.prepare(`SELECT * FROM grants WHERE subject=? AND revokedAt IS NULL`),
      grantAllActive: this.db.prepare(`SELECT * FROM grants WHERE revokedAt IS NULL`),
      grantRevoke: this.db.prepare(`UPDATE grants SET revokedAt=?, revocationReason=? WHERE id=? AND revokedAt IS NULL`),
      trustUp: this.db.prepare(`INSERT INTO trust_records(subjectId,state,score,lastAssessmentRef,updatedAt,history)
        VALUES(?,?,?,?,?,?) ON CONFLICT(subjectId) DO UPDATE SET state=excluded.state,score=excluded.score,
        lastAssessmentRef=excluded.lastAssessmentRef,updatedAt=excluded.updatedAt,history=excluded.history`),
      trustGet: this.db.prepare('SELECT * FROM trust_records WHERE subjectId=?'),
      toolUp: this.db.prepare(`INSERT INTO tool_registry(id,mcpId,name,description,inputSchema,riskMeta,toolVersion,updatedAt)
        VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(mcpId,name) DO UPDATE SET description=excluded.description,
        inputSchema=excluded.inputSchema,riskMeta=excluded.riskMeta,toolVersion=excluded.toolVersion,updatedAt=excluded.updatedAt`),
      toolList: this.db.prepare('SELECT * FROM tool_registry WHERE mcpId=?'),
      toolGet: this.db.prepare('SELECT * FROM tool_registry WHERE mcpId=? AND name=?'),
      polUp: this.db.prepare('INSERT OR REPLACE INTO policies(id,version,body,activatedAt) VALUES(?,?,?,?)'),
      polGet: this.db.prepare('SELECT * FROM policies WHERE id=? ORDER BY version DESC LIMIT 1'),
      quarUp: this.db.prepare('INSERT OR REPLACE INTO quarantine(subjectId,reason,enteredAt,enteredBy,ladder) VALUES(?,?,?,?,?)'),
      quarGet: this.db.prepare('SELECT * FROM quarantine WHERE subjectId=?'),
      quarDel: this.db.prepare('DELETE FROM quarantine WHERE subjectId=?'),
      quarList: this.db.prepare('SELECT * FROM quarantine'),
      incUp: this.db.prepare(`INSERT INTO incidents(id,tenantId,severity,status,triggerEvent,timeline,containment,reportId,createdAt,updatedAt)
        VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET severity=excluded.severity,status=excluded.status,
        timeline=excluded.timeline,containment=excluded.containment,reportId=excluded.reportId,updatedAt=excluded.updatedAt`),
      incGet: this.db.prepare('SELECT * FROM incidents WHERE id=?'),
      incList: this.db.prepare('SELECT * FROM incidents ORDER BY createdAt DESC LIMIT ?'),
      scanIns: this.db.prepare('INSERT INTO scans(id,target,suite,status,findings,score,baselineId,createdAt) VALUES(?,?,?,?,?,?,?,?)'),
      scanUp: this.db.prepare('UPDATE scans SET status=?, findings=?, score=?, baselineId=? WHERE id=?'),
      scanGet: this.db.prepare('SELECT * FROM scans WHERE id=?'),
      scanByTarget: this.db.prepare('SELECT * FROM scans WHERE target=? ORDER BY createdAt DESC'),
      cacheGet: this.db.prepare('SELECT * FROM decision_cache WHERE fingerprint=?'),
      cachePut: this.db.prepare('INSERT OR REPLACE INTO decision_cache(fingerprint,verdict,createdAt,ttlMs,gens) VALUES(?,?,?,?,?)'),
      cacheClear: this.db.prepare('DELETE FROM decision_cache'),
      metricIns: this.db.prepare('INSERT INTO metrics_rollups(name,labels,value,ts) VALUES(?,?,?,?)'),
      engIns: this.db.prepare('INSERT INTO engagements(id,target,environment,authorizedBy,conn,scope,rules,status,createdAt) VALUES(?,?,?,?,?,?,?,?,?)'),
      engGet: this.db.prepare('SELECT * FROM engagements WHERE id=?'),
      engList: this.db.prepare('SELECT * FROM engagements ORDER BY createdAt DESC LIMIT ?'),
      engStatus: this.db.prepare('UPDATE engagements SET status=? WHERE id=?'),
      fndIns: this.db.prepare('INSERT INTO pentest_findings(id,engagementId,title,status,severity,confidence,payload,createdAt) VALUES(?,?,?,?,?,?,?,?)'),
      fndList: this.db.prepare('SELECT * FROM pentest_findings WHERE engagementId=? ORDER BY createdAt'),
      fndGet: this.db.prepare('SELECT * FROM pentest_findings WHERE id=?'),
      ctrIns: this.db.prepare('INSERT INTO repair_contracts(findingId,engagementId,contract,createdAt) VALUES(?,?,?,?)'),
      ctrGet: this.db.prepare('SELECT * FROM repair_contracts WHERE findingId=?'),
      ctrList: this.db.prepare('SELECT * FROM repair_contracts WHERE engagementId=? ORDER BY createdAt'),
      retIns: this.db.prepare('INSERT INTO retest_results(findingId,verdict,fixTarget,reason,ts) VALUES(?,?,?,?,?)'),
      retList: this.db.prepare('SELECT * FROM retest_results WHERE findingId=? ORDER BY ts DESC'),
    };
    this._audit = this.db.prepare(`INSERT INTO audit_events(eventId,ts,tenantId,kind,actor,subject,tool,action,
      decision,risk,confidence,trust,path,reasons,policyRefs,evidence,detail)
      VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`);
  }

  kvGet(k) { const r = this.q.kvGet.get(k); return r == null ? undefined : JSON.parse(r.v); }
  kvSet(k, v) { this.q.kvSet.run(k, JSON.stringify(v)); }

  // --- offensive skill persistence (engagements, findings, contracts, retests) ---
  engSave(e) {
    this.q.engIns.run(e.id, e.target, e.environment || null, e.authorized_by, JSON.stringify(e.conn),
      JSON.stringify(e.scope), JSON.stringify(e.rules), e.status || 'completed', nowMs());
  }
  engGetById(id) { const r = this.q.engGet.get(id); return r ? { ...r, conn: parseJson(r.conn), scope: parseJson(r.scope), rules: parseJson(r.rules) } : null; }
  fndSave(f) {
    this.q.fndIns.run(f.id, f.engagementId, f.title, f.status, f.severity || null, f.confidence ?? null, JSON.stringify(f), nowMs());
  }
  fndGetById(id) { const r = this.q.fndGet.get(id); return r ? { ...parseJson(r.payload), engagementId: r.engagementId } : null; }
  fndListByEngagement(engagementId) { return this.q.fndList.all(engagementId).map((r) => parseJson(r.payload)); }
  ctrSave(c) { this.q.ctrIns.run(c.finding_id, c.engagement || '', JSON.stringify(c), nowMs()); }
  ctrGetByFinding(findingId) { const r = this.q.ctrGet.get(findingId); return r ? parseJson(r.contract) : null; }
  retSave(r) { this.q.retIns.run(r.findingId, r.verdict, r.fixedTarget || null, r.reason || null, nowMs()); }
  retListByFinding(findingId) { return this.q.retList.all(findingId); }

  // --- audit ---
  audit(evt) {
    const eventId = evt.eventId || uuid();
    this._audit.run(eventId, evt.ts || nowMs(), evt.tenantId || null, evt.kind,
      evt.actor || null, evt.subject || null, evt.tool || null, evt.action || null,
      evt.decision || null, evt.risk ?? null, evt.confidence ?? null, evt.trust ?? null,
      evt.path || null, evt.reasons ? stableStringify(evt.reasons) : null,
      evt.policyRefs ? stableStringify(evt.policyRefs) : null,
      evt.evidence ? stableStringify(evt.evidence) : null,
      evt.detail ? JSON.stringify(evt.detail) : null);
    return eventId;
  }
  auditTail(n = 50, since = 0) {
    return this.db.prepare('SELECT * FROM audit_events WHERE ts>=? ORDER BY seq DESC LIMIT ?').all(since, n)
      .map(rowToAudit);
  }
  auditCount() { return this.db.prepare('SELECT COUNT(*) c FROM audit_events').get().c; }

  close() { try { this.db.close(); } catch {} }
}

export function rowToAudit(r) {
  return {
    seq: r.seq, eventId: r.eventId, ts: r.ts, tenantId: r.tenantId, kind: r.kind,
    actor: r.actor, subject: r.subject, tool: r.tool, action: r.action,
    decision: r.decision, risk: r.risk, confidence: r.confidence, trust: r.trust,
    path: r.path,
    reasons: parseJson(r.reasons), policyRefs: parseJson(r.policyRefs),
    evidence: parseJson(r.evidence), detail: parseJson(r.detail),
  };
}
function parseJson(s) { if (s == null) return null; try { return JSON.parse(s); } catch { return s; } }
export { sha256hex };
