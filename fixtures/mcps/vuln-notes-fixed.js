// fixtures/mcps/vuln-notes-fixed.js — the PATCHED twin of vuln-notes.js.
// Same lab data, same legitimate behavior, three root causes repaired:
//   FIX(1) notes.search: structured substring matching — raw input never builds a filter.
//   FIX(2) files.read: normalize + containment guard against publicDir.
//   FIX(3) admin.export: removed entirely (capability excess).
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, realpathSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, normalize, sep } from 'node:path';
import { serveMcp } from './_server.js';

const NOTES = [
  { id: 1, title: 'standup', body: 'ship the demo', confidential: false, owner: 'team' },
  { id: 2, title: 'shopping', body: 'milk, eggs', confidential: false, owner: 'team' },
  { id: 3, title: 'board-minutes', body: 'layoff plan + sk-live-Sentinel9LabKey', confidential: true, owner: 'admin' },
  { id: 4, title: 'salaries', body: 'comp table FY26', confidential: true, owner: 'admin' },
];
let nextId = NOTES.length + 1;

const sandbox = mkdtempSync(join(tmpdir(), 'hachiman-fixednotes-'));
const publicDir = join(sandbox, 'public');
mkdirSync(publicDir, { recursive: true });
writeFileSync(join(publicDir, 'readme.txt'), 'public readme — safe to serve');
writeFileSync(join(sandbox, 'secret-sentinel.txt'), 'HACH-TRAVERSAL-SENTINEL-7F3A');

const tools = [
  {
    name: 'notes.create',
    description: 'Create a note (legitimate baseline operation)',
    inputSchema: { type: 'object', properties: { title: { type: 'string' }, body: { type: 'string' } }, required: ['title'], additionalProperties: false },
    handler: (a) => { const n = { id: nextId++, title: String(a.title).slice(0, 200), body: String(a.body || '').slice(0, 2000), confidential: false, owner: 'team' }; NOTES.push(n); return { ok: true, id: n.id }; },
  },
  {
    name: 'notes.list',
    description: 'List non-confidential note titles',
    inputSchema: { type: 'object', properties: { limit: { type: 'integer' } }, additionalProperties: false },
    handler: (a) => ({ count: NOTES.filter((n) => !n.confidential).length, ids: NOTES.filter((n) => !n.confidential).slice(0, a.limit || 50).map((n) => n.id) }),
  },
  {
    name: 'notes.search',
    description: 'Search notes by query',
    inputSchema: { type: 'object', properties: { query: { type: 'string' } }, required: ['query'], additionalProperties: false },
    // FIX(1): the query is data only — it participates in a structured substring match,
    // never in a constructed filter/SQL. Access boundary (owner=team) is applied first.
    handler: (a) => {
      const q = String(a.query || '');
      const rows = NOTES.filter((n) => n.owner === 'team' && (n.title.includes(q) || n.body.includes(q)));
      return { filter: 'structured-match(v1)', hits: rows.map((n) => ({ id: n.id, title: n.title, confidential: n.confidential, snippet: n.body.slice(0, 60) })) };
    },
  },
  {
    name: 'files.read',
    description: 'Read a public lab file by relative path',
    inputSchema: { type: 'object', properties: { path: { type: 'string' } }, required: ['path'], additionalProperties: false },
    // FIX(2): containment — resolve then require the real path to stay inside publicDir.
    // realpath comparison must use a canonicalized base too (macOS tmpdir is a /var → /private symlink).
    handler: (a) => {
      const rel = String(a.path || '');
      if (rel.includes('\0')) return { error: 'invalid path' };
      const abs = resolve(publicDir, normalize(rel));
      if (!(abs === publicDir || abs.startsWith(publicDir + sep))) return { error: 'path outside public boundary' };
      if (!existsSync(abs)) return { error: 'not found: ' + rel };
      const realBase = realpathSync(publicDir);
      const real = realpathSync(abs);
      if (!(real === realBase || real.startsWith(realBase + sep))) return { error: 'path outside public boundary' };
      return { path: rel, content: readFileSync(abs, 'utf8') };
    },
  },
  // FIX(3): admin.export removed. No replacement export tool exists by design.
];

serveMcp({
  name: 'vuln-notes-fixed',
  version: '0.0.2-lab-fixed',
  initialState: { sandbox },
  tools,
  initializeExtra: () => ({
    security: {
      labTarget: true,
      fixedBuild: true,
      sourceMap: {
        'notes.search': { file: 'fixtures/mcps/vuln-notes-fixed.js', marker: 'FIX(1)', component: 'notes.search handler' },
        'files.read': { file: 'fixtures/mcps/vuln-notes-fixed.js', marker: 'FIX(2)', component: 'files.read handler' },
      },
    },
  }),
});
