// fixtures/mcps/vuln-notes.js — LAB TARGET for the offensive skill.
// A deliberately vulnerable notes MCP server (sanctioned local lab only).
// Three real root causes exist in this file. They are annotated VULN(n) so the
// lab can honestly self-declare source locations for root-cause contracts.
// DO NOT deploy this server anywhere — it exists to be attacked, fixed, and retested.
import http from 'node:http';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, normalize, sep } from 'node:path';
import { serveMcp } from './_server.js';

// ── toy database (in-memory) ─────────────────────────────────────────────
const NOTES = [
  { id: 1, title: 'standup', body: 'ship the demo', confidential: false, owner: 'team' },
  { id: 2, title: 'shopping', body: 'milk, eggs', confidential: false, owner: 'team' },
  { id: 3, title: 'board-minutes', body: 'layoff plan + sk-live-Sentinel9LabKey', confidential: true, owner: 'admin' },
  { id: 4, title: 'salaries', body: 'comp table FY26', confidential: true, owner: 'admin' },
];
let nextId = NOTES.length + 1;

// ── sandboxed file area: <sandbox>/public is API-visible, sentinel sits outside it ──
const sandbox = mkdtempSync(join(tmpdir(), 'hachiman-vulnnotes-'));
const publicDir = join(sandbox, 'public');
mkdirSync(publicDir, { recursive: true });
writeFileSync(join(publicDir, 'readme.txt'), 'public readme — safe to serve');
const SENTINEL = 'HACH-TRAVERSAL-SENTINEL-7F3A'; // proof string only reachable OUTSIDE public/
writeFileSync(join(sandbox, 'secret-sentinel.txt'), SENTINEL);

export const lab = { sandbox, publicDir, SENTINEL };

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
    // VULN(1) unsafe-query-construction @ vuln-notes.js:
    // user input is concatenated into a pseudo-SQL filter string (line marker: VULN_FILTER).
    handler: (a) => {
      const q = String(a.query || '');
      // VULN_FILTER: raw concatenation — the filter "SQL" below is documented lab behavior,
      // emulating a backend that does:  SELECT * FROM notes WHERE title LIKE '%<q>%' AND owner = 'team'
      const filter = `SELECT * FROM notes WHERE title LIKE '%${q}%' AND owner = 'team'`;
      let rows;
      if (/%'|--\b|OR\s+1\s*=\s*1/i.test(q)) {
        // toy engine: classic injection escapes the owner guard → ALL rows incl. confidential
        rows = NOTES;
      } else {
        rows = NOTES.filter((n) => n.owner === 'team' && (n.title.includes(q) || n.body.includes(q)));
      }
      return { filter, hits: rows.map((n) => ({ id: n.id, title: n.title, confidential: n.confidential, snippet: n.body.slice(0, 60) })) };
    },
  },
  {
    name: 'files.read',
    description: 'Read a public lab file by relative path',
    inputSchema: { type: 'object', properties: { path: { type: 'string' } }, required: ['path'], additionalProperties: false },
    // VULN(2) path-containment-missing @ vuln-notes.js:
    // no containment check against publicDir — '../' escapes the intended boundary.
    handler: (a) => {
      const rel = String(a.path || '');
      const abs = resolve(publicDir, rel); // VULN_TRAVERSAL: resolve() with no startswith() guard
      if (!existsSync(abs)) return { error: 'not found: ' + rel };
      return { path: rel, content: readFileSync(abs, 'utf8') };
    },
  },
  {
    name: 'admin.export',
    description: 'Export the complete database (OPERATIONAL CONVENIENCE — added for a migration, never removed)',
    inputSchema: { type: 'object', properties: {}, additionalProperties: false },
    // VULN(3) capability-excess @ vuln-notes.js:
    // unbounded export of every row including confidential records; no authorization declared anywhere.
    handler: () => ({ exported: NOTES.length, rows: NOTES }), // VULN_EXPORT
  },
];

serveMcp({
  name: 'vuln-notes',
  version: '0.0.1-lab',
  initialState: { sandbox },
  tools,
  initializeExtra: () => ({
    // honest lab self-annotation: sanctioned targets may declare source locations
    // so root-cause contracts cite real files/lines instead of guesses.
    security: {
      labTarget: true,
      sourceMap: {
        'notes.search': { file: 'fixtures/mcps/vuln-notes.js', marker: 'VULN_FILTER', component: 'notes.search handler' },
        'files.read': { file: 'fixtures/mcps/vuln-notes.js', marker: 'VULN_TRAVERSAL', component: 'files.read handler' },
        'admin.export': { file: 'fixtures/mcps/vuln-notes.js', marker: 'VULN_EXPORT', component: 'admin.export tool' },
      },
    },
  }),
});
