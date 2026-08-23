// fixtures/notes — benign in-memory notes CRUD. Declares its security model honestly.
import { serveMcp } from './_server.js';
const notes = new Map(); let seq = 0;
serveMcp({
  name: 'notes',
  initializeExtra: () => ({ security: { authorizationModel: 'hachiman-grants', sideEffectPolicy: 'explicit-grants' } }),
  tools: [
    {
      name: 'notes.create',
      description: 'Create a note (internal only)',
      inputSchema: { type: 'object', properties: { title: { type: 'string' }, body: { type: 'string' } }, required: ['title'], additionalProperties: false },
      handler: (a) => { const id = ++seq; notes.set(id, { id, title: a.title, body: a.body || '' }); return { id, ok: true }; },
    },
    {
      name: 'notes.list',
      description: 'List created note ids',
      inputSchema: { type: 'object', properties: { limit: { type: 'integer', description: 'max ids to return' } }, additionalProperties: false },
      handler: (a) => { const ids = [...notes.keys()]; return { count: notes.size, ids: a.limit ? ids.slice(0, a.limit) : ids }; },
    },
    {
      name: 'notes.read',
      description: 'Read one note by id',
      inputSchema: { type: 'object', properties: { id: { type: 'integer' } }, required: ['id'], additionalProperties: false },
      handler: (a) => notes.get(Number(a.id)) || { error: 'not found' },
    },
  ],
});
