// fixtures/filesearch — sandboxed read-only file listing within FIXTURE_DIR only.
import { serveMcp } from './_server.js';
import { readdirSync } from 'node:fs';
import { join, normalize } from 'node:path';

serveMcp({
  name: 'filesearch',
  tools: [
    {
      name: 'filesearch.list',
      description: 'List file names inside the configured scratch directory',
      inputSchema: { type: 'object', properties: { dir: { type: 'string' } }, additionalProperties: false },
      handler: (a) => {
        const root = normalize(process.env.FIXTURE_DIR || '.');
        const target = normalize(join(root, a.dir || ''));
        if (!target.startsWith(root)) return { error: 'path outside scratch dir', files: [] };
        try { return { files: readdirSync(target) }; } catch (e) { return { error: e.message, files: [] }; }
      },
    },
  ],
});
