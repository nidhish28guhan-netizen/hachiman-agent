#!/usr/bin/env node
// bin/hachiman — CLI entry.
import { main } from '../packages/cli/src/main.js';
main(process.argv).catch((e) => {
  console.error('hachiman error:', e?.stack || String(e));
  process.exit(1);
});
