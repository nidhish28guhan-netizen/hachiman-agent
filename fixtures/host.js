// fixtures/host — spawn fixture MCP servers + the exfil sink for scans/e2e.
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const HERE = dirname(fileURLToPath(import.meta.url));

let portCounter = 9600 + Math.floor(Math.random() * 200);
const nextPort = () => ++portCounter;

async function waitHttp(url, timeoutMs = 6000) {
  const t0 = Date.now();
  while (Date.now() - t0 < timeoutMs) {
    try {
      const res = await fetch(url, {
        method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', id: 'probe', method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'probe', version: '0' } } }),
      });
      if (res.ok) return true;
    } catch {}
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error('fixture did not become ready: ' + url);
}

/** Start a fixture MCP server over HTTP. Returns {name, port, url, proc, stop}. */
export async function startFixture(name, { env = {}, file } = {}) {
  const port = nextPort();
  const proc = spawn(process.execPath, [file || join(HERE, 'mcps', name + '.js')], {
    stdio: ['ignore', 'ignore', 'ignore'],
    env: { ...process.env, FIXTURE_HTTP_PORT: String(port), ...env },
  });
  const url = `http://127.0.0.1:${port}/mcp`;
  try { await waitHttp(url); } catch (e) { proc.kill(); throw e; }
  return {
    name, port, url, proc,
    stop: () => { try { proc.kill(); } catch {} },
  };
}

/** Start the exfil sink. Returns {port, url, hits(), reset(), stop}. */
export async function startSink(port = nextPort()) {
  const proc = spawn(process.execPath, [join(HERE, 'mcps', 'sink.js')], {
    stdio: ['ignore', 'ignore', 'ignore'],
    env: { ...process.env, SINK_PORT: String(port) },
  });
  const base = `http://127.0.0.1:${port}`;
  const t0 = Date.now();
  while (Date.now() - t0 < 6000) {
    try { const r = await fetch(base + '/hits'); if (r.ok) break; } catch {}
    await new Promise((r) => setTimeout(r, 100));
  }
  return {
    port, url: base,
    hits: async () => (await (await fetch(base + '/hits')).json()).hits || [],
    reset: async () => { try { await fetch(base + '/reset', { method: 'POST' }); } catch {} },
    stop: () => { try { proc.kill(); } catch {} },
  };
}

export function fixtureFile(name) { return join(HERE, 'mcps', name + '.js'); }
