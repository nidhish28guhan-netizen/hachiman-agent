// fixtures/_server — tiny MCP server helper: stdio (line-delimited JSON-RPC) or HTTP mode.
// Mode: env FIXTURE_HTTP_PORT -> HTTP; otherwise stdio.
import http from 'node:http';
import { createInterface } from 'node:readline';

export function serveMcp(def) {
  const port = process.env.FIXTURE_HTTP_PORT ? Number(process.env.FIXTURE_HTTP_PORT) : null;
  const state = { listCalls: 0, callLog: [], ...def.initialState };
  const handlers = {
    'initialize': async () => ({
      protocolVersion: '2025-06-18',
      capabilities: { tools: {} },
      serverInfo: { name: def.name, version: def.version || '1.0.0' },
      ...(def.initializeExtra ? def.initializeExtra(state) : {}),
    }),
    'tools/list': async () => {
      state.listCalls++;
      const tools = def.dynamicTools ? def.dynamicTools(state) : def.tools;
      return { tools: tools.map(stripHandler) };
    },
    'tools/call': async (params) => {
      const name = params?.name;
      const args = params?.arguments || {};
      const tool = (def.dynamicTools ? def.dynamicTools(state) : def.tools).find((t) => t.name === name);
      if (!tool) return { content: [{ type: 'text', text: `unknown tool: ${name}` }], isError: true };
      state.callLog.push({ tool: name, args, ts: Date.now() });
      if (def.beforeCall) { const r = await def.beforeCall(tool, args, state); if (r) return r; }
      try {
        const out = await tool.handler(args, state);
        return typeof out === 'object' && out.content ? out : { content: [{ type: 'text', text: typeof out === 'string' ? out : JSON.stringify(out) }] };
      } catch (e) {
        return { content: [{ type: 'text', text: `tool error: ${e.message}` }], isError: true };
      }
    },
  };

  const dispatch = async (msg) => {
    if (!msg.method) return null;
    if (msg.id == null) return null; // notification
    try {
      const fn = handlers[msg.method];
      if (!fn) return { jsonrpc: '2.0', id: msg.id, error: { code: -32601, message: `method not found: ${msg.method}` } };
      const result = await fn(msg.params || {});
      return { jsonrpc: '2.0', id: msg.id, result };
    } catch (e) {
      return { jsonrpc: '2.0', id: msg.id, error: { code: -32000, message: String(e.message) } };
    }
  };

  if (port) {
    const server = http.createServer((req, res) => {
      let body = '';
      req.on('data', (c) => { body += c; if (body.length > 1_000_000) req.destroy(); });
      req.on('end', async () => {
        try {
          const msg = JSON.parse(body);
          const out = await dispatch(msg);
          res.writeHead(200, { 'content-type': 'application/json' });
          res.end(out ? JSON.stringify(out) : '{}');
        } catch (e) {
          res.writeHead(400, { 'content-type': 'application/json' });
          res.end(JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32700, message: String(e.message) } }));
        }
      });
    });
    server.listen(port, '127.0.0.1', () => {
      if (process.send) process.send({ ready: true, port });
      console.error(`[fixture:${def.name}] http on 127.0.0.1:${port}`);
    });
    return { mode: 'http', port, server };
  }

  // stdio mode
  const rl = createInterface({ input: process.stdin, terminal: false });
  rl.on('line', async (line) => {
    if (!line.trim()) return;
    let msg; try { msg = JSON.parse(line); } catch { return; }
    const out = await dispatch(msg);
    if (out) process.stdout.write(JSON.stringify(out) + '\n');
  });
  return { mode: 'stdio' };
}

function stripHandler(t) {
  const { handler, ...rest } = t;
  return rest;
}
