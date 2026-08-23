// gateway/stdio-bridge — expose one protected gateway MCP server over stdio.
// Stdio-only MCP clients (Claude Desktop classic, Codex CLI, many local agents) spawn this
// as a subprocess; it relays newline-delimited JSON-RPC to the Hachiman HTTP gateway,
// which evaluates every call through the security pipeline before it reaches the backend.
//
// Env:
//   HACHIMAN_GATEWAY  base URL of a running `hachiman guard` (default http://127.0.0.1:7420)
//   HACHIMAN_SESSION  session token binding this client to a registered agent identity
import { createInterface } from 'node:readline';

export function runBridge({ gatewayUrl, server, sessionToken = null, input = process.stdin, output = process.stdout, onIdle = null } = {}) {
  if (!gatewayUrl || !server) throw new Error('stdio-bridge requires gatewayUrl + server');
  const target = gatewayUrl.replace(/\/$/, '') + '/mcp/' + encodeURIComponent(server);
  const headers = { 'content-type': 'application/json' };
  if (sessionToken) headers['x-hachiman-session'] = sessionToken;

  const rl = createInterface({ input, terminal: false });
  let accepting = true;      // still reading new requests?
  let inFlight = 0;          // requests whose response has not been written yet
  let finished = false;
  const settle = () => { if (finished) return; if (!accepting && inFlight === 0) { finished = true; if (onIdle) onIdle(); } };

  rl.on('close', () => { accepting = false; settle(); });
  rl.on('line', async (line) => {
    const t = line.trim();
    if (!t) return;
    let msg;
    try { msg = JSON.parse(t); } catch { return; }
    if (msg.id == null) return; // notifications: gateway does not require them from clients
    inFlight++;
    try {
      const res = await fetch(target, { method: 'POST', headers, body: JSON.stringify(msg) });
      const out = await res.json();
      output.write(JSON.stringify(out) + '\n');
    } catch (e) {
      output.write(JSON.stringify({ jsonrpc: '2.0', id: msg.id, error: { code: -32000, message: `hachiman-bridge: ${e.message}` } }) + '\n');
    } finally {
      inFlight--; settle();
    }
  });
  return {
    target,
    stop: () => { accepting = false; try { rl.close(); } catch {} settle(); },
  };
}
