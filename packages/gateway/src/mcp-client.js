// gateway/mcp-client — minimal MCP client (stdio spawn + HTTP) speaking JSON-RPC 2.0.
import { spawn } from 'node:child_process';
import { uuid } from '../../core/src/utils.js';

const DEFAULT_TIMEOUT = 10_000;

/** MCP client over stdio: newline-delimited JSON-RPC against a spawned server. */
export class StdioMcpClient {
  constructor(command, args = [], { env = {}, cwd } = {}) {
    this.command = command; this.args = args; this.env = env; this.cwd = cwd;
    this.proc = null; this.pending = new Map(); this.buf = '';
    this.onNotification = null;
  }
  start() {
    // Windows: MCP servers installed via npm resolve to .cmd shims that spawn()
    // cannot exec directly; shell:true is the standard remedy (same as MCP SDKs).
    this.proc = spawn(this.command, this.args, {
      stdio: ['pipe', 'pipe', 'ignore'],
      env: { ...process.env, ...this.env }, cwd: this.cwd,
      windowsHide: true,
      ...(process.platform === 'win32' ? { shell: true } : {}),
    });
    this.proc.stdout.setEncoding('utf8');
    this.proc.stdout.on('data', (chunk) => this._onData(chunk));
    this.proc.on('exit', (code) => {
      for (const [, p] of this.pending) p.reject(new Error(`mcp stdio exited code=${code}`));
      this.pending.clear();
    });
    return this;
  }
  _onData(chunk) {
    this.buf += chunk;
    let idx;
    while ((idx = this.buf.indexOf('\n')) >= 0) {
      const line = this.buf.slice(0, idx).trim(); this.buf = this.buf.slice(idx + 1);
      if (!line) continue;
      let msg; try { msg = JSON.parse(line); } catch { continue; }
      this._dispatch(msg);
    }
  }
  _dispatch(msg) {
    if (msg.id != null && this.pending.has(msg.id)) {
      const p = this.pending.get(msg.id); this.pending.delete(msg.id);
      clearTimeout(p.timer);
      if (msg.error) p.reject(new Error(msg.error.message || 'mcp error'));
      else p.resolve(msg.result);
    } else if (msg.method && this.onNotification) {
      try { this.onNotification(msg); } catch {}
    }
  }
  request(method, params, timeoutMs = DEFAULT_TIMEOUT) {
    const id = uuid();
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => { this.pending.delete(id); reject(new Error(`mcp request timeout: ${method}`)); }, timeoutMs);
      this.pending.set(id, { resolve, reject, timer });
      this.proc.stdin.write(JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n');
    });
  }
  notify(method, params) {
    this.proc.stdin.write(JSON.stringify({ jsonrpc: '2.0', method, params }) + '\n');
  }
  stop() { try { this.proc?.kill(); } catch {} }
}

/** MCP client over HTTP: POST JSON-RPC bodies to url/mcp. */
export class HttpMcpClient {
  constructor(url, { headers = {} } = {}) { this.url = url.replace(/\/$/, ''); this.headers = headers; }
  async request(method, params, timeoutMs = DEFAULT_TIMEOUT) {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), timeoutMs);
    try {
      const res = await fetch(this.url, {
        method: 'POST',
        headers: { 'content-type': 'application/json', ...this.headers },
        body: JSON.stringify({ jsonrpc: '2.0', id: uuid(), method, params }),
        signal: ctrl.signal,
      });
      if (!res.ok) throw new Error(`mcp http ${res.status}`);
      const msg = await res.json();
      if (msg.error) throw new Error(msg.error.message || 'mcp error');
      return msg.result;
    } finally { clearTimeout(timer); }
  }
  notify() {}
  stop() {}
}

export function createMcpClient(spec) {
  if (spec.url) return new HttpMcpClient(spec.url, { headers: spec.headers });
  if (spec.command) return new StdioMcpClient(spec.command, spec.args || [], { env: spec.env || {}, cwd: spec.cwd });
  throw new Error('mcp spec requires url or command');
}
