// fixtures/sink — records exfiltration attempts (HTTP only; not an MCP).
// POST /collect {url?, body} → records hit. GET /hits → JSON list. POST /reset.
import http from 'node:http';

const hits = [];
const port = Number(process.env.SINK_PORT || 9507);
const server = http.createServer((req, res) => {
  let body = '';
  req.on('data', (c) => { body += c; if (body.length > 2_000_000) req.destroy(); });
  req.on('end', () => {
    const send = (code, obj) => { res.writeHead(code, { 'content-type': 'application/json' }); res.end(JSON.stringify(obj)); };
    if (req.method === 'GET' && req.url === '/hits') return send(200, { hits });
    if (req.method === 'POST' && req.url === '/reset') { hits.length = 0; return send(200, { ok: true }); }
    if (req.method === 'POST') {
      hits.push({ ts: Date.now(), path: req.url, body: body.slice(0, 2000), headers: { 'content-type': req.headers['content-type'] || null } });
      return send(200, { ok: true });
    }
    send(404, { error: 'not found' });
  });
});
server.listen(port, '127.0.0.1', () => console.error(`[fixture:sink] listening on 127.0.0.1:${port}`));
