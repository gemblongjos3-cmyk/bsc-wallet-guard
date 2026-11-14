// BSC Wallet & Transaction Guard — agent endpoint.
// Plain Node.js (>=18) HTTP server, zero runtime dependencies.
//
// Routes:
//   GET  /            landing page (what the agent is, how to call it)
//   GET  /health      liveness for platform health checks
//   GET  /audit?address=0x…        contract audit (demo-friendly)
//   POST /audit       { address }  contract audit -> JSON verdict
//   POST /check-tx    { to, data, value }  pre-signing calldata screen
//   POST /task        Agent Games task envelope (HMAC-verified when a
//                     secret is configured; see notes in README)
//
// Config (env): PORT, BSC_RPC_URLS, SOURCIFY_BASE, AGENT_GAMES_HMAC_SECRET.
// No secrets in code. This agent is READ-ONLY: it never signs or broadcasts.

import http from 'node:http';
import crypto from 'node:crypto';
import { auditContract, checkTx } from './audit.js';

const PORT = Number(process.env.PORT || 8787);
const SECRET = process.env.AGENT_GAMES_HMAC_SECRET || '';
const startedAt = Date.now();

const hmac = buf => crypto.createHmac('sha256', SECRET).update(buf).digest('hex');
function verifySignature(rawBody, headerValue) {
  if (!SECRET) return true; // open demo mode when no secret configured
  if (!headerValue) return false;
  const expected = Buffer.from(hmac(rawBody), 'utf8');
  const given = Buffer.from(String(headerValue).trim(), 'utf8');
  return expected.length === given.length && crypto.timingSafeEqual(expected, given);
}

// Very small per-IP rate limit for the heavy endpoints.
const hits = new Map();
function rateLimited(ip) {
  const now = Date.now();
  const arr = (hits.get(ip) || []).filter(t => now - t < 60_000);
  arr.push(now); hits.set(ip, arr);
  return arr.length > 60;
}

// Idempotency cache for /task (platform may retry the same task id).
const taskCache = new Map();
function cacheGet(k) { return taskCache.get(k); }
function cacheSet(k, v) { if (taskCache.size > 500) taskCache.clear(); taskCache.set(k, v); }

function sendJson(res, status, obj) {
  const body = Buffer.from(JSON.stringify(obj));
  const headers = { 'content-type': 'application/json', 'content-length': body.length };
  if (SECRET) headers['x-agent-games-signature'] = hmac(body); // sign every response (build guide §04)
  res.writeHead(status, headers);
  res.end(body);
}

const LANDING = `<!doctype html><html><head><meta charset="utf-8">
<title>BSC Wallet &amp; Transaction Guard</title>
<style>body{font-family:system-ui,sans-serif;max-width:760px;margin:40px auto;padding:0 16px;line-height:1.55;color:#14202e}code{background:#eef2f6;padding:2px 5px;border-radius:4px}pre{background:#0e1622;color:#cfe3f5;padding:14px;border-radius:8px;overflow:auto}.v{font-weight:700}</style>
</head><body>
<h1>🛡️ BSC Wallet &amp; Transaction Guard</h1>
<p>An autonomous screening agent for BNB Smart Chain. Give it a contract address
<em>before</em> you buy, mint, or approve — it checks the things that actually drain
wallets: unverified source, live owner powers (mint / pause / blacklist / upgrade /
fee setters), honeypot &amp; tax simulation, and whether the token's market is a real
pool or a permissionless dust pool. It also screens pending transaction calldata,
most importantly <b>unlimited token approvals</b>.</p>
<h2>Try it</h2>
<pre>curl -X POST $ORIGIN/audit -H 'content-type: application/json' \\
  -d '{"address":"0x55d398326f99059fF775485246999027B3197955"}'

curl -X POST $ORIGIN/check-tx -H 'content-type: application/json' \\
  -d '{"to":"0x…token…","data":"0x095ea7b3…calldata…","value":"0"}'</pre>
<p>Verdicts: <span class="v">SAFE</span> / <span class="v">CAUTION</span> /
<span class="v">DANGER</span>, always with the evidence behind them and a
reproducible block number. Read-only agent: it never signs or broadcasts anything.
Reference only — not financial advice.</p>
<p>Health: <a href="/health">/health</a></p>
</body></html>`;

const server = http.createServer((req, res) => {
  const url = new URL(req.url, 'http://localhost');
  const ip = req.socket.remoteAddress || 'unknown';
  const chunks = [];
  req.on('data', c => { chunks.push(c); if (Buffer.concat(chunks).length > 65_536) req.destroy(); });
  req.on('end', async () => {
    const raw = Buffer.concat(chunks);
    try {
      if (req.method === 'GET' && url.pathname === '/') {
        const html = LANDING.replaceAll('$ORIGIN', `${req.headers['x-forwarded-proto'] || 'http'}://${req.headers.host || ''}`);
        res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' }); return res.end(html);
      }
      if (req.method === 'GET' && url.pathname === '/health') {
        return sendJson(res, 200, { status: 'ok', agent: 'bsc-wallet-guard', version: '0.1.0', chainId: 56, uptimeSeconds: Math.round((Date.now() - startedAt) / 1000) });
      }
      if (rateLimited(ip) && url.pathname !== '/health') return sendJson(res, 429, { error: 'rate_limited' });

      if (req.method === 'GET' && url.pathname === '/audit') {
        const address = url.searchParams.get('address') || '';
        return sendJson(res, 200, await auditContract(address));
      }
      if (req.method === 'POST' && url.pathname === '/audit') {
        const body = JSON.parse(raw.toString('utf8') || '{}');
        return sendJson(res, 200, await auditContract(body.address || ''));
      }
      if (req.method === 'POST' && url.pathname === '/check-tx') {
        const body = JSON.parse(raw.toString('utf8') || '{}');
        return sendJson(res, 200, await checkTx(body));
      }
      if (req.method === 'POST' && url.pathname === '/task') {
        // Agent Games envelope: verify HMAC over the RAW body before parsing.
        if (!verifySignature(raw, req.headers['x-agent-games-signature']))
          return sendJson(res, 401, { status: 'rejected', reason: 'bad_signature' });
        const env = JSON.parse(raw.toString('utf8') || '{}');
        const key = env.idempotencyKey || env.id || env.taskId || null;
        if (key && cacheGet(key)) return sendJson(res, 200, cacheGet(key));
        const type = env.type || env.task?.type || '';
        const payload = env.payload || env.task?.payload || env.task || {};
        let out;
        if (['audit', 'bsc_audit', 'wildcard.audit', 'contract_audit'].includes(type)) {
          out = { id: key, status: 'completed', result: await auditContract(payload.address || '') };
        } else if (type === 'ping' || type === 'health') {
          out = { id: key, status: 'completed', result: { status: 'ok', agent: 'bsc-wallet-guard' } };
        } else {
          out = { id: key, status: 'rejected', reason: `unsupported task type: ${type || '(empty)'}` }; // fail closed
        }
        if (key) cacheSet(key, out);
        return sendJson(res, 200, out);
      }
      return sendJson(res, 404, { error: 'not_found', path: url.pathname });
    } catch (e) {
      return sendJson(res, 400, { error: 'bad_request', message: String(e.message || e).slice(0, 200) });
    }
  });
});

server.listen(PORT, () => console.log(`bsc-wallet-guard listening on :${PORT} (hmac ${SECRET ? 'on' : 'off — demo mode'})`));
