// Zero-dependency web proxy. Needs Node 18+.  Run: node server.js
const http = require('http'), fs = require('fs'), path = require('path');
const dns = require('dns').promises, net = require('net');
const { Readable } = require('stream');

const PORT = process.env.PORT || 8080;
const ACCESS_CODE = process.env.ACCESS_CODE || '';          // optional: require a code to use the site
const ALLOW_PRIVATE = process.env.ALLOW_PRIVATE === '1';    // testing only
const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36';
const RAW_HOSTS = new Set(['cdn.jsdelivr.net', 'data.jsdelivr.com']);

// ---- safety: never let the proxy reach private or local addresses ----
function isPrivateIp(ip) {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split('.').map(Number);
    return a === 10 || a === 127 || a === 0 || a >= 224 || (a === 169 && b === 254) ||
           (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127);
  }
  const l = ip.toLowerCase();
  return l === '::1' || l === '::' || l.startsWith('fc') || l.startsWith('fd') || l.startsWith('fe80') || l.startsWith('::ffff:');
}
async function checkTarget(u) {
  if (!/^https?:$/.test(u.protocol)) throw new Error('Only http and https links are supported.');
  if (ALLOW_PRIVATE) return;
  const host = u.hostname.replace(/^\[|\]$/g, '');
  const addrs = net.isIP(host) ? [{ address: host }] : await dns.lookup(host, { all: true });
  if (addrs.some(a => isPrivateIp(a.address))) throw new Error('That address is blocked.');
}
async function fetchFollow(u, opts) {
  for (let i = 0; i < 6; i++) {
    await checkTarget(u);
    const r = await fetch(u, { ...opts, redirect: 'manual' });
    const loc = r.headers.get('location');
    if (r.status >= 300 && r.status < 400 && loc) {
      u = new URL(loc, u);
      if (opts.method === 'POST' && r.status <= 303) opts = { ...opts, method: 'GET', body: undefined };
      continue;
    }
    return { r, u };
  }
  throw new Error('Too many redirects.');
}

// ---- rewriting ----
const SKIP = /^(#|data:|blob:|javascript:|mailto:|tel:|about:)/i;
const P = (v, base) => {
  const t = (v || '').trim();
  if (!t || SKIP.test(t)) return v;
  try { return '/go?url=' + encodeURIComponent(new URL(t, base).href); } catch { return v; }
};
const unesc = s => s.replace(/&amp;/g, '&');
function rewriteCss(css, base) {
  return css
    .replace(/url\(\s*(['"]?)(.*?)\1\s*\)/gi, (m, q, u) => `url(${q}${P(u, base)}${q})`)
    .replace(/@import\s+(['"])(.*?)\1/gi, (m, q, u) => `@import ${q}${P(u, base)}${q}`);
}
function clientScript(base) {
  return `<script>(function(){var B=${JSON.stringify(base)};
function P(u){try{u=String(u);if(/^(#|data:|blob:|javascript:|mailto:|tel:)/i.test(u)||u.indexOf('/go?url=')===0)return u;return '/go?url='+encodeURIComponent(new URL(u,B).href)}catch(e){return u}}
var of=window.fetch;window.fetch=function(i,o){try{if(typeof i==='string')i=P(i);else if(i&&i.url)i=new Request(P(i.url),i)}catch(e){}return of.call(this,i,o)};
var ox=XMLHttpRequest.prototype.open;XMLHttpRequest.prototype.open=function(m,u){arguments[1]=P(u);return ox.apply(this,arguments)};
var oo=window.open;window.open=function(u){if(u){location.href=P(u);return null}return oo.apply(this,arguments)};
document.addEventListener('click',function(e){var a=e.target.closest&&e.target.closest('a[href]');if(!a)return;var h=a.getAttribute('href');if(h&&h.indexOf('/go?url=')!==0&&!/^(#|javascript:|mailto:|tel:)/i.test(h)){e.preventDefault();location.href=P(h)}},true);
document.addEventListener('submit',function(e){var f=e.target;if(!f||f.tagName!=='FORM')return;var a=new URL(f.getAttribute('action')||'',B);if((f.method||'get').toLowerCase()==='get'){e.preventDefault();var q=new URLSearchParams();new FormData(f).forEach(function(v,k){if(typeof v==='string')q.append(k,v)});a.search=q.toString();location.href=P(a.href)}else{f.action=P(a.href)}},true);
})();</script>`;
}
function rewriteHtml(html, base) {
  html = html
    .replace(/<meta[^>]+http-equiv=["']?content-security-policy[^>]*>/gi, '')
    .replace(/<base\b[^>]*>/gi, '')
    .replace(/\s(integrity|nonce|crossorigin)=("[^"]*"|'[^']*'|[^\s>]+)/gi, '')
    .replace(/\starget=("_blank"|'_blank'|_blank)/gi, ' target="_self"')
    .replace(/(\s(?:href|src|poster|data-src)\s*=\s*)(["'])(.*?)\2/gi, (m, a, q, v) => a + q + P(unesc(v), base) + q)
    .replace(/(\ssrcset\s*=\s*)(["'])(.*?)\2/gi, (m, a, q, v) =>
      a + q + v.split(',').map(s => { const [u, ...r] = s.trim().split(/\s+/); return [P(unesc(u), base), ...r].join(' '); }).join(', ') + q)
    .replace(/<style([^>]*)>([\s\S]*?)<\/style>/gi, (m, a, css) => `<style${a}>${rewriteCss(css, base)}</style>`);
  const inject = clientScript(base);
  return /<head[^>]*>/i.test(html) ? html.replace(/<head[^>]*>/i, m => m + inject) : inject + html;
}

// ---- helpers ----
const readBody = req => new Promise(res => { const c = []; req.on('data', d => c.push(d)); req.on('end', () => res(Buffer.concat(c))); });
const page = (code, msg) => `<!doctype html><meta charset="utf-8"><body style="font-family:system-ui;color:#7a1f3d;background:#fff1f5;text-align:center;padding:18vh 20px 0"><h2>${code}</h2><p>${String(msg).replace(/[<&]/g, '')}</p></body>`;
function sendStream(res, r, extra = {}) {
  const h = { 'content-type': r.headers.get('content-type') || 'application/octet-stream', ...extra };
  res.writeHead(r.status, h);
  if (r.body) Readable.fromWeb(r.body).pipe(res); else res.end();
}

async function handleGo(req, res, url) {
  const target = new URL(url.searchParams.get('url') || '');
  const opts = { method: req.method === 'POST' ? 'POST' : 'GET',
    headers: { 'user-agent': UA, 'accept': req.headers.accept || '*/*', 'accept-language': 'en-US,en;q=0.9' } };
  if (opts.method === 'POST') { opts.body = await readBody(req); if (req.headers['content-type']) opts.headers['content-type'] = req.headers['content-type']; }
  const { r, u } = await fetchFollow(target, opts);
  const type = r.headers.get('content-type') || '';
  if (/text\/html/i.test(type)) {
    const out = rewriteHtml(await r.text(), u.href);
    res.writeHead(r.status, { 'content-type': 'text/html; charset=utf-8' }); res.end(out);
  } else if (/text\/css/i.test(type)) {
    res.writeHead(r.status, { 'content-type': type }); res.end(rewriteCss(await r.text(), u.href));
  } else sendStream(res, r);
}
async function handleRaw(req, res, url) {
  const target = new URL(url.searchParams.get('url') || '');
  if (!RAW_HOSTS.has(target.hostname)) { res.writeHead(403); return res.end('Not allowed'); }
  const { r } = await fetchFollow(target, { method: 'GET', headers: { 'user-agent': UA } });
  sendStream(res, r, { 'cache-control': 'public, max-age=3600' });
}

http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, 'http://localhost');
    if (ACCESS_CODE) {
      const ok = (req.headers.cookie || '').includes('ac=' + encodeURIComponent(ACCESS_CODE));
      if (!ok) {
        if (url.searchParams.get('code') === ACCESS_CODE) {
          res.writeHead(302, { 'set-cookie': 'ac=' + encodeURIComponent(ACCESS_CODE) + '; Path=/; HttpOnly; SameSite=Lax', location: '/' });
          return res.end();
        }
        res.writeHead(401, { 'content-type': 'text/html' });
        return res.end(page('Access code needed', 'Add ?code=YOUR_CODE to the address.'));
      }
    }
    if (url.pathname === '/' || url.pathname === '/index.html') {
      const html = fs.readFileSync(path.join(__dirname, 'public', 'index.html'), 'utf8').replace('window.PROXY_MODE=false', 'window.PROXY_MODE=true');
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' }); return res.end(html);
    }
    if (url.pathname === '/go') return await handleGo(req, res, url);
    if (url.pathname === '/raw') return await handleRaw(req, res, url);
    res.writeHead(404, { 'content-type': 'text/html' }); res.end(page('Not found', 'That page does not exist.'));
  } catch (e) {
    if (!res.headersSent) res.writeHead(502, { 'content-type': 'text/html' });
    res.end(page('Could not load that page', e.message || 'Unknown error'));
  }
}).listen(PORT, () => console.log('Running at http://localhost:' + PORT));
