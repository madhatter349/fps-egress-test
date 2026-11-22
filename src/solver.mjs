// Cloudflare managed-challenge harness.
//
// fetchChallengePage -> the 403 challenge document (it still carries the page)
// extractChallenge   -> the window._cf_chl_opt fields the VM needs
// runVm              -> run the orchestrate script in jsdom and capture the
//                       challenge POST(s) it builds (URL, headers, body)
//
// The VM needs a handful of browser APIs jsdom lacks; see ./polyfills.mjs.
// ReadableStream/WritableStream/TransformStream are the load-bearing ones: the
// VM's feature battery reads ReadableStream.prototype.pipeTo and unwinds before
// xhr.send() without them.

import { JSDOM, VirtualConsole, ResourceLoader } from 'jsdom';
import { installPolyfills } from './polyfills.mjs';

// The site's WAF challenges requests whose UA advertises Chrome < 155 even when
// a valid cf_clearance is presented (measured: 151/152/153 -> 403, 155..160 ->
// 200 with the same cookie pair). curl_cffi's newest TLS profile is chrome152,
// so the UA header says 157 while the TLS/JA4 stays chrome152.
export const CHROME_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/157.0.0.0 Safari/537.36';
const UA = CHROME_UA;

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function browserHeaders(url, extra = {}) {
  return {
    'user-agent': UA,
    accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
    'accept-language': 'en-US,en;q=0.9',
    'sec-ch-ua': '"Chromium";v="157", "Not?A_Brand";v="24", "Google Chrome";v="157"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    'sec-fetch-dest': 'document',
    'sec-fetch-mode': 'navigate',
    'sec-fetch-site': 'none',
    'sec-fetch-user': '?1',
    'upgrade-insecure-requests': '1',
    referer: new URL(url).origin + '/',
    ...extra,
  };
}

async function fetchText(url, headers, attempts = 3) {
  let lastErr;
  for (let i = 0; i < attempts; i++) {
    try {
      const res = await fetch(url, { headers, redirect: 'follow' });
      const text = await res.text();
      if (text) return { status: res.status, text, headers: res.headers };
      lastErr = new Error(`empty response (${res.status}) from ${url}`);
    } catch (err) {
      lastErr = err;
    }
    await sleep(400 * (i + 1));
  }
  throw lastErr;
}

// The site allows roughly 4-5 page loads per IP before its own rate limiter
// answers 429 (fps-access/docs/session-flow.md). A test run asks for the same
// challenge page several times, so hold it briefly: the body is identical and
// only the ray token ages, which matters to the live solve (it fetches its own
// instance) but not to parsing.
const PAGE_TTL_MS = Number(process.env.CF_PAGE_TTL_MS || 60000);
const pageCache = new Map();
const scriptCache = new Map();

// The challenge document is served with 403 + cf-mitigated: challenge, but the
// body is the real challenge page. Treat any non-empty HTML as success.
export async function fetchChallengePage(url) {
  const hit = pageCache.get(url);
  if (hit && Date.now() - hit.at < PAGE_TTL_MS) return hit.text;
  const { text } = await fetchText(url, browserHeaders(url));
  if (!text.includes('_cf_chl_opt')) {
    throw new Error(`no challenge page at ${url} (${text.length} bytes, no _cf_chl_opt)`);
  }
  pageCache.set(url, { at: Date.now(), text });
  return text;
}

function unquote(raw) {
  const quote = raw[0];
  const body = raw.slice(1, -1);
  if (quote === '"') {
    try { return JSON.parse(raw); } catch { /* fall through */ }
  }
  return body.replace(/\\(['"\\])/g, '$1').replace(/\\n/g, '\n').replace(/\\t/g, '\t');
}

// Pull the `window._cf_chl_opt = { ... }` literal out of the page and read its
// scalar fields. Deliberately not eval'd: the page is remote input.
export function extractChallenge(html) {
  const marker = html.indexOf('_cf_chl_opt');
  if (marker === -1) throw new Error('_cf_chl_opt not found');
  const open = html.indexOf('{', marker);
  if (open === -1) throw new Error('_cf_chl_opt object not found');

  let depth = 0;
  let quote = null;
  let end = -1;
  for (let i = open; i < html.length; i++) {
    const ch = html[i];
    if (quote) {
      if (ch === '\\') { i++; continue; }
      if (ch === quote) quote = null;
      continue;
    }
    if (ch === "'" || ch === '"') { quote = ch; continue; }
    if (ch === '{') depth++;
    else if (ch === '}' && --depth === 0) { end = i + 1; break; }
  }
  if (end === -1) throw new Error('unterminated _cf_chl_opt object');

  const literal = html.slice(open, end);
  const out = {};
  const pair = /([A-Za-z_$][\w$]*)\s*:\s*('(?:\\.|[^'\\])*'|"(?:\\.|[^"\\])*"|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?|true|false|null)/g;
  for (const m of literal.matchAll(pair)) {
    const [, key, raw] = m;
    if (raw[0] === "'" || raw[0] === '"') out[key] = unquote(raw);
    else if (raw === 'true') out[key] = true;
    else if (raw === 'false') out[key] = false;
    else if (raw === 'null') out[key] = null;
    else out[key] = Number(raw);
  }
  return out;
}

function challengeScriptUrl(html, pageUrl) {
  const m = html.match(/\/cdn-cgi\/challenge-platform\/[^'"\s\\]+/);
  if (!m) throw new Error('challenge orchestrate script URL not found');
  return new URL(m[0], pageUrl).href;
}

// jsdom 24 has no requestInterceptor; a ResourceLoader is the supported hook.
class ChallengeResourceLoader extends ResourceLoader {
  constructor(script) {
    super();
    this.script = script;
  }
  fetch(url) {
    const u = String(url);
    if (u.includes('/cdn-cgi/challenge-platform/')) {
      return Promise.resolve(Buffer.from(this.script, 'utf8'));
    }
    // Turnstile api.js and everything else: empty is enough. The VM defines its
    // own body encoder and sends the challenge POST without the widget.
    return Promise.resolve(Buffer.from(''));
  }
}

function bodyToString(body) {
  if (body == null) return '';
  if (typeof body === 'string') return body;
  if (typeof URLSearchParams !== 'undefined' && body instanceof URLSearchParams) return body.toString();
  if (typeof ArrayBuffer !== 'undefined' && body instanceof ArrayBuffer) return Buffer.from(body).toString('utf8');
  if (ArrayBuffer.isView(body)) return Buffer.from(body.buffer, body.byteOffset, body.byteLength).toString('utf8');
  if (typeof Blob !== 'undefined' && body instanceof Blob) return `[Blob type=${body.type} size=${body.size}]`;
  if (typeof FormData !== 'undefined' && body instanceof FormData) {
    return [...body.entries()].map(([k, v]) => `${k}=${typeof v === 'string' ? v : '[file]'}`).join('&');
  }
  return String(body);
}

// Hook every outbound path the VM can use. We record the payload and do not
// let it hit the network: the harness is about capturing what the VM builds.
function hookNetwork(window, posts, transport) {
  const record = (entry) => {
    const method = String(entry.method || 'GET').toUpperCase();
    if (method === 'GET' && !entry.body) return;
    posts.push(entry);
  };

  if (transport) {
    // Live mode: patch jsdom's real XMLHttpRequest instead of replacing it. The
    // VM inspects the XHR object it created (instanceof, readyState constants,
    // response headers), and a hand-rolled stand-in makes its response decoder
    // throw. The request never reaches the network: send() hands the payload to
    // the transport and dispatches the real response.
    const proto = window.XMLHttpRequest.prototype;
    const open = proto.open;
    const setRequestHeader = proto.setRequestHeader;
    const send = proto.send;
    let current = null;
    proto.open = function (method, url, ...rest) {
      current = { method: String(method).toUpperCase(), url: String(url), headers: {} };
      if (process.env.CF_DEBUG === '1') console.error(`[cf] open ${current.method} ${current.url.slice(0, 60)}`);
      return open.call(this, method, url, ...rest);
    };
    proto.setRequestHeader = function (name, value) {
      if (current) current.headers[name] = String(value);
      return setRequestHeader.call(this, name, value);
    };
    proto.send = function (body) {
      const self = this;
      const entry = {
        via: 'xhr',
        method: current ? current.method : 'GET',
        url: current ? current.url : '',
        headers: current ? { ...current.headers } : {},
        body: bodyToString(body),
      };
      record(entry);
      if (process.env.CF_DEBUG === '1') {
        console.error(`[cf +${Date.now() % 100000}] xhr ${entry.method} ${entry.url.slice(0, 90)} len=${entry.body.length}`);
      }
      Promise.resolve()
        .then(() => transport(entry))
        .then((res) => {
          if (window.__cfClosed) return;
          if (process.env.CF_DEBUG === '1') console.error('[cf] then start');
          if (process.env.CF_DEBUG === '1') {
            const h = createHash('sha1').update(res.body || '').digest('hex').slice(0, 12);
            console.error(`[cf +${Date.now() % 100000}] <- ${res.status} len=${(res.body || '').length} sha1=${h} head=${JSON.stringify((res.body || '').slice(0, 40))}`);
          }
          const headers = res.headers || {};
          Object.defineProperty(self, 'readyState', { value: 4, configurable: true });
          Object.defineProperty(self, 'status', { value: res.status, configurable: true });
          Object.defineProperty(self, 'statusText', { value: res.status === 200 ? 'OK' : '', configurable: true });
          Object.defineProperty(self, 'responseURL', { value: entry.url, configurable: true });
          Object.defineProperty(self, 'responseText', { value: res.body || '', configurable: true });
          Object.defineProperty(self, 'response', { value: res.body || '', configurable: true });
          self.getAllResponseHeaders = () => Object.entries(headers).map(([k, v]) => `${k}: ${v}`).join('\r\n');
          self.getResponseHeader = (name) => {
            const key = String(name).toLowerCase();
            const hit = Object.entries(headers).find(([k]) => k.toLowerCase() === key);
            return hit ? String(hit[1]) : null;
          };
          try { if (self.onreadystatechange) self.onreadystatechange(); } catch (e) {
            if (process.env.CF_DEBUG === '1') console.error(`[cf] rsc threw: ${e && (e.stack || e.message)}`.slice(0, 400));
          }
          try { if (self.onload) self.onload(); } catch (e) {
            if (process.env.CF_DEBUG === '1') console.error(`[cf] onload threw: ${e && (e.stack || e.message)}`.slice(0, 400));
          }
          try { if (self.onloadend) self.onloadend(); } catch { /* ignore */ }
        })
        .catch((e) => {
          if (process.env.CF_DEBUG === '1') console.error(`[cf] transport failed: ${e && e.message}`);
          Object.defineProperty(self, 'readyState', { value: 4, configurable: true });
          Object.defineProperty(self, 'status', { value: 0, configurable: true });
          try { if (self.onreadystatechange) self.onreadystatechange(); } catch { /* ignore */ }
          try { if (self.onerror) self.onerror({ type: 'error' }); } catch { /* ignore */ }
          try { if (self.onloadend) self.onloadend(); } catch { /* ignore */ }
        });
    };
    return;
  }

  // A stand-in XHR: it records the payload and then reports an empty 200 so the
  // VM continues to its follow-up POST. Nothing is submitted to Cloudflare.
  window.XMLHttpRequest = class XMLHttpRequest {
    static UNSENT = 0;
    static OPENED = 1;
    static HEADERS_RECEIVED = 2;
    static LOADING = 3;
    static DONE = 4;
    constructor() {
      this.UNSENT = 0;
      this.OPENED = 1;
      this.HEADERS_RECEIVED = 2;
      this.LOADING = 3;
      this.DONE = 4;
      this.readyState = 0;
      this.status = 0;
      this.statusText = '';
      this.response = '';
      this.responseText = '';
      this.responseType = '';
      this.responseURL = '';
      this.timeout = 0;
      this.withCredentials = false;
      this.upload = { addEventListener() {}, removeEventListener() {} };
      this._method = 'GET';
      this._url = '';
      this._headers = {};
      this._listeners = {};
      this.onreadystatechange = null;
      this.onload = null;
      this.onloadend = null;
      this.onerror = null;
      this.onabort = null;
      this.ontimeout = null;
      this.onprogress = null;
    }
    open(method, url) {
      this._method = String(method).toUpperCase();
      this._url = String(url);
      this.readyState = 1;
      this._fire('readystatechange');
    }
    setRequestHeader(name, value) {
      this._headers[name] = String(value);
    }
    overrideMimeType() {}
    getAllResponseHeaders() {
      return Object.entries(this._responseHeaders || {})
        .map(([k, v]) => `${k}: ${v}`)
        .join('\r\n');
    }
    getResponseHeader(name) {
      const key = String(name).toLowerCase();
      const hit = Object.entries(this._responseHeaders || {}).find(([k]) => k.toLowerCase() === key);
      return hit ? String(hit[1]) : null;
    }
    abort() {
      this.readyState = 0;
      this._fire('abort');
      this._fire('loadend');
    }
    send(body) {
      const entry = {
        via: 'xhr',
        method: this._method,
        url: this._url,
        headers: { ...this._headers },
        body: bodyToString(body),
      };
      record(entry);
      if (process.env.CF_DEBUG === '1') console.error(`[cf +${Date.now() % 100000}] xhr ${this._method} ${this._url.slice(0, 90)} len=${entry.body.length} responseType=${this.responseType}`);
      if (transport) {
        // Live mode: the VM sees the real response, which is what lets it build
        // its follow-up POST. Offline mode answers with an empty 200 and the VM
        // stops after its first payload.
        Promise.resolve()
          .then(() => transport(entry))
          .then((res) => {
            this._responseHeaders = res.headers || {};
            this.readyState = 4;
            this.status = res.status;
            this.statusText = res.status === 200 ? 'OK' : '';
            this.responseURL = this._url;
            this.responseText = res.body || '';
            this.response = this.responseText;
            this._fire('readystatechange');
            this._fire('load');
            this._fire('loadend');
          })
          .catch(() => {
            this.readyState = 4;
            this.status = 0;
            this._fire('readystatechange');
            this._fire('error');
            this._fire('loadend');
          });
        return;
      }
      const finish = () => {
        this.readyState = 2;
        this._fire('readystatechange');
        this.readyState = 3;
        this._fire('readystatechange');
        this.readyState = 4;
        this.status = 200;
        this.statusText = 'OK';
        this.responseURL = this._url;
        if (this.responseType === 'arraybuffer') this.response = new ArrayBuffer(0);
        else if (this.responseType === 'json') this.response = null;
        else { this.responseText = ''; this.response = ''; }
        this._fire('readystatechange');
        this._fire('load');
        this._fire('loadend');
      };
      // Async XHRs (the normal case) get their response on the next tick.
      setTimeout(finish, 0);
    }
    addEventListener(type, fn) {
      (this._listeners[type] ||= []).push(fn);
    }
    removeEventListener(type, fn) {
      const list = this._listeners[type];
      if (list) this._listeners[type] = list.filter((f) => f !== fn);
    }
    _fire(type) {
      const event = { type, target: this, currentTarget: this };
      const debug = process.env.CF_DEBUG === '1';
      const handler = this['on' + type];
      if (typeof handler === 'function') {
        try { handler.call(this, event); } catch (e) { if (debug) console.error(`[cf] ${type} handler threw: ${e && (e.stack || e.message || String(e))}`.slice(0, 600)); }
      }
      for (const fn of this._listeners[type] || []) {
        try { fn.call(this, event); } catch (e) { if (debug) console.error(`[cf] ${type} listener threw: ${e && e.message}`); }
      }
    }
  };

  window.fetch = async (input, init = {}) => {
    const url = typeof input === 'string' ? input : input && input.url;
    const method = init.method || (input && input.method) || 'GET';
    const headers = {};
    const rawHeaders = init.headers || (input && input.headers);
    if (rawHeaders) {
      if (typeof rawHeaders.forEach === 'function' && !Array.isArray(rawHeaders)) {
        rawHeaders.forEach((v, k) => { headers[k] = String(v); });
      } else if (Array.isArray(rawHeaders)) {
        for (const [k, v] of rawHeaders) headers[k] = String(v);
      } else {
        for (const [k, v] of Object.entries(rawHeaders)) headers[k] = String(v);
      }
    }
    record({ via: 'fetch', method, url: String(url), headers, body: bodyToString(init.body) });
    return new Response('', { status: 200, headers: { 'content-type': 'text/plain' } });
  };

  if (window.navigator) {
    window.navigator.sendBeacon = (url, data) => {
      record({ via: 'beacon', method: 'POST', url: String(url), headers: {}, body: bodyToString(data) });
      return true;
    };
  }
}

export async function runVm(html, url, options = {}) {
  let script = options.script;
  if (!script) {
    const scriptUrl = challengeScriptUrl(html, url);
    const hit = scriptCache.get(scriptUrl);
    if (hit && Date.now() - hit.at < PAGE_TTL_MS) {
      script = hit.text;
    } else {
      ({ text: script } = await fetchText(scriptUrl, browserHeaders(url, {
        accept: '*/*',
        'sec-fetch-dest': 'script',
        'sec-fetch-mode': 'no-cors',
        'sec-fetch-site': 'same-origin',
      })));
      scriptCache.set(scriptUrl, { at: Date.now(), text: script });
    }
  }

  const posts = [];
  const virtualConsole = new VirtualConsole();
  virtualConsole.on('jsdomError', () => {});
  virtualConsole.on('error', () => {});
  virtualConsole.on('warn', () => {});

  const dom = new JSDOM(html, {
    url,
    referer: new URL(url).origin + '/',
    runScripts: 'dangerously',
    pretendToBeVisual: true,
    virtualConsole,
    resources: new ChallengeResourceLoader(script),
    beforeParse(window) {
      installPolyfills(window);
      if (process.env.CF_DEBUG === '1') {
        const names = ['TextDecoder','TextEncoder','atob','btoa','Uint8Array','ArrayBuffer','Blob','URL','crypto','ReadableStream','structuredClone','queueMicrotask'];
        console.error('[cf] globals: ' + names.map((n) => `${n}=${typeof window[n]}`).join(' '));
      }
      hookNetwork(window, posts, options.transport);
    },
  });

  try {
    // The VM sends its first POST within ~1s of the script running. Wait for
    // one, then give it a short settle window to emit the follow-up POST(s).
    // The VM sends its first POST within ~1s. In live mode the response to that
    // POST is ~230 KB of encoded data; decoding it and building the follow-up
    // POST takes a few seconds in jsdom, so wait for the stream to go quiet
    // rather than for a fixed settle window.
    // Measured: the VM's first POST lands in ~1s; in live mode it needs ~10s
    // after the ~230 KB response to decode it and build the follow-up POST.
    const quietMs = options.transport ? 15000 : 1500;
    const quietAfterFollowUp = 2500;
    const deadline = Date.now() + (options.transport ? 60000 : 20000);
    let lastCount = 0;
    let quietSince = Date.now();
    while (Date.now() < deadline) {
      await sleep(100);
      if (posts.length !== lastCount) {
        lastCount = posts.length;
        quietSince = Date.now();
      }
      const quiet = posts.length >= 2 ? quietAfterFollowUp : quietMs;
      if (posts.length > 0 && Date.now() - quietSince > quiet) break;
    }
  } finally {
    dom.window.__cfClosed = true;
    for (const worker of dom.window.__cfWorkers || []) {
      try { worker.terminate(); } catch { /* ignore */ }
    }
    try { dom.window.close(); } catch { /* ignore */ }
  }

  return posts;
}

// ---------------------------------------------------------------------------
// Submission half: TLS-matched transport
//
// The VM builds the payload; this half puts it on the wire over a Chrome
// TLS/JA3+JA4 + HTTP/2 fingerprint that agrees with the UA the VM reported.
// curl_cffi (Python) is the client: Node has no maintained TLS-impersonation
// stack, and undici's TLS is not browser-like. scripts/cf_transport.py owns the
// session so the challenge GET, every POST and the clearance GET share one
// cookie jar and one connection pool.
//
// Session state is keyed by target URL under $CF_SESSION_DIR (default
// os.tmpdir()/cf-solver-sessions) and holds the cookie jar (cf_clearance +
// __cf_bm) plus the last challenge metadata.
//
// Two-phase vs live: an offline runVm only produces the first POST, because the
// VM needs the real response to that POST before it can build the second one.
// submitChallenge therefore submits the payloads it was given and, if they do
// not mint a clearance, completes the challenge live over the same session
// (solveLive). Set CF_NO_LIVE_FALLBACK=1 to disable that and get null instead.
// ---------------------------------------------------------------------------

import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const TRANSPORT = path.join(HERE, '..', 'scripts', 'cf_transport.py');
const PYTHON = process.env.CF_PYTHON || '/tmp/cffi-venv/bin/python';
const SESSION_DIR = process.env.CF_SESSION_DIR || path.join(os.tmpdir(), 'cf-solver-sessions');

/** Deterministic session-state path for a target URL. */
export function sessionPath(url) {
  const hash = createHash('sha1').update(String(url)).digest('hex').slice(0, 16);
  return path.join(SESSION_DIR, `${hash}.json`);
}

/** Diagnostics from the last submitChallenge call (statuses, headers, bodies). */
export let lastSubmit = null;

function runTransport(args) {
  return new Promise((resolve, reject) => {
    const child = spawn(PYTHON, [TRANSPORT, ...args], { stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '';
    let err = '';
    child.stdout.on('data', (d) => { out += d; });
    child.stderr.on('data', (d) => { err += d; });
    child.on('error', (e) => reject(new Error(`cannot run ${PYTHON}: ${e.message}`)));
    child.on('close', (code) => {
      const line = out.trim().split('\n').filter(Boolean).pop();
      if (!line) {
        return reject(new Error(`transport produced no output (exit ${code}): ${err.slice(0, 400)}`));
      }
      let parsed;
      try { parsed = JSON.parse(line); } catch {
        return reject(new Error(`transport output was not JSON: ${line.slice(0, 300)}`));
      }
      if (!parsed.ok) return reject(new Error(parsed.error || 'transport failed'));
      resolve(parsed);
    });
  });
}

// --- live bridge -----------------------------------------------------------
// The offline VM stops after its first POST: it answers its own XHR with an
// empty 200, and the VM needs the real response to that POST to build the
// second one. Measured on this challenge: offline -> 1 POST (the /fo
// fingerprint report), no clearance; live -> 2 POSTs, the second one mints
// cf_clearance. So the transport can also drive the VM live over one session.

function openBridge(key) {
  return new Promise((resolve, reject) => {
    const child = spawn(PYTHON, [TRANSPORT, 'serve', sessionPath(key)], {
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    let buf = '';
    let stderr = '';
    let exited = false;
    const waiters = [];
    child.stderr.on('data', (d) => { stderr += d; });
    child.stdout.on('data', (d) => {
      buf += d;
      let i;
      while ((i = buf.indexOf('\n')) >= 0) {
        const line = buf.slice(0, i);
        buf = buf.slice(i + 1);
        if (!line.trim()) continue;
        const waiter = waiters.shift();
        if (waiter) waiter(JSON.parse(line));
      }
    });
    child.on('error', (e) => reject(new Error(`cannot run ${PYTHON}: ${e.message}`)));
    child.on('exit', (code) => {
      exited = true;
      while (waiters.length) waiters.shift()({ ok: false, error: `bridge exited (${code}): ${stderr.slice(0, 300)}` });
    });
    // A bridge that dies (or wedges) must not leave the caller pending forever:
    // a pipeline that hangs is worse than one that fails and retries.
    const CALL_TIMEOUT_MS = Number(process.env.CF_BRIDGE_TIMEOUT_MS || 120_000);
    const call = (obj) => new Promise((res) => {
      if (exited) {
        return res({ ok: false, error: `bridge already exited: ${stderr.slice(0, 300)}` });
      }
      const timer = setTimeout(() => {
        const i = waiters.indexOf(settle);
        if (i >= 0) waiters.splice(i, 1);
        res({ ok: false, error: `bridge call timed out after ${CALL_TIMEOUT_MS}ms` });
      }, CALL_TIMEOUT_MS);
      timer.unref?.();
      const settle = (v) => { clearTimeout(timer); res(v); };
      waiters.push(settle);
      try {
        child.stdin.write(JSON.stringify(obj) + '\n');
      } catch (e) {
        const i = waiters.indexOf(settle);
        if (i >= 0) waiters.splice(i, 1);
        clearTimeout(timer);
        res({ ok: false, error: `bridge write failed: ${e.message}` });
      }
    });
    child.unref();
    if (child.stdin) child.stdin.unref?.();
    resolve({
      call,
      close() {
        return new Promise((done) => {
          const finish = () => {
            // The stdio pipes are the only thing that keeps the event loop
            // alive after the child is gone; destroy them explicitly.
            try { child.stdout?.destroy(); } catch { /* ignore */ }
            try { child.stderr?.destroy(); } catch { /* ignore */ }
            try { child.stdin?.destroy(); } catch { /* ignore */ }
            done();
          };
          if (child.exitCode !== null) return finish();
          child.once('exit', finish);
          try { child.stdin.end(JSON.stringify({ cmd: 'quit' }) + '\n'); } catch { /* ignore */ }
          const t = setTimeout(() => {
            try { child.kill('SIGKILL'); } catch { /* ignore */ }
            finish();
          }, 1000);
          t.unref?.();
        });
      },
    });
  });
}

function readState(key) {
  try {
    return JSON.parse(fs.readFileSync(sessionPath(key), 'utf8'));
  } catch {
    return null;
  }
}

function readClearance(key) {
  const st = readState(key);
  const c = st && (st.cookies || []).find((x) => x.name === 'cf_clearance');
  return c ? c.value : null;
}

// A clearance minted minutes ago in this same session is still good; re-solving
// costs one of the IP's ~4-5 page loads for nothing.
const CLEARANCE_REUSE_MS = Number(process.env.CF_CLEARANCE_REUSE_MS || 5 * 60 * 1000);

function freshClearance(key) {
  const st = readState(key);
  if (!st || !st.saved_at) return null;
  if (Date.now() / 1000 - st.saved_at > CLEARANCE_REUSE_MS / 1000) return null;
  const c = (st.cookies || []).find((x) => x.name === 'cf_clearance');
  return c ? c.value : null;
}

/**
 * Run the whole challenge live: challenge GET, VM with real responses, clearance.
 *
 * @param {string} url
 * @param {{sessionKey?: string}} [opts] sessionKey shares one cookie jar across
 *   URLs on the same host (cf_clearance is host-scoped, so one jar is enough and
 *   keeps __cf_bm warm — which matters when the IP's page-load budget is ~4-5).
 * @returns {Promise<{posts: Array, clearance: string|null, challengeStatus: number}>}
 */
export async function solveLive(url, opts = {}) {
  const key = opts.sessionKey || url;
  fs.mkdirSync(SESSION_DIR, { recursive: true });
  const bridge = await openBridge(key);
  try {
    let ch = await bridge.call({ cmd: 'challenge', url });
    if (!ch.ok) throw new Error(ch.error || 'challenge GET failed');
    if (process.env.CF_DEBUG === '1') {
      console.error(`[cf] solveLive challenge status=${ch.status} cookies=${JSON.stringify(ch.cookies)}`);
    }
    if (ch.status === 200) {
      // Served without a challenge. If the jar already holds a clearance, use
      // it; otherwise the 200 came from a warm __cf_bm (a side effect of an
      // earlier POST) and there is no cookie to return, so force a challenge
      // with a clean jar.
      const existing = readClearance(key);
      if (existing) return { posts: [], clearance: existing, challengeStatus: ch.status };
      ch = await bridge.call({ cmd: 'challenge', url, fresh: true });
      if (!ch.ok) throw new Error(ch.error || 'challenge GET failed');
      if (process.env.CF_DEBUG === '1') {
        console.error(`[cf] solveLive fresh challenge status=${ch.status}`);
      }
      if (ch.status === 200) return { posts: [], clearance: readClearance(key), challengeStatus: ch.status };
    }
    const html = fs.readFileSync(ch.html_path, 'utf8');
    const script = fs.readFileSync(ch.script_path, 'utf8');
    const posts = await runVm(html, url, {
      script,
      transport: async (entry) => {
        const res = await bridge.call({
          cmd: 'post',
          url: entry.url,
          headers: entry.headers,
          body_b64: Buffer.from(entry.body, 'utf8').toString('base64'),
        });
        if (!res.ok) throw new Error(res.error || 'bridge POST failed');
        if (process.env.CF_DEBUG === '1') console.error(`[cf +${Date.now() % 100000}] <- ${res.status} len=${Buffer.from(res.body_b64, 'base64').length}`);
        return {
          status: res.status,
          headers: res.headers,
          body: Buffer.from(res.body_b64, 'base64').toString('utf8'),
        };
      },
    });
    const clearance = readClearance(key);
    if (process.env.CF_DEBUG === '1') {
      console.error(`[cf] solveLive posts=${posts.length} clearance=${clearance ? clearance.length : null}`);
    }
    return { posts, clearance, challengeStatus: ch.status };
  } finally {
    await bridge.close();
  }
}

function normalizePosts(posts) {
  const list = Array.isArray(posts) ? posts : [];
  return list
    .filter((p) => p && p.url && p.body != null && String(p.body).length > 0)
    .map((p) => ({
      url: String(p.url),
      body: String(p.body),
      headers: p.headers && typeof p.headers === 'object' ? p.headers : {},
    }));
}

/**
 * Submit the VM's challenge POST(s) over the TLS-matched session.
 *
 * @param {Array<{url:string, body:string, headers?:object}>} posts
 * @param {string} url  the page the challenge was served for
 * @returns {Promise<string|null>} the cf_clearance value, or null if the
 *   challenge was answered but no clearance was minted.
 */
export async function submitChallenge(posts, url) {
  const list = normalizePosts(posts);
  if (list.length === 0) throw new Error('submitChallenge: no POST payloads to submit');

  fs.mkdirSync(SESSION_DIR, { recursive: true });
  const state = sessionPath(url);

  if (process.env.CF_REUSE_CLEARANCE !== '0') {
    const cached = freshClearance(url);
    if (cached) {
      lastSubmit = { reused: true, cf_clearance: cached };
      return cached;
    }
  }

  if (!fs.existsSync(state)) {
    if (process.env.CF_PRIME_SESSION === '1') {
      // Optional: share a cookie jar with the challenge GET. Costs one request.
      try { await runTransport(['challenge', url, state]); } catch { /* best effort */ }
    }
    if (!fs.existsSync(state)) {
      fs.writeFileSync(state, JSON.stringify({ url, cookies: [] }));
    }
  }

  // A single /fo/ fingerprint report cannot mint a clearance: the VM only
  // builds the POST that does after it has seen the response to that one.
  // Submitting it anyway would burn one of the IP's ~4-5 page budget for
  // nothing, so go straight to the live solve in that case.
  const looksComplete = list.length >= 2 || list.some((p) => /\/eb\//.test(p.url));
  let res = null;
  if (looksComplete) {
    const postsFile = path.join(SESSION_DIR, `posts-${process.pid}-${Date.now()}.json`);
    fs.writeFileSync(postsFile, JSON.stringify(list));
    try {
      res = await runTransport(['submit', state, postsFile]);
      lastSubmit = res;
    } finally {
      try { fs.unlinkSync(postsFile); } catch { /* ignore */ }
    }
    if (res.cf_clearance) return res.cf_clearance;
  }

  // The payloads did not mint a clearance. That is the expected outcome for an
  // offline runVm: the VM needs the real response to its first POST before it
  // can build the second one. Complete the challenge live over the same
  // transport so the caller still gets a usable cookie.
  if (process.env.CF_NO_LIVE_FALLBACK === '1') return null;
  const live = await solveLive(url);
  lastSubmit = { ...(res || {}), live: { challengeStatus: live.challengeStatus, posts: live.posts.length } };
  return live.clearance || null;
}

/**
 * GET a page with a cf_clearance cookie over the same TLS-matched session.
 *
 * @param {string} url
 * @param {string} cookie  the cf_clearance value from submitChallenge
 * @param {{sessionKey?: string}} [opts] sessionKey shares one cookie jar across
 *   URLs on the same host; without it every URL gets its own jar.
 * @returns {Promise<{status:number, body:string, headers:object}>}
 */
export async function fetchWithClearance(url, cookie, opts = {}) {
  if (!cookie) throw new Error('fetchWithClearance: no cf_clearance cookie');

  const key = opts.sessionKey || url;
  fs.mkdirSync(SESSION_DIR, { recursive: true });
  const state = sessionPath(key);
  let st = {};
  if (fs.existsSync(state)) {
    try { st = JSON.parse(fs.readFileSync(state, 'utf8')); } catch { st = {}; }
  }
  const host = new URL(url).hostname;
  const all = Array.isArray(st.cookies) ? st.cookies : [];
  const previous = all.find((c) => c.name === 'cf_clearance');
  const cookies = all.filter((c) => c.name !== 'cf_clearance');
  cookies.push({
    name: 'cf_clearance',
    value: cookie,
    domain: (previous && previous.domain) || host,
    path: (previous && previous.path) || '/',
  });
  st.url = st.url || url;
  st.cookies = cookies;
  fs.writeFileSync(state, JSON.stringify(st));

  let res = await runTransport(['fetch', state, url]);

  // On this IP a clearance is often good for a single page load: the next
  // request comes back as a fresh challenge (403/429 with _cf_chl_opt). Re-solve
  // once and retry rather than handing the caller a challenge page.
  const challenged = (res.status === 403 || res.status === 429) && /_cf_chl_opt/.test(res.body || '');
  if (challenged && process.env.CF_NO_REVALIDATE !== '1') {
    const live = await solveLive(url, { sessionKey: key });
    if (live.clearance) {
      const st2 = readState(key) || {};
      const all2 = Array.isArray(st2.cookies) ? st2.cookies : [];
      const prev2 = all2.find((c) => c.name === 'cf_clearance');
      const cookies2 = all2.filter((c) => c.name !== 'cf_clearance');
      cookies2.push({
        name: 'cf_clearance',
        value: live.clearance,
        domain: (prev2 && prev2.domain) || host,
        path: (prev2 && prev2.path) || '/',
      });
      st2.url = st2.url || url;
      st2.cookies = cookies2;
      fs.writeFileSync(state, JSON.stringify(st2));
      res = await runTransport(['fetch', state, url]);
    }
  }

  return { status: res.status, body: res.body, headers: res.headers };
}
