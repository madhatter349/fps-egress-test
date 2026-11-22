// FastPeopleSearch person pipeline on top of cf-solver.
//
// The binding constraint is not the challenge, it is the app-level limiter:
// this VPS IP gets roughly 4-5 page loads before the site answers 429 / a
// reCAPTCHA wall, and every solve() itself costs 2-3 loads. So the design is:
//
//   * one clearance, one cookie jar, reused for as many pages as it survives;
//   * a hard page-load budget per window, then a long cooldown;
//   * sequential requests only, with a delay between them;
//   * exponential backoff + re-solve on 429 / bot-check, and a stop after
//     repeated blocks instead of hammering the IP;
//   * every result appended to a JSONL checkpoint as it lands, so a killed run
//     resumes where it stopped.
//
// No proxies. VPS egress only.

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { JSDOM } from 'jsdom';

import { solveLive, fetchWithClearance } from './solver.mjs';

export const BASE = 'https://www.fastpeoplesearch.com';

// cf_clearance is host-scoped, so one jar serves every person page.
const SESSION_KEY = process.env.FPS_SESSION_KEY || `${BASE}/`;

// ---------------------------------------------------------------------------
// phones and URLs
// ---------------------------------------------------------------------------

/** Normalize any US phone spelling to 10 digits. Throws on anything else. */
export function digits(phone) {
  const raw = String(phone ?? '').replace(/\D/g, '');
  const ten = raw.length === 11 && raw.startsWith('1') ? raw.slice(1) : raw;
  if (ten.length !== 10) {
    throw new Error(`not a 10-digit US phone number: ${JSON.stringify(phone)}`);
  }
  return ten;
}

/** The URL the task specifies: /<10-digit-phone>. */
export function personUrl(phone) {
  return `${BASE}/${digits(phone)}`;
}

/** The URL the site itself links to: /<xxx-xxx-xxxx>. */
export function canonicalUrl(phone) {
  const d = digits(phone);
  return `${BASE}/${d.slice(0, 3)}-${d.slice(3, 6)}-${d.slice(6)}`;
}

// ---------------------------------------------------------------------------
// page classification
// ---------------------------------------------------------------------------

const RE_BOTCHECK = /are you human|g-recaptcha|security check to access|recaptcha\/api/i;
const RE_CHALLENGE = /_cf_chl_opt|just a moment|challenge-running|cf-mitigated|checking your browser/i;
const RE_RATELIMIT = /rate[- ]limit|too many requests|please try again later/i;
const RE_NOTFOUND = /no results found|could not find any records|no records found/i;

function isPersonPage(html) {
  return (
    /class="people-list"/.test(html) ||
    /id="details-header"/.test(html) ||
    /id="phone_number_section"/.test(html) ||
    /class="detail-box"/.test(html)
  );
}

/**
 * Decide what a response actually is. This is what the budget accounting and
 * the backoff logic key off, so it is deliberately explicit.
 *
 * @returns {'ok'|'challenge'|'bot-check'|'rate-limited'|'not-found'|'error'}
 */
export function classifyPage(status, body) {
  const html = String(body || '');
  const s = Number(status) || 0;

  if (s === 200 && isPersonPage(html)) return 'ok';
  if (RE_BOTCHECK.test(html)) return 'bot-check';
  if (RE_CHALLENGE.test(html)) return 'challenge';
  if (s === 429 || RE_RATELIMIT.test(html)) return 'rate-limited';
  if (s === 404 || RE_NOTFOUND.test(html)) return 'not-found';
  return 'error';
}

// ---------------------------------------------------------------------------
// extraction
// ---------------------------------------------------------------------------

function clean(s) {
  return String(s ?? '')
    .replace(/\u00a0/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

/** textContent with <br> turned into ", " so addresses keep their separator. */
function textWithBreaks(el) {
  if (!el) return '';
  const clone = el.cloneNode(true);
  for (const br of clone.querySelectorAll('br')) br.replaceWith(', ');
  return clean(clone.textContent)
    .replace(/,\s*,/g, ',')
    .replace(/\s*,\s*$/, '');
}

function parseAge(text) {
  const m = String(text || '').match(/Age\s+(\d+)/i);
  return m ? Number(m[1]) : null;
}

function parseBorn(text) {
  const m = String(text || '').match(/Born\s+([A-Z][a-z]+ \d{4})/);
  return m ? m[1] : null;
}

function emptyPerson(reason) {
  return {
    ok: false,
    blocked: reason === 'challenge' || reason === 'bot-check' || reason === 'rate-limited',
    reason,
    source: null,
    name: null,
    age: null,
    born: null,
    address: null,
    addresses: [],
    phones: [],
    relatives: [],
    aka: [],
    people: [],
    id: null,
    url: null,
  };
}

function parseProfile(doc) {
  const name =
    clean(doc.querySelector('.fullname')?.textContent) ||
    clean(doc.querySelector('#details-header')?.textContent).split(/\s+in\s+/)[0] ||
    null;

  // The summary <p> under the h1: "Age 73, Born June 1953 / Lives in ... / (917) ..."
  const summary = [...doc.querySelectorAll('p')].find((p) => /^Age\s+\d+/i.test(clean(p.textContent)));
  const summaryText = clean(summary?.textContent);

  const address = textWithBreaks(doc.querySelector('#current_address_section h3 a')) || null;

  const phones = [...doc.querySelectorAll('#phone_number_section dl')].map((dl) => {
    const dds = [...dl.querySelectorAll('dd')].map((d) => clean(d.textContent));
    const reported = dds.find((x) => /^First reported/i.test(x));
    return {
      number: clean(dl.querySelector('dt')?.textContent) || null,
      type: dds[0] || null,
      carrier: dds[1] || null,
      firstReported: reported ? reported.replace(/^First reported\s*/i, '') : null,
    };
  }).filter((p) => p.number);

  const relatives = [...doc.querySelectorAll('#relative-links dl')].map((dl) => {
    const a = dl.querySelector('dt a');
    const dd = clean(dl.querySelector('dd')?.textContent);
    return {
      name: clean(a?.textContent) || null,
      age: parseAge(dd),
      born: (dd.match(/\(([^)]+)\)/) || [])[1] || null,
      url: a?.getAttribute('href') || null,
    };
  }).filter((r) => r.name);

  const aka = [...doc.querySelectorAll('#aka-links a, .aka-list a')]
    .map((a) => clean(a.textContent))
    .filter(Boolean);

  const self = {
    name,
    age: parseAge(summaryText),
    born: parseBorn(summaryText),
    address,
    addresses: address ? [address] : [],
    relatives,
    aka,
    id: (doc.querySelector('link[rel="canonical"]')?.getAttribute('href') || '').match(/_id_([^/?#]+)/)?.[1] || null,
    url: doc.querySelector('link[rel="canonical"]')?.getAttribute('href') || null,
  };

  return {
    ok: true,
    blocked: false,
    reason: null,
    source: 'profile',
    name: self.name,
    age: self.age,
    born: self.born,
    address: self.address,
    addresses: self.addresses,
    phones,
    relatives,
    aka,
    people: [self],
    id: self.id,
    url: self.url,
  };
}

function parsePhonePage(doc, html) {
  const cards = [...doc.querySelectorAll('.people-list .card')];

  const people = cards.map((card) => {
    const title = card.querySelector('h3.card-title');
    const name =
      clean(title?.querySelector('.larger')?.textContent) ||
      clean(title?.querySelector('a')?.textContent) ||
      null;

    const grey = clean(title?.querySelector('.grey')?.textContent);
    const age = parseAge(grey);
    // Deceased records carry "Deceased (1923 - 1990)" where the age would be.
    const dead = grey.match(/Deceased\s*\((\d{4})\s*-\s*(\d{4})\)/i);
    const location = clean(
      grey
        .replace(/Age\s+\d+/i, '')
        .replace(/Deceased\s*\([^)]*\)/i, '')
        .replace(/^[•\s]+/, ''),
    ) || null;

    const addresses = [];
    const relatives = [];
    let aka = [];

    for (const div of card.querySelectorAll('.card-block > div')) {
      const label = clean(div.querySelector('h4')?.textContent).replace(/:$/, '').toLowerCase();
      if (!label) continue;
      if (label === 'addresses') {
        addresses.push(...[...div.querySelectorAll('a')].map((a) => clean(a.textContent)).filter(Boolean));
      } else if (label === 'relatives') {
        relatives.push(
          ...[...div.querySelectorAll('a')]
            .map((a) => ({ name: clean(a.textContent), age: null, born: null, url: a.getAttribute('href') || null }))
            .filter((r) => r.name),
        );
      } else if (label === 'aka') {
        aka = clean(div.textContent)
          .replace(/^AKA:\s*/i, '')
          .split('•')
          .map((s) => s.trim())
          .filter(Boolean);
      }
    }

    return {
      name,
      age,
      born: dead ? dead[1] : null,
      died: dead ? dead[2] : null,
      deceased: !!dead,
      address: location,
      addresses,
      relatives,
      aka,
      id: card.id || null,
      url: card.getAttribute('data-link') || null,
    };
  });

  // The queried number, from the h1: "Who Owns The Phone Number (212)862-9173"
  const m = html.match(/\((\d{3})\)\s*(\d{3})-(\d{4})/);
  const queried = m ? `(${m[1]}) ${m[2]}-${m[3]}` : null;

  const primary = people[0] || {};

  return {
    ok: true,
    blocked: false,
    reason: null,
    source: 'phone',
    name: primary.name ?? null,
    age: primary.age ?? null,
    born: null,
    address: primary.address ?? null,
    addresses: primary.addresses ?? [],
    phones: queried ? [{ number: queried, type: null, carrier: null, firstReported: null }] : [],
    relatives: primary.relatives ?? [],
    aka: primary.aka ?? [],
    people,
    id: primary.id ?? null,
    url: primary.url ?? null,
  };
}

/**
 * Parse a FastPeopleSearch page into person data.
 *
 * Handles both shapes the site serves: the reverse-phone results page
 * (`/212-862-9173`, several `.people-list .card` records) and a full profile
 * page (`/olivia-coakley_id_...`, one person with typed phones).
 *
 * Never throws. A blocked or unparseable page comes back as `{ok:false}` with
 * `blocked`/`reason` set, so the caller can back off instead of recording junk.
 */
export function extractPerson(html) {
  const raw = String(html || '');
  if (!raw.trim()) return emptyPerson('error');

  const kind = classifyPage(200, raw);
  if (kind !== 'ok') return emptyPerson(kind);

  let doc;
  try {
    doc = new JSDOM(raw).window.document;
  } catch {
    return emptyPerson('error');
  }

  try {
    const isProfile = !!doc.querySelector('#details-header, #phone_number_section');
    const isPhonePage = !!doc.querySelector('.people-list .card');
    if (isProfile) return parseProfile(doc);
    if (isPhonePage) return parsePhonePage(doc, raw);
    return emptyPerson('error');
  } catch {
    return emptyPerson('error');
  }
}

// ---------------------------------------------------------------------------
// network
// ---------------------------------------------------------------------------

function parseRetryAfter(headers) {
  const h = headers || {};
  const raw = h['retry-after'] ?? h['Retry-After'];
  if (raw == null) return null;
  const secs = Number(raw);
  if (Number.isFinite(secs)) return Math.max(0, secs * 1000);
  const when = Date.parse(raw);
  if (Number.isFinite(when)) return Math.max(0, when - Date.now());
  return null;
}

const REDIRECTS = new Set([301, 302, 303, 307, 308]);

/**
 * GET one person page.
 *
 * @param {string} phone
 * @param {string} clearance  cf_clearance value from solve()
 * @param {{transport?: Function, url?: string, sessionKey?: string}} [opts]
 * @returns {Promise<{status:number, body:string, headers:object, url:string,
 *   kind:string, retryAfterMs:number|null}>}
 */
export async function fetchPerson(phone, clearance, opts = {}) {
  if (!clearance) throw new Error('fetchPerson: no cf_clearance cookie');

  const sessionKey = opts.sessionKey || SESSION_KEY;
  const transport =
    opts.transport || ((url, cookie) => fetchWithClearance(url, cookie, { sessionKey }));

  // The site's own canonical (dashed) form is the edge-cache key; the undashed
  // form is a different key and is never a HIT. Default to the dashed form.
  let url = opts.url || canonicalUrl(phone);
  let res = await transport(url, clearance);

  // A redirect into /bot-check or /rate-limited *is* the block — fetching that
  // wall would burn one of the ~4-5 page loads for nothing, so report it
  // straight away. The site sends this as a 429 *with* a location header, not
  // only as a 3xx, so check it before the redirect loop.
  const wallTarget = (r) => {
    const location = r.headers?.location ?? r.headers?.Location;
    if (!location) return null;
    const next = new URL(location, url).toString();
    const wall = next.match(/\/(bot-check|rate-limited)\b/i);
    if (!wall) return null;
    return {
      status: Number(r.status) || 0,
      body: '',
      headers: r.headers || {},
      url: next,
      kind: wall[1].toLowerCase() === 'bot-check' ? 'bot-check' : 'rate-limited',
      retryAfterMs: parseRetryAfter(r.headers),
    };
  };

  const wall = wallTarget(res);
  if (wall) return wall;

  // /2128629173 may answer 30x to the canonical dashed path; follow it on the
  // same clearance.
  for (let hop = 0; hop < 2 && REDIRECTS.has(Number(res.status)); hop += 1) {
    const location = res.headers?.location ?? res.headers?.Location;
    if (!location) break;
    url = new URL(location, url).toString();
    res = await transport(url, clearance);
    const wall2 = wallTarget(res);
    if (wall2) return wall2;
  }

  const headers = res.headers || {};
  return {
    status: Number(res.status) || 0,
    body: String(res.body ?? ''),
    headers,
    url,
    kind: classifyPage(res.status, res.body),
    retryAfterMs: parseRetryAfter(headers),
  };
}

/**
 * Mint a cf_clearance for the site.
 *
 * @param {{url?: string, solver?: Function, sessionKey?: string}} [opts]
 * @returns {Promise<{clearance: string|null, challengeStatus: number|null, posts: number, ms: number}>}
 */
export async function solve(opts = {}) {
  const solver = opts.solver || solveLive;
  const url = opts.url || `${BASE}/`;
  const sessionKey = opts.sessionKey || SESSION_KEY;
  const t0 = Date.now();
  const r = (await solver(url, { sessionKey })) || {};
  return {
    clearance: r.clearance || null,
    challengeStatus: r.challengeStatus ?? null,
    posts: Array.isArray(r.posts) ? r.posts.length : 0,
    ms: Date.now() - t0,
  };
}

// ---------------------------------------------------------------------------
// pool driver
// ---------------------------------------------------------------------------

function readJsonl(file) {
  if (!fs.existsSync(file)) return [];
  const rows = [];
  for (const line of fs.readFileSync(file, 'utf8').split('\n')) {
    if (!line.trim()) continue;
    try {
      rows.push(JSON.parse(line));
    } catch {
      // A torn last line from a killed run is expected; ignore it.
    }
  }
  return rows;
}

function appendJsonl(file, record) {
  fs.appendFileSync(file, `${JSON.stringify(record)}\n`);
}

/**
 * Walk a pool of people, one request at a time, inside the IP's page budget.
 *
 * Resumable: results are appended to `out` as JSONL and any phone already
 * recorded as `ok` or `not-found` is skipped on the next run.
 *
 * @param {Array<{phone:string,name?:string}|string>} pool
 * @param {object} [opts]
 * @param {string} [opts.out]                 JSONL checkpoint/output path
 * @param {number} [opts.minDelayMs=8000]     delay between page loads
 * @param {number} [opts.jitterMs=4000]       extra random delay (0..jitterMs)
 * @param {number} [opts.loadsPerWindow=4]    page loads allowed before a cooldown
 * @param {number} [opts.cooldownMs=300000]   cooldown length
 * @param {number} [opts.maxAttempts=3]       attempts per person
 * @param {number} [opts.maxConsecutiveBlocks=3] stop the run after this many
 * @param {number} [opts.backoffBaseMs=60000] exponential backoff base
 * @param {number} [opts.backoffMaxMs=1800000] backoff ceiling
 * @param {Function} [opts.fetchPerson]       injectable for tests
 * @param {Function} [opts.solve]             injectable for tests
 * @param {Function} [opts.sleep]             injectable for tests
 * @param {Function} [opts.now]               injectable clock
 * @param {Function} [opts.log]               progress logger
 * @returns {Promise<{total:number, done:number, skipped:number, failed:number,
 *   notFound:number, blocked:number, stopped:string|null, results:Array}>}
 */
export async function runPool(pool, opts = {}) {
  const out = opts.out || path.join(process.cwd(), 'out', 'persons.jsonl');
  const sleep = opts.sleep || ((ms) => new Promise((r) => setTimeout(r, ms)));
  const now = opts.now || (() => Date.now());
  const log = opts.log || (() => {});
  const fetchFn = opts.fetchPerson || fetchPerson;
  const solveFn = opts.solve || solve;

  const minDelayMs = opts.minDelayMs ?? 8000;
  const jitterMs = opts.jitterMs ?? 4000;
  const loadsPerWindow = opts.loadsPerWindow ?? 4;
  // Measured on this IP (work/waf-duration/trigger.json): after ~4 hammered
  // pages the app-level "Rate Limited" wall clears in 2.6-8 min, median 4.3.
  const cooldownMs = opts.cooldownMs ?? 5 * 60 * 1000;
  const maxAttempts = opts.maxAttempts ?? 3;
  const maxConsecutiveBlocks = opts.maxConsecutiveBlocks ?? 3;
  const backoffBaseMs = opts.backoffBaseMs ?? 60 * 1000;
  const backoffMaxMs = opts.backoffMaxMs ?? 30 * 60 * 1000;

  const items = (pool || []).map((p) =>
    typeof p === 'string' ? { phone: digits(p), name: null } : { ...p, phone: digits(p.phone) },
  );

  fs.mkdirSync(path.dirname(out), { recursive: true });
  const finished = new Set(
    readJsonl(out)
      .filter((r) => r && r.phone && (r.status === 'ok' || r.status === 'not-found'))
      .map((r) => r.phone),
  );

  const summary = {
    total: items.length,
    done: 0,
    skipped: 0,
    failed: 0,
    notFound: 0,
    blocked: 0,
    stopped: null,
    results: [],
  };

  let clearance = null;
  let loads = 0;
  let consecutiveBlocks = 0;
  let first = true;

  const stamp = () => new Date(now()).toISOString();

  for (const item of items) {
    if (finished.has(item.phone)) {
      summary.skipped += 1;
      continue;
    }

    // Budget: after N page loads the app-level limiter is about to trip, so
    // stop and let the window reset instead of collecting a 429.
    if (loads >= loadsPerWindow) {
      log(`cooldown ${cooldownMs}ms after ${loads} page loads`);
      await sleep(cooldownMs);
      loads = 0;
      clearance = null;
    }

    if (!first) await sleep(minDelayMs + Math.floor(Math.random() * jitterMs));
    first = false;

    let attempts = 0;
    let record = null;

    while (attempts < maxAttempts) {
      attempts += 1;

      if (!clearance) {
        // Solve on the page we are about to load, not the homepage: the
        // clearance is bound to the URL it was minted for, and a homepage
        // clearance gets bounced to /bot-check on a person path.
        const s = await solveFn({ url: opts.solveUrl || canonicalUrl(item.phone) });
        clearance = s && s.clearance ? s.clearance : null;
        loads += 1; // a solve costs page loads too
        if (!clearance) log('solve() returned no clearance');
      }

      let res;
      try {
        res = await fetchFn(item.phone, clearance, { at: now() });
      } catch (err) {
        res = { kind: 'error', status: 0, body: '', headers: {}, url: null, error: String(err?.message || err) };
      }
      loads += 1;

      if (res.kind === 'ok') {
        const person = extractPerson(res.body);
        if (person.ok) {
          record = {
            phone: item.phone,
            name: item.name ?? person.name,
            status: 'ok',
            attempts,
            fetchedAt: stamp(),
            url: res.url || null,
            person,
          };
          consecutiveBlocks = 0;
          break;
        }
        res = { ...res, kind: 'error', error: 'unparseable page' };
      }

      if (res.kind === 'not-found') {
        record = {
          phone: item.phone,
          name: item.name ?? null,
          status: 'not-found',
          attempts,
          fetchedAt: stamp(),
          url: res.url || null,
          person: null,
        };
        consecutiveBlocks = 0;
        break;
      }

      const blocked = res.kind === 'challenge' || res.kind === 'rate-limited' || res.kind === 'bot-check';
      if (blocked) {
        consecutiveBlocks += 1;
        summary.blocked += 1;
      }
      if (consecutiveBlocks >= maxConsecutiveBlocks) break;

      const backoff = Math.min(backoffMaxMs, backoffBaseMs * 2 ** (attempts - 1));
      const wait = res.retryAfterMs ? Math.max(res.retryAfterMs, backoff) : backoff;
      log(`${res.kind} on ${item.phone} (attempt ${attempts}), backing off ${wait}ms`);
      await sleep(wait);
      clearance = null; // the old cookie is dead; mint a new one
      loads = 0;
    }

    if (consecutiveBlocks >= maxConsecutiveBlocks) {
      summary.stopped = 'blocked';
      log(`stopping: ${consecutiveBlocks} consecutive blocks — IP is throttled`);
      break;
    }

    if (!record) {
      record = {
        phone: item.phone,
        name: item.name ?? null,
        status: 'failed',
        attempts,
        fetchedAt: stamp(),
        url: null,
        person: null,
        error: 'exhausted attempts',
      };
      summary.failed += 1;
    } else if (record.status === 'ok') {
      summary.done += 1;
    } else if (record.status === 'not-found') {
      summary.notFound += 1;
    }

    appendJsonl(out, record);
    summary.results.push(record);
  }

  return summary;
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

// node src/pipeline.mjs --pool ../testpool/pool-100.json --out out/persons.jsonl [--limit 5]
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const arg = (name, fallback) => {
    const i = process.argv.indexOf(`--${name}`);
    return i >= 0 && process.argv[i + 1] ? process.argv[i + 1] : fallback;
  };

  const poolPath = arg('pool', path.join('..', 'testpool', 'pool-100.json'));
  const out = arg('out', path.join('out', 'persons.jsonl'));
  const limit = Number(arg('limit', '0')) || 0;

  const pool = JSON.parse(fs.readFileSync(poolPath, 'utf8'));
  const slice = limit > 0 ? pool.slice(0, limit) : pool;

  console.error(`pool=${poolPath} (${slice.length} people) out=${out}`);
  const summary = await runPool(slice, {
    out,
    log: (m) => console.error(`[pool] ${m}`),
  });

  const { results, ...counts } = summary;
  console.log(JSON.stringify(counts, null, 2));
  if (summary.stopped) {
    console.error('Run stopped early — re-run the same command to resume from the checkpoint.');
    process.exitCode = 2;
  }
}
