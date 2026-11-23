#!/usr/bin/env node
/**
 * fetch-intel.mjs
 * Pulls CISA KEV, NVD, GitHub Advisories, EPSS, Cloudflare Zero Wire and vendor/news RSS feeds
 * and writes ONE static JSON file (site/data/intel.json) that index.html reads.
 *
 * - Zero dependencies, Node >= 20 (uses built-in fetch).
 * - A failing source never breaks the run: its previous data is carried forward and flagged "stale".
 * - The run only FAILS (exit 1, nothing published) if KEV, NVD and GitHub Advisories all fail.
 */
import { readFile, writeFile, mkdir, appendFile } from 'node:fs/promises';
import path from 'node:path';

const E = process.env;
const int = (v, d, lo, hi) => { const n = parseInt(v, 10); return Number.isFinite(n) ? Math.min(hi, Math.max(lo, n)) : d; };

const OUT_FILE = E.OUT_FILE || 'site/data/intel.json';
const PREV_FILE = E.PREV_FILE || '';
const FEEDS_FILE = E.FEEDS_FILE || 'config/feeds.json';
const NVD_KEY = (E.NVD_API_KEY || '').trim();
const GH_TOKEN = (E.GITHUB_TOKEN || E.GH_TOKEN || '').trim();
const NVD_DAYS = int(E.NVD_DAYS, 14, 2, 60);          // how many days of HIGH/CRITICAL CVEs to keep
const KEV_DAYS = int(E.KEV_DAYS, 180, 14, 3650);      // how many days of KEV entries to keep
const FEED_ITEMS = int(E.FEED_ITEMS, 40, 5, 200);     // items kept per RSS feed
const NVD_PAGE = int(E.NVD_PAGE_SIZE, 500, 2, 2000);  // NVD records are large; keep pages moderate
const NVD_PACE = int(E.NVD_PACE_MS, NVD_KEY ? 700 : 6500, 0, 60000); // NVD: 5 req/30s without key, 50/30s with key
const BACKOFF = Number(E.BACKOFF_SCALE || 1);
const FEED_PROXY = E.FEED_PROXY_FALLBACK !== '0';     // last-resort public CORS proxies for feeds that block GitHub runners
const DAY = 864e5, HOUR = 36e5;
const REPO = E.GITHUB_REPOSITORY || '';
const UA = `Mozilla/5.0 (compatible; CyberBriefingBot/1.0${REPO ? '; +https://github.com/' + REPO : ''})`;

const log = (...a) => console.log(...a);
const ghaMsg = (level, title, msg) => console.log(`::${level} title=${title}::${String(msg).replace(/\r?\n/g, ' ')}`);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function errMsg(e) {
  if (!e) return 'unknown error';
  if (e.name === 'TimeoutError' || e.name === 'AbortError') return 'timeout';
  const code = e.cause && (e.cause.code || e.cause.message);
  return (e.message || String(e)) + (code ? ` (${code})` : '');
}
function shortErr(msg) {
  msg = String(msg || '').split(' | ')[0];   // first part = the direct attempt (the real cause)
  if (/timeout/i.test(msg)) return '超时';
  const m = msg.match(/HTTP (\d{3})/);
  if (m) return (m[1] === '403' || m[1] === '429') ? `被限流/拒绝 ${m[1]}` : `HTTP ${m[1]}`;
  if (/not RSS|no items/i.test(msg)) return '返回内容无效';
  return '网络错误';
}

// ---------------------------------------------------------------- HTTP
async function http(url, { json = false, timeout = 20000, retries = 2, backoff = 2000, headers = {} } = {}) {
  let last;
  for (let i = 0; i <= retries; i++) {
    try {
      const res = await fetch(url, {
        headers: { 'User-Agent': UA, Accept: json ? 'application/json' : '*/*', ...headers },
        signal: AbortSignal.timeout(timeout),
        redirect: 'follow'
      });
      if (res.ok) return json ? await res.json() : await res.text();
      const err = new Error(`HTTP ${res.status}`);
      err.status = res.status;
      err.retryAfter = Number(res.headers.get('retry-after')) || 0;
      throw err;
    } catch (e) {
      last = e;
      const s = e.status || 0;
      const retry = i < retries && (!s || s === 408 || s === 429 || s === 403 || s >= 500);
      if (!retry) break;
      const wait = e.retryAfter ? Math.min(e.retryAfter, 60) * 1000 : backoff * 2 ** i * BACKOFF;
      log(`  retry ${i + 1}/${retries} in ${Math.round(wait / 1000)}s — ${errMsg(e)} — ${url.slice(0, 100)}`);
      await sleep(wait);
    }
  }
  throw last;
}
async function pool(items, n, fn) {
  const out = []; let i = 0;
  await Promise.all(Array.from({ length: Math.min(n, items.length) }, async () => {
    while (i < items.length) { const k = i++; out[k] = await fn(items[k], k); }
  }));
  return out;
}
async function run(fn) {
  const t0 = Date.now();
  try { return { ok: true, data: await fn(), ms: Date.now() - t0, error: '' }; }
  catch (e) { return { ok: false, data: null, ms: Date.now() - t0, error: errMsg(e) }; }
}

// ---------------------------------------------------------------- text helpers
const ENT = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ', ndash: '-', mdash: '-', hellip: '...', rsquo: "'", lsquo: "'", ldquo: '"', rdquo: '"' };
function decodeEntities(s) {
  return String(s)
    .replace(/&#x([0-9a-f]+);/gi, (_, h) => { try { return String.fromCodePoint(parseInt(h, 16)); } catch { return ' '; } })
    .replace(/&#(\d+);/g, (_, d) => { try { return String.fromCodePoint(parseInt(d, 10)); } catch { return ' '; } })
    .replace(/&([a-z]+);/gi, (m, n) => (n.toLowerCase() === 'amp' ? m : (ENT[n.toLowerCase()] ?? m)))
    .replace(/&amp;/gi, '&');
}
function textOf(raw) {
  if (!raw) return '';
  let s = String(raw);
  const hadCdata = /<!\[CDATA\[/.test(s);
  s = s.replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, '$1');
  if (!hadCdata) s = decodeEntities(s);
  s = s.replace(/<(script|style)[\s\S]*?<\/\1>/gi, ' ').replace(/<br\s*\/?>/gi, ' ').replace(/<[^>]+>/g, ' ');
  return decodeEntities(s).replace(/\s+/g, ' ').trim();
}
const trunc = (s, n) => { s = String(s || ''); return s.length > n ? s.slice(0, n - 1) + '…' : s; };
const httpUrl = (u) => { try { const x = new URL(String(u || '').trim()); return /^https?:$/.test(x.protocol) ? x.href : ''; } catch { return ''; } };
const extractCves = (t) => [...new Set((String(t || '').match(/CVE-\d{4}-\d{4,7}/gi) || []).map((x) => x.toUpperCase()))];

// ---------------------------------------------------------------- RSS / Atom
function tagText(block, names) {
  for (const n of names) {
    const m = block.match(new RegExp(`<${n}\\b[^>]*>([\\s\\S]*?)</${n}>`, 'i'));
    if (m) return m[1];
  }
  return '';
}
function parseFeed(xml) {
  const items = [];
  const re = /<(item|entry)\b[^>]*>([\s\S]*?)<\/\1>/gi;
  let m;
  while ((m = re.exec(xml))) {
    const b = m[2];
    const title = textOf(tagText(b, ['title']));
    if (!title) continue;
    let link = '';
    for (const lm of b.matchAll(/<link\b([^>]*?)\/?>/gi)) {
      const attrs = lm[1];
      const href = (attrs.match(/href\s*=\s*["']([^"']+)["']/i) || [])[1];
      const rel = (attrs.match(/rel\s*=\s*["']([^"']+)["']/i) || [])[1];
      if (href && (!rel || rel === 'alternate')) { link = href; break; }
    }
    if (!link) link = textOf(tagText(b, ['link'])) || textOf(tagText(b, ['guid', 'id']));
    const description = textOf(tagText(b, ['description', 'summary', 'content:encoded', 'content']));
    const date = Date.parse(textOf(tagText(b, ['pubDate', 'published', 'updated', 'dc:date']))) || 0;
    items.push({ title: trunc(title, 300), link: httpUrl(decodeEntities(link)), description: trunc(description, 500), pubDate: date });
  }
  return items;
}
async function fetchFeed(url) {
  const routes = [['direct', url]];
  if (FEED_PROXY) {
    routes.push(['allorigins', `https://api.allorigins.win/raw?url=${encodeURIComponent(url)}`]);
    routes.push(['corsproxy', `https://corsproxy.io/?url=${encodeURIComponent(url)}`]);
  }
  const errs = [];
  for (const [via, u] of routes) {
    try {
      const xml = await http(u, {
        timeout: via === 'direct' ? 25000 : 15000, retries: via === 'direct' ? 1 : 0, backoff: 1500,
        headers: { Accept: 'application/rss+xml, application/atom+xml, application/xml, text/xml;q=0.9, */*;q=0.8' }
      });
      if (!/<(rss|feed|rdf:RDF)[\s>]/i.test(xml)) throw new Error('response is not RSS/Atom');
      const items = parseFeed(xml).slice(0, FEED_ITEMS);
      if (!items.length) throw new Error('feed has no items');
      if (via !== 'direct') log(`  ${url} fetched via ${via}`);
      return { items, via };
    } catch (e) { errs.push(`${via}: ${errMsg(e)}`); log(`  ${via} failed: ${errMsg(e)} — ${url}`); }
  }
  throw new Error(errs.join(' | '));
}
async function fetchZeroWire(urls) {
  const errs = [];
  for (const u of urls) {
    try { const r = await fetchFeed(u); return { ...r, url: u }; } catch (e) { errs.push(e.message); }
  }
  throw new Error(errs.join(' | ') || 'no Zero Wire URL configured');
}

// ---------------------------------------------------------------- CISA KEV
async function fetchKev(now) {
  const urls = [
    'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
    'https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json'
  ];
  let j, last;
  for (const u of urls) {
    try { j = await http(u, { json: true, timeout: 30000, retries: 1 }); if (Array.isArray(j.vulnerabilities)) break; j = null; }
    catch (e) { last = e; log(`  KEV ${u} failed: ${errMsg(e)}`); }
  }
  if (!j) throw last || new Error('KEV: unexpected response');
  const day = (v) => Date.parse(`${v.dateAdded}T00:00:00Z`) || 0;
  const all = j.vulnerabilities.slice().sort((a, b) => day(b) - day(a));
  let keep = all.filter((v) => day(v) >= now - KEV_DAYS * DAY);
  if (keep.length < 10) keep = all.slice(0, 10);
  return {
    total: all.length,
    recent7d: all.filter((v) => day(v) >= now - 7 * DAY).length,
    items: keep.map((v) => ({
      cveID: v.cveID, vendorProject: v.vendorProject, product: v.product, vulnerabilityName: v.vulnerabilityName,
      dateAdded: v.dateAdded, dueDate: v.dueDate, requiredAction: trunc(v.requiredAction, 300),
      shortDescription: trunc(v.shortDescription, 400), knownRansomwareCampaignUse: v.knownRansomwareCampaignUse
    }))
  };
}

// ---------------------------------------------------------------- NVD
const nvdDate = (ms) => new Date(ms).toISOString().replace('Z', '+00:00');
function slimNvd(cve, q) {
  if (!cve || cve.vulnStatus === 'Rejected') return null;
  const m = cve.metrics || {};
  const pick = m.cvssMetricV31?.[0] || m.cvssMetricV30?.[0] || m.cvssMetricV40?.[0] || m.cvssMetricV2?.[0];
  const md = pick?.cvssData || {};
  const desc = (cve.descriptions || []).find((d) => d.lang === 'en')?.value || cve.descriptions?.[0]?.value || '';
  const seen = new Set(), cpes = [];
  for (const cfg of cve.configurations || []) for (const n of cfg.nodes || []) for (const cm of n.cpeMatch || []) {
    if (cm.vulnerable === false) continue;
    const p = String(cm.criteria || '').split(':');
    if (p.length < 6) continue;
    const c = { vendor: p[3], product: p[4], version: p[5], vsi: cm.versionStartIncluding, vse: cm.versionStartExcluding, vei: cm.versionEndIncluding, vee: cm.versionEndExcluding };
    const k = JSON.stringify(c);
    if (seen.has(k) || cpes.length >= 40) continue;
    seen.add(k); cpes.push(c);
  }
  return {
    id: cve.id, published: Date.parse(cve.published) || 0, score: typeof md.baseScore === 'number' ? md.baseScore : null,
    sev: String(md.baseSeverity || pick?.baseSeverity || '').toUpperCase(), q, desc: trunc(desc, 600), cpes
  };
}
async function fetchNvdSeverity(sev, now) {
  const items = [];
  let startIndex = 0, total = Infinity;
  while (startIndex < total) {
    const qs = new URLSearchParams({
      pubStartDate: nvdDate(now - NVD_DAYS * DAY), pubEndDate: nvdDate(now), cvssV3Severity: sev,
      resultsPerPage: String(NVD_PAGE), startIndex: String(startIndex)
    });
    const j = await http(`https://services.nvd.nist.gov/rest/json/cves/2.0?${qs}`, {
      json: true, timeout: 120000, retries: 3, backoff: NVD_KEY ? 3000 : 8000, headers: NVD_KEY ? { apiKey: NVD_KEY } : {}
    });
    total = j.totalResults || 0;
    const page = j.vulnerabilities || [];
    for (const v of page) { const s = slimNvd(v.cve, sev); if (s) items.push(s); }
    if (!page.length) break;
    startIndex += page.length;
    log(`  NVD ${sev}: ${Math.min(startIndex, total)}/${total}`);
    if (startIndex < total) await sleep(NVD_PACE);
  }
  return items;
}
async function fetchNvdAll(now, prev) {
  const t0 = Date.now(), out = [], errors = [];
  let okCount = 0;
  for (const sev of ['CRITICAL', 'HIGH']) {
    try { out.push(...await fetchNvdSeverity(sev, now)); okCount++; }
    catch (e) {
      errors.push(`${sev}: ${errMsg(e)}`);
      const carried = (prev?.nvd?.items || []).filter((x) => x.q === sev && x.published >= now - NVD_DAYS * DAY);
      out.push(...carried);
      log(`  NVD ${sev} failed (${errMsg(e)}); carried ${carried.length} previous items`);
    }
    if (sev === 'CRITICAL') await sleep(NVD_PACE);
  }
  const byId = new Map(); for (const x of out) if (!byId.has(x.id)) byId.set(x.id, x);
  return { ok: okCount > 0, partial: okCount === 1, errors, items: [...byId.values()].sort((a, b) => b.published - a.published), ms: Date.now() - t0 };
}

// ---------------------------------------------------------------- GitHub advisories
async function fetchGhsa() {
  const headers = { Accept: 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28' };
  if (GH_TOKEN) headers.Authorization = `Bearer ${GH_TOKEN}`;
  const arr = await http('https://api.github.com/advisories?type=reviewed&per_page=100&sort=published&direction=desc', { json: true, headers, retries: 2 });
  if (!Array.isArray(arr)) throw new Error('GHSA: unexpected response');
  return arr.map((v) => ({
    ghsa_id: v.ghsa_id, cve_id: v.cve_id, summary: trunc(v.summary, 300), severity: v.severity,
    description: trunc(textOf(v.description), 700), published_at: v.published_at, html_url: httpUrl(v.html_url),
    vulnerabilities: (v.vulnerabilities || []).slice(0, 5).map((x) => ({
      package: x.package, vulnerable_version_range: x.vulnerable_version_range, first_patched_version: x.first_patched_version
    }))
  }));
}

// ---------------------------------------------------------------- EPSS
async function fetchEpss(ids) {
  const list = [...new Set(ids)].filter((c) => /^CVE-\d{4}-\d{4,}$/.test(c));
  const chunks = []; for (let i = 0; i < list.length; i += 80) chunks.push(list.slice(i, i + 80));
  const map = {}; let failed = 0, lastErr = '';
  await pool(chunks, 3, async (chunk) => {
    try {
      const j = await http(`https://api.first.org/data/v1/epss?cve=${chunk.join(',')}`, { json: true, timeout: 20000, retries: 2 });
      for (const d of j.data || []) { const v = parseFloat(d.epss); if (Number.isFinite(v)) map[String(d.cve).toUpperCase()] = Math.round(v * 1e5) / 1e5; }
    } catch (e) { failed++; lastErr = errMsg(e); }
  });
  if (failed === chunks.length && chunks.length) throw new Error(lastErr || 'EPSS failed');
  return { map, requested: list.length, failedChunks: failed };
}

// ---------------------------------------------------------------- config / previous snapshot
const DEFAULT_CFG = {
  zeroWire: ['https://radar.cloudflare.com/security/zero-wire/rss'],
  feeds: [
    { id: 'cisa', name: 'CISA 公告', url: 'https://www.cisa.gov/cybersecurity-advisories/all.xml', on: true },
    { id: 'pan', name: 'Palo Alto PSIRT', url: 'https://security.paloaltonetworks.com/rss.xml', on: true },
    { id: 'msrc', name: 'Microsoft MSRC', url: 'https://api.msrc.microsoft.com/update-guide/rss', on: true },
    { id: 'fortinet', name: 'Fortinet PSIRT', url: 'https://filestore.fortinet.com/fortiguard/rss/ir.xml', on: true },
    { id: 'cisco', name: 'Cisco PSIRT', url: 'https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml', on: true },
    { id: 'bleep', name: 'BleepingComputer', url: 'https://www.bleepingcomputer.com/feed/', on: true },
    { id: 'thn', name: 'The Hacker News', url: 'https://feeds.feedburner.com/TheHackersNews', on: true },
    { id: 'sans', name: 'SANS ISC', url: 'https://isc.sans.edu/rssfeed.xml', on: true }
  ]
};
async function readJson(file) { try { return JSON.parse(await readFile(file, 'utf8')); } catch { return null; } }
async function loadConfig() {
  const c = await readJson(FEEDS_FILE);
  if (!c) { log(`No ${FEEDS_FILE}; using built-in feed list`); return DEFAULT_CFG; }
  const feeds = (Array.isArray(c.feeds) ? c.feeds : DEFAULT_CFG.feeds)
    .filter((f) => f && f.on !== false && f.id && f.name && httpUrl(f.url))
    .map((f) => ({ id: String(f.id).replace(/[^\w-]/g, '').slice(0, 30), name: String(f.name).slice(0, 60), url: httpUrl(f.url) }));
  const zw = (Array.isArray(c.zeroWire) ? c.zeroWire : DEFAULT_CFG.zeroWire).map(httpUrl).filter(Boolean);
  return { zeroWire: zw, feeds };
}
async function loadPrev() {
  if (!PREV_FILE) return null;
  const p = await readJson(PREV_FILE);
  if (p && p.schema === 1 && p.generatedAt) { log(`Previous snapshot: ${p.generatedAt}`); return p; }
  log('No usable previous snapshot (first run, or cache expired)');
  return null;
}
function idsOf(j) {
  const s = new Set();
  (j?.kev?.items || []).forEach((k) => s.add(k.cveID));
  (j?.nvd?.items || []).forEach((n) => s.add(n.id));
  (j?.ghsa || []).forEach((g) => { s.add(g.ghsa_id); if (g.cve_id) s.add(String(g.cve_id).toUpperCase()); });
  (j?.zw || []).forEach((i) => s.add(i.link || i.title));
  (j?.feeds || []).forEach((f) => (f.items || []).forEach((i) => s.add(i.link || i.title)));
  return s;
}
const ageH = (iso) => Math.max(0, Math.round((Date.now() - Date.parse(iso)) / HOUR));

// ---------------------------------------------------------------- main
async function main() {
  const T0 = Date.now(), now = Date.now();
  log(`CyberBriefing fetch started ${new Date(now).toISOString()} (NVD ${NVD_DAYS}d, key ${NVD_KEY ? 'yes' : 'no'}, GH token ${GH_TOKEN ? 'yes' : 'no'})`);
  const prev = await loadPrev();
  const cfg = await loadConfig();
  const prevSrc = (id) => prev?.sources?.[id];

  const [kevR, nvdR, ghsaR, zwR, ...feedR] = await Promise.all([
    run(() => fetchKev(now)),
    fetchNvdAll(now, prev),
    run(() => fetchGhsa()),
    run(() => fetchZeroWire(cfg.zeroWire)),
    ...cfg.feeds.map((f) => run(() => fetchFeed(f.url)))
  ]);

  const sources = {};
  const stale = (id, name, r, hasPrev) => {
    const since = prevSrc(id)?.since || prev?.generatedAt || '';
    return hasPrev
      ? { name, ok: false, stale: true, since, text: `失败，沿用 ${ageH(since)} 小时前数据`, error: r.error, ms: r.ms }
      : { name, ok: false, stale: false, text: shortErr(r.error), error: r.error, ms: r.ms };
  };

  // KEV
  let kev;
  if (kevR.ok) { kev = kevR.data; sources.kev = { name: 'CISA KEV', ok: true, stale: false, text: `${kev.recent7d} 条近7天 / 共 ${kev.total}`, error: '', ms: kevR.ms }; }
  else { kev = prev?.kev || { total: 0, recent7d: 0, items: [] }; sources.kev = stale('kev', 'CISA KEV', kevR, !!prev?.kev?.items?.length); }

  // NVD
  const nvdItems = nvdR.items;
  const n48 = nvdItems.filter((x) => x.published >= now - 2 * DAY).length;
  if (nvdR.ok) {
    sources.nvd = { name: 'NVD', ok: true, stale: false, partial: nvdR.partial, ms: nvdR.ms, error: nvdR.errors.join('; '),
      text: `近${NVD_DAYS}天 ${nvdItems.length} 枚（近48h ${n48}）${nvdR.partial ? '·部分' : ''}` };
  } else {
    const hasPrev = nvdItems.length > 0;
    sources.nvd = hasPrev
      ? { name: 'NVD', ok: false, stale: true, since: prevSrc('nvd')?.since || prev?.generatedAt, text: `失败，沿用 ${ageH(prevSrc('nvd')?.since || prev?.generatedAt)} 小时前数据`, error: nvdR.errors.join('; '), ms: nvdR.ms }
      : { name: 'NVD', ok: false, stale: false, text: shortErr(nvdR.errors[0]), error: nvdR.errors.join('; '), ms: nvdR.ms };
  }

  // GHSA
  let ghsa;
  if (ghsaR.ok) { ghsa = ghsaR.data; sources.ghsa = { name: 'GitHub Advisory', ok: true, stale: false, text: `${ghsa.length} 条公告`, error: '', ms: ghsaR.ms }; }
  else { ghsa = prev?.ghsa || []; sources.ghsa = stale('ghsa', 'GitHub Advisory', ghsaR, ghsa.length > 0); }

  // Zero Wire
  let zw;
  if (zwR.ok) { zw = zwR.data.items; sources.zw = { name: 'Cloudflare Zero Wire', ok: true, stale: false, text: `${zw.length} 条简报${zwR.data.via !== 'direct' ? '（经代理）' : ''}`, error: '', ms: zwR.ms }; }
  else { zw = prev?.zw || []; sources.zw = stale('zw', 'Cloudflare Zero Wire', zwR, zw.length > 0); }

  // RSS feeds
  const feeds = [];
  cfg.feeds.forEach((f, i) => {
    const r = feedR[i], id = `feed_${f.id}`;
    if (r.ok) { feeds.push({ id: f.id, name: f.name, items: r.data.items }); sources[id] = { name: f.name, ok: true, stale: false, text: `${r.data.items.length} 条${r.data.via !== 'direct' ? '（经代理）' : ''}`, error: '', ms: r.ms }; }
    else {
      const old = (prev?.feeds || []).find((x) => x.id === f.id);
      if (old?.items?.length) feeds.push({ id: f.id, name: f.name, items: old.items });
      sources[id] = stale(id, f.name, r, !!old?.items?.length);
    }
  });

  // Refuse to publish a run that has no fresh core data at all
  if (!kevR.ok && !nvdR.ok && !ghsaR.ok) {
    ghaMsg('error', 'All core sources failed', `KEV: ${kevR.error} | NVD: ${nvdR.errors.join('; ')} | GHSA: ${ghsaR.error}`);
    await summary(sources, now, T0, true);
    process.exit(1);
  }

  // EPSS (for every CVE we are about to publish)
  const out = {
    schema: 1,
    generatedAt: new Date(now).toISOString(),
    run: E.GITHUB_RUN_ID ? { id: E.GITHUB_RUN_ID, event: E.GITHUB_EVENT_NAME || '', repo: REPO, url: `${E.GITHUB_SERVER_URL || 'https://github.com'}/${REPO}/actions/runs/${E.GITHUB_RUN_ID}` } : null,
    config: { nvdDays: NVD_DAYS, kevDays: KEV_DAYS },
    sources, kev, nvd: { windowDays: NVD_DAYS, items: nvdItems }, ghsa, zw, feeds, epss: {}, newIds: []
  };
  const cveIds = [
    ...kev.items.map((k) => k.cveID), ...nvdItems.map((n) => n.id), ...ghsa.map((g) => g.cve_id).filter(Boolean).map((c) => String(c).toUpperCase()),
    ...[...zw, ...feeds.flatMap((f) => f.items)].flatMap((i) => extractCves(`${i.title} ${i.description}`))
  ];
  const epssR = await run(() => fetchEpss(cveIds));
  const idSet = new Set(cveIds);
  if (epssR.ok) {
    out.epss = epssR.data.map;
    sources.epss = { name: 'EPSS', ok: true, stale: false, partial: epssR.data.failedChunks > 0, ms: epssR.ms, error: '',
      text: `已评分 ${Object.keys(out.epss).length} 枚${epssR.data.failedChunks ? '·部分' : ''}` };
  } else {
    for (const [k, v] of Object.entries(prev?.epss || {})) if (idSet.has(k)) out.epss[k] = v;
    sources.epss = stale('epss', 'EPSS', epssR, Object.keys(out.epss).length > 0);
  }

  // "New since last run"
  if (prev) { const old = idsOf(prev); out.newIds = [...idsOf(out)].filter((x) => x && !old.has(x)).slice(0, 5000); }

  await mkdir(path.dirname(OUT_FILE), { recursive: true });
  await writeFile(OUT_FILE, JSON.stringify(out));
  const kb = Math.round(JSON.stringify(out).length / 1024);
  log(`Wrote ${OUT_FILE} (${kb} KB): KEV ${kev.items.length}, NVD ${nvdItems.length}, GHSA ${ghsa.length}, ZW ${zw.length}, feeds ${feeds.reduce((s, f) => s + f.items.length, 0)}, EPSS ${Object.keys(out.epss).length}, new ${out.newIds.length}`);
  for (const s of Object.values(sources)) if (!s.ok) ghaMsg('warning', `Source: ${s.name}`, `${s.text} — ${s.error}`);
  await summary(sources, now, T0, false, out);
}

async function summary(sources, now, T0, failed, out) {
  const lines = [`## CyberBriefing intel ${failed ? '❌ FAILED' : '✅ published'}`, '',
    `Generated: \`${new Date(now).toISOString()}\` · took ${Math.round((Date.now() - T0) / 1000)} s`, '',
    '| Source | Status | Detail | ms |', '|---|---|---|---|'];
  for (const s of Object.values(sources)) lines.push(`| ${s.name} | ${s.ok ? (s.partial ? '🟡 partial' : '🟢 ok') : s.stale ? '🟠 stale' : '🔴 failed'} | ${(s.text || '').replace(/\|/g, '/')}${s.error && !s.ok ? ' — ' + s.error.replace(/\|/g, '/').slice(0, 160) : ''} | ${s.ms ?? ''} |`);
  if (out) lines.push('', `New since last run: **${out.newIds.length}** · file size ≈ ${Math.round(JSON.stringify(out).length / 1024)} KB`);
  if (E.GITHUB_STEP_SUMMARY) await appendFile(E.GITHUB_STEP_SUMMARY, lines.join('\n') + '\n');
}

main().catch(async (e) => { ghaMsg('error', 'fetch-intel crashed', errMsg(e)); console.error(e); process.exit(1); });
