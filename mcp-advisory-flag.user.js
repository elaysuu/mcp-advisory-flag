// ==UserScript==
// @name         MCP Advisory Flag
// @namespace    https://github.com/elaysuu/mcp-advisory-flag
// @version      1.0.1
// @description  Flags MCP servers and AI-agent packages with known security advisories on github.com and npmjs.com package pages. Data: agent-advisory-gate (AKRENON CC BY 4.0) + OSV.
// @author       elaysuu
// @license      MIT
// @match        https://github.com/*
// @match        https://www.npmjs.com/*
// @grant        GM_xmlhttpRequest
// @grant        GM_getValue
// @grant        GM_setValue
// @grant        GM_registerMenuCommand
// @connect      raw.githubusercontent.com
// @connect      api.osv.dev
// @connect      api.gumroad.com
// @antifeature  membership Pro features (fix hints, search badges) need a Gumroad license key
// @run-at       document-idle
// ==/UserScript==
(function () {
  'use strict';
  const DATA_URL = 'https://raw.githubusercontent.com/elaysuu/agent-advisory-gate/main/data/mcp-advisories.json';
  const PRODUCT_ID = '-ZV9cuYRgFKsXvqkLtR3fA==';
  const BUY_URL = 'https://setrov.gumroad.com/l/hqviee';
  const CACHE_MS = 6 * 3600e3;

  // ---------- pure helpers (unit-tested) ----------
  function npmNameFromUrl(u) {
    const m = /^https:\/\/www\.npmjs\.com\/package\/((?:@[^/]+\/)?[^/?#]+)/.exec(u);
    return m ? decodeURIComponent(m[1]) : null;
  }
  function githubRepoFromUrl(u) {
    const m = /^https:\/\/github\.com\/([^/?#]+)\/([^/?#]+)\/?(?:$|[?#]|tree\/|blob\/)/.exec(u);
    if (!m) return null;
    const reserved = ['orgs', 'settings', 'marketplace', 'topics', 'search', 'notifications', 'explore', 'sponsors', 'features', 'login', 'about', 'pricing', 'collections', 'trending', 'issues', 'pulls'];
    return reserved.includes(m[1]) ? null : { owner: m[1], repo: m[2].replace(/\.git$/, '') };
  }
  function matchDataset(dataset, name, ecosystem) {
    return (dataset.advisories || []).filter(a => a.package === name && (!ecosystem || a.ecosystem === ecosystem));
  }
  function mergeOsv(local, osvVulns) {
    const seen = new Set(local.map(a => a.id));
    const out = local.map(a => ({ id: a.id, summary: a.summary, severity: a.severity || '', fixed: a.fixed || null, src: 'dataset' }));
    for (const v of osvVulns || []) {
      if (seen.has(v.id) || (v.aliases || []).some(x => seen.has(x)) || v.withdrawn) continue;
      out.push({ id: v.id, summary: v.summary || v.details?.slice(0, 120) || '', severity: (v.database_specific?.severity || '').toUpperCase(), fixed: fixedFromOsv(v), src: 'osv' });
    }
    return out;
  }
  function fixedFromOsv(v) {
    const f = [];
    for (const a of v.affected || []) for (const r of a.ranges || []) for (const e of r.events || []) if (e.fixed) f.push(e.fixed);
    return f.length ? f[f.length - 1] : null;
  }
  function licenseState(resp) {
    if (!resp || !resp.success) return { pro: false, reason: 'invalid key' };
    const p = resp.purchase || {};
    if (p.refunded || p.chargebacked || p.disputed) return { pro: false, reason: 'refunded/disputed' };
    for (const f of ['subscription_cancelled_at', 'subscription_ended_at', 'subscription_failed_at']) if (p[f]) return { pro: false, reason: f };
    return { pro: true, reason: 'ok' };
  }
  function badgeText(list, pro) {
    if (!list.length) return null;
    const crit = list.filter(a => /CRITICAL|HIGH/.test(a.severity)).length;
    let t = `\u26a0 ${list.length} known advisor${list.length > 1 ? 'ies' : 'y'}${crit ? ` (${crit} high/critical)` : ''}`;
    if (pro) { const fx = list.map(a => a.fixed).filter(Boolean); if (fx.length) t += ` \u2192 upgrade to \u2265 ${fx.sort(cmpVer).pop()}`; }
    return t;
  }
  function cmpVer(a, b) { const pa = a.split(/[.-]/).map(Number), pb = b.split(/[.-]/).map(Number); for (let i = 0; i < 3; i++) { if ((pa[i] || 0) !== (pb[i] || 0)) return (pa[i] || 0) - (pb[i] || 0); } return 0; }

  if (typeof module !== 'undefined' && module.exports) { module.exports = { npmNameFromUrl, githubRepoFromUrl, matchDataset, mergeOsv, fixedFromOsv, licenseState, badgeText, cmpVer }; return; }

  // ---------- browser side ----------
  const req = (method, url, data, headers) => new Promise((res, rej) => GM_xmlhttpRequest({ method, url, data, headers, timeout: 10000,
    onload: r => res(r), onerror: rej, ontimeout: rej }));
  async function dataset() {
    const c = GM_getValue('ds'); if (c && Date.now() - c.t < CACHE_MS) return c.d;
    const r = await req('GET', DATA_URL); const d = JSON.parse(r.responseText); GM_setValue('ds', { t: Date.now(), d }); return d;
  }
  async function osv(name, eco) {
    const r = await req('POST', 'https://api.osv.dev/v1/query', JSON.stringify({ package: { name, ecosystem: eco } }), { 'content-type': 'application/json' });
    return (JSON.parse(r.responseText).vulns) || [];
  }
  async function isPro() {
    const key = GM_getValue('key'); if (!key || PRODUCT_ID.startsWith('REPLACE_')) return false;
    const c = GM_getValue('lic'); if (c && c.key === key && Date.now() - c.t < 864e5) return c.pro;
    try {
      const r = await req('POST', 'https://api.gumroad.com/v2/licenses/verify', `product_id=${encodeURIComponent(PRODUCT_ID)}&license_key=${encodeURIComponent(key)}&increment_uses_count=false`, { 'content-type': 'application/x-www-form-urlencoded' });
      const s = licenseState(JSON.parse(r.responseText)); GM_setValue('lic', { key, t: Date.now(), pro: s.pro }); return s.pro;
    } catch { return false; }
  }
  GM_registerMenuCommand('MCP Advisory Flag: enter Pro license key', () => { const k = prompt('Gumroad license key (Pro: fix-version hints + search badges). Buy: ' + BUY_URL); if (k !== null) { GM_setValue('key', k.trim()); GM_setValue('lic', null); location.reload(); } });

  function banner(list, pro, name) {
    const el = document.createElement('div');
    el.id = 'mcp-adv-flag';
    el.style.cssText = 'position:sticky;top:0;z-index:9999;background:#7f1d1d;color:#fff;padding:8px 14px;font:14px system-ui';
    el.textContent = `${name}: ${badgeText(list, pro)} `;
    const ul = document.createElement('div'); ul.style.cssText = 'font-size:12px;margin-top:4px';
    for (const a of list.slice(0, 8)) { const l = document.createElement('a'); l.href = `https://osv.dev/vulnerability/${a.id}`; l.target = '_blank'; l.style.color = '#fecaca'; l.textContent = `${a.id} ${a.severity} ${a.summary}${pro && a.fixed ? ` (fixed ${a.fixed})` : ''}`; ul.append(l, document.createElement('br')); }
    if (!pro) { const s = document.createElement('a'); s.href = BUY_URL; s.target = '_blank'; s.style.color = '#fde68a'; s.textContent = 'Get fix-version hints + search badges (Pro, $5)'; ul.append(s); }
    el.append(ul); document.body.prepend(el);
  }
  async function check(name, eco) { const d = await dataset(); return mergeOsv(matchDataset(d, name, eco), await osv(name, eco)); }

  async function run() {
    document.getElementById('mcp-adv-flag')?.remove();
    const pro = await isPro(); const u = location.href;
    const npm = npmNameFromUrl(u);
    if (npm) { const l = await check(npm, 'npm'); if (l.length) banner(l, pro, npm); return; }
    if (/^https:\/\/www\.npmjs\.com\/search/.test(u)) {
      if (!pro) return;
      for (const a of document.querySelectorAll('a[href^="/package/"]')) {
        if (a.dataset.mcpFlag) continue; a.dataset.mcpFlag = 1;
        const n = npmNameFromUrl('https://www.npmjs.com' + a.getAttribute('href')); if (!n) continue;
        const l = await check(n, 'npm'); const t = badgeText(l, true);
        if (t) { const b = document.createElement('span'); b.textContent = ' ' + t; b.style.cssText = 'background:#b91c1c;color:#fff;border-radius:4px;padding:0 4px;margin-left:6px;font-size:12px'; a.after(b); }
      }
      return;
    }
    const gh = githubRepoFromUrl(u);
    if (gh) {
      for (const [file, eco, rx] of [['package.json', 'npm', null], ['pyproject.toml', 'PyPI', /^\s*name\s*=\s*["']([^"']+)/m]]) {
        const r = await req('GET', `https://raw.githubusercontent.com/${gh.owner}/${gh.repo}/HEAD/${file}`);
        if (r.status !== 200) continue;
        let name = null; try { name = rx ? (rx.exec(r.responseText) || [])[1] : JSON.parse(r.responseText).name; } catch {}
        if (!name) continue;
        const l = await check(name, eco); if (l.length) banner(l, pro, name); return;
      }
    }
  }
  let last = ''; setInterval(() => { if (location.href !== last) { last = location.href; run().catch(() => {}); } }, 1000);
})();
