# MCP Advisory Flag (userscript)

Shows a red banner on **npmjs.com package pages** and **GitHub repo pages** when the package (or the repo's package.json / pyproject.toml name) has known security advisories.

Data: the public advisory file of [agent-advisory-gate](https://github.com/elaysuu/agent-advisory-gate) (AKRENON MCP dataset, CC BY 4.0) plus a live [OSV](https://osv.dev) query. Nothing else leaves your browser.

## Install
1. Install Tampermonkey or Violentmonkey.
2. Open `mcp-advisory-flag.user.js` (Greasy Fork or raw GitHub) and click Install.

## Free
- Banner with advisory IDs, severity, summary, links to OSV.

## Pro ($5 one-time, Gumroad license key)

Buy Pro: https://setrov.gumroad.com/l/hqviee
- Fix-version hints ("upgrade to >= 0.1.16") in the banner.
- Badges next to flagged packages in npmjs.com search results.
Enter the key via the userscript menu: "MCP Advisory Flag: enter Pro license key". The key is checked with Gumroad's license API (increment_uses_count=false) and cached for 24 h.

## Test
`node --test test/` (fixtures: real dataset snapshot + real OSV response for mcp-remote, GHSA-6xpm-ggf7-wc3p / CVE-2025-6514).

MIT. Advisory data CC BY 4.0, AKRENON Security, https://data.akrenon.com/mcp-advisories/
