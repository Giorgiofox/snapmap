# Snapmap — implementation spec (module contracts)

Snapmap: fast nmap sweep of a subnet → discover exposed web interfaces → HTTP
probe → Playwright screenshots → **one self-contained HTML page (no pagination)**
with client-side search/filter/sort, per-endpoint **issues** and a **recap**.

Package root: `snapmap/` (this dir). Python package: `snapmap/snapmap/`.
Python 3.10+. Use `from __future__ import annotations`. Deps available:
`httpx`, `jinja2`, `mmh3`, `playwright`. Style: concise, typed, docstrings like
the existing foundation files. **Only edit the file(s) you own.**

## Foundation (already written — DO NOT modify, just import)

- `models.py`: `Service`, `Host`, `CredCandidate`, `Issue`, `Endpoint`, `Options`,
  `DEFAULT_UA`. Read this file for exact fields.
- `ports.py`: `resolve_ports(spec)->str`, `parse_port_list(spec)->list[int]`,
  `SECURE_PORTS:set[int]`, `PORT_ALIASES`.
- `creds.py`: `match_products(*signals, max_products=3, max_per_product=10)->list[CredCandidate]`,
  `update_db(url=?, dest=?)->(int,int)`, `db_stats()->(int,int)`, `DEFAULT_CREDS_URL`.
- `fingerprint.py`: `fingerprint(headers:dict[str,str], body:bytes, *extra)->list[str]`
  (headers keys MUST be lower-cased), `security_headers(headers)->dict[str,bool]`,
  `SECURITY_HEADERS`.
- `issues.py`: `generate_issues(ep:Endpoint)->list[Issue]`,
  `interest_score(issues)->int`, `SEVERITIES`, `SEVERITY_ORDER`, `SEVERITY_WEIGHT`.

## Modules to build

### `nmap_scan.py`  (owner: agent 1)
- `nmap_available() -> bool`
- `run_nmap(target:str, ports:str, *, rate:int=5000, timing:int=4, no_ping:bool=False,
   service_detection:bool=True, extra_args:list[str]|None=None, sudo:bool=False,
   log=print) -> str`  → returns nmap XML (uses `-oX -`). Build a FAST command:
   `nmap -n -T{timing} --min-rate {rate} --open -p {resolve_ports(ports)} -oX -`,
   add `-Pn` if no_ping, `-sV --version-light` if service_detection, then extra_args,
   then `*target.split()`. Prepend `sudo` if sudo. Log the command via `log`.
   Raise `NmapNotFound` if nmap missing; raise RuntimeError on failure with stderr.
- `parse_nmap_xml(xml_text:str) -> list[Host]`  (stdlib xml.etree). Skip hosts
   `down`, skip mac addresses, only `state==open` tcp ports. Fill Service fields
   (name, product, version, extrainfo, tunnel).
- `scheme_for_service(svc:Service) -> str|None`  → "http"/"https"/None. Rules:
   skip clearly non-web ssl services (smtp/imap/pop3/ftp/ssh/...); tunnel ssl/tls
   or name containing https/ssl → https; name containing http → http; empty/unknown
   → https if `svc.port in SECURE_PORTS` else http.
- `build_url(scheme:str, host:str, port:int) -> str`  (bracket ipv6; omit port for
   80/http and 443/https).
- `build_endpoints(hosts:list[Host], *, include_hostnames:bool=True) -> list[Endpoint]`
   one Endpoint per (name, service) deduped by url; name set = [address] (+ hostnames);
   copy nmap_service/product/version onto the Endpoint.

### `prober.py`  (owner: agent 2)  — pure network, no creds/issues imports
- `async def probe_all(endpoints:list[Endpoint], opts:Options, log=print) -> None`
   mutate endpoints in place. Use one `httpx.AsyncClient` (verify=opts.verify_tls,
   follow_redirects=opts.follow_redirects, timeout=opts.timeout, proxy=opts.proxy,
   headers {UA + opts.headers}), `asyncio.Semaphore(opts.concurrency)`.
   For each endpoint GET its url; on connect/SSL failure retry ONCE with the other
   scheme (rebuild url via same host:port) and update ep.url/ep.scheme on success.
   On success fill: probed, status, reason, final_url, redirects (history urls),
   response_headers (lower-cased), server, content_type, content_length
   (header or len(body)), title (regex `<title>...</title>`, stripped/collapsed),
   technologies (`fingerprint(headers, body, ep.nmap_product, ep.nmap_service)`),
   security_headers. On failure set ep.error and leave status None.
- If `opts.do_tls` and https success: grab TLS via a blocking helper run in a
   thread (`asyncio.to_thread`): connect ssl with check_hostname off / CERT_NONE,
   record `{"version":..., "cipher":..., "insecure":bool}` where insecure = version
   in {SSLv3, TLSv1, TLSv1.1}. Best-effort, swallow errors.
- If `opts.do_favicon` and success: GET `/favicon.ico` (urljoin on final_url); if
   200 with content compute `mmh3.hash(base64.encodebytes(content))` → ep.favicon_hash.
   Guard `import mmh3` (optional). Best-effort.

### `screenshot.py`  (owner: agent 3)
- `async def capture_all(endpoints:list[Endpoint], opts:Options, log=print) -> None`
   Only shoot `ep.alive`. Lazy `from playwright.async_api import async_playwright`
   inside the function; if ImportError or Chromium launch fails, `log(...)` a clear
   hint (`playwright install chromium`) and return WITHOUT raising. Launch one
   chromium (headless, args ignore-certificate-errors + no-sandbox), a
   `Semaphore(opts.screenshot_concurrency)`, a fresh context per page
   (ignore_https_errors=True, viewport 1280x800). goto(final_url or url,
   wait_until="domcontentloaded", timeout=opts.screenshot_timeout); optional
   `wait_for_timeout(opts.screenshot_delay)`; screenshot png (full_page=opts.full_page);
   store base64 (no prefix) in ep.screenshot. Per-endpoint try/except; never abort
   the whole batch on one failure.

### `report.py`  (owner: agent 4)  — also owns `templates/report.html.j2`
- `endpoint_to_dict(ep:Endpoint, include_screenshot:bool=True) -> dict` — flat dict
   with ALL these keys: url, scheme, ip, port, host, nmap_service, nmap_product,
   nmap_version, status, reason, title, server, content_type, content_length,
   final_url, redirects, technologies, security_headers, tls, favicon_hash,
   cred_candidates (list of {product,username,password}), issues (list of
   {id,title,severity,detail,source}), interest, error, alive (bool), subnet,
   screenshot (b64 str, "" if excluded/absent).
- `render_html(endpoints:list[Endpoint], meta:dict) -> str` — render the Jinja2
   template. Inject the endpoints as JSON into `<script type="application/json"
   id="snapmap-data">` (escape `<` as `<`). Also inject `meta` and the
   severity list/weights so the JS can render + score. Autoescape must not corrupt
   the JSON (use a `|safe` block for the pre-escaped JSON string).
- `write_html(endpoints, meta:dict, path:str) -> None`
- `write_json(endpoints, path:str, meta:dict|None=None) -> None`  (EXCLUDE screenshot)
- `write_csv(endpoints, path:str) -> None` columns: url, ip, port, scheme, status,
   title, server, technologies (`;`-joined), tls_version, tls_insecure,
   cred_products (`;`-joined unique), issue_count, top_severity, interest.

`meta` dict keys provided by cli: `target`, `generated_at` (ISO str),
`tool_version`, `nmap_cmd` (str or ""), `group_by`, `total`, `alive`.

**Template `report.html.j2` requirements** (single self-contained file, inline CSS
+ vanilla JS, NO external assets, NO framework, NO pagination):
- Dark theme, responsive card grid. Each card: screenshot (lazy-loaded via
  IntersectionObserver from the base64 in JS — set `img.src` only when near
  viewport, use a placeholder otherwise), title, url (clickable, target=_blank),
  status badge (colour by 2xx/3xx/4xx/5xx), ip:port, technologies chips, a severity
  dot summarising the worst issue, and an interest score.
- Sticky toolbar: free-text search (url/title/ip/server/tech), filters for
  status class, scheme, has-screenshot, has-issues, has-default-creds; sort by
  interest (default, desc) / status / url; group-by toggle host | subnet | none
  (from meta.group_by default). Live result count. All client-side, instant.
- Click a card → detail modal: full url + final_url + redirects, all response
  headers, security headers presence, TLS info, nmap service/product/version,
  favicon hash, the **default-cred candidates table** (product/user/pass), and the
  **issues editor**.
- Issues editor (the recap feature): show auto issues (read-only) + let the analyst
  ADD manual issues (title + severity select + optional note) and delete manual
  ones. Persist manual issues in `localStorage` keyed by endpoint url. Auto issues
  come from the data; manual ones merge on top.
- **Recap view/panel**: aggregate ALL issues (auto + manual, across all endpoints)
  → counts per severity (coloured), and a grouped list "issue → affected endpoints".
  Include a "Export findings" button that downloads a JSON (and a Markdown) recap of
  every endpoint with its issues. Toggle between "Endpoints" and "Recap" views.
- Header bar shows meta (target, generated_at, totals) and severity legend.

### `pipeline.py`  (owner: agent 5)
- `async def process(endpoints:list[Endpoint], opts:Options, log=print) -> None`:
  1. `await prober.probe_all(endpoints, opts, log)`
  2. for each alive endpoint: `ep.cred_candidates = creds.match_products(ep.nmap_product,
     ep.server, ep.title, " ".join(ep.technologies), ep.nmap_service)`;
     `ep.issues = issues.generate_issues(ep)`; `ep.interest = issues.interest_score(ep.issues)`
  3. if `opts.screenshots`: `await screenshot.capture_all(endpoints, opts, log)`

### `cli.py`  (owner: agent 5)
- `main(argv=None) -> int`; `[project.scripts] snapmap = "snapmap.cli:main"`.
- argparse subcommands:
  - `scan TARGET [options]` → `nmap_scan.run_nmap` → `parse_nmap_xml` →
    `build_endpoints` → `asyncio.run(pipeline.process(...))` → write outputs.
  - `report [--nmap FILE]` (or read XML from stdin if no file) → parse → build →
    process → write outputs. (input is nmap/masscan XML.)
  - `update-creds [--url URL]` → `creds.update_db`, print `db_stats`.
- Common options → populate `Options`: `-o/--output`, `--json`, `--csv`, `--ports`,
  `--rate`, `--timing`, `-Pn/--no-ping`, `--no-sv`, `--sudo`, `--concurrency`,
  `--timeout`, `--no-redirect`, `--proxy`, `-H/--header` (repeatable `k:v`),
  `--no-screenshot`, `--full-page`, `--screenshot-delay`, `--screenshot-timeout`,
  `--group-by {host,subnet,none}`, `--no-tls`, `--no-favicon`, `--no-hostnames`.
- Build the `meta` dict, print a short summary (counts, top issues) at the end.
- Log helper: simple timestamped stderr printer honoring a `--silent` flag.
