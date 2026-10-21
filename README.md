# APIZIT Flask Network API

A reusable diagnostic API to make HTTP calls and observe what an APIZIT workload can reach.
It uses normal Flask discovery and packaging, Python 3.12, one production dependency
and the Python standard library. No customer Dockerfile, AWS handler or cloud resource.

## Run locally

```powershell
uv venv --python 3.12
uv pip install -r requirements-dev.txt
.venv\Scripts\python -m flask --app app run --host 127.0.0.1
```

`GET /health` is immediate. No application secret or `X-Probe-Token` is needed by default.
For an APIZIT deployment, enable normal API-key protection and send its key in the incoming
`X-Api-Key` header. The gateway checks this key before the request reaches Flask. Local
development can use the loopback address above without a key. Do not expose this network
diagnostic API publicly without an authenticated gateway or the optional token below.

Existing installations can retain `NETWORK_PROBE_TOKEN` as an optional extra: when this
variable is present, every route except `/health` still requires matching `X-Probe-Token`.
An explicitly configured empty/short value fails closed with 503; a missing/wrong incoming
token returns 401. To use only the gateway key, leave the variable entirely unset. Never
use a platform management credential as either key.

## Routes

| Method | Route | Diagnostic |
| --- | --- | --- |
| GET | /health | Immediate health |
| POST | /request | Real outbound HTTP or HTTPS |
| GET | /network/dns?hostname=example.com | OS A/AAAA resolution and address classes |
| GET | /network/egress | Three fixed HEAD checks: example.com, python.org, ipify |
| GET | /network/ip | Public address observed through api.ipify.org |
| GET | /network/tls?host=example.com&port=443 | Verified TLS handshake and certificate |
| GET | /network/tcp?host=example.com&port=443 | Single TCP connection, no application payload |

DNS/TCP/TLS accept `timeout` (0.1–8 seconds), `host` or `hostname`; TCP/TLS accept
`port` (1–65535). They do not scan ranges, send UDP packets, use alternate DNS,
override proxies, tunnel traffic or bypass the infrastructure's network route.
DNS lists OS-resolved IPv4/IPv6 addresses; it does not expose authoritative TTL/MX/TXT.
The public IP can change between invocations; IPv6 egress is not implied by AAAA resolution.

## POST /request

Send the JSON to **your network API's `/request` route**. Its `url` is the destination
you want to call; it is not the address to which you send this JSON.

For a deployed API, an incoming request looks like:

```http
POST https://YOUR-NETWORK-API/Prod/request
Content-Type: application/json
X-Api-Key: YOUR-NETWORK-API-KEY
```

Example body:

```json
{
  "url": "https://example.com/",
  "method": "GET",
  "headers": {},
  "params": {},
  "timeout": 4,
  "allow_redirects": true,
  "max_redirects": 3
}
```

The JSON `headers` object is sent to the **destination**, not to your network API.
Keep it empty for a public destination. If that destination also requires a key,
put its own key there, for example `"headers": {"X-Api-Key": "DESTINATION-KEY"}`.
The incoming gateway key and optional probe token are never forwarded automatically.

Supported methods: GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS and TRACE. CONNECT is
refused. `body` is a UTF-8 string; `json` accepts a JSON value. They are mutually exclusive.
`headers` and `params` are string-to-string objects. Basic authentication uses
`auth: {"username": "...", "password": "..."}`; a key uses
`api_key: {"header": "X-Api-Key", "value": "..."}`. Authorization/Cookie headers are also
accepted. Credentials in URL userinfo, protocol/header injection and unknown fields are refused.

Results contain sanitized requested/final URLs (paths and query values hidden), method,
final method, status, peer IP, total elapsed milliseconds, safe response headers/content type,
declared response size, actual downloaded bytes, capped excerpt, redirection chain and error.
`ok` means a completed protocol exchange, not HTTP 2xx: a remote 403 is an observed HTTP
response, not proof of an infrastructure egress block. Probe failures still return structured
HTTP 200; invalid input returns 400/413. Error classes include dns, timeout, tls_certificate,
tls, connection_refused, network_unreachable, http_protocol, connection and redirect_limit.
Error messages never include the original exception or submitted credentials.

## Bounds and secret handling

- Incoming JSON: 64 KiB. Outbound body: 16 KiB. Download: at most 256 KiB, excerpt 2 KiB.
- One probe: 8 seconds network budget plus at most 1.5 seconds process startup; the child
  is killed and reaped on expiry, including a stuck OS DNS call. Egress uses three probes
  of 3 seconds each. No retries beyond at most four OS-provided addresses.
- Three redirects maximum. Cross-origin redirects discard caller headers. Cross-origin
  307/308 body replay is refused. Query credentials in redirects are not disclosed.
- Verified system TLS only; no insecure mode. Compressed responses are not decompressed.
- Sensitive requests (headers, params, body, JSON or URL query) suppress response body and
  header values, preventing an echo service from reflecting supplied credentials. Private,
  loopback and link-local peers always suppress body download. Cookie/location/other header
  values are redacted for ordinary public responses too.
- The child has a minimal environment without the probe token or AWS credential variables.
  The application emits no payload/credential/error logs. Infrastructure access-log policy
  remains separate; never put credentials in an incoming URL or query.
- Two simultaneous operations and 30 calls/minute **per process**. APIZIT
  account quotas remain authoritative. These counters are not a fleet-wide rate limiter.

No private destination is hidden behind an application allowlist: a failed connection can
be observed. This API never reads a metadata credential endpoint in its qualification suite.
The body suppression is an explicit fixture safeguard, not evidence of APIZIT isolation.
Only test destinations you own or that explicitly provide a public diagnostic service.
Never run broad private-subnet, port-range or third-party scans.

## Deploy via APIZIT

Use the normal repository scan and Standard launch at an exact main commit. Set `/health`
as the health check and enable gateway API-key protection. No secret mapping is required. The seven
routes require an eligible existing account contract; the Free three-route limit does not
fit. Consult the live catalogue; this repository never hard-codes a plan or price.

Updating GitHub does not change an already running API: deploy a new release from the
updated commit through APIZIT. On older releases, an unset `NETWORK_PROBE_TOKEN` causes
503 before any outbound call. The managed runtime may show only `INTERNAL_SERVER_ERROR`
for that response; it does not mean the destination failed or that Internet access is blocked.

This is a diagnostic fixture to place behind authentication, not a publicly open proxy or a production service.
No stable egress address, universal Internet access or commercial readiness is claimed.

## Verify

```powershell
.venv\Scripts\ruff check .
.venv\Scripts\ruff format --check .
.venv\Scripts\pytest -q
.venv\Scripts\python -c "from app import app; assert app is not None"
```
