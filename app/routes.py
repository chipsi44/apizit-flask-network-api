"""Literal Flask routes for normal APIZIT discovery."""

import hmac
import ipaddress
import os
import threading
import time

from flask import request
from werkzeug.exceptions import HTTPException

from app import app, probes
from app.validation import MAX_TIMEOUT, hostname, http_payload, number, port

SLOTS = threading.BoundedSemaphore(2)
LOCK = threading.Lock()
CALLS = []


@app.before_request
def authorize():
    if request.path == "/health":
        return None
    expected = os.environ.get("NETWORK_PROBE_TOKEN", "")
    if len(expected) < 32:
        return {"error": "probe_not_configured"}, 503
    supplied = request.headers.get("X-Probe-Token", "")
    if not hmac.compare_digest(supplied.encode(), expected.encode()):
        return {"error": "unauthorized"}, 401
    with LOCK:
        now = time.monotonic()
        CALLS[:] = [x for x in CALLS if now - x < 60]
        if len(CALLS) >= 30:
            return {"error": "process_rate_limit", "scope": "per-process"}, 429
        CALLS.append(now)
    if not SLOTS.acquire(blocking=False):
        return {"error": "probe_busy"}, 429
    request.environ["probe_slot"] = True
    return None


@app.teardown_request
def release(_error):
    if request.environ.pop("probe_slot", False):
        SLOTS.release()


@app.errorhandler(Exception)
def clean_error(error):
    if isinstance(error, ValueError):
        return {"error": "validation", "message": "Invalid diagnostic parameters."}, 400
    if isinstance(error, HTTPException):
        return {"error": "http_request", "status": error.code}, error.code
    return {"error": "internal_error"}, 500


@app.after_request
def secure_response(response):
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


@app.get("/health")
def health():
    """Immediate health check without network activity."""
    return {"status": "ok"}


@app.post("/request")
def outbound_request():
    """Run one authenticated, bounded outbound HTTP/HTTPS request."""
    payload = http_payload(request.get_json(silent=True))
    return probes.run("request", payload)


def network_arguments(default_port):
    if any(len(request.args.getlist(k)) != 1 for k in request.args):
        raise ValueError("Duplicate network query field.")
    if set(request.args) - {"host", "hostname", "port", "timeout"}:
        raise ValueError("Unknown network query field.")
    return {
        "host": hostname(request.args.get("host", request.args.get("hostname"))),
        "port": port(request.args.get("port", default_port)),
        "timeout": number(request.args.get("timeout", 4), 0.1, MAX_TIMEOUT, "timeout"),
    }


@app.get("/network/dns")
def dns():
    """Resolve one hostname through the operating system resolver."""
    return probes.run("dns", network_arguments(443))


@app.get("/network/tcp")
def tcp():
    """Connect to one host and TCP port without sending application data."""
    return probes.run("tcp", network_arguments(443))


@app.get("/network/tls")
def tls():
    """Verify one TLS handshake and return public certificate information."""
    return probes.run("tls", network_arguments(443))


@app.get("/network/egress")
def egress():
    """Observe HTTP and HTTPS access to two fixed public example targets."""
    # Independent HTTP and HTTPS checks, each bounded to three seconds.
    results = [
        probes.run("request", http_payload({"url": url, "method": "HEAD", "timeout": 3}))
        for url in ("http://example.com/", "https://example.com/")
    ]
    return {
        "tests": results,
        "internet_http_observed": any(x.get("status_code") for x in results),
        "scope": "two fixed destinations; not a universal egress guarantee",
    }


@app.get("/network/ip")
def public_ip():
    """Observe the public egress address through an external echo service."""
    result = probes.run("request", http_payload({"url": "https://api.ipify.org/", "timeout": 3}))
    try:
        address = ipaddress.ip_address(result.get("body_excerpt", "").strip())
        if not address.is_global or result.get("status_code") != 200:
            raise ValueError
    except (ValueError, AttributeError):
        return {
            "observable": False,
            "error": result.get("error")
            or {"type": "ip_observation", "message": "Public IP was not observable."},
        }
    return {
        "observable": True,
        "public_ip": str(address),
        "provider": "api.ipify.org",
        "elapsed_ms": result["elapsed_ms"],
        "stable_ip_guaranteed": False,
    }
