"""Closed request contract. Errors never interpolate caller-supplied values."""

import base64
import ipaddress
import json
import math
import re
from urllib.parse import urlencode, urlsplit, urlunsplit

MAX_DOWNLOAD = 262144
MAX_SEND = 16384
MAX_PREVIEW = 2048
MAX_TIMEOUT = 8.0
MAX_REDIRECTS = 3
METHODS = {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE"}
HEADER = re.compile(r"^[!#$%&'*+.^_`|~0-9a-zA-Z-]{1,64}$")
FORBIDDEN_HEADERS = {
    "host",
    "connection",
    "content-length",
    "transfer-encoding",
    "upgrade",
    "expect",
    "proxy-authorization",
    "proxy-connection",
    "trailer",
    "te",
    "x-probe-token",
}


def hostname(value):
    if not isinstance(value, str) or not value or len(value) > 253:
        raise ValueError("A hostname or IP address is required.")
    if any(ord(c) < 33 or ord(c) > 126 for c in value) or "%" in value:
        raise ValueError("The hostname is invalid.")
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        if not re.fullmatch(r"[a-zA-Z0-9.-]+", value):
            raise ValueError("The hostname is invalid.") from None
        labels = value.rstrip(".").split(".")
        if any(
            not re.fullmatch(r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?", x) for x in labels
        ):
            raise ValueError("The hostname is invalid.") from None
        return value.lower()


def number(value, low, high, field):
    if isinstance(value, bool):
        raise ValueError(f"Invalid {field}.")
    try:
        result = float(value)
    except (TypeError, ValueError):
        raise ValueError(f"Invalid {field}.") from None
    if not math.isfinite(result) or not low <= result <= high:
        raise ValueError(f"Invalid {field}.")
    return result


def port(value):
    result = number(value, 1, 65535, "port")
    if result != int(result):
        raise ValueError("Invalid port.")
    return int(result)


def target_url(value):
    if not isinstance(value, str) or len(value) > 2048:
        raise ValueError("An HTTP or HTTPS URL is required.")
    if any(ord(c) < 33 or ord(c) > 126 for c in value) or "\\" in value:
        raise ValueError("The URL is invalid.")
    try:
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or parsed.username or parsed.password:
            raise ValueError
        hostname(parsed.hostname)
        if parsed.port is not None:
            port(parsed.port)
        if parsed.fragment:
            raise ValueError
    except (ValueError, TypeError):
        raise ValueError("Only credential-free HTTP/HTTPS URLs are allowed.") from None
    return value


def safe_url(value):
    parsed = urlsplit(value)
    # A path can itself contain credentials. Only origin and query presence are disclosed.
    return urlunsplit(
        (
            parsed.scheme,
            parsed.netloc,
            "/[path-redacted]" if parsed.path not in {"", "/"} else parsed.path,
            "[query-redacted]" if parsed.query else "",
            "",
        )
    )


def string_map(value, field, limit=32):
    if not isinstance(value, dict) or len(value) > limit:
        raise ValueError(f"Invalid {field}.")
    if any(not isinstance(k, str) or not isinstance(v, str) for k, v in value.items()):
        raise ValueError(f"Invalid {field}.")
    if len(json.dumps(value).encode()) > 8192:
        raise ValueError(f"Invalid {field}.")
    return value.copy()


def http_payload(payload):
    if not isinstance(payload, dict) or set(payload) - {
        "url",
        "method",
        "headers",
        "params",
        "body",
        "json",
        "timeout",
        "allow_redirects",
        "max_redirects",
        "auth",
        "api_key",
    }:
        raise ValueError("Invalid request fields.")
    url = target_url(payload.get("url"))
    method = payload.get("method", "GET")
    if not isinstance(method, str) or method.upper() not in METHODS:
        raise ValueError("Unsupported HTTP method.")
    headers = string_map(payload.get("headers", {}), "headers")
    if len({x.lower() for x in headers}) != len(headers):
        raise ValueError("Duplicate header names.")
    for key, value in headers.items():
        if not HEADER.fullmatch(key) or key.lower() in FORBIDDEN_HEADERS:
            raise ValueError("Unsupported header.")
        if any(ord(c) < 32 or ord(c) > 126 for c in value):
            raise ValueError("Invalid header value.")
    auth = payload.get("auth")
    if auth is not None:
        auth = string_map(auth, "auth", 2)
        if set(auth) != {"username", "password"} or ":" in auth["username"]:
            raise ValueError("Basic auth requires username and password.")
        if any(k.lower() == "authorization" for k in headers):
            raise ValueError("Conflicting authentication.")
        credentials = (auth["username"] + ":" + auth["password"]).encode()
        headers["Authorization"] = "Basic " + base64.b64encode(credentials).decode()
    api_key = payload.get("api_key")
    if api_key is not None:
        api_key = string_map(api_key, "api_key", 2)
        if set(api_key) != {"header", "value"}:
            raise ValueError("api_key requires header and value.")
        key, value = api_key["header"], api_key["value"]
        if (
            not HEADER.fullmatch(key)
            or key.lower() in FORBIDDEN_HEADERS
            or any(k.lower() == key.lower() for k in headers)
            or any(ord(c) < 32 or ord(c) > 126 for c in value)
        ):
            raise ValueError("Invalid API key header.")
        headers[key] = value
    if "body" in payload and "json" in payload:
        raise ValueError("body and json are mutually exclusive.")
    body = None
    if "json" in payload:
        try:
            body = json.dumps(payload["json"], allow_nan=False).encode()
        except (ValueError, TypeError):
            raise ValueError("Invalid JSON body.") from None
        headers.setdefault("Content-Type", "application/json")
    elif "body" in payload:
        if not isinstance(payload["body"], str):
            raise ValueError("body must be a string.")
        body = payload["body"].encode()
    if body is not None and len(body) > MAX_SEND:
        raise ValueError("The outbound body exceeds 16384 bytes.")
    params = string_map(payload.get("params", {}), "params")
    if params:
        parsed = urlsplit(url)
        query = parsed.query + ("&" if parsed.query else "") + urlencode(params)
        url = target_url(urlunsplit(parsed._replace(query=query)))
    redirects = payload.get("allow_redirects", True)
    if not isinstance(redirects, bool):
        raise ValueError("allow_redirects must be boolean.")
    count = number(payload.get("max_redirects", MAX_REDIRECTS), 0, MAX_REDIRECTS, "max_redirects")
    if count != int(count):
        raise ValueError("Invalid max_redirects.")
    return {
        "url": url,
        "method": method.upper(),
        "headers": headers,
        "body": None if body is None else base64.b64encode(body).decode(),
        "timeout": number(payload.get("timeout", 4), 0.1, MAX_TIMEOUT, "timeout"),
        "allow_redirects": redirects,
        "max_redirects": int(count),
        "sensitive": bool(headers or body is not None or params or urlsplit(url).query),
    }
