"""Isolated bounded diagnostic operation. No environment/credential inspection or logging."""

import base64
import errno
import hashlib
import http.client
import ipaddress
import json
import socket
import ssl
import sys
import time
from urllib.parse import urljoin, urlsplit

from app.validation import MAX_DOWNLOAD, MAX_PREVIEW, hostname, safe_url, target_url

http.client._MAXLINE = 8192
http.client._MAXHEADERS = 64


class ResolutionFailure(OSError):
    """An OS resolver failure, including platforms that return a plain OSError."""


def classified(error):
    if isinstance(error, (socket.gaierror, ResolutionFailure)):
        kind = "dns"
    elif isinstance(error, ssl.SSLCertVerificationError):
        kind = "tls_certificate"
    elif isinstance(error, ssl.SSLError):
        kind = "tls"
    elif isinstance(error, TimeoutError):
        kind = "timeout"
    elif isinstance(error, ConnectionRefusedError):
        kind = "connection_refused"
    elif isinstance(error, OSError) and error.errno in {errno.ENETUNREACH, errno.EHOSTUNREACH}:
        kind = "network_unreachable"
    elif isinstance(error, http.client.HTTPException):
        kind = "http_protocol"
    elif isinstance(error, ValueError):
        kind = "validation"
    else:
        kind = "connection"
    result = {
        "type": kind,
        "message": "Probe failed: " + kind + ".",
        "exception_class": type(error).__name__,
    }
    if isinstance(getattr(error, "errno", None), int):
        result["os_error_code"] = error.errno
    return result


def resolve(host, port):
    try:
        return socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError as error:
        raise ResolutionFailure(error.errno, "OS DNS resolution failed.") from None


def addresses(host, port):
    result = []
    for family, _, _, _, address in resolve(host, port):
        item = {
            "address": address[0],
            "family": "IPv6" if family == socket.AF_INET6 else "IPv4",
            "global": ipaddress.ip_address(address[0]).is_global,
        }
        if item not in result:
            result.append(item)
    return result[:16]


def remaining(deadline):
    value = deadline - time.monotonic()
    if value <= 0:
        raise TimeoutError
    return value


def connect(host, port, deadline):
    """Resolve normally and connect directly; no proxy or alternative network route."""
    entries = resolve(host, port)[:4]
    last_error = OSError("Connection failed")
    for family, kind, protocol, _, address in entries:
        channel = socket.socket(family, kind, protocol)
        try:
            channel.settimeout(remaining(deadline))
            channel.connect(address)
            return channel
        except OSError as error:
            channel.close()
            last_error = error
    raise last_error


def origin(url):
    parsed = urlsplit(url)
    return parsed.scheme, parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80)


def request_probe(payload):
    start = time.monotonic()
    deadline = start + payload["timeout"]
    url, method, headers = payload["url"], payload["method"], payload["headers"].copy()
    body = None if payload["body"] is None else base64.b64decode(payload["body"])
    result = {
        "requested_url": safe_url(url),
        "final_url": safe_url(url),
        "method": method,
        "status_code": None,
        "redirects": [],
        "error": None,
        "downloaded_bytes": 0,
        "response_size_bytes": None,
        "truncated": False,
        "body_excerpt": None,
    }
    try:
        while True:
            parsed = urlsplit(url)
            scheme, host, port = origin(url)
            channel = connect(host, port, deadline)
            peer = channel.getpeername()[0]
            restricted = not ipaddress.ip_address(peer).is_global
            connection = http.client.HTTPConnection(host, port)
            try:
                if scheme == "https":
                    channel.settimeout(remaining(deadline))
                    channel = ssl.create_default_context().wrap_socket(
                        channel, server_hostname=host
                    )
                connection.sock = channel
                channel.settimeout(remaining(deadline))
                outgoing = {"Accept-Encoding": "identity", **headers}
                path = parsed.path or "/"
                if parsed.query:
                    path += "?" + parsed.query
                connection.request(method, path, body=body, headers=outgoing)
                channel.settimeout(remaining(deadline))
                response = connection.getresponse()
                result.update(
                    final_url=safe_url(url),
                    final_method=method,
                    status_code=response.status,
                    peer_ip=peer,
                    peer_global=not restricted,
                )
                sensitive = payload["sensitive"] or restricted or bool(parsed.query)
                result["response_headers"] = {
                    k: (
                        "[redacted]"
                        if sensitive
                        or k.lower()
                        not in {
                            "content-type",
                            "content-length",
                            "content-encoding",
                            "server",
                            "date",
                        }
                        else v[:512]
                    )
                    for k, v in response.getheaders()
                }
                result["content_type"] = (
                    "[redacted]" if sensitive else response.getheader("Content-Type", "")[:256]
                )
                location = response.getheader("Location")
                if response.status in {301, 302, 303, 307, 308} and location:
                    next_url = target_url(urljoin(url, location))
                    result["redirects"].append(
                        {
                            "status_code": response.status,
                            "from": safe_url(url),
                            "to": safe_url(next_url),
                        }
                    )
                    if payload["allow_redirects"]:
                        if len(result["redirects"]) > payload["max_redirects"]:
                            result["error"] = {
                                "type": "redirect_limit",
                                "message": "Redirect limit.",
                            }
                            break
                        if origin(url) != origin(next_url):
                            if body is not None and response.status in {307, 308}:
                                result["error"] = {
                                    "type": "redirect_credentials",
                                    "message": "Cross-origin body replay refused.",
                                }
                                break
                            headers = {}
                            result["cross_origin_credentials_stripped"] = True
                        if (response.status == 303 and method != "HEAD") or (
                            response.status in {301, 302} and method == "POST"
                        ):
                            method, body = "GET", None
                            headers = {
                                k: v for k, v in headers.items() if k.lower() != "content-type"
                            }
                        url = next_url
                        continue
                declared = response.getheader("Content-Length", "")
                result["response_size_bytes"] = int(declared) if declared.isdigit() else None
                if sensitive:
                    result["body_excerpt"] = "[suppressed: request data or non-global destination]"
                    result["body_suppressed"] = True
                    break
                chunks, downloaded = [], 0
                while downloaded < MAX_DOWNLOAD and not response.isclosed():
                    channel.settimeout(remaining(deadline))
                    chunk = response.read1(min(8192, MAX_DOWNLOAD - downloaded))
                    if not chunk:
                        break
                    downloaded += len(chunk)
                    result["downloaded_bytes"] = downloaded
                    if sum(map(len, chunks)) < MAX_PREVIEW:
                        chunks.append(chunk[: MAX_PREVIEW - sum(map(len, chunks))])
                result["truncated"] = downloaded == MAX_DOWNLOAD
                excerpt = b"".join(chunks)
                if response.getheader("Content-Encoding", "identity").lower() != "identity":
                    result["body_excerpt"] = "[encoded body omitted; no decompression]"
                elif result["content_type"].startswith(("text/", "application/json")):
                    result["body_excerpt"] = excerpt.decode("utf-8", errors="replace")
                else:
                    result["body_excerpt"] = "[binary body omitted]"
                result["excerpt_truncated"] = downloaded > MAX_PREVIEW
                break
            finally:
                connection.close()
                channel.close()
    except (OSError, http.client.HTTPException, ValueError) as error:
        result["error"] = classified(error)
    result["elapsed_ms"] = round((time.monotonic() - start) * 1000, 2)
    result["ok"] = result["error"] is None
    return result


def network_probe(action, payload):
    start = time.monotonic()
    result = {"host": payload["host"], "error": None}
    try:
        if action == "dns":
            result["addresses"] = addresses(payload["host"], 443)
        else:
            result["port"] = payload["port"]
            with connect(payload["host"], payload["port"], start + payload["timeout"]) as channel:
                result["peer_ip"] = channel.getpeername()[0]
                result["connected"] = True
                if action == "tls":
                    channel.settimeout(remaining(start + payload["timeout"]))
                    with ssl.create_default_context().wrap_socket(
                        channel, server_hostname=payload["host"]
                    ) as secure:
                        cert = secure.getpeercert()
                        result.update(
                            tls_version=secure.version(),
                            cipher=secure.cipher()[0],
                            certificate_sha256=hashlib.sha256(
                                secure.getpeercert(binary_form=True)
                            ).hexdigest(),
                            certificate={
                                k: cert.get(k)
                                for k in (
                                    "subject",
                                    "issuer",
                                    "notBefore",
                                    "notAfter",
                                    "subjectAltName",
                                )
                            },
                            certificate_verified=True,
                        )
    except (OSError, ValueError) as error:
        result["error"] = classified(error)
    result["elapsed_ms"] = round((time.monotonic() - start) * 1000, 2)
    result["ok"] = result["error"] is None
    return result


def main():
    try:
        raw = sys.stdin.buffer.read(65537)
        if len(raw) > 65536:
            raise ValueError
        message = json.loads(raw)
        action, payload = message["action"], message["payload"]
        if action == "request":
            result = request_probe(payload)
        elif action in {"dns", "tls", "tcp"}:
            hostname(payload["host"])
            result = network_probe(action, payload)
        else:
            raise ValueError
    except Exception:
        result = {"ok": False, "error": {"type": "probe_failure", "message": "Probe failed."}}
    sys.stdout.write(json.dumps(result, allow_nan=False))


if __name__ == "__main__":
    main()
