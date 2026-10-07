import contextlib
import json
import socket
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from app import app, probes, routes, worker
from app.validation import MAX_DOWNLOAD, hostname, http_payload, safe_url, target_url

TOKEN = "synthetic-test-token-0123456789abcdef"


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("NETWORK_PROBE_TOKEN", TOKEN)
    routes.CALLS.clear()
    return app.test_client()


class Peer(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/")
            self.end_headers()
            return
        if self.path == "/loop":
            self.send_response(302)
            self.send_header("Location", "/loop")
            self.end_headers()
            return
        if self.path == "/slow":
            time.sleep(0.7)
        content = b"x" * (MAX_DOWNLOAD + 8192) if self.path == "/large" else b"synthetic body"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Set-Cookie", "synthetic-secret-cookie")
        self.end_headers()
        with contextlib.suppress(OSError):
            self.wfile.write(content)

    def do_POST(self):
        self.do_GET()


@pytest.fixture
def peer():
    server = ThreadingHTTPServer(("127.0.0.1", 0), Peer)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()
    server.server_close()
    thread.join()


def test_fail_closed_and_health(client, monkeypatch):
    assert client.get("/health").json == {"status": "ok"}
    assert client.get("/network/ip").status_code == 401
    monkeypatch.delenv("NETWORK_PROBE_TOKEN")
    assert client.get("/network/ip", headers={"X-Probe-Token": TOKEN}).status_code == 503


@pytest.mark.parametrize(
    "field,value",
    [
        ("url", "file:///etc/passwd"),
        ("url", "http://user:secret@example.com"),
        ("url", "http://example.com\\@localhost/"),
        ("url", "http://example.com/\n"),
        ("timeout", 9),
        ("timeout", True),
        ("timeout", float("nan")),
        ("method", "CONNECT"),
        ("allow_redirects", "false"),
        ("max_redirects", 4),
        ("headers", {"Host": "localhost"}),
        ("headers", {"X-Key": "a\r\nb"}),
        ("headers", {"X-Probe-Token": "secret"}),
        ("body", "x" * 16385),
        ("unknown", 1),
        ("params", {"key": []}),
        ("api_key", {"header": "X-Key", "value": "a\n"}),
    ],
)
def test_validation(field, value):
    with pytest.raises(ValueError):
        http_payload({"url": "https://example.com/", field: value})


@pytest.mark.parametrize(
    "method", ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE"]
)
def test_methods(method):
    assert http_payload({"url": "https://example.com/", "method": method})["method"] == method


def test_auth_and_secret_safe_urls():
    payload = http_payload(
        {
            "url": "https://example.com/secret?key=secret",
            "json": {"x": "y"},
            "auth": {"username": "u", "password": "synthetic-password"},
        }
    )
    assert payload["sensitive"]
    assert "synthetic-password" not in safe_url(payload["url"])
    assert "secret" not in safe_url(payload["url"])
    with pytest.raises(ValueError):
        http_payload({"url": "https://example.com", "body": "x", "json": {}})
    with pytest.raises(ValueError):
        hostname("localhost%00")
    with pytest.raises(ValueError):
        target_url("http://example.com:0/")


def test_private_destination_suppresses_body(peer):
    result = probes.run("request", http_payload({"url": peer + "/"}))
    assert result["status_code"] == 200
    assert result["body_suppressed"] and result["downloaded_bytes"] == 0
    assert "synthetic-secret-cookie" not in json.dumps(result)
    assert "synthetic body" not in json.dumps(result)


def test_redirect_and_loop(peer):
    result = probes.run("request", http_payload({"url": peer + "/redirect"}))
    assert result["status_code"] == 200 and len(result["redirects"]) == 1
    result = probes.run("request", http_payload({"url": peer + "/loop", "max_redirects": 1}))
    assert result["error"]["type"] == "redirect_limit"
    result = probes.run(
        "request", http_payload({"url": peer + "/redirect", "allow_redirects": False})
    )
    assert result["status_code"] == 302 and result["error"] is None


def test_byte_cap_for_public_peer_simulation(peer, monkeypatch):
    original = worker.ipaddress.ip_address

    class Global:
        is_global = True

    monkeypatch.setattr(
        worker.ipaddress,
        "ip_address",
        lambda value: Global() if value == "127.0.0.1" else original(value),
    )
    result = worker.request_probe(http_payload({"url": peer + "/large"}))
    assert result["downloaded_bytes"] == MAX_DOWNLOAD and result["truncated"]
    assert len(result["body_excerpt"]) == 2048
    assert "synthetic-secret-cookie" not in json.dumps(result)


def test_credentials_suppress_echo(peer):
    marker = "synthetic-secret-marker"
    result = probes.run(
        "request",
        http_payload(
            {"url": peer + "/", "method": "POST", "headers": {"X-Key": marker}, "body": marker}
        ),
    )
    assert result["status_code"] == 200 and marker not in json.dumps(result)
    assert result["body_suppressed"]


def test_timeout_refusal_dns_tls(peer):
    result = probes.run("request", http_payload({"url": peer + "/slow", "timeout": 0.1}))
    assert result["error"]["type"] == "timeout"
    result = probes.run("dns", {"host": "localhost", "timeout": 2})
    assert result["ok"] and result["addresses"]
    with socket.socket() as channel:
        channel.bind(("127.0.0.1", 0))
        closed_port = channel.getsockname()[1]
    result = probes.run("tcp", {"host": "127.0.0.1", "port": closed_port, "timeout": 0.3})
    # Windows can silently drop a closed-port SYN before reporting a refusal.
    assert result["error"]["type"] in {"connection_refused", "timeout"}
    result = probes.run(
        "tls", {"host": "127.0.0.1", "port": int(peer.rsplit(":", 1)[1]), "timeout": 0.3}
    )
    assert result["error"]["type"] in {"tls", "timeout"}


def test_all_routes_and_limits(client, monkeypatch):
    monkeypatch.setattr(
        probes, "run", lambda action, payload: {"ok": True, "action": action, "payload": payload}
    )
    headers = {"X-Probe-Token": TOKEN}
    for path in (
        "/network/dns?hostname=example.com",
        "/network/tls?host=example.com",
        "/network/tcp?host=example.com",
        "/network/egress",
        "/network/ip",
    ):
        assert client.get(path, headers=headers).status_code == 200
    assert len(client.get("/network/egress", headers=headers).json["tests"]) == 3
    assert (
        client.post("/request", json={"url": "https://example.com"}, headers=headers).status_code
        == 200
    )
    assert client.get("/network/tcp?host=localhost&port=0", headers=headers).status_code == 400
    assert (
        client.post(
            "/request", data=b"x" * 65537, content_type="application/json", headers=headers
        ).status_code
        == 413
    )
    routes.CALLS[:] = [time.monotonic()] * 30
    assert client.get("/network/ip", headers=headers).status_code == 429
    assert client.get("/health").status_code == 200


def test_dns_error_classification():
    assert worker.classified(socket.gaierror()) == {"type": "dns", "message": "Probe failed: dns."}


def test_hard_deadline_kills_and_reaps(monkeypatch):
    class Child:
        returncode = None
        killed = False
        calls = 0

        def communicate(self, *args, **kwargs):
            self.calls += 1
            if self.calls == 1:
                raise subprocess.TimeoutExpired("synthetic", 0.1)
            return b"", b""

        def kill(self):
            self.killed = True

    child = Child()
    captured = {}

    def spawn(*args, **kwargs):
        captured.update(kwargs)
        return child

    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "synthetic-aws-secret")
    monkeypatch.setenv("NETWORK_PROBE_TOKEN", TOKEN)
    monkeypatch.setattr(probes.subprocess, "Popen", spawn)
    result = probes.run("dns", {"host": "example.com", "timeout": 0.1})
    assert result["error"]["type"] == "timeout" and child.killed and child.calls == 2
    assert "AWS_SECRET_ACCESS_KEY" not in captured["env"]
    assert "NETWORK_PROBE_TOKEN" not in captured["env"]


@pytest.mark.parametrize(
    "status,method,body,expected_method",
    [
        (302, "POST", "secret-body", "GET"),
        (303, "PUT", "secret-body", "GET"),
        (307, "GET", None, "GET"),
        (308, "POST", "secret-body", None),
    ],
)
def test_cross_origin_secret_redirects(monkeypatch, status, method, body, expected_method):
    calls = []

    class Channel:
        def settimeout(self, _value):
            pass

        def getpeername(self):
            return ("93.184.215.14", 80)

        def close(self):
            pass

    class Response:
        def __init__(self, first):
            self.status = status if first else 200
            self.first = first

        def getheader(self, name, default=None):
            if self.first and name == "Location":
                return "http://second.example/"
            return default

        def getheaders(self):
            return [("Set-Cookie", "synthetic-echo-secret")]

    class Connection:
        def __init__(self, *_args):
            self.sock = None

        def request(self, method, path, body, headers):
            calls.append({"method": method, "headers": headers, "body": body})

        def getresponse(self):
            return Response(len(calls) == 1)

        def close(self):
            pass

    monkeypatch.setattr(worker, "connect", lambda *_args: Channel())
    monkeypatch.setattr(worker.http.client, "HTTPConnection", Connection)
    data = {
        "url": "http://first.example/",
        "method": method,
        "headers": {"Authorization": "Bearer synthetic-echo-secret"},
    }
    if body is not None:
        data["body"] = body
    result = worker.request_probe(http_payload(data))
    assert "synthetic-echo-secret" not in json.dumps(result)
    if expected_method is None:
        assert len(calls) == 1 and result["error"]["type"] == "redirect_credentials"
    else:
        assert len(calls) == 2 and calls[1]["method"] == expected_method
        assert "Authorization" not in calls[1]["headers"] and calls[1]["body"] is None
