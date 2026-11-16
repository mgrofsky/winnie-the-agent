"""Outbound connectors: validation, caps, secrets, sanitising and failure handling.
No test touches the network; transport, resolver and SMTP are fakes."""

from __future__ import annotations

import configparser
import io
import json
import socket
import ssl

import pytest

from agents.connectors import Connectors
from agents.connectors.base import Notification
from agents.connectors.enrich import sanitise
from agents.connectors.base import DestinationError, pin_address
from agents.connectors.email import PinnedSMTP
from agents.connectors.http import (MAX_RESPONSE_BYTES, PinnedHTTPSConnection, ResponseTooLarge,
                                    UrlTransport)

pytestmark = pytest.mark.usefixtures("public_test_net")

SECRET = "s3cr3t-token-value-XYZ"


class FakeTransport:
    def __init__(self, status=200, body=b"{}", exc=None):
        self.calls = []
        self.status, self.body, self.exc = status, body, exc

    def request(self, method, url, headers, body, timeout, address):
        self.calls.append({"method": method, "url": url, "headers": dict(headers),
                           "body": body, "timeout": timeout, "address": address})
        if self.exc is not None:
            raise self.exc
        return self.status, self.body


def public_resolver(host, port, proto=0):
    return [(socket.AF_INET, socket.SOCK_STREAM, proto, "", ("198.51.100.34", port))]


def private_resolver(host, port, proto=0):
    return [(socket.AF_INET, socket.SOCK_STREAM, proto, "", ("10.1.2.3", port))]


class FakeSMTP:
    instances: list["FakeSMTP"] = []

    def __init__(self, host, port, timeout, address=None):
        self.host, self.port, self.timeout, self.address = host, port, timeout, address
        self.tls_context = None
        self.log = []
        self.messages = []
        FakeSMTP.instances.append(self)

    def ehlo(self):
        self.log.append("ehlo")

    def starttls(self, context=None):
        self.log.append("starttls")
        self.tls_context = context

    def login(self, user, password):
        self.log.append(("login", user))

    def send_message(self, msg, from_addr=None, to_addrs=None):
        self.messages.append((msg, from_addr, to_addrs))

    def quit(self):
        self.log.append("quit")


def make_config(sections: dict[str, dict[str, str]]) -> configparser.ConfigParser:
    cfg = configparser.ConfigParser()
    for name, values in sections.items():
        cfg[name] = values
    return cfg


def note(**kw) -> Notification:
    base = dict(playbook="honeytoken_reuse", title="Honeytoken reused",
                summary="Token from mysql reused over ssh", record_id="r-1",
                source="203.0.113.9", protocol="ssh", judgement="malicious", stage="actions",
                details={"token": "AKIA-FAKE", "urls": ["http://x.example/a"]})
    base.update(kw)
    return Notification(**base)


def http_section(url="https://hooks.example.com/x", **extra):
    values = {"enabled": "true", "url": url}
    values.update(extra)
    return values


def build(tmp_path, sections, transport=None, resolver=public_resolver, smtp_factory=None):
    transport = transport or FakeTransport()
    c = Connectors(make_config(sections), tmp_path, transport=transport,
                   smtp_factory=smtp_factory, resolver=resolver)
    return c, transport


# --- disabled -----------------------------------------------------------------------------

def test_missing_or_disabled_connectors_make_no_call(tmp_path):
    c, t = build(tmp_path, {"connector.webhook": {"enabled": "false",
                                                  "url": "https://hooks.example.com/x"}})
    assert not c.enabled("webhook")
    assert c.notify("webhook", note()).status == "disabled"
    assert c.notify("siem_http", note()).status == "disabled"
    assert c.notify("email", note()).status == "disabled"
    assert c.enrich("203.0.113.9").status == "disabled"
    assert c.open_ticket({"title": "x"}).status == "disabled"
    assert c.block("203.0.113.9", "r").status == "disabled"
    assert t.calls == []
    assert c.errors == []


def test_enabled_defaults_to_false(tmp_path):
    c, t = build(tmp_path, {"connector.webhook": {"url": "https://hooks.example.com/x"}})
    assert not c.enabled("webhook")
    assert c.notify("webhook", note()).ok is False
    assert t.calls == []


def test_unknown_notify_name_is_an_error_not_a_call(tmp_path):
    c, t = build(tmp_path, {"connector.webhook": http_section()})
    assert c.notify("enrich", note()).status == "error: unknown_connector"
    assert t.calls == []


# --- destination validation ---------------------------------------------------------------

@pytest.mark.parametrize("url", [
    "http://hooks.example.com/x",
    "https://10.0.0.5/x",
    "https://127.0.0.1/x",
    "https://169.254.169.254/latest/meta-data",
    "https://[::1]/x",
    "https://192.168.1.1/x",
    "https://localhost/x",
    "https://user:pw@hooks.example.com/x",
    "ftp://hooks.example.com/x",
])
def test_bad_destinations_refused_at_load(tmp_path, url):
    c, t = build(tmp_path, {"connector.webhook": http_section(url)})
    assert not c.enabled("webhook")
    assert len(c.errors) == 1 and "connector.webhook" in c.errors[0]
    assert "pw" not in c.errors[0]
    assert c.notify("webhook", note()).status == "disabled"
    assert t.calls == []


def test_private_literal_accepted_with_allow_private(tmp_path):
    c, t = build(tmp_path, {"connector.webhook": http_section("https://10.0.0.5/x",
                                                              allow_private="true")},
                 resolver=private_resolver)
    assert c.errors == []
    assert c.notify("webhook", note()).status == "sent"
    assert len(t.calls) == 1


def test_http_still_refused_with_allow_private(tmp_path):
    c, _ = build(tmp_path, {"connector.webhook": http_section("http://10.0.0.5/x",
                                                              allow_private="true")})
    assert not c.enabled("webhook") and c.errors


def test_public_name_resolving_to_private_refused_at_send(tmp_path):
    c, t = build(tmp_path, {"connector.siem_http": http_section("https://collector.example.com/")},
                 resolver=private_resolver)
    assert c.enabled("siem_http")
    r = c.notify("siem_http", note())
    assert r.ok is False and r.status == "error: DestinationError"
    assert t.calls == []


def test_one_bad_connector_does_not_disable_others(tmp_path):
    c, _ = build(tmp_path, {"connector.webhook": http_section("http://x.example.com/"),
                            "connector.siem_http": http_section("https://c.example.com/"),
                            "connector.bogus": {"enabled": "true"}})
    assert not c.enabled("webhook") and c.enabled("siem_http")
    assert len(c.errors) == 2


@pytest.mark.parametrize("extra", [{"timeout": "31"}, {"timeout": "0"}, {"timeout": "x"},
                                   {"max_per_day": "-1"}, {"secret_env": "not a name!"},
                                   {"enabled": "maybe"}])
def test_bad_limits_refused(tmp_path, extra):
    c, _ = build(tmp_path, {"connector.webhook": http_section(**extra)})
    assert not c.enabled("webhook") and c.errors


def test_secret_env_value_not_echoed_in_errors(tmp_path):
    c, _ = build(tmp_path, {"connector.webhook": http_section(secret_env=f"{SECRET} oops")})
    assert c.errors and SECRET not in " ".join(c.errors)


# --- payloads -----------------------------------------------------------------------------

def test_webhook_payload_and_timeout(tmp_path):
    c, t = build(tmp_path, {"connector.webhook": http_section(timeout="5")})
    r = c.notify("webhook", note())
    assert r.ok and r.status == "sent"
    call = t.calls[0]
    assert call["method"] == "POST" and call["timeout"] == 5.0
    body = json.loads(call["body"])
    assert body["text"] == "Honeytoken reused: Token from mysql reused over ssh"
    assert body["event"]["record_id"] == "r-1"
    assert call["headers"]["Content-Type"] == "application/json"


def test_siem_event_shape(tmp_path):
    c, t = build(tmp_path, {"connector.siem_http": http_section("https://c.example.com/ingest")})
    assert c.notify("siem_http", note()).ok
    event = json.loads(t.calls[0]["body"])
    assert event["source"] == "winnie"
    assert event["@timestamp"].endswith("Z")
    assert event["event"]["playbook"] == "honeytoken_reuse"


def test_ticket_and_block_payloads(tmp_path):
    c, t = build(tmp_path, {"connector.ticket": http_section("https://t.example.com/new"),
                            "connector.block_webhook": http_section("https://fw.example.com/b")})
    r = c.open_ticket({"title": "T\r\nInjected: 1", "summary": "s", "priority": "high",
                       "source": "winnie", "record_id": "r-9", "extra": "dropped"})
    assert r.ok
    body = json.loads(t.calls[0]["body"])
    assert set(body) == {"title", "summary", "priority", "source", "record_id"}
    assert "\n" not in body["title"]
    assert c.block("203.0.113.9", "honeytoken reuse").ok
    assert json.loads(t.calls[1]["body"]) == {"ip": "203.0.113.9", "reason": "honeytoken reuse"}
    assert c.block("not-an-ip", "x").status == "error: invalid_ip"
    assert len(t.calls) == 2


def test_block_accepts_ipv6_network_keys(tmp_path):
    c, t = build(tmp_path, {"connector.block_webhook": http_section("https://fw.example.com/b")})
    assert c.block("2001:db8:1:2::/64", "noisy").ok
    assert json.loads(t.calls[0]["body"]) == {"network": "2001:db8:1:2::/64", "reason": "noisy"}
    assert c.block("2001:db8:1:2::/64\nx", "noisy").status == "error: invalid_ip"
    assert c.block("10.0.0.0/8", "x").status == "error: invalid_ip"     # only IPv6 /64 keys
    assert len(t.calls) == 1


# --- responses and failures ---------------------------------------------------------------

@pytest.mark.parametrize("status", [301, 302, 307, 308])
def test_redirect_responses_are_errors(tmp_path, status):
    c, t = build(tmp_path, {"connector.webhook": http_section()},
                 transport=FakeTransport(status=status))
    r = c.notify("webhook", note())
    assert r.ok is False and r.status == f"error: redirect_{status}"
    assert len(t.calls) == 1


def test_http_error_status(tmp_path):
    c, _ = build(tmp_path, {"connector.webhook": http_section()},
                 transport=FakeTransport(status=500))
    assert c.notify("webhook", note()).status == "error: http_500"


@pytest.mark.parametrize("exc", [TimeoutError("t"), ConnectionResetError(),
                                 OSError("boom"), RuntimeError(SECRET)])
def test_transport_exceptions_become_error_results(tmp_path, monkeypatch, exc):
    monkeypatch.setenv("HOOK_TOKEN", SECRET)
    c, _ = build(tmp_path, {"connector.webhook": http_section(secret_env="HOOK_TOKEN")},
                 transport=FakeTransport(exc=exc))
    r = c.notify("webhook", note())
    assert r.ok is False and r.status == f"error: {type(exc).__name__}"
    assert SECRET not in repr(r)


def test_resolver_failure_is_error_result(tmp_path):
    def failing(host, port, proto=0):
        raise socket.gaierror("nope")
    c, t = build(tmp_path, {"connector.webhook": http_section()}, resolver=failing)
    assert c.notify("webhook", note()).status == "error: DestinationError"
    assert t.calls == []


# --- caps ---------------------------------------------------------------------------------

def test_daily_cap_stops_calls_and_persists(tmp_path):
    sections = {"connector.webhook": http_section(max_per_day="2")}
    c, t = build(tmp_path, sections)
    assert c.notify("webhook", note()).ok
    assert c.notify("webhook", note()).ok
    assert c.notify("webhook", note()).status == "cap_reached"
    assert len(t.calls) == 2
    assert (tmp_path / "connector_webhook.json").exists()
    c2, t2 = build(tmp_path, sections)
    assert c2.notify("webhook", note()).status == "cap_reached"
    assert t2.calls == []


def test_caps_are_per_connector(tmp_path):
    c, t = build(tmp_path, {"connector.webhook": http_section(max_per_day="1"),
                            "connector.siem_http": http_section("https://c.example.com/",
                                                                max_per_day="1")})
    assert c.notify("webhook", note()).ok
    assert c.notify("siem_http", note()).ok
    assert c.notify("webhook", note()).status == "cap_reached"


# --- secrets ------------------------------------------------------------------------------

def test_secret_read_from_env_by_name_and_never_in_results(tmp_path, monkeypatch):
    monkeypatch.setenv("HOOK_TOKEN", SECRET)
    c, t = build(tmp_path, {"connector.webhook": http_section(secret_env="HOOK_TOKEN")})
    r = c.notify("webhook", note())
    assert r.ok
    assert t.calls[0]["headers"]["Authorization"] == f"Bearer {SECRET}"
    assert SECRET not in repr(r) and SECRET not in " ".join(c.errors)
    assert SECRET not in t.calls[0]["body"].decode()


def test_missing_secret_makes_no_call(tmp_path, monkeypatch):
    monkeypatch.delenv("HOOK_TOKEN", raising=False)
    c, t = build(tmp_path, {"connector.webhook": http_section(secret_env="HOOK_TOKEN")})
    assert c.notify("webhook", note()).status == "error: secret_missing"
    assert t.calls == []


def test_enrich_custom_header_carries_raw_key(tmp_path, monkeypatch):
    monkeypatch.setenv("INTEL_KEY", SECRET)
    c, t = build(tmp_path, {"connector.enrich": http_section(
        "https://intel.example.com/v1/ip/{ip}", secret_env="INTEL_KEY", header="X-Api-Key")},
        transport=FakeTransport(body=b'{"score": 90}'))
    r = c.enrich("203.0.113.9")
    assert r.ok and r.data == {"score": 90}
    assert t.calls[0]["headers"]["X-Api-Key"] == SECRET
    assert SECRET not in repr(r)


# --- enrich -------------------------------------------------------------------------------

def test_enrich_url_template_encodes_ip(tmp_path):
    c, t = build(tmp_path, {"connector.enrich": http_section(
        "https://intel.example.com/check?ip={ip}")})
    assert c.enrich("2001:db8::1").ok
    assert t.calls[0]["url"] == "https://intel.example.com/check?ip=2001%3Adb8%3A%3A1"
    assert t.calls[0]["method"] == "GET"
    assert c.enrich("203.0.113.4/../../admin").status == "error: invalid_ip"
    assert len(t.calls) == 1


@pytest.mark.parametrize("url", ["https://intel.example.com/check",
                                 "https://{ip}.intel.example.com/",
                                 "http://intel.example.com/{ip}",
                                 "https://10.0.0.1/{ip}"])
def test_enrich_bad_templates_refused_at_load(tmp_path, url):
    c, _ = build(tmp_path, {"connector.enrich": http_section(url)})
    assert not c.enabled("enrich") and c.errors


def test_enrich_sanitises_hostile_response(tmp_path):
    deep: dict = {"leaf": "bottom"}
    for _ in range(50):
        deep = {"n": deep}
    hostile = {
        "huge": "A" * 10000,
        "ctrl": "evil\x1b[31m\r\nInjected: yes\x00",
        "k" * 500: "long key",
        "deep": deep,
        "nested": {"a": {"b": {"c": 1}}},
        "list": [1, "two", None, {"x": True}],
        "none": None,
        "many": {f"f{i}": i for i in range(200)},
    }
    body = json.dumps(hostile).encode()
    assert len(body) < MAX_RESPONSE_BYTES
    c, _ = build(tmp_path, {"connector.enrich": http_section("https://i.example.com/{ip}")},
                 transport=FakeTransport(body=body))
    r = c.enrich("203.0.113.9")
    assert r.ok
    data = r.data
    assert len(data) <= 32
    for k, v in data.items():
        assert isinstance(k, str) and len(k) <= 128
        assert isinstance(v, (str, int, float, bool))
        if isinstance(v, str):
            assert len(v) <= 128
            assert all(ch.isprintable() for ch in v)
        assert all(ch.isprintable() for ch in k)
    assert data["huge"] == "A" * 128
    assert "\x1b" not in data["ctrl"] and "\n" not in data["ctrl"]
    assert data["nested.a.b.c"] == 1
    assert "none" not in data
    assert not any(k.startswith("deep.n.n.n.n.n.n.n.n") for k in data)


def test_sanitise_non_finite_and_huge_numbers():
    out = sanitise({"nan": float("nan"), "big": 10 ** 40, "ok": 1.5, "b": False})
    assert out == {"ok": 1.5, "b": False}


@pytest.mark.parametrize("body", [b"not json", b"\xff\xfe", b"[" * 100000,
                                  b'{"a": "' + b"x" * (MAX_RESPONSE_BYTES + 10) + b'"}'])
def test_enrich_rejects_non_json_and_oversized(tmp_path, body):
    c, _ = build(tmp_path, {"connector.enrich": http_section("https://i.example.com/{ip}")},
                 transport=FakeTransport(body=body))
    r = c.enrich("203.0.113.9")
    assert r.ok is False and r.status.startswith("error:")
    assert r.data == {}


# --- email --------------------------------------------------------------------------------

def email_section(**extra):
    values = {"enabled": "true", "host": "smtp.example.com", "port": "587",
              "from": "winnie@example.com", "to": "soc@example.com, oncall@example.com"}
    values.update(extra)
    return values


def test_email_sends_plain_text_with_starttls(tmp_path, monkeypatch):
    monkeypatch.setenv("SMTP_USER", "relay-user")
    monkeypatch.setenv("SMTP_PASS", SECRET)
    FakeSMTP.instances.clear()
    c, t = build(tmp_path, {"connector.email": email_section(username_env="SMTP_USER",
                                                             password_env="SMTP_PASS")},
                 smtp_factory=FakeSMTP)
    r = c.notify("email", note())
    assert r.ok and r.status == "sent"
    smtp = FakeSMTP.instances[-1]
    assert (smtp.host, smtp.port, smtp.timeout) == ("smtp.example.com", 587, 10.0)
    assert smtp.address == "198.51.100.34"
    assert smtp.tls_context.verify_mode == ssl.CERT_REQUIRED
    assert smtp.tls_context.check_hostname is True
    assert smtp.log.index("starttls") < smtp.log.index(("login", "relay-user"))
    msg, sender, rcpts = smtp.messages[0]
    assert msg["Subject"] == "Honeytoken reused"
    assert msg.get_content_type() == "text/plain"
    assert "Token from mysql reused over ssh" in msg.get_content()
    assert rcpts == ["soc@example.com", "oncall@example.com"]
    assert SECRET not in repr(r) and SECRET not in msg.as_string()
    assert t.calls == []


def test_email_refuses_credentials_without_starttls(tmp_path, monkeypatch):
    monkeypatch.setenv("SMTP_USER", "u")
    monkeypatch.setenv("SMTP_PASS", SECRET)
    FakeSMTP.instances.clear()
    c, _ = build(tmp_path, {"connector.email": email_section(
        starttls="false", username_env="SMTP_USER", password_env="SMTP_PASS")},
        smtp_factory=FakeSMTP)
    assert not c.enabled("email")
    assert any("starttls" in e for e in c.errors)
    assert c.notify("email", note()).status == "disabled"
    assert FakeSMTP.instances == []


def test_email_without_credentials_may_skip_starttls(tmp_path):
    FakeSMTP.instances.clear()
    c, _ = build(tmp_path, {"connector.email": email_section(starttls="false")},
                 smtp_factory=FakeSMTP)
    assert c.notify("email", note()).ok
    assert "starttls" not in FakeSMTP.instances[-1].log


def test_email_starttls_failure_never_logs_in(tmp_path, monkeypatch):
    monkeypatch.setenv("SMTP_USER", "u")
    monkeypatch.setenv("SMTP_PASS", SECRET)

    class NoTls(FakeSMTP):
        def starttls(self, context=None):
            raise RuntimeError("STARTTLS extension not supported by server")

    FakeSMTP.instances.clear()
    c, _ = build(tmp_path, {"connector.email": email_section(username_env="SMTP_USER",
                                                             password_env="SMTP_PASS")},
                 smtp_factory=NoTls)
    r = c.notify("email", note())
    assert r.status == "error: RuntimeError"
    smtp = FakeSMTP.instances[-1]
    assert not any(isinstance(x, tuple) and x[0] == "login" for x in smtp.log)
    assert "quit" in smtp.log


@pytest.mark.parametrize("extra", [{"host": "127.0.0.1"}, {"host": "localhost"},
                                   {"host": "smtp.example.com/evil"},
                                   {"to": "a@example.com\r\nBcc: x@evil.example"},
                                   {"to": ""}, {"from": "not-an-address"},
                                   {"username_env": "SMTP_USER"}])
def test_email_bad_config_refused(tmp_path, extra):
    c, _ = build(tmp_path, {"connector.email": email_section(**extra)}, smtp_factory=FakeSMTP)
    assert not c.enabled("email") and c.errors


def test_email_host_resolving_private_refused(tmp_path):
    FakeSMTP.instances.clear()
    c, _ = build(tmp_path, {"connector.email": email_section()}, smtp_factory=FakeSMTP,
                 resolver=private_resolver)
    assert c.notify("email", note()).status == "error: DestinationError"
    assert FakeSMTP.instances == []


def test_email_cap(tmp_path):
    c, _ = build(tmp_path, {"connector.email": email_section(max_per_day="1")},
                 smtp_factory=FakeSMTP)
    assert c.notify("email", note()).ok
    assert c.notify("email", note()).status == "cap_reached"


def test_email_smtp_factory_exception(tmp_path):
    def boom(host, port, timeout, address=None):
        raise ConnectionRefusedError()
    c, _ = build(tmp_path, {"connector.email": email_section()}, smtp_factory=boom)
    assert c.notify("email", note()).status == "error: ConnectionRefusedError"


# --- address pinning ----------------------------------------------------------------------
#
# The host name is resolved once per call; the connection goes to that validated address
# and the name is used only for TLS (SNI, certificate hostname) and the Host header. These
# tests use a resolver whose answer changes from public to private after the first lookup.

PUBLIC_IP = "198.51.100.34"
PRIVATE_IP = "10.1.2.3"


class RebindingResolver:
    """Public answer on the first lookup, private answer on every later one."""

    def __init__(self):
        self.calls = []

    def __call__(self, host, port, *args, **kw):
        self.calls.append((host, port))
        ip = PUBLIC_IP if len(self.calls) == 1 else PRIVATE_IP
        return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, port))]


class FakeSocket:
    """Socket stand-in: records bytes sent and replays a scripted server byte stream."""

    def __init__(self, incoming: bytes):
        self.sent = b""
        self.stream = io.BytesIO(incoming)
        self.closed = False

    def sendall(self, data):
        self.sent += bytes(data)

    def makefile(self, mode="rb", *args, **kw):
        return self.stream

    def close(self):
        self.closed = True


class FakeTlsContext:
    """Records the server_hostname used for each TLS wrap and returns the same socket."""

    verify_mode = ssl.CERT_REQUIRED
    check_hostname = True

    def __init__(self):
        self.server_hostnames = []

    def wrap_socket(self, sock, server_hostname=None, **kw):
        self.server_hostnames.append(server_hostname)
        return sock


class FakeNetwork:
    """``create_connection`` stand-in that records every address it is asked to reach."""

    def __init__(self, incoming: bytes):
        self.incoming = incoming
        self.connects = []
        self.sockets = []

    def __call__(self, address, timeout=None, source_address=None):
        self.connects.append((address, timeout))
        sock = FakeSocket(self.incoming)
        self.sockets.append(sock)
        return sock


def http_reply(status=200, body=b"{}", extra=b""):
    return (f"HTTP/1.1 {status} X\r\nContent-Length: {len(body)}\r\n".encode() + extra
            + b"\r\n" + body)


class RecordingFactory:
    """Connection factory for ``UrlTransport`` that builds a real ``PinnedHTTPSConnection``
    on a fake socket layer, and records the arguments the transport passed."""

    def __init__(self, reply: bytes):
        self.net = FakeNetwork(reply)
        self.tls = FakeTlsContext()
        self.calls = []

    def __call__(self, host, port, address, timeout, context):
        self.calls.append({"host": host, "port": port, "address": address,
                           "timeout": timeout, "context": context})
        return PinnedHTTPSConnection(host, port, address, timeout=timeout, context=self.tls,
                                     create_connection=self.net)


def test_pin_address_returns_validated_address():
    assert pin_address("hooks.example.com", 443, resolver=public_resolver) == PUBLIC_IP
    with pytest.raises(DestinationError):
        pin_address("hooks.example.com", 443, resolver=private_resolver)
    assert pin_address("hooks.example.com", 443, allow_private=True,
                       resolver=private_resolver) == PRIVATE_IP


def test_pin_address_rejects_any_private_answer():
    def mixed(host, port, proto=0):
        return [(socket.AF_INET, socket.SOCK_STREAM, proto, "", (PUBLIC_IP, port)),
                (socket.AF_INET, socket.SOCK_STREAM, proto, "", (PRIVATE_IP, port))]
    with pytest.raises(DestinationError):
        pin_address("hooks.example.com", 443, resolver=mixed)
    with pytest.raises(DestinationError):
        pin_address("hooks.example.com", 443, resolver=lambda h, p, proto=0: [])


def test_endpoint_resolves_once_and_passes_pinned_address(tmp_path):
    resolver = RebindingResolver()
    c, t = build(tmp_path, {"connector.webhook": http_section()}, resolver=resolver)
    assert c.notify("webhook", note()).ok
    assert resolver.calls == [("hooks.example.com", 443)]
    assert t.calls[0]["address"] == PUBLIC_IP
    assert t.calls[0]["url"] == "https://hooks.example.com/x"


def test_rebinding_answer_never_reaches_private_address(tmp_path, monkeypatch):
    resolver = RebindingResolver()
    # Any second lookup anywhere in the stack would see the private answer.
    monkeypatch.setattr(socket, "getaddrinfo", resolver)
    factory = RecordingFactory(http_reply(200, b"{}"))
    c = Connectors(make_config({"connector.webhook": http_section(
        "https://hooks.example.com:8443/x?a=1")}), tmp_path,
        transport=UrlTransport(connection_factory=factory), resolver=resolver)
    r = c.notify("webhook", note())
    assert r.ok and r.status == "sent"
    assert len(resolver.calls) == 1
    assert factory.net.connects == [((PUBLIC_IP, 8443), 10.0)]
    assert all(addr[0] != PRIVATE_IP for addr, _ in factory.net.connects)
    assert factory.tls.server_hostnames == ["hooks.example.com"]
    sent = factory.net.sockets[0].sent
    request_line, _, rest = sent.partition(b"\r\n")
    assert request_line == b"POST /x?a=1 HTTP/1.1"
    assert b"\r\nHost: hooks.example.com:8443\r\n" in b"\r\n" + rest
    assert PUBLIC_IP.encode() not in sent
    ctx = factory.calls[0]["context"]
    assert ctx.verify_mode == ssl.CERT_REQUIRED and ctx.check_hostname is True


def test_rebinding_on_later_send_is_refused(tmp_path):
    resolver = RebindingResolver()
    c, t = build(tmp_path, {"connector.webhook": http_section()}, resolver=resolver)
    assert c.notify("webhook", note()).ok
    assert c.notify("webhook", note()).status == "error: DestinationError"
    assert [call["address"] for call in t.calls] == [PUBLIC_IP]


def test_email_connects_to_pinned_address(tmp_path):
    resolver = RebindingResolver()
    FakeSMTP.instances.clear()
    c, _ = build(tmp_path, {"connector.email": email_section()}, smtp_factory=FakeSMTP,
                 resolver=resolver)
    assert c.notify("email", note()).ok
    smtp = FakeSMTP.instances[-1]
    assert (smtp.host, smtp.address) == ("smtp.example.com", PUBLIC_IP)
    assert resolver.calls == [("smtp.example.com", 587)]


def test_pinned_smtp_starttls_verifies_configured_name(monkeypatch):
    monkeypatch.setattr(socket, "getfqdn", lambda *a: "sensor.example.com")
    monkeypatch.setattr(socket, "getaddrinfo", RebindingResolver())
    net = FakeNetwork(b"220 relay ready\r\n250-relay\r\n250 STARTTLS\r\n220 go ahead\r\n")
    smtp = PinnedSMTP("smtp.example.com", 587, 5.0, PUBLIC_IP, create_connection=net)
    tls = FakeTlsContext()
    smtp.starttls(context=tls)
    assert net.connects == [((PUBLIC_IP, 587), 5.0)]
    assert tls.server_hostnames == ["smtp.example.com"]
    assert b"STARTTLS" in net.sockets[0].sent


# --- default transport --------------------------------------------------------------------

def test_default_transport_uses_verifying_tls_context():
    factory = RecordingFactory(http_reply(200, b"{}"))
    UrlTransport(connection_factory=factory).request("GET", "https://a.example.com/", {},
                                                     None, 5, PUBLIC_IP)
    call = factory.calls[0]
    assert (call["host"], call["port"], call["address"], call["timeout"]) == \
        ("a.example.com", 443, PUBLIC_IP, 5)
    assert call["context"].verify_mode == ssl.CERT_REQUIRED
    assert call["context"].check_hostname is True


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
def test_default_transport_does_not_follow_redirects(status):
    factory = RecordingFactory(http_reply(status, b"moved",
                                          b"Location: https://169.254.169.254/latest\r\n"))
    t = UrlTransport(connection_factory=factory)
    code, _ = t.request("GET", "https://a.example.com/", {}, None, 5, PUBLIC_IP)
    assert code == status
    assert len(factory.calls) == 1
    assert factory.net.connects == [((PUBLIC_IP, 443), 5)]


def test_default_transport_ok_and_size_cap():
    t = UrlTransport(connection_factory=RecordingFactory(http_reply(200, b'{"ok": 1}')))
    assert t.request("POST", "https://a.example.com/", {}, b"{}", 5, PUBLIC_IP) == \
        (200, b'{"ok": 1}')
    big = UrlTransport(connection_factory=RecordingFactory(
        http_reply(200, b"x" * (MAX_RESPONSE_BYTES + 1))))
    with pytest.raises(ResponseTooLarge):
        big.request("GET", "https://a.example.com/", {}, None, 5, PUBLIC_IP)


def test_default_transport_refuses_plain_http():
    factory = RecordingFactory(http_reply())
    with pytest.raises(ValueError):
        UrlTransport(connection_factory=factory).request("GET", "http://a.example.com/", {},
                                                         None, 5, PUBLIC_IP)
    assert factory.calls == []


def test_default_transport_ignores_proxy_env(monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://10.0.0.1:3128")
    factory = RecordingFactory(http_reply(200, b"{}"))
    t = UrlTransport(connection_factory=factory)
    assert t.request("GET", "https://a.example.com/", {}, None, 5, PUBLIC_IP)[0] == 200
    assert factory.net.connects == [((PUBLIC_IP, 443), 5)]
    assert factory.tls.server_hostnames == ["a.example.com"]
    assert factory.net.sockets[0].closed


def test_email_overall_deadline_stops_before_sending(tmp_path, monkeypatch):
    from agents.connectors import email as email_mod

    clock = [0.0]
    monkeypatch.setattr(email_mod, "_clock", lambda: clock[0])

    class SlowSMTP(FakeSMTP):
        def ehlo(self):
            clock[0] += 6.0                          # each step inside the socket timeout
            super().ehlo()

    FakeSMTP.instances.clear()
    c, _ = build(tmp_path, {"connector.email": email_section(timeout="10")}, smtp_factory=SlowSMTP)
    r = c.notify("email", note())
    assert r.status == "error: DeadlineExceeded"
    assert FakeSMTP.instances[-1].messages == []
