"""SIP trap (UDP and TCP on the same port): fake PBX that accepts fake registrations.

REGISTER without credentials gets a 401 Digest challenge. With credentials the digest is
logged, the password is recovered when it is a configured extension password, a common
password or the username itself, and the login policy decides whether the registration is
accepted (200 OK). INVITE is logged with the dialed number and always ends in 486 or 480.

INVITE from a source with no live registration is challenged with 407 (Proxy-Authenticate)
first; the retry carrying Proxy-Authorization gets the 486/480.

Safety:
- never any SDP, never a call placed or bridged, never a packet to anyone but the source;
- UDP: at most ONE response datagram per request (an INVITE over UDP gets only its final
  486/480 after a short delay, no 100/180), every response gated by the per-source
  response limiter ``ctx.udp_resp_rate`` and the global ``ctx.udp_global``, requests gated
  by ``ctx.udp_rate``, datagrams larger than ``2 * max_line_bytes`` dropped;
- UDP responses are never larger than the datagram that triggered them (compact header
  names and dropped optional headers when needed; nothing is sent if it still does not
  fit), requests with more than ``MAX_UDP_VIA`` Via hops are dropped, and SIP responses
  are never answered. Together these keep the listener useless as a reflector;
- malformed datagrams and limit events go through ``ctx.gate`` (first occurrence, then
  periodic counter lines).

Spoofed-source floods:
- the per-source request limit (``rate_per_ip_per_minute``) is checked first, then a
  global inbound token bucket (``udp_requests_per_second``), both before any parsing;
  datagrams over the global bucket are dropped and counted, and one aggregated ``limit``
  event per ``UDP_DROP_REPORT_SECONDS`` reports how many;
- over UDP, events from a source that has not completed a nonce round trip go through
  ``ctx.gate`` in its ``unverified`` pool (first occurrence per source and event, then
  periodic lines carrying the ``suppressed`` count), so log growth does not scale with the
  number of forged sources and a forged flood cannot crowd out other lines. Every UDP event
  carries ``data.source_verified``.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import re
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Optional

from listeners.base import ConnClosed, Conn, ListenerContext, ServiceSettings, TokenBucket, \
    start_tcp
from listeners.events import new_task_name
from listeners.wordlist import common_passwords

INVITE_FINAL_DELAY = 1.5          # seconds before 486/480 (tests patch this)
UDP_DROP_REPORT_SECONDS = 60.0    # at most one "datagrams dropped" event per this period
MAX_REGISTRATIONS_IPS = 10_000
MAX_ISSUED_NONCES = 50_000
MAX_USERS_PER_IP = 50
MAX_TRACKED_DIALOGS = 20_000
MAX_HEADERS = 64
MAX_UDP_VIA = 5                   # more Via hops than this over UDP: dropped, never answered
DEFAULT_SERVER = "Asterisk PBX 18.20.0"
DEFAULT_REALM = "asterisk"
DEFAULT_EXPIRES = 3600
ALLOW = "OPTIONS, REGISTER, SUBSCRIBE, NOTIFY, PUBLISH, INVITE, ACK, BYE, CANCEL, UPDATE, PRACK, MESSAGE, REFER"

COMPACT = {"f": "from", "t": "to", "m": "contact", "i": "call-id", "v": "via", "l": "content-length",
           "c": "content-type", "k": "supported", "s": "subject", "e": "content-encoding",
           "o": "event", "u": "allow-events", "r": "refer-to", "x": "session-expires"}
SHORT_NAMES = {"Via": "v", "From": "f", "To": "t", "Call-ID": "i", "Contact": "m",
               "Content-Length": "l", "Content-Type": "c", "Supported": "k"}
OPTIONAL_HEADERS = {"Allow", "Date", "Supported", "Accept"}   # dropped first when squeezing
REASONS = {100: "Trying", 180: "Ringing", 200: "OK", 400: "Bad Request", 401: "Unauthorized",
           405: "Method Not Allowed", 407: "Proxy Authentication Required",
           480: "Temporarily Unavailable",
           481: "Call/Transaction Does Not Exist", 486: "Busy Here", 489: "Bad Event"}
REQUEST_LINE_RE = re.compile(r"^([A-Za-z]{2,16})\s+(\S{1,512})\s+SIP/2\.0$", re.IGNORECASE)
AUTH_PARAM_RE = re.compile(r'([A-Za-z0-9_-]+)\s*=\s*(?:"((?:[^"\\]|\\.)*)"|([^\s,]+))')
URI_USER_RE = re.compile(r"(?:sips?|tel):([^@;>?\s]{1,128})", re.IGNORECASE)


# ---- parsing --------------------------------------------------------------------------------

@dataclass
class SipRequest:
    method: str
    uri: str
    headers: list[tuple[str, str]] = field(default_factory=list)
    body_len: int = 0

    def get(self, name: str) -> Optional[str]:
        for k, v in self.headers:
            if k == name:
                return v
        return None

    def all(self, name: str) -> list[str]:
        return [v for k, v in self.headers if k == name]


def parse_request(data: bytes) -> Optional[SipRequest]:
    """Tolerant parser. Returns None for anything that is not a SIP request."""
    text = data.decode("utf-8", errors="replace")
    head = re.split(r"\r?\n\r?\n", text, maxsplit=1)[0]
    lines = re.split(r"\r?\n", head)
    while lines and not lines[0].strip():
        lines.pop(0)
    if not lines:
        return None
    m = REQUEST_LINE_RE.match(lines[0].strip())
    if not m:
        return None
    req = SipRequest(method=m.group(1).upper(), uri=m.group(2))
    for line in lines[1:]:
        if line[:1] in (" ", "\t") and req.headers:       # folded continuation line
            k, v = req.headers[-1]
            req.headers[-1] = (k, f"{v} {line.strip()}")
            continue
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        name = name.strip().lower()
        name = COMPACT.get(name, name)
        if name == "via":   # Via may be comma-joined; keep each hop separately
            req.headers.extend(("via", v.strip()) for v in value.split(",") if v.strip())
        else:
            req.headers.append((name, value.strip()))
        if len(req.headers) >= MAX_HEADERS:
            break
    try:
        req.body_len = max(0, int(req.get("content-length") or 0))
    except ValueError:
        req.body_len = 0
    return req


def parse_auth(value: Optional[str]) -> Optional[dict[str, str]]:
    if not value:
        return None
    scheme, _, rest = value.strip().partition(" ")
    if scheme.lower() != "digest":
        return {"scheme": scheme[:32]}
    params = {"scheme": "Digest"}
    for m in AUTH_PARAM_RE.finditer(rest):
        key = m.group(1).lower()
        if key not in params:
            params[key] = m.group(2) if m.group(2) is not None else (m.group(3) or "")
    return params


def via_host(via: str) -> str:
    """'SIP/2.0/UDP 192.0.2.1:5060;branch=x' -> '192.0.2.1'."""
    sent_by = via.split(";", 1)[0].split()[-1] if via.split() else ""
    if sent_by.startswith("["):
        return sent_by[1:].split("]", 1)[0]
    return sent_by.rsplit(":", 1)[0] if sent_by.count(":") == 1 else sent_by


def uri_user(value: Optional[str]) -> str:
    if not value:
        return ""
    m = URI_USER_RE.search(value)
    return m.group(1) if m else ""


def _hash(algorithm: str, text: str) -> str:
    if algorithm.startswith("SHA-256"):
        return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()
    return hashlib.md5(text.encode("utf-8", errors="replace")).hexdigest()


def digest_response(algorithm: str, username: str, realm: str, password: str, method: str,
                    uri: str, nonce: str, qop: str = "", nc: str = "", cnonce: str = "") -> str:
    alg = algorithm.upper() or "MD5"
    ha1 = _hash(alg, f"{username}:{realm}:{password}")
    if alg.endswith("-SESS"):
        ha1 = _hash(alg, f"{ha1}:{nonce}:{cnonce}")
    ha2 = _hash(alg, f"{method}:{uri}")
    if qop:
        return _hash(alg, f"{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}")
    return _hash(alg, f"{ha1}:{nonce}:{ha2}")


def recover_password(auth: dict[str, str], method: str, candidates: list[str]) -> Optional[str]:
    """Recompute the digest for each candidate (MD5 and SHA-256, with/without qop)."""
    target = auth.get("response", "").lower()
    if not re.fullmatch(r"[0-9a-f]{32}|[0-9a-f]{64}", target):
        return None
    user, realm = auth.get("username", ""), auth.get("realm", "")
    uri, nonce = auth.get("uri", ""), auth.get("nonce", "")
    qop, nc, cnonce = auth.get("qop", ""), auth.get("nc", ""), auth.get("cnonce", "")
    stated = (auth.get("algorithm") or "MD5").upper()
    algorithms = [stated] if stated in ("MD5", "MD5-SESS", "SHA-256", "SHA-256-SESS") else []
    algorithms += [a for a in ("MD5", "SHA-256") if a not in algorithms]
    algorithms = [a for a in algorithms if (len(target) == 64) == a.startswith("SHA-256")]
    qops = [qop, ""] if qop else [""]
    for pw in candidates:
        for alg in algorithms:
            for q in qops:
                if digest_response(alg, user, realm, pw, method, uri, nonce, q, nc, cnonce) == target:
                    return pw
    return None


# ---- responses -------------------------------------------------------------------------------

@dataclass
class Hdr:
    name: str
    value: str
    short: Optional[str] = None      # shorter value to use when squeezing (e.g. a challenge)


def render(status: str, headers: list[Hdr], limit: Optional[int]) -> Optional[bytes]:
    """Render a response; with ``limit`` (UDP), squeeze it to at most ``limit`` bytes.

    Steps, stopping at the first that fits: full form; optional headers dropped; compact
    header names; shortest values and no Content-Length (optional over UDP); no Server
    header (kept as long as possible: scanners fingerprint the PBX by it). None when even
    that is larger than the request, so the caller sends nothing.
    """
    def build(drop_optional: bool, compact: bool, minimal: bool, no_server: bool) -> bytes:
        lines = [status]
        for h in headers:
            if drop_optional and h.name in OPTIONAL_HEADERS:
                continue
            if (minimal and h.name == "Content-Length") or (no_server and h.name == "Server"):
                continue
            name = SHORT_NAMES.get(h.name, h.name) if compact else h.name
            value = h.short if minimal and h.short is not None else h.value
            lines.append(f"{name}: {value}")
        return ("\r\n".join(lines) + "\r\n\r\n").encode("utf-8", errors="replace")

    for step in ((False, False, False, False), (True, False, False, False),
                 (True, True, False, False), (True, True, True, False), (True, True, True, True)):
        out = build(*step)
        if limit is None or len(out) <= limit:
            return out
    return None


# ---- core (shared by UDP and TCP) -----------------------------------------------------------



class SipCore:
    def __init__(self, ctx: ListenerContext, settings: ServiceSettings) -> None:
        self.ctx = ctx
        self.settings = settings
        svc = ctx.scenario.scenario.services.sip if ctx.scenario is not None else None
        self.realm = svc.realm if svc is not None else DEFAULT_REALM
        self.server = settings.banner or (svc.server_header if svc is not None else DEFAULT_SERVER)
        self.max_expires = svc.register_expires if svc is not None else DEFAULT_EXPIRES
        self.registrations: OrderedDict[str, dict[str, float]] = OrderedDict()
        self.tasks: OrderedDict[tuple[str, str], str] = OrderedDict()
        self.seen_sources: OrderedDict[str, None] = OrderedDict()
        # Nonces we issued, keyed to the source IP they were sent to. A source that answers
        # with one of these has received our datagram, so its address is not spoofed.
        self.issued_nonces: OrderedDict[str, str] = OrderedDict()
        self.verified_sources: OrderedDict[str, None] = OrderedDict()

    # ---- helpers -------------------------------------------------------------------------

    @property
    def live_settings(self) -> ServiceSettings:
        """The settings object the overlay reload updates in place (read per decision)."""
        return self.ctx.settings.get("sip", self.settings)

    @property
    def accounts(self) -> list[tuple[str, str]]:
        """Configured extensions, read at decision time so tuner changes apply at once."""
        accounts = list(self.live_settings.accounts)
        if self.ctx.scenario is not None:
            accounts += [a for a in self.ctx.scenario.accounts_for("sip") if a not in accounts]
        return accounts

    def candidates(self, username: str) -> list[str]:
        out: list[str] = []
        accounts = self.accounts
        for user, pw in accounts:               # this extension's own password first
            if user == username and pw and pw != "*":
                out.append(pw)
        for _user, pw in accounts:
            if pw and pw != "*" and pw not in out:
                out.append(pw)
        out += [w for w in common_passwords() if w not in out]
        if username and username not in out:
            out.append(username)
        return out

    def task_for(self, ip: str, call_id: str) -> str:
        key = (ip, call_id[:128])
        name = self.tasks.get(key)
        if name is None:
            name = new_task_name("sip")
            self.tasks[key] = name
            if len(self.tasks) > MAX_TRACKED_DIALOGS:
                self.tasks.popitem(last=False)
        else:
            self.tasks.move_to_end(key)
        return name

    def tag(self, call_id: str) -> str:
        return hashlib.sha256(f"{self.ctx.seed}|tag|{call_id}".encode()).hexdigest()[:10]

    def is_registered(self, ip: str) -> bool:
        users = self.registrations.get(ip)
        now = time.monotonic()
        return bool(users) and any(exp > now for exp in users.values())

    def register(self, ip: str, user: str, expires: int) -> None:
        users = self.registrations.get(ip)
        if expires <= 0:
            if users is not None:
                users.pop(user, None)
                if not users:
                    self.registrations.pop(ip, None)
            return
        if users is None:
            users = {}
            self.registrations[ip] = users
            if len(self.registrations) > MAX_REGISTRATIONS_IPS:
                self.registrations.popitem(last=False)
        else:
            self.registrations.move_to_end(ip)
        if user not in users and len(users) >= MAX_USERS_PER_IP:
            users.pop(next(iter(users)))
        users[user] = time.monotonic() + expires

    def log_gated(self, src: tuple[str, int], dst: tuple[str, int], transport: str,
                  event: str, message: str, reason: str, task: Optional[str] = None,
                  **data) -> None:
        """Low-value lines (limits, malformed input): first occurrence per source and
        reason, then one line per gate window carrying the ``suppressed`` count. Lines about
        unverified UDP sources draw from the gate's own pool for them."""
        pool = "unverified" if transport == "udp" and src[0] not in self.verified_sources \
            else "default"
        suppressed = self.ctx.gate.check(f"{src[0]}|sip|{reason}", pool=pool)
        if suppressed is None:
            return
        self.ctx.writer.emit(task_name=task or new_task_name("sip"), src_ip=src[0],
                             src_port=src[1], dst_ip=dst[0], dst_port=dst[1], message=message,
                             sensor_protocol="sip", event=event, transport=transport,
                             level="WARNING", data={"reason": reason, "suppressed": suppressed,
                                                    **data})

    def limit(self, src: tuple[str, int], dst: tuple[str, int], transport: str, reason: str) -> None:
        self.log_gated(src, dst, transport, "limit", "SIP limit", reason)

    def response(self, req: SipRequest, code: int, src: tuple[str, int], transport: str,
                 extra: Optional[list[Hdr]] = None, to_tag: bool = True,
                 limit: Optional[int] = None) -> Optional[bytes]:
        """Build a response; with ``limit`` (UDP) it is at most that many bytes, or None."""
        headers: list[Hdr] = []
        for i, via in enumerate(req.all("via")):
            if i == 0 and transport == "udp":
                rport = re.search(r";rport(?=;|$)", via) is not None
                via = re.sub(r";rport(?=;|$)", f";rport={src[1]}", via)
                # RFC 3261 18.2.1: "received" only when sent-by differs (or rport asked).
                if ";received=" not in via and (rport or via_host(via) != src[0]):
                    via += f";received={src[0]}"
            headers.append(Hdr("Via", via))
        headers.append(Hdr("From", req.get("from") or ""))
        to = req.get("to") or ""
        if to_tag and code > 100 and ";tag=" not in to.lower():
            to += f";tag={self.tag(req.get('call-id') or '')}"
        headers.append(Hdr("To", to))
        headers.append(Hdr("Call-ID", req.get("call-id") or ""))
        headers.append(Hdr("CSeq", req.get("cseq") or ""))
        headers.append(Hdr("Server", self.server))
        headers.append(Hdr("Allow", ALLOW))
        headers.extend(extra or [])
        headers.append(Hdr("Content-Length", "0"))
        return render(f"SIP/2.0 {code} {REASONS.get(code, 'OK')}", headers, limit)

    def challenge(self, ip: str, proxy: bool = False) -> Hdr:
        nonce = self.issue_nonce(ip)
        name = "Proxy-Authenticate" if proxy else "WWW-Authenticate"
        return Hdr(name, f'Digest realm="{self.realm}",nonce="{nonce}",opaque="",'
                         f'algorithm=MD5,qop="auth"',
                   short=f'Digest realm="{self.realm}",nonce="{nonce}"')

    # ---- dispatch ------------------------------------------------------------------------

    def handle(self, data: bytes, src: tuple[str, int], dst: tuple[str, int], transport: str,
               task_name: Optional[str] = None,
               max_response: Optional[int] = None) -> list[tuple[float, bytes]]:
        """Process one request; return [(delay_seconds, response_bytes), ...].

        UDP always gets at most one element. ``max_response`` caps each response's size
        (the UDP listener passes the request's size); a response that cannot be squeezed
        under it is not sent.
        """
        ip = src[0]
        udp = transport == "udp"
        if data[:8].upper() == b"SIP/2.0 ":
            # A response (or a reflected one). Answering responses is how SIP devices end
            # up in reflection loops; log it and never reply.
            self.log_gated(src, dst, transport, "error", "SIP response received, ignored",
                           "sip_response", task_name, size=len(data), head=data[:120])
            return []
        req = parse_request(data)

        def emit(event: str, message: str, **fields) -> None:
            if udp and ip not in self.verified_sources:
                # Possibly spoofed: aggregated per source and event, never one line each.
                suppressed = self.ctx.gate.check(f"{ip}|sip|unverified_{event}",
                                                 pool="unverified")
                if suppressed is None:
                    return
                fields["data"] = {**(fields.get("data") or {}), "source_verified": False,
                                  "suppressed": suppressed}
            elif udp:
                fields["data"] = {**(fields.get("data") or {}), "source_verified": True}
            self.ctx.writer.emit(task_name=task, src_ip=ip, src_port=src[1], dst_ip=dst[0],
                                 dst_port=dst[1], message=message, sensor_protocol="sip",
                                 event=event, transport=transport, **fields)

        if req is None:
            self.log_gated(src, dst, transport, "error", "Malformed SIP message", "malformed",
                           task_name, size=len(data), head=data[:120])
            return []
        if udp and len(req.all("via")) > MAX_UDP_VIA:
            self.log_gated(src, dst, transport, "limit", "SIP request with too many Via hops",
                           "too_many_via", task_name, method=req.method[:16],
                           via_hops=len(req.all("via")), size=len(data))
            return []
        call_id = req.get("call-id") or ""
        task = task_name or self.task_for(ip, call_id)
        if udp and ip not in self.seen_sources:
            self.seen_sources[ip] = None
            if len(self.seen_sources) > MAX_REGISTRATIONS_IPS:
                self.seen_sources.popitem(last=False)
            emit("connection", "First SIP datagram from source")
        if not (req.all("via") and req.get("from") and req.get("to") and call_id
                and req.get("cseq")):
            self.log_gated(src, dst, transport, "error", "SIP request missing mandatory headers",
                           "missing_headers", task, method=req.method[:16], size=len(data))
            return []
        limit = max_response

        def respond(code: int, extra: Optional[list[Hdr]] = None, to_tag: bool = True,
                    delay: float = 0.0) -> list[tuple[float, bytes]]:
            out = self.response(req, code, src, transport, extra, to_tag, limit)
            if out is None:
                self.log_gated(src, dst, transport, "limit", "SIP response larger than request",
                               "response_too_large", task, method=req.method[:16], code=code,
                               size=len(data))
                return []
            return [(delay, out)]

        ua = req.get("user-agent")
        common = {"method": req.method, "uri": req.uri, "from": req.get("from") or "",
                  "to": req.get("to") or "", "contact": req.get("contact") or "",
                  "call_id": call_id}
        m = req.method
        if m == "REGISTER":
            return self.on_register(req, src, transport, emit, ua, common, respond)
        if m == "INVITE":
            return self.on_invite(req, src, transport, emit, ua, common, respond)
        if m == "OPTIONS":
            emit("options", "SIP OPTIONS", client=ua, data=common)
            return respond(200, [Hdr("Accept", "application/sdp"),
                                 Hdr("Supported", "path, replaces")])
        emit("command", f"SIP {m}", client=ua, data=common)
        if m == "ACK":
            return []
        if m in ("CANCEL", "NOTIFY"):
            return respond(200)
        if m == "BYE":
            return respond(481)
        if m == "SUBSCRIBE":
            return respond(489)
        return respond(405)

    def on_invite(self, req: SipRequest, src: tuple[str, int], transport: str, emit,
                  ua: Optional[str], common: dict, respond) -> list[tuple[float, bytes]]:
        ip = src[0]
        dialed = uri_user(req.uri)
        registered = self.is_registered(ip)
        auth = parse_auth(req.get("proxy-authorization") or req.get("authorization"))
        answered = auth is not None and auth.get("scheme") == "Digest" and bool(auth.get("response"))
        data = {**common, "dialed": dialed, "registered": registered,
                "has_sdp": req.body_len > 0, "high_signal": True, "signal": "sip_dialed_number"}
        if registered or answered:
            data["stage"] = "answered"
            if answered:
                username = auth.get("username", "")
                recovered = recover_password(auth, req.method, self.candidates(username))
                data.update(auth_username=username, password_recovered=recovered is not None,
                            nonce_verified=self.nonce_round_trip(ip, auth.get("nonce", "")))
                if recovered is not None:
                    data["auth_password"] = recovered
        else:
            data["stage"] = "challenge"
        data["source_verified"] = transport == "tcp" or ip in self.verified_sources
        emit("invite", "SIP INVITE", client=ua, username=uri_user(req.get("from")) or None,
             data=data)
        if data["stage"] == "challenge":
            # Like a PBX with no registration for this source: authenticate the call first.
            return respond(407, [self.challenge(ip, proxy=True)])
        code = 486 if hashlib.sha256(dialed.encode()).digest()[0] % 2 == 0 else 480
        if transport == "udp":
            return respond(code, delay=INVITE_FINAL_DELAY)
        return (respond(100, to_tag=False) + respond(180)
                + respond(code, delay=INVITE_FINAL_DELAY))

    def on_register(self, req: SipRequest, src: tuple[str, int], transport: str, emit,
                    ua: Optional[str], common: dict, respond) -> list[tuple[float, bytes]]:
        ip = src[0]
        auth = parse_auth(req.get("authorization") or req.get("proxy-authorization"))
        to_user = uri_user(req.get("to"))
        expires = self.requested_expires(req)
        if not auth or auth.get("scheme") != "Digest" or not auth.get("response"):
            emit("register", "SIP REGISTER challenged", client=ua, username=to_user or None,
                 data={**common, "stage": "challenge", "expires": expires,
                       "auth_scheme": (auth or {}).get("scheme", "")})
            return respond(401, [self.challenge(ip)])
        username = auth.get("username", "") or to_user
        accounts = self.accounts
        recovered = recover_password(auth, req.method, self.candidates(username))
        # An unrecovered digest changes with every nonce, so a fixed marker keeps the
        # "found credential keeps working" rule usable for re-registers.
        secret = recovered if recovered is not None else "<digest-unrecovered>"
        ok = self.ctx.logins.decide("sip", ip, username, secret, self.live_settings.policy,
                                    accounts)
        data = {**common, "realm": auth.get("realm", ""), "auth_uri": auth.get("uri", ""),
                "nonce": auth.get("nonce", ""), "response": auth.get("response", ""),
                "algorithm": auth.get("algorithm", "MD5"), "qop": auth.get("qop", ""),
                "nc": auth.get("nc", ""), "cnonce": auth.get("cnonce", ""),
                "password_recovered": recovered is not None, "expires": expires,
                "nonce_verified": self.nonce_round_trip(ip, auth.get("nonce", ""))}
        token = self.ctx.honeytoken_in(username, recovered)
        if token:
            data["honeytoken"] = token
        emit("auth_attempt", "Authentication attempt", username=username, password=recovered,
             client=ua, success=ok, data=data)
        if not ok:
            emit("register", "SIP REGISTER rejected", client=ua, username=username,
                 success=False, data={**common, "stage": "rejected"})
            return respond(401, [self.challenge(ip)])
        contact = req.get("contact") or ""
        self.register(ip, username, expires)
        stage = "unregistered" if expires == 0 else "registered"
        emit("register", f"SIP REGISTER {stage}", client=ua, username=username, success=True,
             data={**common, "stage": stage, "expires": expires})
        extra = [Hdr("Expires", str(expires)),
                 Hdr("Date", time.strftime('%a, %d %b %Y %H:%M:%S GMT', time.gmtime()))]
        if expires and contact and contact != "*":
            uri = contact.split(";", 1)[0] if contact.startswith("<") else contact.split(";")[0]
            extra.append(Hdr("Contact", f"{uri};expires={expires}"))
        return respond(200, extra)

    def issue_nonce(self, ip: str) -> str:
        nonce = f"{int(time.time())}/{os.urandom(8).hex()}"
        self.issued_nonces[nonce] = ip
        if len(self.issued_nonces) > MAX_ISSUED_NONCES:
            self.issued_nonces.popitem(last=False)
        return nonce

    def nonce_round_trip(self, ip: str, nonce: str) -> bool:
        """True when ``nonce`` was issued by us to ``ip`` (proves the source is reachable)."""
        if self.issued_nonces.get(nonce) != ip:
            return False
        self.verified_sources[ip] = None
        self.verified_sources.move_to_end(ip)
        if len(self.verified_sources) > MAX_REGISTRATIONS_IPS:
            self.verified_sources.popitem(last=False)
        return True

    def requested_expires(self, req: SipRequest) -> int:
        raw = None
        m = re.search(r";\s*expires\s*=\s*(\d+)", req.get("contact") or "", re.IGNORECASE)
        if m:
            raw = m.group(1)
        elif req.get("expires") is not None:
            raw = req.get("expires")
        try:
            value = int(str(raw).strip()) if raw is not None else self.max_expires
        except ValueError:
            value = self.max_expires
        if value <= 0 or (req.get("contact") or "").strip() == "*":
            return 0
        return max(60, min(value, self.max_expires))


# ---- UDP ------------------------------------------------------------------------------------

class SipUdpProtocol(asyncio.DatagramProtocol):
    def __init__(self, core: SipCore) -> None:
        self.core = core
        self.transport: Optional[asyncio.DatagramTransport] = None
        self.dst: tuple[str, int] = ("-", 0)
        # All sources together, checked before any parsing: forged sources each pass the
        # per-source limits, so only a global cap bounds the work they cause.
        self.inbound = TokenBucket(core.ctx.limits.udp_requests_per_second)
        self.dropped = 0
        self.drop_report: Optional[asyncio.TimerHandle] = None

    def connection_made(self, transport) -> None:  # type: ignore[override]
        self.transport = transport
        sock = transport.get_extra_info("sockname") or ("-", 0)
        self.dst = (str(sock[0]), sock[1])

    def datagram_received(self, data: bytes, addr) -> None:
        src = (str(addr[0]), addr[1])
        ctx = self.core.ctx
        # Per source first, so one busy source cannot spend the budget shared by all.
        if not ctx.udp_rate.allow(src[0]):
            self.core.limit(src, self.dst, "udp", "rate_per_ip_per_minute")
            return
        if not self.inbound.allow():
            self.dropped += 1
            if self.drop_report is None:
                self.drop_report = asyncio.get_running_loop().call_later(
                    UDP_DROP_REPORT_SECONDS, self.report_drops)
            return
        try:
            if len(data) > ctx.limits.max_line_bytes * 2:
                self.core.limit(src, self.dst, "udp", "packet_size")
                return
            # Hard rules: one response per request, never larger than the request (plus the
            # operator's optional slack, capped at 512 bytes).
            slack = min(max(0, ctx.limits.sip_udp_slack_bytes), 512)
            responses = self.core.handle(data, src, self.dst, "udp",
                                         max_response=len(data) + slack)[:1]
        except Exception as exc:  # noqa: BLE001 - malformed input never kills the listener
            self.core.log_gated(src, self.dst, "udp", "error", "Handler error",
                                type(exc).__name__)
            return
        # Per-source tarpit (bounded by the source-state schema); still one response.
        tarpit = ctx.tarpit_seconds(src[0])
        for delay, payload in responses:
            delay += tarpit
            if delay > 0:
                asyncio.get_running_loop().call_later(delay, self.send, payload, src)
            else:
                self.send(payload, src)

    def report_drops(self) -> None:
        """One aggregated line for the datagrams the inbound limit dropped."""
        dropped, self.dropped, self.drop_report = self.dropped, 0, None
        if dropped:
            self.core.ctx.writer.emit(
                task_name=new_task_name("sip"), src_ip="-", src_port=0, dst_ip=self.dst[0],
                dst_port=self.dst[1], message=f"Dropped {dropped} SIP datagrams (inbound limit)",
                sensor_protocol="sip", event="limit", transport="udp", level="WARNING",
                data={"reason": "udp_requests_per_second", "dropped": dropped,
                      "period_seconds": UDP_DROP_REPORT_SECONDS})

    def send(self, payload: bytes, src: tuple[str, int]) -> None:
        if self.transport is None or self.transport.is_closing():
            return
        # Every response, of any size, passes the per-source response limiter.
        if not self.core.ctx.udp_resp_rate.allow(src[0]):
            self.core.limit(src, self.dst, "udp", "udp_responses_per_ip_per_minute")
            return
        # ... and the global cap shared by all sources (spoofed-source floods).
        if not self.core.ctx.udp_global.allow():
            self.core.limit(src, self.dst, "udp", "udp_responses_per_second")
            return
        self.transport.sendto(payload, src)   # only ever back to the request's source


# ---- TCP ------------------------------------------------------------------------------------

async def read_tcp_message(conn: Conn) -> bytes:
    lines: list[bytes] = []
    total = 0
    cap = conn.ctx.limits.max_line_bytes * 2
    while True:
        line = await conn.readline(strip=False)
        if not lines and not line.strip():
            continue            # keep-alive CRLFs between messages
        if not line.strip():
            break
        lines.append(line)
        total += len(line)
        if total > cap:
            conn.emit("limit", "SIP message too large", data={"reason": "packet_size"})
            raise ConnClosed("packet_size")
    head = b"".join(lines)
    req = parse_request(head)
    if req is not None and req.body_len:
        if req.body_len + total > cap:
            conn.emit("limit", "SIP message too large", data={"reason": "packet_size"})
            raise ConnClosed("packet_size")
        await conn.readexactly(req.body_len)   # body (SDP etc.) read and discarded
    return head + b"\r\n"


def make_tcp_handler(core: SipCore):
    async def handle(conn: Conn) -> None:
        src = (conn.src_ip, conn.src_port)
        dst = (conn.dst_ip, conn.dst_port)
        pending: list[asyncio.Task] = []
        try:
            while True:
                msg = await read_tcp_message(conn)
                if not conn.command():
                    break
                for delay, payload in core.handle(msg, src, dst, "tcp", task_name=conn.task_name):
                    if delay > 0:
                        pending.append(asyncio.create_task(_delayed_write(conn, delay, payload)))
                    else:
                        await conn.write(payload)
                pending = [t for t in pending if not t.done()]
        finally:
            for t in pending:
                t.cancel()

    return handle


async def _delayed_write(conn: Conn, delay: float, payload: bytes) -> None:
    await asyncio.sleep(delay)
    try:
        await conn.write(payload)
    except ConnClosed:
        pass


# ---- entry point ----------------------------------------------------------------------------

async def start(ctx: ListenerContext, settings: ServiceSettings) -> list:
    core = SipCore(ctx, settings)
    svc = ctx.scenario.scenario.services.sip if ctx.scenario is not None else None
    use_udp = svc.udp if svc is not None else True
    use_tcp = svc.tcp if svc is not None else True
    out: list = []
    port = settings.port
    if use_udp:
        loop = asyncio.get_running_loop()
        transport, _ = await loop.create_datagram_endpoint(
            lambda: SipUdpProtocol(core), local_addr=(ctx.bind_host, port))
        out.append(transport)
        if port == 0:
            port = transport.get_extra_info("sockname")[1]
    if use_tcp:
        try:
            server = await start_tcp(ctx, "sip", port, make_tcp_handler(core))
        except OSError:
            if settings.port != 0:
                raise
            server = await start_tcp(ctx, "sip", 0, make_tcp_handler(core))
        out.append(server)
    return out
