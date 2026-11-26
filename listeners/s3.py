"""S3-compatible storage trap: enough of the Amazon S3 REST API (plain HTTP) for the AWS CLI,
boto3, s3cmd or curl to believe they found a storage endpoint.

Buckets and objects come from ``scenario.services.s3``. Object bodies are literal text, a
scenario table rendered as CSV, or deterministic filler generated on demand for any byte
range: the size on paper may be large, nothing of that size is ever allocated, and one
response sends at most ``get_max_bytes`` before the connection is closed.

Requests are path-style (``/bucket/key``) or virtual-hosted (``bucket.<anything>`` in Host).
AWS Signature V4 (header and presigned query) and V2 are parsed for the access key id,
region, service and signed headers. A signature is verified only for a scenario account
that carries a secret; every other key is decided by the service's login policy, keyed on
the access key id. A planted (honeytoken) key raises the high-value signal whatever the
policy says. Buckets flagged ``public_list`` / ``public_read`` answer anonymous requests.

PutObject and UploadPart bodies stream into the capped quarantine with the same per-file
cap, quotas and truncation as FTP uploads (``Expect: 100-continue`` and ``aws-chunked``
payloads are handled; ``Transfer-Encoding`` is refused as S3 does). An upload appears in
listings for that source only, for ``UPLOAD_WINDOW`` seconds; DeleteObject pretends to
succeed. CopyObject copies between the objects the source can see (scenario objects and
its own uploads) into that same per-source state; object tags, multipart uploads and their
parts are per source too, with the same window and caps. Nothing an attacker sends is
executed, fetched or connected to.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import bisect
import csv
import datetime
import email.utils
import hashlib
import hmac
import heapq
import io
import json
import os
import re
import struct
import time
import weakref
from collections import OrderedDict, deque
from dataclasses import dataclass, field
from typing import Iterator, Optional
from urllib.parse import parse_qsl, quote, quote_plus, unquote, urlsplit
from xml.sax.saxutils import escape

from agents.budget import ip_key
from listeners.base import (Conn, ConnClosed, ListenerContext, QuarantineResult,
                            ServiceSettings, start_tcp)
from listeners.ftp import AWS_CREDENTIALS_PATH, aws_profile
from listeners.http import HttpError, Request, content_length, read_head

XMLNS = "http://s3.amazonaws.com/doc/2006-03-01/"
XML_DECL = '<?xml version="1.0" encoding="UTF-8"?>\n'
DEFAULT_GET_MAX = 4_194_304          # schema default for get_max_bytes
DEFAULT_REGION = "us-east-1"
MAX_SMALL_BODY = 65_536              # bodies of non-upload requests (DeleteObjects, ...)
MAX_OBJECT_SIZE = 5 * 1024 ** 3      # the largest single PUT S3 accepts
MAX_KEY_BYTES = 1024
MAX_LIST_KEYS = 1000
MAX_CHUNK_LINE = 4096
MAX_TRAILERS = 16
CHUNK_OVERHEAD_SLACK = 1_048_576     # aws-chunked framing bytes allowed beyond 2x the data
SEND_CHUNK = 65_536
MAX_CONN_SERVED = 64 * 1024 * 1024   # body bytes served per connection
UPLOAD_WINDOW = 3600.0               # an upload stays visible to its source this long
MAX_UPLOADS_PER_SOURCE = 200
MAX_DELETED_PER_SOURCE = 1000
MAX_MULTIPART_PER_SOURCE = 32
MAX_TAGGED_PER_SOURCE = 1000         # objects with tags set by one source
MAX_OBJECT_TAGS = 10
MAX_LIST_PARTS = 1000
MAX_UPLOAD_ID = 256                  # longest upload-id-marker kept from a request
MAX_SOURCES = 5000
KEEP_UPLOAD_BYTES = 65_536           # an upload this small is echoed back on GET
KEEP_TOTAL_BYTES = 16 * 1024 * 1024  # all kept upload bytes together
BULK_DOWNLOAD_COUNT = 25             # GetObject calls by one source within BULK_WINDOW ...
BULK_DOWNLOAD_BYTES = 64 * 1024 * 1024  # ... or this many body bytes
BULK_WINDOW = 600.0
FAKE_ACCOUNT_ID = "123456789012"     # the account id AWS documentation uses in examples
DEFAULT_MTIME = datetime.datetime(2026, 3, 2, 9, 14, tzinfo=datetime.timezone.utc)

REASONS = {100: "Continue", 200: "OK", 204: "No Content", 206: "Partial Content",
           301: "Moved Permanently", 400: "Bad Request", 403: "Forbidden", 404: "Not Found",
           405: "Method Not Allowed", 411: "Length Required", 416: "Requested Range Not Satisfiable",
           500: "Internal Server Error", 501: "Not Implemented", 503: "Service Unavailable"}

ERRORS = {
    "AccessDenied": (403, "Access Denied"),
    "AuthorizationHeaderMalformed": (400, "The authorization header is malformed."),
    "AuthorizationQueryParametersError": (400, "Error parsing the X-Amz-Credential parameter."),
    "BadRequest": (400, "An error occurred when parsing the HTTP request."),
    "EntityTooLarge": (400, "Your proposed upload exceeds the maximum allowed size"),
    "IncompleteBody": (400, "You did not provide the number of bytes specified by the "
                            "Content-Length HTTP header"),
    "InvalidAccessKeyId": (403, "The AWS Access Key Id you provided does not exist in our "
                                "records."),
    "InvalidArgument": (400, "Invalid Argument"),
    "InvalidBucketName": (400, "The specified bucket is not valid."),
    "InvalidPart": (400, "One or more of the specified parts could not be found."),
    "InvalidRange": (416, "The requested range is not satisfiable"),
    "InvalidRequest": (400, "Invalid Request"),
    "InvalidTag": (400, "The tag provided was not a valid tag."),
    "MalformedXML": (400, "The XML you provided was not well-formed or did not validate "
                          "against our published schema"),
    "MaxMessageLengthExceeded": (400, "Your request was too big."),
    "MethodNotAllowed": (405, "The specified method is not allowed against this resource."),
    "MissingContentLength": (411, "You must provide the Content-Length HTTP header."),
    "NoSuchBucket": (404, "The specified bucket does not exist"),
    "NoSuchBucketPolicy": (404, "The bucket policy does not exist"),
    "NoSuchKey": (404, "The specified key does not exist."),
    "NoSuchTagSet": (404, "The TagSet does not exist"),
    "NoSuchUpload": (404, "The specified upload does not exist. The upload ID may be invalid, "
                          "or the upload may have been aborted or completed."),
    "NotImplemented": (501, "A header you provided implies functionality that is not "
                            "implemented"),
    "RequestHeaderSectionTooLarge": (400, "Your request header section exceeds the maximum "
                                          "allowed size."),
    "RequestTimeout": (400, "Your socket connection to the server was not read from or "
                            "written to within the timeout period. Idle connections will be "
                            "closed."),
    "SignatureDoesNotMatch": (403, "The request signature we calculated does not match the "
                                   "signature you provided. Check your key and signing "
                                   "method."),
    "SlowDown": (503, "Please reduce your request rate."),
}

BUCKET_NAME_RE = re.compile(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]")
KEY_ID_RE = re.compile(r"[A-Za-z0-9]{1,128}")
REGION_RE = re.compile(r"[a-z0-9-]{1,32}")
SERVICE_RE = re.compile(r"[a-z0-9-]{1,32}")
HEADER_NAME_RE = re.compile(r"[a-z0-9-]{1,64}")
SIG_RE = re.compile(r"[0-9a-f]{64}")
AMZ_DATE_RE = re.compile(r"\d{8}T\d{6}Z")
CHUNK_SIZE_RE = re.compile(rb"[0-9a-fA-F]{1,8}")
CHUNK_EXT_RE = re.compile(rb"[A-Za-z0-9._=-]{0,128}")
SERIES_RE = re.compile(r"\{n(?::0([1-9])d)?\}")
REDACT_PARAMS = {"x-amz-signature", "signature", "x-amz-security-token"}
BUCKET_SUBRESOURCES = ("accelerate", "analytics", "cors", "encryption", "intelligent-tiering",
                       "inventory", "lifecycle", "logging", "metrics", "notification",
                       "object-lock", "ownershipControls", "policyStatus", "publicAccessBlock",
                       "replication", "requestPayment", "tagging", "versioning", "website")


# ---- errors and responses -----------------------------------------------------------------

class S3Error(Exception):
    def __init__(self, code: str, message: Optional[str] = None, close: bool = False,
                 **extra: str) -> None:
        status, default = ERRORS[code]
        super().__init__(code)
        self.code, self.status = code, status
        self.message = message or default
        self.close = close
        self.extra = extra


def xml_text(value: object) -> str:
    """Escape for XML 1.0; characters XML cannot carry become U+FFFD."""
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f￾￿]", "�", str(value))
    return escape(text, {'"': "&quot;"})


def request_ids() -> tuple[str, str]:
    return os.urandom(8).hex().upper(), base64.b64encode(os.urandom(57)).decode()


def http_date(ts: float) -> str:
    return email.utils.formatdate(ts, usegmt=True)


def iso_date(ts: float) -> str:
    return datetime.datetime.fromtimestamp(ts, datetime.timezone.utc) \
        .strftime("%Y-%m-%dT%H:%M:%S.000Z")


def error_xml(err: S3Error, request_id: str, host_id: str) -> bytes:
    extra = "".join(f"<{k}>{xml_text(v)}</{k}>" for k, v in err.extra.items())
    return (f"{XML_DECL}<Error><Code>{err.code}</Code><Message>{xml_text(err.message)}"
            f"</Message>{extra}<RequestId>{request_id}</RequestId><HostId>{host_id}</HostId>"
            "</Error>").encode()


def response_head(status: int, server: str, request_id: str, host_id: str,
                  headers: list[tuple[str, str]], length: Optional[int],
                  keep_alive: bool) -> bytes:
    lines = [f"HTTP/1.1 {status} {REASONS.get(status, 'OK')}",
             f"x-amz-id-2: {host_id}", f"x-amz-request-id: {request_id}",
             f"Date: {http_date(time.time())}"]
    for k, v in headers:
        lines.append(k + ": " + re.sub(r"[\r\n]", "", v))
    if length is not None:
        lines.append(f"Content-Length: {length}")
    if not keep_alive:
        lines.append("Connection: close")
    lines.append(f"Server: {server}")
    return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1", "replace")


# ---- auth ---------------------------------------------------------------------------------

@dataclass
class AuthInfo:
    scheme: str = "anonymous"   # anonymous | sigv4 | sigv4_query | sigv2 | sigv2_query | unknown
    access_key_id: Optional[str] = None
    region: Optional[str] = None
    service: Optional[str] = None
    scope: Optional[str] = None             # date/region/service/aws4_request
    signed_headers: list[str] = field(default_factory=list)
    signature: Optional[str] = None
    security_token: Optional[str] = None
    amz_date: Optional[str] = None
    expires: Optional[int] = None
    malformed: Optional[str] = None


def _v4_credential(info: AuthInfo, cred: str) -> None:
    pieces = cred.split("/")
    key = pieces[0] if pieces else ""
    if KEY_ID_RE.fullmatch(key):
        info.access_key_id = key
    if len(pieces) != 5 or pieces[4] != "aws4_request" or info.access_key_id is None \
            or not re.fullmatch(r"\d{8}", pieces[1]) or not REGION_RE.fullmatch(pieces[2]) \
            or not SERVICE_RE.fullmatch(pieces[3]):
        info.malformed = info.malformed or "credential"
        return
    info.region, info.service = pieces[2], pieces[3]
    info.scope = "/".join(pieces[1:])


def _signed_headers(info: AuthInfo, value: str) -> None:
    names = [h.strip().lower() for h in value.split(";")]
    if not value or len(names) > 40 or not all(HEADER_NAME_RE.fullmatch(h) for h in names):
        info.malformed = info.malformed or "signed_headers"
        return
    info.signed_headers = names


def parse_auth(req: Request, q: dict[str, str]) -> AuthInfo:
    """Who the request claims to be. Never raises; ``malformed`` names what was wrong."""
    info = AuthInfo()
    authz = req.header("authorization")
    info.security_token = (req.header("x-amz-security-token")
                           or q.get("X-Amz-Security-Token") or None)
    if authz is not None:
        authz = authz.strip()
        if authz.startswith("AWS4-HMAC-SHA256 "):
            info.scheme = "sigv4"
            parts: dict[str, str] = {}
            for item in authz[len("AWS4-HMAC-SHA256 "):].split(",")[:8]:
                k, sep, v = item.strip().partition("=")
                if sep:
                    parts[k.strip()] = v.strip()
            if "Credential" not in parts or "SignedHeaders" not in parts \
                    or "Signature" not in parts:
                info.malformed = "fields"
                if "Credential" in parts:
                    _v4_credential(info, parts["Credential"][:400])
                return info
            _v4_credential(info, parts["Credential"][:400])
            _signed_headers(info, parts["SignedHeaders"][:2000])
            if not SIG_RE.fullmatch(parts["Signature"]):
                info.malformed = info.malformed or "signature"
            else:
                info.signature = parts["Signature"]
            info.amz_date = req.header("x-amz-date") or req.header("date")
        elif authz.startswith("AWS "):
            info.scheme = "sigv2"
            key, sep, sig = authz[4:].partition(":")
            key = key.strip()
            if KEY_ID_RE.fullmatch(key):
                info.access_key_id = key
            if not sep or info.access_key_id is None or not sig.strip():
                info.malformed = "fields"
            else:
                info.signature = sig.strip()[:200]
        else:
            info.scheme, info.malformed = "unknown", "scheme"
        return info
    if "X-Amz-Algorithm" in q or "X-Amz-Credential" in q:
        info.scheme = "sigv4_query"
        if q.get("X-Amz-Algorithm") != "AWS4-HMAC-SHA256":
            info.malformed = "algorithm"
        _v4_credential(info, q.get("X-Amz-Credential", "")[:400])
        _signed_headers(info, q.get("X-Amz-SignedHeaders", "")[:2000])
        sig = q.get("X-Amz-Signature", "")
        if SIG_RE.fullmatch(sig):
            info.signature = sig
        else:
            info.malformed = info.malformed or "signature"
        info.amz_date = q.get("X-Amz-Date")
        if not AMZ_DATE_RE.fullmatch(info.amz_date or ""):
            info.malformed = info.malformed or "date"
        exp = q.get("X-Amz-Expires", "")
        if re.fullmatch(r"\d{1,6}", exp) and int(exp) <= 604_800:
            info.expires = int(exp)
        else:
            info.malformed = info.malformed or "expires"
        return info
    if "AWSAccessKeyId" in q:
        info.scheme = "sigv2_query"
        key = q.get("AWSAccessKeyId", "")
        if KEY_ID_RE.fullmatch(key):
            info.access_key_id = key
        exp = q.get("Expires", "")
        if re.fullmatch(r"\d{1,12}", exp):
            info.expires = int(exp)
        if info.access_key_id is None or info.expires is None or not q.get("Signature"):
            info.malformed = "fields"
        return info
    return info


def expired(info: AuthInfo, now: float) -> bool:
    if info.scheme == "sigv2_query":
        return info.expires is not None and info.expires < now
    if info.scheme == "sigv4_query" and info.amz_date and info.expires is not None:
        try:
            start = datetime.datetime.strptime(info.amz_date, "%Y%m%dT%H%M%SZ") \
                .replace(tzinfo=datetime.timezone.utc).timestamp()
        except ValueError:
            return True
        return start + info.expires < now
    return False


def _uri_encode(value: str) -> str:
    return quote(value, safe="-_.~")


def canonical_query(raw_query: str, drop_signature: bool) -> str:
    pairs = []
    for item in raw_query.split("&")[:100]:
        if not item:
            continue
        k, _, v = item.partition("=")
        k, v = unquote(k), unquote(v)
        if drop_signature and k == "X-Amz-Signature":
            continue
        pairs.append((_uri_encode(k), _uri_encode(v)))
    return "&".join(f"{k}={v}" for k, v in sorted(pairs))


def verify_sigv4(req: Request, info: AuthInfo, secret: str) -> bool:
    """True when the request was signed with ``secret`` (header or presigned SigV4)."""
    if info.scope is None or info.signature is None or not info.amz_date:
        return False
    try:
        split = urlsplit(req.target)
    except ValueError:
        return False
    canon_headers = []
    for name in info.signed_headers:
        values = [" ".join(v.split()) for k, v in req.headers if k.lower() == name]
        canon_headers.append(f"{name}:{','.join(values)}\n")
    query = info.scheme == "sigv4_query"
    payload = req.header("x-amz-content-sha256") or (
        "UNSIGNED-PAYLOAD" if query else hashlib.sha256(b"").hexdigest())
    creq = "\n".join([req.method, split.path or "/", canonical_query(split.query, query),
                      "".join(canon_headers), ";".join(info.signed_headers), payload])
    sts = "\n".join(["AWS4-HMAC-SHA256", info.amz_date, info.scope,
                     hashlib.sha256(creq.encode()).hexdigest()])
    key = ("AWS4" + secret).encode()
    for part in info.scope.split("/"):
        key = hmac.new(key, part.encode(), hashlib.sha256).digest()
    expected = hmac.new(key, sts.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, info.signature)


# ---- addressing ---------------------------------------------------------------------------

def _host_name(host: str) -> str:
    host = host.strip().lower()
    if host.startswith("["):
        return host.split("]")[0] + "]"
    return host.rsplit(":", 1)[0] if host.count(":") == 1 else host


def _is_address(host: str) -> bool:
    return host.startswith("[") or bool(re.fullmatch(r"[\d.]+", host)) or ":" in host


def split_target(host: Optional[str], path: str, known: set[str]) -> tuple[Optional[str], str, str]:
    """(bucket, key, style). Virtual-hosted when Host starts with a known bucket name, or
    looks like ``<bucket>.s3.<...>``; path-style otherwise."""
    name = _host_name(host or "")
    if name and "." in name and not _is_address(name):
        for bucket in sorted(known, key=len, reverse=True):
            if name.startswith(bucket + "."):
                return bucket, path[1:], "virtual"
        m = re.match(r"^([a-z0-9.-]{3,63})\.s3[.-]", name)
        if m:
            return m.group(1), path[1:], "virtual"
    rest = path[1:] if path.startswith("/") else path
    if not rest:
        return None, "", "path"
    bucket, _, key = rest.partition("/")
    return bucket, key, "path"


def parse_range(value: Optional[str], size: int):
    """(first, last) inclusive; ``"invalid"`` when unsatisfiable; None to serve it all."""
    if not value:
        return None
    m = re.fullmatch(r"\s*bytes=(\d{0,19})-(\d{0,19})\s*", value)
    if not m or (not m.group(1) and not m.group(2)):
        return None
    first, last = m.group(1), m.group(2)
    if not first:
        n = int(last)
        if n == 0 or size == 0:
            return "invalid"
        return max(0, size - n), size - 1
    a = int(first)
    b = int(last) if last else size - 1
    if last and b < a:
        return None
    if a >= size:
        return "invalid"
    return a, min(b, size - 1)


def parse_chunk_size(line: bytes) -> Optional[int]:
    """Size of one aws-chunked chunk from its header line (CRLF removed), or None."""
    size, sep, ext = line.partition(b";")
    if not CHUNK_SIZE_RE.fullmatch(size) or (sep and not CHUNK_EXT_RE.fullmatch(ext)):
        return None
    return int(size, 16)


# ---- the catalog --------------------------------------------------------------------------

@dataclass(frozen=True)
class ObjMeta:
    bucket: str
    key: str
    size: int
    etag: str
    mtime: float
    content_type: str
    kind: str                   # text | table | filler | upload | planted
    seed: str = ""


def _h(*parts: object) -> bytes:
    return hashlib.sha256("|".join(str(p) for p in parts).encode()).digest()


def _frac(*parts: object) -> float:
    return int.from_bytes(_h(*parts)[:4], "big") / 2 ** 32


def _parse_mtime(value: Optional[str]) -> Optional[float]:
    if not value:
        return None
    fmt = "%Y-%m-%d %H:%M" if " " in value else "%Y-%m-%d"
    try:
        return datetime.datetime.strptime(value, fmt).replace(
            tzinfo=datetime.timezone.utc).timestamp()
    except ValueError:
        return None


def _series_key(template: str, n: int) -> str:
    def sub(m: re.Match) -> str:
        width = m.group(1)
        return f"{n:0{width}d}" if width else str(n)
    return SERIES_RE.sub(sub, template, count=1)


def _wav_header(size: int) -> bytes:
    pcm = max(0, size - 44)
    return (b"RIFF" + struct.pack("<I", 36 + pcm) + b"WAVEfmt "
            + struct.pack("<IHHIIHH", 16, 1, 1, 8000, 16000, 2, 16) + b"data"
            + struct.pack("<I", pcm))


def filler_kind(key: str, content_type: str) -> str:
    low = key.lower()
    if low.endswith((".gz", ".tgz")) or "gzip" in content_type:
        return "gz"
    if low.endswith(".wav") or content_type in ("audio/wav", "audio/x-wav"):
        return "wav"
    if low.endswith(".zip") or content_type == "application/zip":
        return "zip"
    if low.endswith(".pdf") or content_type == "application/pdf":
        return "pdf"
    if content_type.startswith("text/") or content_type in ("application/json",
                                                             "application/x-ndjson") \
            or low.endswith((".log", ".txt", ".csv", ".json", ".sql", ".cdr")):
        return "text"
    return "bin"


LINE_WIDTH = 80


def _text_lines(seed: bytes, first: int, last: int) -> bytes:
    out = []
    for i in range(first, last + 1):
        h = hashlib.sha256(seed + i.to_bytes(8, "big")).hexdigest()
        line = f"{i:010d} {h[:8]} {h[8:12]} status=ok ref={h[12:28]} len={int(h[28:32], 16)}"
        out.append(line[:LINE_WIDTH - 1].ljust(LINE_WIDTH - 1) + "\n")
    return "".join(out).encode()


def filler_bytes(meta: ObjMeta, start: int, end: int) -> bytes:
    """Bytes ``[start, end)`` of a filler object: random access, no full-size buffer."""
    end = min(end, meta.size)
    if start >= end:
        return b""
    seed = _h(meta.seed, meta.bucket, meta.key)
    kind = filler_kind(meta.key, meta.content_type)
    if kind == "text":
        data = _text_lines(seed, start // LINE_WIDTH, (end - 1) // LINE_WIDTH)
        off = start - (start // LINE_WIDTH) * LINE_WIDTH
        return data[off:off + end - start]
    block = 65_536
    parts = []
    for b in range(start // block, (end - 1) // block + 1):
        parts.append(hashlib.shake_256(seed + b.to_bytes(8, "big")).digest(block))
    data = b"".join(parts)
    off = start - (start // block) * block
    data = bytearray(data[off:off + end - start])
    header = {"gz": b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03",
              "wav": _wav_header(meta.size), "zip": b"PK\x03\x04\x14\x00\x00\x00\x08\x00",
              "pdf": b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n"}.get(kind, b"")
    if start < len(header):
        piece = header[start:min(len(header), end)]
        data[:len(piece)] = piece
    return bytes(data)


class BucketView:
    """One scenario bucket: sorted keys, per-key metadata and body generation."""

    def __init__(self, cat: "Catalog", spec) -> None:
        self.cat = cat
        self.spec = spec
        self.name: str = spec.name
        self.region: str = spec.region or cat.region
        self.created = _parse_mtime(spec.created) or (
            datetime.datetime(2025, 1, 6, tzinfo=datetime.timezone.utc).timestamp()
            + int(_frac(cat.seed, "s3created", spec.name) * 300 * 86400))
        self._keys: Optional[list[str]] = None
        self._entries: dict[str, tuple[int, int]] = {}
        self._bodies: dict[str, bytes] = {}

    @property
    def keys(self) -> list[str]:
        if self._keys is None:
            entries: dict[str, tuple[int, int]] = {}
            for idx, obj in enumerate(self.spec.objects):
                for n in range(obj.count):
                    key = _series_key(obj.key, n) if obj.count > 1 else obj.key
                    entries.setdefault(key, (idx, n))
            self._entries = entries
            self._keys = sorted(entries)
        return self._keys

    def _body(self, key: str, obj) -> bytes:
        body = self._bodies.get(key)
        if body is None:
            if obj.text is not None:
                body = obj.text.encode("utf-8")
            else:
                body = render_table(self.cat.ctx, obj.table, obj.table_limit)
            self._bodies[key] = body
        return body

    def meta(self, key: str) -> Optional[ObjMeta]:
        _ = self.keys
        entry = self._entries.get(key)
        if entry is None:
            return None
        idx, n = entry
        obj = self.spec.objects[idx]
        seed = self.cat.seed
        base = _parse_mtime(obj.mtime) or (
            DEFAULT_MTIME.timestamp() + int(_frac(seed, "s3mtime", self.name, obj.key)
                                            * 240 * 86400))
        mtime = min(base + n * (60 + int(_frac(seed, "s3step", self.name, key) * 900)),
                    time.time() - 3600)
        if obj.text is not None or obj.table is not None:
            body = self._body(key, obj)
            return ObjMeta(self.name, key, len(body), hashlib.md5(body).hexdigest(), mtime,
                           obj.content_type, "text" if obj.text is not None else "table", seed)
        if obj.size is not None:
            size = obj.size if obj.count == 1 else int(
                obj.size * (0.6 + 0.8 * _frac(seed, "s3size", self.name, key)))
        else:
            size = 512 + int(_frac(seed, "s3size", self.name, key) * 30_000)
        etag = hashlib.md5(_h(seed, "s3etag", self.name, key)).hexdigest()
        return ObjMeta(self.name, key, size, etag, mtime, obj.content_type, "filler", seed)

    def body(self, meta: ObjMeta, start: int, end: int) -> Iterator[bytes]:
        """Chunks of bytes ``[start, end)``."""
        end = min(end, meta.size)
        if meta.kind in ("text", "table"):
            entry = self._entries.get(meta.key)
            if entry is not None:
                yield self._body(meta.key, self.spec.objects[entry[0]])[start:end]
            return
        pos = start
        while pos < end:
            nxt = min(end, pos + SEND_CHUNK)
            yield filler_bytes(meta, pos, nxt)
            pos = nxt


def render_table(ctx: ListenerContext, ref: Optional[str], limit: int) -> bytes:
    scen = ctx.scenario
    if scen is None or not ref:
        return b""
    try:
        cols, rows = scen.lookup(ref)
    except Exception:  # noqa: BLE001 - bad scenario data -> empty file
        return b""
    out = io.StringIO()
    w = csv.writer(out, lineterminator="\n")
    if cols:
        w.writerow(cols)
    for row in rows[:limit]:
        w.writerow(["" if v is None else v for v in row])
    return out.getvalue().encode("utf-8")


@dataclass
class Upload:
    size: int
    etag: str
    mtime: float
    content_type: str
    content: Optional[bytes]
    expires: float
    origin: Optional[tuple[str, str]] = None    # (bucket, key) whose body a copy serves


@dataclass
class SourceView:
    uploads: OrderedDict = field(default_factory=OrderedDict)    # (bucket, key) -> Upload
    deleted: dict = field(default_factory=dict)                   # (bucket, key) -> expires
    multipart: OrderedDict = field(default_factory=OrderedDict)  # upload id -> dict
    tags: OrderedDict = field(default_factory=OrderedDict)       # (bucket, key) -> (tags, expires)
    downloads: deque = field(default_factory=deque)               # (time, bytes)
    bulk_signalled: float = -1e18


class Catalog:
    """Per-context scenario buckets plus what each source changed (uploads, deletes)."""

    def __init__(self, ctx: ListenerContext) -> None:
        self.ctx = ctx
        self.seed = ctx.seed
        self.scenario = None
        self.buckets: dict[str, BucketView] = {}
        self.region = DEFAULT_REGION
        self.owner_name = "ops"
        self.server = "AmazonS3"
        self.get_max = DEFAULT_GET_MAX
        self.sources: OrderedDict[str, SourceView] = OrderedDict()
        self.kept_bytes = 0
        self.refresh()

    def refresh(self) -> None:
        scen = self.ctx.scenario
        if scen is self.scenario and (self.buckets or scen is None):
            return
        self.scenario = scen
        svc = scen.scenario.services.s3 if scen is not None else None
        self.buckets = {}
        if svc is not None:
            self.region = svc.region
            self.owner_name = svc.owner_name
            self.server = self.ctx.service("s3").banner or svc.server_header
            self.get_max = svc.get_max_bytes
            for b in svc.buckets:
                self.buckets[b.name] = BucketView(self, b)

    @property
    def owner_id(self) -> str:
        return hashlib.sha256(f"{self.seed}|s3owner".encode()).hexdigest()

    def bucket(self, name: Optional[str]) -> Optional[BucketView]:
        self.refresh()
        return self.buckets.get(name or "")

    def token_bucket(self) -> Optional[str]:
        for name in self.buckets:
            if "config" in name or "backup" in name:
                return name
        return next(iter(self.buckets), None)

    # ---- per-source state ---------------------------------------------------------------

    def source(self, ip: str) -> SourceView:
        key = ip_key(ip)
        view = self.sources.get(key)
        if view is None:
            view = self.sources[key] = SourceView()
            while len(self.sources) > MAX_SOURCES:
                _, old = self.sources.popitem(last=False)
                self._release(old.uploads.values())
        else:
            self.sources.move_to_end(key)
        now = time.monotonic()
        stale = [k for k, u in view.uploads.items() if u.expires < now]
        for k in stale:
            self._release([view.uploads.pop(k)])
        for k in [k for k, exp in view.deleted.items() if exp < now]:
            view.deleted.pop(k, None)
        for k in [k for k, m in view.multipart.items() if m["expires"] < now]:
            view.multipart.pop(k, None)
        for k in [k for k, (_t, exp) in view.tags.items() if exp < now]:
            view.tags.pop(k, None)
        return view

    def _release(self, uploads) -> None:
        for u in uploads:
            if u.content is not None:
                self.kept_bytes -= len(u.content)

    def add_upload(self, ip: str, bucket: str, key: str, size: int, etag: str,
                   content_type: str, content: Optional[bytes],
                   origin: Optional[tuple[str, str]] = None) -> None:
        view = self.source(ip)
        view.tags.pop((bucket, key), None)
        if content is not None and (len(content) > KEEP_UPLOAD_BYTES
                                    or self.kept_bytes + len(content) > KEEP_TOTAL_BYTES):
            content = None
        old = view.uploads.pop((bucket, key), None)
        if old is not None:
            self._release([old])
        view.uploads[(bucket, key)] = Upload(size, etag, time.time(), content_type, content,
                                             time.monotonic() + UPLOAD_WINDOW, origin)
        if content is not None:
            self.kept_bytes += len(content)
        view.deleted.pop((bucket, key), None)
        while len(view.uploads) > MAX_UPLOADS_PER_SOURCE:
            _, dropped = view.uploads.popitem(last=False)
            self._release([dropped])

    def delete(self, ip: str, bucket: str, key: str) -> None:
        view = self.source(ip)
        view.tags.pop((bucket, key), None)
        old = view.uploads.pop((bucket, key), None)
        if old is not None:
            self._release([old])
        view.deleted[(bucket, key)] = time.monotonic() + UPLOAD_WINDOW
        while len(view.deleted) > MAX_DELETED_PER_SOURCE:
            view.deleted.pop(next(iter(view.deleted)))

    def planted_for(self, ip: str, bucket: str) -> Optional[bytes]:
        """An AWS credentials file holding the source's own token, for ``plant_token``."""
        if bucket != self.token_bucket():
            return None
        entry = self.ctx.source(ip)
        if entry is None or not entry.plant_token:
            return None
        key_id, secret = self.ctx.source_token(ip)
        return aws_profile("backup", key_id, secret).encode()

    def object(self, ip: str, bucket: BucketView, key: str) -> Optional[ObjMeta]:
        view = self.source(ip)
        up = view.uploads.get((bucket.name, key))
        if up is not None:
            return ObjMeta(bucket.name, key, up.size, up.etag, up.mtime, up.content_type,
                           "upload", self.seed)
        if (bucket.name, key) in view.deleted:
            return None
        if key == AWS_CREDENTIALS_PATH.lstrip("/"):
            body = self.planted_for(ip, bucket.name)
            if body is not None:
                return ObjMeta(bucket.name, key, len(body), hashlib.md5(body).hexdigest(),
                               DEFAULT_MTIME.timestamp(), "text/plain", "planted", self.seed)
        return bucket.meta(key)

    def body(self, ip: str, bucket: BucketView, meta: ObjMeta, start: int,
             end: int) -> Iterator[bytes]:
        if meta.kind == "planted":
            yield (self.planted_for(ip, bucket.name) or b"")[start:end]
            return
        if meta.kind == "upload":
            up = self.source(ip).uploads.get((bucket.name, meta.key))
            if up is not None and up.content is not None:
                yield up.content[start:end]
                return
            origin = up.origin if up is not None else None
            if origin is not None:
                view = self.bucket(origin[0])
                src = view.meta(origin[1]) if view is not None else None
                if view is not None and src is not None and src.size == meta.size:
                    yield from view.body(src, start, end)
                    return
            ob, ok = origin or (meta.bucket, meta.key)
            meta = ObjMeta(ob, ok, meta.size, meta.etag, meta.mtime,
                           "binary/octet-stream", "filler", self.seed)
        yield from bucket.body(meta, start, end)

    def copy(self, ip: str, src_bucket: BucketView, src: ObjMeta, bucket: str, key: str,
             content_type: str) -> None:
        """Store a copy of ``src`` at ``bucket/key`` for this source: kept bytes are copied,
        anything else serves the source's own body (or the same filler)."""
        content: Optional[bytes] = None
        origin: Optional[tuple[str, str]] = (src_bucket.name, src.key)
        if src.kind == "planted":
            content, origin = self.planted_for(ip, src_bucket.name), None
        elif src.kind == "upload":
            up = self.source(ip).uploads.get((src_bucket.name, src.key))
            if up is not None and up.content is not None:
                content, origin = up.content, None
            elif up is not None and up.origin is not None:
                origin = up.origin
        self.add_upload(ip, bucket, key, src.size, src.etag, content_type, content, origin)

    def listing_keys(self, bucket: str, ip: str) -> list[str]:
        """Every key the source would see in ``bucket`` (tests and small buckets)."""
        view = self.bucket(bucket)
        if view is None:
            return []
        return list(self.iter_keys(ip, view, ""))

    def iter_keys(self, ip: str, bucket: BucketView, after: str) -> Iterator[str]:
        """Sorted keys strictly after ``after`` as this source sees them."""
        src = self.source(ip)
        extra = sorted(k for (b, k) in src.uploads if b == bucket.name and k > after)
        planted = AWS_CREDENTIALS_PATH.lstrip("/")
        if planted > after and planted not in bucket.keys and \
                self.planted_for(ip, bucket.name) is not None and planted not in extra:
            bisect.insort(extra, planted)
        base = bucket.keys
        start = bisect.bisect_right(base, after) if after else 0
        last = None
        for key in heapq.merge((base[i] for i in range(start, len(base))), extra):
            if key == last or (bucket.name, key) in src.deleted:
                continue
            last = key
            yield key


_CATALOGS: "weakref.WeakKeyDictionary[ListenerContext, Catalog]" = weakref.WeakKeyDictionary()


def catalog(ctx: ListenerContext) -> Catalog:
    cat = _CATALOGS.get(ctx)
    if cat is None:
        cat = _CATALOGS[ctx] = Catalog(ctx)
    cat.refresh()
    return cat


# ---- listing ------------------------------------------------------------------------------

@dataclass
class Page:
    contents: list[ObjMeta]
    prefixes: list[str]
    truncated: bool
    last: Optional[str]


def _after_upload_markers(ups: list, key_marker: str, id_marker: str) -> list:
    """The uploads, sorted by (key, initiated, upload id), that come after the markers:
    keys after ``key_marker``, plus uploads of ``key_marker`` itself after ``id_marker``.
    A known marker id resumes after that upload in listing order; an unknown one compares
    upload ids as strings."""
    if not id_marker:
        return [u for u in ups if u[0] > key_marker]
    same = [u for u in ups if u[0] == key_marker]
    ids = [u[2] for u in same]
    if id_marker in ids:
        same = same[ids.index(id_marker) + 1:]
    else:
        same = [u for u in same if u[2] > id_marker]
    return same + [u for u in ups if u[0] > key_marker]


def list_page(cat: Catalog, ip: str, bucket: BucketView, prefix: str, delimiter: str,
              after: str, max_keys: int) -> Page:
    contents: list[ObjMeta] = []
    prefixes: list[str] = []
    last: Optional[str] = None
    count = 0
    start = after
    if prefix:
        # Jump to the prefix range without walking every earlier key.
        idx = bisect.bisect_left(bucket.keys, prefix)
        start = max(after, bucket.keys[idx - 1] if idx > 0 else "")
    skip_prefix = after if delimiter and after.endswith(delimiter) else None
    truncated = False
    for key in cat.iter_keys(ip, bucket, start):
        if key <= after:
            continue
        if not key.startswith(prefix):
            if key < prefix:
                continue
            break
        if skip_prefix and key.startswith(skip_prefix):
            continue
        if delimiter:
            i = key.find(delimiter, len(prefix))
            if i >= 0:
                cp = key[:i + len(delimiter)]
                if prefixes and prefixes[-1] == cp:
                    continue
                if count >= max_keys:
                    truncated = True
                    break
                prefixes.append(cp)
                last, count = cp, count + 1
                skip_prefix = cp
                continue
        if count >= max_keys:
            truncated = True
            break
        meta = cat.object(ip, bucket, key)
        if meta is None:
            continue
        contents.append(meta)
        last, count = key, count + 1
    return Page(contents, prefixes, truncated, last)


def encode_token(key: str) -> str:
    return base64.b64encode(b"\x01" + key.encode("utf-8")).decode()


def decode_token(token: str) -> Optional[str]:
    if len(token) > 2048:
        return None
    try:
        raw = base64.b64decode(token, validate=True)
    except (binascii.Error, ValueError):
        return None
    if not raw.startswith(b"\x01"):
        return None
    try:
        return raw[1:].decode("utf-8")
    except UnicodeDecodeError:
        return None


# ---- one request --------------------------------------------------------------------------

def classify(method: str, bucket: Optional[str], key: str, q: dict[str, str],
             req: Request) -> str:
    sub = lambda name: name in q  # noqa: E731
    if method not in ("GET", "HEAD", "PUT", "POST", "DELETE"):
        return "MethodNotAllowed"
    if bucket is None:
        return "ListBuckets" if method in ("GET", "HEAD") else "MethodNotAllowed"
    if not key:
        if method == "GET":
            for name, op in (("location", "GetBucketLocation"), ("acl", "GetBucketAcl"),
                             ("policy", "GetBucketPolicy"), ("uploads", "ListMultipartUploads"),
                             ("versions", "ListObjectVersions")):
                if sub(name):
                    return op
            for name in BUCKET_SUBRESOURCES:
                if sub(name):
                    return "GetBucket" + name[0].upper() + name[1:]
            return "ListObjectsV2" if q.get("list-type") == "2" else "ListObjects"
        if method == "HEAD":
            return "HeadBucket"
        if method == "PUT":
            return "CreateBucket" if not any(sub(n) for n in BUCKET_SUBRESOURCES + ("acl", "policy")) \
                else "PutBucketConfig"
        if method == "DELETE":
            return "DeleteBucket" if not q else "DeleteBucketConfig"
        return "DeleteObjects" if sub("delete") else "PostObject"
    if method == "GET":
        if sub("uploadId"):
            return "ListParts"
        if sub("acl"):
            return "GetObjectAcl"
        if sub("tagging"):
            return "GetObjectTagging"
        if sub("attributes") or sub("retention") or sub("legal-hold"):
            return "GetObjectConfig"
        return "GetObject"
    if method == "HEAD":
        return "HeadObject"
    if method == "PUT":
        copy = req.header("x-amz-copy-source") is not None
        if sub("uploadId") and sub("partNumber"):
            return "UploadPartCopy" if copy else "UploadPart"
        if sub("tagging"):
            return "PutObjectTagging"
        if copy:
            return "CopyObject"
        if sub("acl") or sub("retention") or sub("legal-hold"):
            return "PutObjectConfig"
        return "PutObject"
    if method == "DELETE":
        if sub("uploadId"):
            return "AbortMultipartUpload"
        return "DeleteObjectTagging" if sub("tagging") else "DeleteObject"
    if sub("uploads"):
        return "CreateMultipartUpload"
    if sub("uploadId"):
        return "CompleteMultipartUpload"
    return "PostObjectConfig" if (sub("restore") or sub("select")) else "MethodNotAllowed"


UPLOAD_OPS = ("PutObject", "UploadPart")
ANON_LIST_OPS = ("ListObjects", "ListObjectsV2")
ANON_READ_OPS = ("GetObject", "HeadObject")
DENIED_OPS = ("ListObjectVersions", "CreateBucket", "PutBucketConfig", "DeleteBucket",
              "DeleteBucketConfig", "PostObject", "GetObjectAcl", "GetObjectConfig",
              "UploadPartCopy", "PutObjectConfig", "PostObjectConfig")
ALLOWED_BUCKET_GETS = ("GetBucketLocation", "GetBucketAcl", "GetBucketPolicy",
                       "GetBucketVersioning", "GetBucketTagging")


class BodyStream:
    """Reads a request body of known length straight from the connection. Bytes count
    toward the connection byte cap only when ``counted`` (no quarantine configured)."""

    def __init__(self, conn: Conn, length: int, counted: bool) -> None:
        self.conn = conn
        self.remaining = length
        self.counted = counted
        self.raw = 0

    def _charge(self, n: int) -> None:
        self.remaining -= n
        self.raw += n
        if self.counted:
            self.conn.count_bytes(n)

    async def read(self, n: int) -> bytes:
        n = min(n, self.remaining)
        if n <= 0:
            return b""
        try:
            data = await asyncio.wait_for(self.conn.reader.read(n), timeout=self.conn.timeout)
        except (asyncio.TimeoutError, ConnectionError):
            raise ConnClosed("timeout") from None
        if not data:
            raise ConnClosed("eof")
        self._charge(len(data))
        return data

    async def readexactly(self, n: int) -> bytes:
        out = b""
        while len(out) < n:
            out += await self.read(n - len(out))
        return out

    async def readline(self, cap: int) -> Optional[bytes]:
        """One CRLF-terminated line inside the body, without the CRLF; None when longer
        than ``cap``, not CRLF-terminated or running past the declared length."""
        if self.remaining <= 0:
            return None
        try:
            line = await asyncio.wait_for(self.conn.reader.readuntil(b"\n"),
                                          timeout=self.conn.timeout)
        except (asyncio.LimitOverrunError, asyncio.IncompleteReadError):
            return None
        except (asyncio.TimeoutError, ConnectionError):
            raise ConnClosed("timeout") from None
        self._charge(len(line))
        if len(line) > cap + 2 or self.remaining < 0 or not line.endswith(b"\r\n"):
            return None
        return line[:-2]


class Exchange:
    """One S3 request and its response, with logging fields gathered along the way."""

    def __init__(self, conn: Conn, req: Request, cat: Catalog) -> None:
        self.conn = conn
        self.ctx = conn.ctx
        self.req = req
        self.cat = cat
        self.ip = conn.src_ip
        self.request_id, self.host_id = request_ids()
        self.log: dict = {}
        self.close = False
        self.status = 200
        self.bytes_out = 0
        try:
            pairs = parse_qsl(req.query, keep_blank_values=True, max_num_fields=50)
        except ValueError:
            pairs = []
            self.log["query_overflow"] = True
        self.q: dict[str, str] = {}
        for k, v in pairs:
            self.q.setdefault(k, v)
        self.auth = parse_auth(req, self.q)
        self.bucket_name, self.key, self.style = split_target(
            req.header("host"), req.path, set(cat.buckets))
        self.op = classify(req.method, self.bucket_name, self.key, self.q, req)

    # ---- sending ------------------------------------------------------------------------

    def keep_alive(self) -> bool:
        conn_hdr = (self.req.header("connection") or "").lower()
        keep = ("close" not in conn_hdr) if self.req.version == "HTTP/1.1" \
            else ("keep-alive" in conn_hdr)
        return keep and not self.close

    async def send(self, status: int, body: bytes = b"", headers=None,
                   content_type: Optional[str] = "application/xml") -> None:
        self.status = status
        hdrs = list(headers or [])
        if content_type and (body or self.req.method == "HEAD"):
            hdrs.insert(0, ("Content-Type", content_type))
        head = response_head(status, self.cat.server, self.request_id, self.host_id, hdrs,
                             len(body), self.keep_alive())
        await self.conn.write(head if self.req.method == "HEAD" else head + body)

    async def send_error(self, err: S3Error, headers=None) -> None:
        self.log["s3_error"] = err.code
        if err.close:
            self.close = True
        body = b"" if self.req.method == "HEAD" else error_xml(err, self.request_id,
                                                               self.host_id)
        hdrs = list(headers or [])
        if err.code == "MethodNotAllowed":
            hdrs.append(("Allow", "GET, HEAD, PUT, POST, DELETE"))
        self.status = err.status
        head = response_head(err.status, self.cat.server, self.request_id, self.host_id,
                             [("Content-Type", "application/xml")] + hdrs, len(body),
                             self.keep_alive())
        await self.conn.write(head + body)

    # ---- auth ---------------------------------------------------------------------------

    def authorize(self) -> None:
        """Raise S3Error when the claimed identity is refused. Anonymous passes here; the
        operation decides what anonymous may do."""
        info = self.auth
        akid = info.access_key_id
        if info.scheme != "anonymous":
            self.log["auth"] = info.scheme
        planted = self.ctx.honeytoken_in(akid) if akid else None
        if planted:
            self.log.update(honeytoken=planted, high_signal=True, signal="s3_planted_key")
        if akid:
            self.log["access_key_id"] = akid
        if info.region:
            self.log["region"] = info.region
        if info.signed_headers:
            self.log["signed_headers"] = ";".join(info.signed_headers)[:200]
        if info.security_token:
            self.log["security_token"] = info.security_token[:500]
        if info.malformed:
            self.log["auth_malformed"] = info.malformed
            if info.scheme == "unknown":
                raise S3Error("InvalidArgument", "Unsupported Authorization Type",
                              ArgumentName="Authorization")
            if info.scheme == "sigv4_query":
                raise S3Error("AuthorizationQueryParametersError")
            raise S3Error("AuthorizationHeaderMalformed")
        if info.scheme == "anonymous":
            return
        if expired(info, time.time()):
            raise S3Error("AccessDenied", "Request has expired",
                          **{"X-Amz-Expires": str(info.expires or 0),
                             "ServerTime": iso_date(time.time())})
        assert akid is not None
        settings = self.ctx.service("s3")
        ok, reason = self.decide(akid, planted, settings)
        cache = self.conn.state.setdefault("s3_auth", {})
        if (akid, ok, reason) not in cache:
            if len(cache) > 64:
                cache.clear()
            cache[(akid, ok, reason)] = True
            data = {"method": info.scheme, "region": info.region or "",
                    "service": info.service or "", "path": self.req.path[:200]}
            if planted:
                data.update(honeytoken=planted, high_signal=True, signal="s3_planted_key")
            if reason:
                data["reason"] = reason
            self.conn.emit("auth_attempt", "Authentication attempt", username=akid,
                           success=ok, client=self.req.header("user-agent"), data=data)
        if not ok:
            if reason == "signature_mismatch":
                raise S3Error("SignatureDoesNotMatch", AWSAccessKeyId=akid)
            raise S3Error("InvalidAccessKeyId", AWSAccessKeyId=akid)
        self.conn.authenticated_as = akid

    def decide(self, akid: str, planted: Optional[str],
               settings: ServiceSettings) -> tuple[bool, Optional[str]]:
        policy = settings.policy
        if policy.accept == "none":
            return False, "policy"
        secret = next((pw for user, pw in settings.accounts if user == akid), None)
        if secret is not None:
            if secret in ("*", "") or self.auth.scheme not in ("sigv4", "sigv4_query"):
                return True, None
            if verify_sigv4(self.req, self.auth, secret):
                return True, None
            return False, "signature_mismatch"
        if planted:
            return True, None
        ok = self.ctx.logins.decide("s3", self.ip, akid, "", policy, [])
        return ok, (None if ok else "policy")

    # ---- dispatch -----------------------------------------------------------------------

    def bucket_or_error(self) -> BucketView:
        name = self.bucket_name or ""
        bucket = self.cat.bucket(name)
        if bucket is None:
            if not BUCKET_NAME_RE.fullmatch(name):
                raise S3Error("InvalidBucketName", BucketName=name[:255])
            raise S3Error("NoSuchBucket", BucketName=name[:255])
        return bucket

    def check_access(self, bucket: Optional[BucketView]) -> None:
        anonymous = self.auth.scheme == "anonymous"
        op = self.op
        if anonymous:
            if bucket is not None and (
                    (op in ANON_LIST_OPS and bucket.spec.public_list)
                    or (op in ANON_READ_OPS and bucket.spec.public_read)
                    or (op in ("HeadBucket", "GetBucketLocation")
                        and (bucket.spec.public_list or bucket.spec.public_read))):
                return
            raise S3Error("AccessDenied")
        if op in DENIED_OPS or op.startswith("GetBucket") and op not in ALLOWED_BUCKET_GETS:
            raise S3Error("AccessDenied")
        if bucket is not None and op != "GetBucketLocation" and self.auth.region \
                and self.auth.region != bucket.region:
            code = "AuthorizationQueryParametersError" if self.auth.scheme == "sigv4_query" \
                else "AuthorizationHeaderMalformed"
            raise S3Error(code, f"The authorization header is malformed; the region "
                                f"'{self.auth.region}' is wrong; expecting '{bucket.region}'",
                          Region=bucket.region)

    async def run(self, length: Optional[int]) -> None:
        req = self.req
        try:
            if self.op in UPLOAD_OPS:
                await self.upload(length)
                return
            if length and length > MAX_SMALL_BODY:
                raise S3Error("MaxMessageLengthExceeded", close=True)
            if length:
                req.body = await BodyStream(self.conn, length, counted=True).readexactly(length)
            if self.key:
                self._note_key()
            self.authorize()
            if self.op == "MethodNotAllowed":
                raise S3Error("MethodNotAllowed", Method=req.method[:16],
                              ResourceType="OBJECT" if self.key else "BUCKET")
            await self.dispatch()
        except S3Error as err:
            headers = []
            if "Region" in err.extra:
                headers.append(("x-amz-bucket-region", err.extra["Region"]))
            await self.send_error(err, headers)

    async def dispatch(self) -> None:
        op = self.op
        if op == "ListBuckets":
            self.check_access(None)
            await self.list_buckets()
            return
        if op == "CreateBucket" and self.auth.scheme != "anonymous":
            raise S3Error("AccessDenied")
        bucket = self.bucket_or_error()
        self.check_access(bucket)
        handler = {
            "HeadBucket": self.head_bucket, "GetBucketLocation": self.bucket_location,
            "GetBucketAcl": self.bucket_acl, "GetBucketPolicy": self.bucket_policy,
            "ListObjects": self.list_objects, "ListObjectsV2": self.list_objects,
            "GetObject": self.get_object, "HeadObject": self.get_object,
            "DeleteObject": self.delete_object, "DeleteObjects": self.delete_objects,
            "CreateMultipartUpload": self.create_multipart,
            "CompleteMultipartUpload": self.complete_multipart,
            "AbortMultipartUpload": self.abort_multipart,
            "ListMultipartUploads": self.list_multipart_uploads, "ListParts": self.list_parts,
            "CopyObject": self.copy_object, "GetObjectTagging": self.get_object_tagging,
            "PutObjectTagging": self.put_object_tagging,
            "DeleteObjectTagging": self.delete_object_tagging,
            "GetBucketVersioning": self.bucket_versioning,
            "GetBucketTagging": self.bucket_tagging,
        }.get(op)
        if handler is None:
            raise S3Error("AccessDenied")
        await handler(bucket)

    # ---- bucket operations --------------------------------------------------------------

    async def list_buckets(self) -> None:
        if self.auth.scheme == "anonymous":
            raise S3Error("AccessDenied")
        self.log["signal"] = self.log.get("signal", "s3_list")
        items = "".join(f"<Bucket><Name>{xml_text(b.name)}</Name><CreationDate>"
                        f"{iso_date(b.created)}</CreationDate></Bucket>"
                        for b in sorted(self.cat.buckets.values(), key=lambda b: b.name))
        body = (f'{XML_DECL}<ListAllMyBucketsResult xmlns="{XMLNS}"><Owner><ID>'
                f"{self.cat.owner_id}</ID><DisplayName>{xml_text(self.cat.owner_name)}"
                f"</DisplayName></Owner><Buckets>{items}</Buckets></ListAllMyBucketsResult>")
        self.log["returned"] = len(self.cat.buckets)
        await self.send(200, body.encode())

    async def head_bucket(self, bucket: BucketView) -> None:
        await self.send(200, b"", [("x-amz-bucket-region", bucket.region),
                                   ("x-amz-access-point-alias", "false")], None)

    async def bucket_location(self, bucket: BucketView) -> None:
        region = "" if bucket.region == "us-east-1" else xml_text(bucket.region)
        body = f'{XML_DECL}<LocationConstraint xmlns="{XMLNS}">{region}</LocationConstraint>'
        await self.send(200, body.encode())

    def _owner(self) -> str:
        return (f"<Owner><ID>{self.cat.owner_id}</ID><DisplayName>"
                f"{xml_text(self.cat.owner_name)}</DisplayName></Owner>")

    async def bucket_acl(self, bucket: BucketView) -> None:
        grants = (f'<Grant><Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" '
                  f'xsi:type="CanonicalUser"><ID>{self.cat.owner_id}</ID><DisplayName>'
                  f"{xml_text(self.cat.owner_name)}</DisplayName></Grantee>"
                  "<Permission>FULL_CONTROL</Permission></Grant>")
        if bucket.spec.public_list or bucket.spec.public_read:
            grants += ('<Grant><Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" '
                       'xsi:type="Group"><URI>http://acs.amazonaws.com/groups/global/AllUsers'
                       "</URI></Grantee><Permission>READ</Permission></Grant>")
        body = (f'{XML_DECL}<AccessControlPolicy xmlns="{XMLNS}">{self._owner()}'
                f"<AccessControlList>{grants}</AccessControlList></AccessControlPolicy>")
        await self.send(200, body.encode())

    async def bucket_policy(self, bucket: BucketView) -> None:
        arn = f"arn:aws:s3:::{bucket.name}"
        statements = []
        if bucket.spec.public_read:
            statements.append({"Sid": "PublicReadGetObject", "Effect": "Allow",
                               "Principal": "*", "Action": "s3:GetObject",
                               "Resource": f"{arn}/*"})
        if bucket.spec.public_list:
            statements.append({"Sid": "PublicList", "Effect": "Allow", "Principal": "*",
                               "Action": "s3:ListBucket", "Resource": arn})
        statements.append({
            "Sid": "AppRoleAccess", "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{FAKE_ACCOUNT_ID}:role/"
                                 f"{self.cat.owner_name}-storage-rw"},
            "Action": ["s3:GetObject", "s3:PutObject", "s3:ListBucket"],
            "Resource": [arn, f"{arn}/*"]})
        body = json.dumps({"Version": "2012-10-17", "Statement": statements})
        await self.send(200, body.encode(), content_type="application/json")

    def _int_param(self, name: str, default: int) -> int:
        raw = self.q.get(name)
        if raw is None:
            return default
        if not re.fullmatch(r"\d{1,9}", raw):
            raise S3Error("InvalidArgument", f"Provided {name} not an integer or within "
                          "integer range", ArgumentName=name, ArgumentValue=raw[:64])
        return int(raw)

    async def list_objects(self, bucket: BucketView) -> None:
        v2 = self.op == "ListObjectsV2"
        q = self.q
        prefix = q.get("prefix", "")[:MAX_KEY_BYTES]
        delimiter = q.get("delimiter", "")[:16]
        max_keys = min(self._int_param("max-keys", MAX_LIST_KEYS), MAX_LIST_KEYS)
        url = q.get("encoding-type") == "url"
        if "encoding-type" in q and not url:
            raise S3Error("InvalidArgument", "Invalid Encoding Method specified in Request",
                          ArgumentName="encoding-type")
        token = None
        if v2:
            start_after = q.get("start-after", "")[:MAX_KEY_BYTES]
            after = start_after
            if "continuation-token" in q:
                token = q["continuation-token"]
                decoded = decode_token(token)
                if decoded is None:
                    raise S3Error("InvalidArgument", "The continuation token provided is "
                                  "incorrect", ArgumentName="continuation-token")
                after = max(after, decoded)
        else:
            after = q.get("marker", "")[:MAX_KEY_BYTES]
        self.log.update(signal=self.log.get("signal", "s3_list"), prefix=prefix[:200],
                        delimiter=delimiter, max_keys=max_keys)
        page = list_page(self.cat, self.ip, bucket, prefix, delimiter, after, max_keys)
        self.log["returned"] = len(page.contents) + len(page.prefixes)
        if page.truncated:
            self.log["truncated"] = True
        enc = (lambda s: quote_plus(s, safe="/")) if url else (lambda s: s)  # noqa: E731
        parts = [f'{XML_DECL}<ListBucketResult xmlns="{XMLNS}"><Name>{xml_text(bucket.name)}'
                 f"</Name><Prefix>{xml_text(enc(prefix))}</Prefix>"]
        if v2:
            if token is not None:
                parts.append(f"<ContinuationToken>{xml_text(token)}</ContinuationToken>")
            if q.get("start-after"):
                parts.append(f"<StartAfter>{xml_text(enc(q['start-after']))}</StartAfter>")
            parts.append(f"<KeyCount>{len(page.contents) + len(page.prefixes)}</KeyCount>")
        else:
            parts.append(f"<Marker>{xml_text(enc(after))}</Marker>")
        parts.append(f"<MaxKeys>{max_keys}</MaxKeys>")
        if delimiter:
            parts.append(f"<Delimiter>{xml_text(enc(delimiter))}</Delimiter>")
        if url:
            parts.append("<EncodingType>url</EncodingType>")
        parts.append(f"<IsTruncated>{'true' if page.truncated else 'false'}</IsTruncated>")
        if page.truncated and page.last is not None:
            if v2:
                parts.append(f"<NextContinuationToken>{encode_token(page.last)}"
                             "</NextContinuationToken>")
            elif delimiter:
                parts.append(f"<NextMarker>{xml_text(enc(page.last))}</NextMarker>")
        owner = "" if v2 else self._owner()
        for m in page.contents:
            parts.append(f"<Contents><Key>{xml_text(enc(m.key))}</Key><LastModified>"
                         f"{iso_date(m.mtime)}</LastModified><ETag>&quot;{m.etag}&quot;</ETag>"
                         f"<Size>{m.size}</Size>{owner}<StorageClass>STANDARD</StorageClass>"
                         "</Contents>")
        for p in page.prefixes:
            parts.append(f"<CommonPrefixes><Prefix>{xml_text(enc(p))}</Prefix></CommonPrefixes>")
        parts.append("</ListBucketResult>")
        await self.send(200, "".join(parts).encode())

    # ---- object operations --------------------------------------------------------------

    def _note_key(self) -> None:
        if ".." in self.key.split("/") or "%2e%2e" in self.req.target.lower():
            self.log["path_traversal"] = True

    async def get_object(self, bucket: BucketView) -> None:
        meta = self.cat.object(self.ip, bucket, self.key)
        if meta is None:
            raise S3Error("NoSuchKey", Key=self.key[:MAX_KEY_BYTES])
        head = self.req.method == "HEAD"
        rng_hdr = self.req.header("range")
        if rng_hdr:
            self.log["range"] = rng_hdr[:100]
        rng = parse_range(rng_hdr, meta.size)
        if rng == "invalid":
            raise S3Error("InvalidRange", RangeRequested=rng_hdr[:100] if rng_hdr else "",
                          ActualObjectSize=str(meta.size))
        status, first, last = 200, 0, meta.size - 1
        headers = [("Last-Modified", http_date(meta.mtime)), ("ETag", f'"{meta.etag}"'),
                   ("Accept-Ranges", "bytes"), ("Content-Type", meta.content_type)]
        if isinstance(rng, tuple):
            status, (first, last) = 206, rng
            headers.append(("Content-Range", f"bytes {first}-{last}/{meta.size}"))
        length = max(0, last - first + 1)
        self.log["size"] = meta.size
        if head:
            self.status = status
            await self.conn.write(response_head(status, self.cat.server, self.request_id,
                                                self.host_id, headers, length,
                                                self.keep_alive()))
            return
        served = self.conn.state.get("s3_served", 0)
        if served >= MAX_CONN_SERVED:
            raise S3Error("SlowDown", close=True)
        cap = min(self.cat.get_max, MAX_CONN_SERVED - served)
        send = min(length, cap)
        if send < length:
            self.close = True
            self.log["truncated"] = True
        self.status = status
        await self.conn.write(response_head(status, self.cat.server, self.request_id,
                                            self.host_id, headers, length, self.keep_alive()))
        for chunk in self.cat.body(self.ip, bucket, meta, first, first + send):
            await self.conn.write(chunk)
            self.bytes_out += len(chunk)
        self.conn.state["s3_served"] = served + self.bytes_out
        self.log["signal"] = self.log.get("signal", "s3_download")
        self.note_download()

    def note_download(self) -> None:
        view = self.cat.source(self.ip)
        now = time.monotonic()
        view.downloads.append((now, self.bytes_out))
        while view.downloads and now - view.downloads[0][0] > BULK_WINDOW:
            view.downloads.popleft()
        while len(view.downloads) > BULK_DOWNLOAD_COUNT * 4:
            view.downloads.popleft()
        total = sum(b for _, b in view.downloads)
        if (len(view.downloads) >= BULK_DOWNLOAD_COUNT or total >= BULK_DOWNLOAD_BYTES) \
                and now - view.bulk_signalled > BULK_WINDOW:
            view.bulk_signalled = now
            # Outranks the planted-key signal: the token name stays in data.honeytoken.
            if self.log.get("signal") in (None, "s3_download", "s3_planted_key"):
                self.log.update(signal="s3_bulk_download", high_signal=True)
            self.log.update(window_downloads=len(view.downloads), window_bytes=total)

    async def bucket_versioning(self, bucket: BucketView) -> None:
        # A bucket that never had versioning enabled: an empty configuration.
        await self.send(200, f'{XML_DECL}<VersioningConfiguration xmlns="{XMLNS}"/>'.encode())

    async def bucket_tagging(self, bucket: BucketView) -> None:
        raise S3Error("NoSuchTagSet", BucketName=bucket.name)

    def _tag_target(self, bucket: BucketView) -> ObjMeta:
        meta = self.cat.object(self.ip, bucket, self.key)
        if meta is None:
            raise S3Error("NoSuchKey", Key=self.key[:MAX_KEY_BYTES])
        return meta

    async def get_object_tagging(self, bucket: BucketView) -> None:
        self._tag_target(bucket)
        tags, _ = self.cat.source(self.ip).tags.get((bucket.name, self.key), ([], 0))
        body = "".join(f"<Tag><Key>{xml_text(k)}</Key><Value>{xml_text(v)}</Value></Tag>"
                       for k, v in tags)
        await self.send(200, f'{XML_DECL}<Tagging xmlns="{XMLNS}"><TagSet>{body}</TagSet>'
                             "</Tagging>".encode())

    async def put_object_tagging(self, bucket: BucketView) -> None:
        self._tag_target(bucket)
        text = self.req.body.decode("utf-8", "replace")
        if "<Tagging" not in text or "<TagSet" not in text:
            raise S3Error("MalformedXML")
        tags: list[tuple[str, str]] = []
        for block in _xml_blocks(text, "Tag")[:MAX_OBJECT_TAGS + 1]:
            k, v = _xml_blocks(block, "Key")[:1], _xml_blocks(block, "Value")[:1]
            if not k or not v:
                raise S3Error("MalformedXML")
            tags.append((_xml_unescape(k[0]), _xml_unescape(v[0])))
        if len(tags) > MAX_OBJECT_TAGS:
            raise S3Error("BadRequest", "Object tags cannot be greater than 10")
        keys = [k for k, _ in tags]
        if any(not k for k in keys):
            raise S3Error("InvalidTag", "The TagKey you have provided is invalid")
        if any(len(k) > 128 for k in keys):
            raise S3Error("InvalidTag", "The TagKey you have provided is too long, max 128")
        if any(len(v) > 256 for _, v in tags):
            raise S3Error("InvalidTag", "The TagValue you have provided is too long, max 256")
        if len(set(keys)) != len(keys):
            raise S3Error("InvalidTag", "Cannot provide multiple Tags with the same key")
        view = self.cat.source(self.ip)
        view.tags.pop((bucket.name, self.key), None)
        view.tags[(bucket.name, self.key)] = (tags, time.monotonic() + UPLOAD_WINDOW)
        while len(view.tags) > MAX_TAGGED_PER_SOURCE:
            view.tags.popitem(last=False)
        self.log["tag_count"] = len(tags)
        await self.send(200, b"", content_type=None)

    async def delete_object_tagging(self, bucket: BucketView) -> None:
        self._tag_target(bucket)
        self.cat.source(self.ip).tags.pop((bucket.name, self.key), None)
        await self.send(204, b"", content_type=None)

    async def copy_object(self, bucket: BucketView) -> None:
        # The query suffix (?versionId=) is split off the encoded header, so an encoded
        # "%3F" in the key stays part of the key.
        header = (self.req.header("x-amz-copy-source") or "")[:6 * MAX_KEY_BYTES]
        encoded, sep, query = header.partition("?")
        raw = unquote(encoded)[:2 * MAX_KEY_BYTES]
        self.log["copy_source"] = (raw + sep + query[:100])[:500]
        path = raw.lstrip("/")
        src_name, _, src_key = path.partition("/")
        if not src_name or not src_key:
            raise S3Error("InvalidArgument", "Copy Source must mention the source bucket and "
                          "key: sourcebucket/sourcekey", ArgumentName="x-amz-copy-source",
                          ArgumentValue=raw[:200])
        if len(self.key.encode()) > MAX_KEY_BYTES:
            raise S3Error("InvalidArgument", "Your key is too long", ArgumentName="key")
        src_bucket = self.cat.bucket(src_name)
        if src_bucket is None:
            raise S3Error("NoSuchBucket", BucketName=src_name[:255])
        src = self.cat.object(self.ip, src_bucket, src_key)
        if src is None:
            raise S3Error("NoSuchKey", Key=src_key[:MAX_KEY_BYTES])
        replace = (self.req.header("x-amz-metadata-directive") or "").upper() == "REPLACE"
        if src_bucket.name == bucket.name and src_key == self.key and not replace:
            raise S3Error("InvalidRequest", "This copy request is illegal because it is trying "
                          "to copy an object to itself without changing the object's metadata, "
                          "storage class, website redirect location or encryption attributes.")
        if src.size > MAX_OBJECT_SIZE:
            raise S3Error("InvalidRequest", "The specified copy source is larger than the "
                          f"maximum allowable size for a copy source: {MAX_OBJECT_SIZE}")
        content_type = (self.req.header("content-type") or "binary/octet-stream") if replace \
            else src.content_type
        self.cat.copy(self.ip, src_bucket, src, bucket.name, self.key, content_type)
        self.log["size"] = src.size
        body = (f'{XML_DECL}<CopyObjectResult xmlns="{XMLNS}"><LastModified>'
                f"{iso_date(time.time())}</LastModified><ETag>&quot;{src.etag}&quot;</ETag>"
                "</CopyObjectResult>")
        await self.send(200, body.encode())

    async def delete_object(self, bucket: BucketView) -> None:
        self.cat.delete(self.ip, bucket.name, self.key)
        await self.send(204, b"", content_type=None)

    async def delete_objects(self, bucket: BucketView) -> None:
        text = self.req.body.decode("utf-8", "replace")
        if "<Delete" not in text:
            raise S3Error("MalformedXML")
        keys = [_xml_unescape(k) for k in re.findall(r"<Key>(.*?)</Key>", text, re.S)[:1000]]
        quiet = bool(re.search(r"<Quiet>\s*true\s*</Quiet>", text, re.I))
        for k in keys:
            self.cat.delete(self.ip, bucket.name, k[:MAX_KEY_BYTES])
        self.log["delete_count"] = len(keys)
        body = "" if quiet else "".join(f"<Deleted><Key>{xml_text(k)}</Key></Deleted>"
                                        for k in keys)
        await self.send(200, f'{XML_DECL}<DeleteResult xmlns="{XMLNS}">{body}</DeleteResult>'
                        .encode())

    # ---- uploads ------------------------------------------------------------------------

    async def create_multipart(self, bucket: BucketView) -> None:
        view = self.cat.source(self.ip)
        uid = base64.urlsafe_b64encode(os.urandom(48)).decode().rstrip("=")
        view.multipart[uid] = {"bucket": bucket.name, "key": self.key, "parts": {},
                               "content_type": self.req.header("content-type")
                               or "binary/octet-stream",
                               "initiated": time.time(),
                               "expires": time.monotonic() + UPLOAD_WINDOW}
        while len(view.multipart) > MAX_MULTIPART_PER_SOURCE:
            view.multipart.popitem(last=False)
        self.log["upload_id"] = uid
        body = (f'{XML_DECL}<InitiateMultipartUploadResult xmlns="{XMLNS}"><Bucket>'
                f"{xml_text(bucket.name)}</Bucket><Key>{xml_text(self.key)}</Key><UploadId>"
                f"{uid}</UploadId></InitiateMultipartUploadResult>")
        await self.send(200, body.encode())

    def _multipart(self, bucket: BucketView) -> dict:
        uid = self.q.get("uploadId", "")
        self.log["upload_id"] = uid[:100]
        mpu = self.cat.source(self.ip).multipart.get(uid)
        if mpu is None or mpu["bucket"] != bucket.name or mpu["key"] != self.key:
            raise S3Error("NoSuchUpload", UploadId=uid[:100])
        return mpu

    async def complete_multipart(self, bucket: BucketView) -> None:
        mpu = self._multipart(bucket)
        text = self.req.body.decode("utf-8", "replace")
        listed = [int(n) for n in re.findall(r"<PartNumber>\s*(\d{1,5})\s*</PartNumber>",
                                             text)[:10_000]]
        if not listed:
            raise S3Error("MalformedXML")
        if any(n not in mpu["parts"] for n in listed):
            raise S3Error("InvalidPart")
        md5s = b"".join(bytes.fromhex(mpu["parts"][n][1]) for n in listed)
        etag = f"{hashlib.md5(md5s).hexdigest()}-{len(listed)}"
        size = sum(mpu["parts"][n][0] for n in listed)
        self.cat.add_upload(self.ip, bucket.name, self.key, size, etag, mpu["content_type"],
                            None)
        self.cat.source(self.ip).multipart.pop(self.q.get("uploadId"), None)
        self.log.update(size=size, parts=len(listed))
        host = self.req.header("host") or "localhost"
        body = (f'{XML_DECL}<CompleteMultipartUploadResult xmlns="{XMLNS}"><Location>'
                f"http://{xml_text(host[:200])}/{xml_text(bucket.name)}/"
                f"{xml_text(quote(self.key))}</Location><Bucket>{xml_text(bucket.name)}"
                f"</Bucket><Key>{xml_text(self.key)}</Key><ETag>&quot;{etag}&quot;</ETag>"
                "</CompleteMultipartUploadResult>")
        await self.send(200, body.encode())

    def _initiator(self) -> str:
        return (f"<Initiator><ID>{self.cat.owner_id}</ID><DisplayName>"
                f"{xml_text(self.cat.owner_name)}</DisplayName></Initiator>{self._owner()}")

    async def list_multipart_uploads(self, bucket: BucketView) -> None:
        prefix = self.q.get("prefix", "")[:MAX_KEY_BYTES]
        max_uploads = min(self._int_param("max-uploads", MAX_LIST_KEYS), MAX_LIST_KEYS)
        key_marker = self.q.get("key-marker", "")[:MAX_KEY_BYTES]
        # S3 ignores upload-id-marker unless key-marker is set.
        id_marker = self.q.get("upload-id-marker", "")[:MAX_UPLOAD_ID] if key_marker else ""
        ups = sorted(((m["key"], m["initiated"], uid)
                      for uid, m in self.cat.source(self.ip).multipart.items()
                      if m["bucket"] == bucket.name and m["key"].startswith(prefix)))
        if key_marker:
            ups = _after_upload_markers(ups, key_marker, id_marker)
            self.log.update(key_marker=key_marker[:200], upload_id_marker=id_marker[:100])
        truncated = len(ups) > max_uploads
        ups = ups[:max_uploads]
        items = "".join(f"<Upload><Key>{xml_text(k)}</Key><UploadId>{uid}</UploadId>"
                        f"{self._initiator()}<StorageClass>STANDARD</StorageClass><Initiated>"
                        f"{iso_date(t)}</Initiated></Upload>" for k, t, uid in ups)
        next_key = xml_text(ups[-1][0]) if ups else ""
        next_id = ups[-1][2] if ups else ""
        prefix_xml = f"<Prefix>{xml_text(prefix)}</Prefix>" if "prefix" in self.q else ""
        body = (f'{XML_DECL}<ListMultipartUploadsResult xmlns="{XMLNS}"><Bucket>'
                f"{xml_text(bucket.name)}</Bucket><KeyMarker>{xml_text(key_marker)}</KeyMarker>"
                f"<UploadIdMarker>{xml_text(id_marker)}</UploadIdMarker><NextKeyMarker>{next_key}</NextKeyMarker>"
                f"<NextUploadIdMarker>{next_id}</NextUploadIdMarker>{prefix_xml}<MaxUploads>"
                f"{max_uploads}</MaxUploads><IsTruncated>{str(truncated).lower()}"
                f"</IsTruncated>{items}</ListMultipartUploadsResult>")
        self.log["returned"] = len(ups)
        await self.send(200, body.encode())

    async def list_parts(self, bucket: BucketView) -> None:
        mpu = self._multipart(bucket)
        max_parts = min(self._int_param("max-parts", MAX_LIST_PARTS), MAX_LIST_PARTS)
        marker = self._int_param("part-number-marker", 0)
        numbers = sorted(n for n in mpu["parts"] if n > marker)
        truncated = len(numbers) > max_parts
        numbers = numbers[:max_parts]
        parts = "".join(f"<Part><PartNumber>{n}</PartNumber><LastModified>"
                        f"{iso_date(mpu['parts'][n][2])}</LastModified><ETag>&quot;"
                        f"{mpu['parts'][n][1]}&quot;</ETag><Size>{mpu['parts'][n][0]}</Size>"
                        "</Part>" for n in numbers)
        body = (f'{XML_DECL}<ListPartsResult xmlns="{XMLNS}"><Bucket>{xml_text(bucket.name)}'
                f"</Bucket><Key>{xml_text(self.key)}</Key><UploadId>{xml_text(self.q.get('uploadId'))}"
                f"</UploadId>{self._initiator()}<StorageClass>STANDARD</StorageClass>"
                f"<PartNumberMarker>{marker}</PartNumberMarker><NextPartNumberMarker>"
                f"{numbers[-1] if numbers else 0}</NextPartNumberMarker><MaxParts>{max_parts}"
                f"</MaxParts><IsTruncated>{str(truncated).lower()}</IsTruncated>{parts}"
                "</ListPartsResult>")
        self.log["returned"] = len(numbers)
        await self.send(200, body.encode())

    async def abort_multipart(self, bucket: BucketView) -> None:
        self._multipart(bucket)
        self.cat.source(self.ip).multipart.pop(self.q.get("uploadId"), None)
        await self.send(204, b"", content_type=None)

    async def upload(self, length: Optional[int]) -> None:
        """PutObject / UploadPart: decide everything that can refuse the request before
        reading a byte of the body, then stream it into the quarantine."""
        req = self.req
        if req.header("transfer-encoding") is not None:
            raise S3Error("MissingContentLength", close=True)
        if length is None:
            raise S3Error("MissingContentLength", close=True)
        self.log["content_length"] = length
        if length > MAX_OBJECT_SIZE:
            raise S3Error("EntityTooLarge", close=True, ProposedSize=str(length),
                          MaxSizeAllowed=str(MAX_OBJECT_SIZE))
        self._note_key()
        try:
            self.authorize()
            bucket = self.bucket_or_error()
            self.check_access(bucket)
            if len(self.key.encode()) > MAX_KEY_BYTES:
                raise S3Error("InvalidArgument", "Your key is too long", ArgumentName="key")
            part = None
            mpu = None
            if self.op == "UploadPart":
                raw = self.q.get("partNumber", "")
                if not re.fullmatch(r"\d{1,5}", raw) or not 1 <= int(raw) <= 10_000:
                    raise S3Error("InvalidArgument", "Part number must be an integer between "
                                  "1 and 10000, inclusive", ArgumentName="partNumber")
                part = int(raw)
                mpu = self._multipart(bucket)
                self.log["part_number"] = part
        except S3Error as err:
            if length:
                err.close = True        # the body was never read
            raise
        if (req.header("expect") or "").lower() == "100-continue":
            await self.conn.write(b"HTTP/1.1 100 Continue\r\n\r\n")
        chunked = "aws-chunked" in (req.header("content-encoding") or "").lower() or \
            (req.header("x-amz-content-sha256") or "").startswith("STREAMING-")
        fields, status = await self.receive(length, chunked)
        etag = fields.pop("_md5", "")
        kept = fields.pop("_kept", None)
        checksums = fields.pop("_checksums", {})
        self.log.update(fields)
        if "signal" not in self.log or self.log["signal"] == "s3_planted_key":
            self.log["signal"] = "s3_upload"
        self.log["high_signal"] = True
        if status in ("ip_quota", "total_quota", "error"):
            raise S3Error("SlowDown", close=True)
        if status == "bad_body":
            raise S3Error("IncompleteBody", close=True)
        if fields.get("truncated"):
            raise S3Error("RequestTimeout", close=True)
        headers = [("ETag", f'"{etag}"')] + list(checksums.items())
        sse = req.header("x-amz-server-side-encryption")
        headers.append(("x-amz-server-side-encryption",
                        "aws:kms" if (sse or "").startswith("aws:kms") else "AES256"))
        if self.op == "UploadPart":
            assert mpu is not None and part is not None
            mpu["parts"][part] = (fields["size"], etag, time.time())
        else:
            self.cat.add_upload(self.ip, bucket.name, self.key, fields["size"], etag,
                                req.header("content-type") or "binary/octet-stream", kept)
        await self.send(200, b"", headers, None)

    async def receive(self, length: int, chunked: bool) -> tuple[dict, str]:
        """Stream the body into the quarantine. Returns (log fields, status)."""
        ctx = self.ctx
        store = ctx.quarantine
        stream = BodyStream(self.conn, length, counted=store is None)
        qw = store.open(self.ip) if store is not None else None
        early = qw if isinstance(qw, QuarantineResult) else None
        sink = None if early is not None else qw
        cap = ctx.limits.quarantine_max_file_bytes
        sha, md5 = hashlib.sha256(), hashlib.md5()
        keep: Optional[bytearray] = bytearray()
        state = {"size": 0, "truncated": False}
        checksums: dict[str, str] = {}
        for k, v in self.req.headers:
            if k.lower().startswith("x-amz-checksum-") and k.lower() != "x-amz-checksum-type":
                checksums[k.lower()[:40]] = v.strip()[:100]

        def take(chunk: bytes) -> bool:
            nonlocal keep
            if len(chunk) > cap - state["size"]:
                chunk, state["truncated"] = chunk[:cap - state["size"]], True
            stored_ok = sink.write(chunk) if sink is not None else True
            if sink is not None and sink.failed:
                return False
            state["size"] += len(chunk)
            sha.update(chunk)
            md5.update(chunk)
            if keep is not None:
                if state["size"] <= KEEP_UPLOAD_BYTES:
                    keep += chunk
                else:
                    keep = None
            return not (state["truncated"] or not stored_ok)

        bad_body = False
        try:
            if early is None:
                if chunked:
                    bad_body = not await self._read_aws_chunked(stream, take, checksums)
                else:
                    while stream.remaining > 0:
                        chunk = await stream.read(SEND_CHUNK)
                        if not take(chunk):
                            break
        except ConnClosed:
            if sink is not None:
                sink.abort()
            self.conn.emit("command", "S3 upload aborted", username=self.conn.authenticated_as,
                           data={"operation": self.op, "bucket": self.bucket_name or "",
                                 "key": self.key[:500], "size": state["size"], "stored": False,
                                 "reason": "connection", "high_signal": True,
                                 "signal": "s3_upload", "request_id": self.request_id})
            raise
        except BaseException:
            if sink is not None:
                sink.abort()
            raise
        if stream.remaining > 0:
            self.close = True
        if bad_body:
            if sink is not None:
                sink.abort()
            return {"size": state["size"], "stored": False, "reason": "bad_body"}, "bad_body"
        result = early if early is not None else (sink.finish() if sink is not None else None)
        status = result.status if result is not None else "disabled"
        fields: dict = {"size": state["size"], "sha256": sha.hexdigest(),
                        "_md5": md5.hexdigest(), "_checksums": checksums,
                        "_kept": bytes(keep) if keep is not None else None}
        if self.req.header("x-amz-decoded-content-length"):
            fields["decoded_length"] = self.req.header("x-amz-decoded-content-length")[:20]
        if status == "stored":
            fields.update(stored=True, quarantine_name=result.name)
        elif status == "duplicate":
            fields.update(stored=False, duplicate=True, quarantine_name=result.name)
        else:
            reasons = {"ip_quota": "quarantine_per_ip_bytes",
                       "total_quota": "quarantine_total_bytes", "disabled": "quarantine_disabled",
                       "error": "quarantine_error"}
            fields.update(stored=False, reason=reasons.get(status, status))
        if state["truncated"] and status not in ("ip_quota", "total_quota", "error"):
            fields.update(truncated=True, reason="quarantine_max_file_bytes")
        if result is not None and result.quota_hit:
            self.quota_event(status, state["size"])
        if status in ("ip_quota", "total_quota"):
            fields.pop("sha256")
        return fields, status

    async def _read_aws_chunked(self, stream: BodyStream, take, checksums: dict) -> bool:
        """Decode an aws-chunked body. False on malformed framing."""
        decoded = 0
        while True:
            line = await stream.readline(MAX_CHUNK_LINE)
            if line is None:
                return False
            size = parse_chunk_size(line)
            if size is None or size + 2 > stream.remaining:
                return False
            if size == 0:
                break
            left = size
            while left > 0:
                chunk = await stream.read(min(SEND_CHUNK, left))
                left -= len(chunk)
                decoded += len(chunk)
                if not take(chunk):
                    return True
            if await stream.readexactly(2) != b"\r\n":
                return False
            if stream.raw > 2 * decoded + CHUNK_OVERHEAD_SLACK:
                return False
        for _ in range(MAX_TRAILERS):
            line = await stream.readline(MAX_CHUNK_LINE)
            if line is None:
                return stream.remaining == 0
            if not line:
                return True
            name, sep, value = line.decode("latin-1").partition(":")
            if sep and name.strip().lower().startswith("x-amz-checksum-"):
                checksums[name.strip().lower()[:40]] = value.strip()[:100]
        return False

    def quota_event(self, status: str, size: int) -> None:
        suppressed = self.ctx.gate.check(f"{self.ip}|s3|quarantine_{status}")
        if suppressed is None:
            return
        self.conn.emit("limit", "Quarantine quota reached; upload not captured",
                       level="WARNING", username=self.conn.authenticated_as,
                       data={"reason": status, "size": size, "suppressed": suppressed,
                             "high_signal": True, "signal": "quarantine_quota"})

    # ---- logging ------------------------------------------------------------------------

    def emit(self) -> None:
        req = self.req
        data: dict = {}
        for k in ("signal", "high_signal", "honeytoken"):
            if k in self.log:
                data[k] = self.log.pop(k)
        data.update(operation=self.op, method=req.method, status=self.status,
                    command=f"{self.op} /{self.bucket_name or ''}"
                            f"{'/' + self.key[:200] if self.key else ''} -> {self.status}",
                    bucket=self.bucket_name or "", key=self.key[:500],
                    path=req.path[:500], query=scrub_query(req.query)[:500],
                    host=req.header("host") or "", request_id=self.request_id,
                    auth=self.log.pop("auth", "anonymous"))
        if self.style != "path":
            data["style"] = self.style
        if self.bytes_out:
            data["bytes_out"] = self.bytes_out
        data.update(self.log)
        conn = self.conn
        conn.emit("command", f"{self.op} {self.bucket_name or ''}/{self.key[:150]}".rstrip("/"),
                  client=req.header("user-agent"), username=conn.authenticated_as
                  if self.auth.scheme != "anonymous" else None, data=data)


def _xml_blocks(text: str, tag: str, limit: int = 64) -> list[str]:
    """The text of up to ``limit`` ``<tag>...</tag>`` elements, in one linear scan."""
    out: list[str] = []
    start, open_tag, close_tag = 0, f"<{tag}>", f"</{tag}>"
    while len(out) < limit:
        i = text.find(open_tag, start)
        if i < 0:
            break
        j = text.find(close_tag, i + len(open_tag))
        if j < 0:
            break
        out.append(text[i + len(open_tag):j])
        start = j + len(close_tag)
    return out


def _xml_unescape(text: str) -> str:
    for a, b in (("&lt;", "<"), ("&gt;", ">"), ("&quot;", '"'), ("&apos;", "'"),
                 ("&amp;", "&")):
        text = text.replace(a, b)
    return text


def scrub_query(query: str) -> str:
    """The query string with signatures and session tokens removed."""
    out = []
    for item in query.split("&")[:60]:
        k, sep, _ = item.partition("=")
        if sep and unquote(k).lower() in REDACT_PARAMS:
            out.append(f"{k}=<redacted>")
        else:
            out.append(item)
    return "&".join(out)


HEAD_ERRORS = {414: "RequestHeaderSectionTooLarge", 431: "RequestHeaderSectionTooLarge"}


async def handle(conn: Conn) -> None:
    cat = catalog(conn.ctx)
    while True:
        try:
            req = await read_head(conn)
        except ConnClosed:
            raise
        except Exception as exc:  # noqa: BLE001 - any parse failure is a 400
            reason = exc.reason if isinstance(exc, HttpError) else "parse_error"
            status = exc.status if isinstance(exc, HttpError) else 400
            err = S3Error(HEAD_ERRORS.get(status, "BadRequest"), close=True)
            conn.emit("error", "Malformed S3 request", data={"reason": reason,
                                                             "status": err.status})
            rid, hid = request_ids()
            body = error_xml(err, rid, hid)
            await conn.write(response_head(err.status, cat.server, rid, hid,
                                           [("Content-Type", "application/xml")], len(body),
                                           False) + body)
            return
        if req is None:
            return
        if not conn.command():
            return
        cat.refresh()
        ex = Exchange(conn, req, cat)
        try:
            length = content_length(req)
        except HttpError:
            ex.close = True
            await ex.send_error(S3Error("BadRequest", close=True))
            ex.emit()
            return
        try:
            await ex.run(length)
        except ConnClosed:
            if ex.op not in UPLOAD_OPS:      # an aborted upload has logged its own line
                ex.log["aborted"] = True
                ex.emit()
            raise
        ex.emit()
        if not ex.keep_alive():
            return


async def start(ctx: ListenerContext, settings: ServiceSettings) -> list:
    catalog(ctx)
    return [await start_tcp(ctx, "s3", settings.port, handle)]
