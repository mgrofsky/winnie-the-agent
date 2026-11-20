"""Reference producer for delivered InternetDB answers: read the sensor's wanted list, ask
Shodan InternetDB about the addresses that have no fresh answer, write the answers object.

It runs outside the sensor (a scheduled Lambda function, or any host with egress to
internetdb.shodan.io) and is one file with nothing from this repository: the standard
library, plus boto3 for the object store (the Lambda Python runtime includes it; the file
store needs nothing). The sensor checks everything this writes again, so this script is not
trusted by the sensor; it validates anyway, with the same rules.

    # Lambda: handler = internetdb_lookup.handler, environment:
    #   BUCKET, WANTED_KEY (events/internetdb/wanted.json), ANSWERS_KEY
    #   (internetdb/answers.json), optional EXPECTED_BUCKET_OWNER, MAX_PER_RUN,
    #   MAX_PER_DAY, CACHE_DAYS
    python3 internetdb_lookup.py --bucket B --wanted-key K --answers-key K [--owner ID]
    python3 internetdb_lookup.py --wanted-file wanted.json --answers-file answers.json

What is sent to InternetDB: one HTTPS GET per address with the address in the path and
nothing else (a generic user agent, no key, no cookie). The host is fixed, the certificate
is verified, redirects are not followed, each call has a 5 s deadline and the answer is read
up to 64 KB. Pacing: one request at a time, at least 1 s apart, at most MAX_PER_RUN per run
and MAX_PER_DAY per UTC day; an answer (also "no information") counts as fresh for
CACHE_DAYS. A 429, a 5xx, a redirect, any other status or a network failure stops the run
and backs off (15 minutes, doubling up to a day). The answers object holds answers for the
addresses on the current wanted list only, so it stays bounded by that list (500 at most).

The answers object's format is documented in docs/operations.md ("Delivered answers"). Its
"producer" key is this script's own state (day count, back-off); the sensor ignores it.
"""

from __future__ import annotations

import argparse
import datetime
import http.client
import ipaddress
import json
import os
import re
import ssl
import sys
import time

UTC = datetime.timezone.utc
HOST = "internetdb.shodan.io"
USER_AGENT = "internetdb-client/1"
TIMEOUT = 5.0
MAX_BODY = 64 * 1024
MAX_WANTED = 500
MAX_WANTED_BYTES = 64 * 1024
MAX_ANSWERS_BYTES = 4 * 1024 * 1024
MIN_INTERVAL = 1.0
BACKOFF_FIRST_MINUTES = 15
BACKOFF_MAX_MINUTES = 24 * 60
DEFAULTS = {"MAX_PER_RUN": 100, "MAX_PER_DAY": 2000, "CACHE_DAYS": 7}
BOUNDS = {"MAX_PER_RUN": (1, 1000), "MAX_PER_DAY": (1, 20000), "CACHE_DAYS": (1, 90)}
# Stop asking when less than this is left of a Lambda invocation.
RESERVE_SECONDS = 20.0

# The sensor's rules (agents/triage.py), repeated here so this file stands alone; a test
# keeps the two in step.
PORTS_MAX = 50
HOSTNAMES_MAX, HOSTNAME_LEN = 10, 253
TAGS_MAX, TAG_LEN = 20, 40
CPES_MAX, CPE_LEN = 20, 128
VULNS_MAX, VULN_LEN = 50, 20
HOSTNAME_PATTERN = (r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
                    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$")
TAG_PATTERN = r"^[a-z0-9][a-z0-9_.+-]{0,39}$"
CPE_PATTERN = r"^cpe:(?:/|2\.3:)[A-Za-z0-9._~%+:*-]{1,120}$"
CVE_PATTERN = r"^CVE-[0-9]{4}-[0-9]{4,7}$"
_RAW_CAP = 512
# Documentation ranges treated as public, for tests only (as agents.addresses does).
TEST_PUBLIC: tuple = ()
_ITEMS_CAP = 1000


class Refused(ValueError):
    """A document this script will not use. Fixed text only."""


# ---- checks --------------------------------------------------------------------------------

def address(value):
    """``value`` as a canonical global unicast address, or None."""
    if not isinstance(value, str) or not value or len(value) > 64 or "/" in value \
            or "%" in value or value != value.strip():
        return None
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return None
    if addr.version == 6 and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    if any(addr in net for net in TEST_PUBLIC):
        return str(addr)
    if not addr.is_global or addr.is_multicast or addr.is_reserved or addr.is_unspecified:
        return None
    return str(addr)


def timestamp(value):
    if not isinstance(value, str) or not value or len(value) > 40:
        return None
    try:
        dt = datetime.datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        return (dt if dt.tzinfo else dt.replace(tzinfo=UTC)).astimezone(UTC)
    except (ValueError, OverflowError):
        return None


def iso(dt):
    return dt.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def _strings(value, pattern, cap, limit, lower=False, strip_dot=False):
    if not isinstance(value, list):
        return []
    regex = re.compile(pattern)
    out = []
    for item in value[:_ITEMS_CAP]:
        if not isinstance(item, str) or len(item) > _RAW_CAP:
            continue
        s = item.lower() if lower else item
        if strip_dot and s.endswith("."):
            s = s[:-1]
        if not s or len(s) > cap or not regex.fullmatch(s) or s in out:
            continue
        out.append(s)
        if len(out) >= limit:
            break
    return out


def _ports(value):
    if not isinstance(value, list):
        return []
    found = {i for i in value[:_ITEMS_CAP]
             if isinstance(i, int) and not isinstance(i, bool) and 1 <= i <= 65535}
    return sorted(found)[:PORTS_MAX]


def clean(doc, ip):
    """The kept fields of an InternetDB answer for ``ip``, or None if it is not one."""
    if not isinstance(doc, dict) or address(doc.get("ip")) != ip:
        return None
    return {"ports": _ports(doc.get("ports")),
            "hostnames": _strings(doc.get("hostnames"), HOSTNAME_PATTERN, HOSTNAME_LEN,
                                  HOSTNAMES_MAX, lower=True, strip_dot=True),
            "tags": _strings(doc.get("tags"), TAG_PATTERN, TAG_LEN, TAGS_MAX, lower=True),
            "cpes": _strings(doc.get("cpes"), CPE_PATTERN, CPE_LEN, CPES_MAX),
            "vulns": _strings(doc.get("vulns"), CVE_PATTERN, VULN_LEN, VULNS_MAX)}


def parse_wanted(body):
    """The addresses of the sensor's wanted list, or Refused."""
    if not isinstance(body, bytes) or len(body) > MAX_WANTED_BYTES:
        raise Refused("the wanted list is missing or too large")
    try:
        doc = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise Refused("the wanted list is not JSON") from None
    if not isinstance(doc, dict) or doc.get("version") != 1 \
            or isinstance(doc.get("version"), bool):
        raise Refused("not a version 1 wanted list")
    items = doc.get("addresses")
    if not isinstance(items, list) or len(items) > MAX_WANTED:
        raise Refused("addresses must be a list of at most 500")
    out = []
    for item in items:
        if address(item) != item or item in out:
            raise Refused("addresses must be distinct canonical global addresses")
        out.append(item)
    return out


def parse_previous(body, now):
    """This script's last answers object: ``(answers by address, producer state)``. Anything
    unusable starts empty; an entry that does not check is dropped."""
    empty = ({}, {})
    if not isinstance(body, bytes) or len(body) > MAX_ANSWERS_BYTES:
        return empty
    try:
        doc = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        return empty
    if not isinstance(doc, dict) or doc.get("version") != 1 \
            or not isinstance(doc.get("answers"), list):
        return empty
    answers = {}
    for item in doc["answers"][:MAX_WANTED * 2]:
        if not isinstance(item, dict):
            continue
        ip = address(item.get("ip"))
        at = timestamp(item.get("checked_at"))
        if ip is None or ip != item.get("ip") or at is None or at > now:
            continue
        if item.get("status") == "not_found":
            answers[ip] = {"ip": ip, "checked_at": iso(at), "status": "not_found"}
        elif item.get("status") == "found":
            kept = clean(item, ip)
            if kept is not None:
                answers[ip] = {"ip": ip, "checked_at": iso(at), "status": "found", **kept}
    producer = doc.get("producer") if isinstance(doc.get("producer"), dict) else {}
    return answers, producer


# ---- InternetDB ----------------------------------------------------------------------------

def fetch(ip):
    """One GET of https://internetdb.shodan.io/<ip>: ``(status, body)``. http.client never
    follows a redirect; the certificate and host name are verified."""
    conn = http.client.HTTPSConnection(HOST, 443, timeout=TIMEOUT,
                                       context=ssl.create_default_context())
    try:
        conn.request("GET", "/" + ip, headers={"User-Agent": USER_AGENT,
                                               "Accept": "application/json"})
        resp = conn.getresponse()
        return resp.status, resp.read(MAX_BODY + 1)
    finally:
        conn.close()


def lookup(wanted_body, previous_body, *, now=None, fetch=None, clock=time.monotonic,
           sleep=time.sleep, remaining=None, limits=None):
    """Build the next answers object. ``remaining`` returns the seconds left (Lambda);
    ``limits`` overrides DEFAULTS. Returns ``(body, summary)``."""
    now = now or datetime.datetime.now(UTC)
    fetch = fetch or globals()["fetch"]
    limits = {**DEFAULTS, **(limits or {})}
    wanted = parse_wanted(wanted_body)
    previous, producer = parse_previous(previous_body, now)
    today = now.date().isoformat()
    day_count = producer.get("day_count") if producer.get("day") == today else 0
    if not isinstance(day_count, int) or isinstance(day_count, bool) or day_count < 0:
        day_count = 0
    minutes = producer.get("backoff_minutes")
    minutes = minutes if isinstance(minutes, int) and not isinstance(minutes, bool) \
        and 0 <= minutes <= BACKOFF_MAX_MINUTES else 0
    until = timestamp(producer.get("backoff_until"))
    refused = {ip: at for ip, at in (producer.get("refused") or {}).items()
               if ip in wanted and timestamp(at) is not None} \
        if isinstance(producer.get("refused"), dict) else {}
    fresh = datetime.timedelta(days=limits["CACHE_DAYS"])

    def last(ip):
        at = timestamp(previous[ip]["checked_at"]) if ip in previous else None
        bad = timestamp(refused.get(ip))
        return max([t for t in (at, bad) if t is not None], default=None)

    # Answers for addresses no longer wanted are dropped: the object follows the list.
    answers = {ip: previous[ip] for ip in wanted if ip in previous}
    due = [ip for ip in wanted if last(ip) is None or now - last(ip) >= fresh]
    due.sort(key=lambda ip: (last(ip) is not None, last(ip) or now))
    summary = {"wanted": len(wanted), "due": len(due), "found": 0, "not_found": 0,
               "refused": 0, "asked": 0}
    stopped = None
    if until is not None and now < until <= now + datetime.timedelta(minutes=BACKOFF_MAX_MINUTES):
        summary["status"] = "backing off"
        batch = []
    else:
        until = None
        batch = due[:max(0, min(limits["MAX_PER_RUN"], limits["MAX_PER_DAY"] - day_count))]
    started = None
    for ip in batch:
        if remaining is not None and remaining() < RESERVE_SECONDS:
            summary["status"] = "out of time"
            break
        if started is not None:
            wait = started + MIN_INTERVAL - clock()
            if wait > 0:
                sleep(wait)
        started = clock()
        day_count += 1
        summary["asked"] += 1
        try:
            status, body = fetch(ip)
        except Exception as exc:  # noqa: BLE001 - unreachable, timeout, TLS, DNS
            stopped = f"request failed ({type(exc).__name__})"
            break
        if status == 200:
            kept = None
            if len(body) <= MAX_BODY:
                try:
                    kept = clean(json.loads(body.decode("utf-8")), ip)
                except (UnicodeDecodeError, ValueError, RecursionError):
                    kept = None
            if kept is None:
                refused[ip] = iso(now)
                summary["refused"] += 1
            else:
                answers[ip] = {"ip": ip, "checked_at": iso(now), "status": "found", **kept}
                refused.pop(ip, None)
                summary["found"] += 1
            minutes = 0
        elif status == 404:
            answers[ip] = {"ip": ip, "checked_at": iso(now), "status": "not_found"}
            refused.pop(ip, None)
            summary["not_found"] += 1
            minutes = 0
        else:
            stopped = f"HTTP {status}"
            break
    if stopped is not None:
        minutes = min(BACKOFF_MAX_MINUTES, max(BACKOFF_FIRST_MINUTES, minutes * 2))
        until = now + datetime.timedelta(minutes=minutes)
        summary.update(status="stopped", stopped=stopped, backoff_minutes=minutes)
    summary.setdefault("status", "done")
    doc = {"version": 1, "generated_at": iso(now),
           "answers": [answers[ip] for ip in wanted if ip in answers],
           "producer": {"day": today, "day_count": day_count, "backoff_minutes": minutes,
                        "backoff_until": iso(until) if until else None, "refused": refused}}
    body = (json.dumps(doc, separators=(",", ":")) + "\n").encode()
    while len(body) > MAX_ANSWERS_BYTES and doc["answers"]:
        doc["answers"].pop()          # least important last; never reached at 500 answers
        body = (json.dumps(doc, separators=(",", ":")) + "\n").encode()
    summary["answers"] = len(doc["answers"])
    return body, summary


# ---- stores --------------------------------------------------------------------------------

class FileStore:
    def __init__(self, path):
        self.path = path

    def get(self, cap):
        try:
            with open(self.path, "rb") as f:
                return f.read(cap + 1)
        except FileNotFoundError:
            return None

    def put(self, body):
        tmp = self.path + ".tmp"
        with open(tmp, "wb") as f:
            f.write(body)
        os.replace(tmp, self.path)


class S3Store:
    """GetObject and PutObject of one key (boto3, imported only here)."""

    def __init__(self, bucket, key, owner=None, client=None):
        if client is None:
            import boto3   # in the Lambda runtime; pip install boto3 elsewhere
            client = boto3.client("s3")
        self.client, self.bucket, self.key, self.owner = client, bucket, key, owner

    def _params(self):
        p = {"Bucket": self.bucket, "Key": self.key}
        if self.owner:
            p["ExpectedBucketOwner"] = self.owner
        return p

    def get(self, cap):
        try:
            resp = self.client.get_object(**self._params())
        except Exception as exc:  # noqa: BLE001 - only "no such key" means "not there yet"
            code = (getattr(exc, "response", None) or {}).get("Error", {}).get("Code")
            if code in ("NoSuchKey", "404"):
                return None
            raise
        body = resp["Body"]
        try:
            return body.read(cap + 1)
        finally:
            body.close()

    def put(self, body):
        self.client.put_object(Body=body, ContentType="application/json", **self._params())


def run(wanted_store, answers_store, **kw):
    """Read, look up, write. Returns the summary; writes nothing when there is no list."""
    wanted = wanted_store.get(MAX_WANTED_BYTES)
    if wanted is None:
        return {"status": "no wanted list yet"}
    body, summary = lookup(wanted, answers_store.get(MAX_ANSWERS_BYTES), **kw)
    answers_store.put(body)
    return summary


def _limits(env):
    out = {}
    for name, (lo, hi) in BOUNDS.items():
        raw = env.get(name)
        if raw:
            value = int(raw)
            if not lo <= value <= hi:
                raise ValueError(f"{name} must be between {lo} and {hi}")
            out[name] = value
    return out


def handler(event, context):
    """Lambda entry point; the settings come from the environment, never from the event."""
    env = os.environ
    owner = env.get("EXPECTED_BUCKET_OWNER") or None
    wanted = S3Store(env["BUCKET"], env["WANTED_KEY"], owner)
    answers = S3Store(env["BUCKET"], env["ANSWERS_KEY"], owner, client=wanted.client)
    remaining = (lambda: context.get_remaining_time_in_millis() / 1000.0) \
        if context is not None and hasattr(context, "get_remaining_time_in_millis") else None
    summary = run(wanted, answers, remaining=remaining, limits=_limits(env))
    print(json.dumps(summary))
    return summary


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--bucket")
    p.add_argument("--wanted-key")
    p.add_argument("--answers-key")
    p.add_argument("--owner", help="expected bucket owner (account id)")
    p.add_argument("--wanted-file")
    p.add_argument("--answers-file")
    args = p.parse_args(argv)
    if args.wanted_file and args.answers_file:
        wanted, answers = FileStore(args.wanted_file), FileStore(args.answers_file)
    elif args.bucket and args.wanted_key and args.answers_key:
        wanted = S3Store(args.bucket, args.wanted_key, args.owner)
        answers = S3Store(args.bucket, args.answers_key, args.owner, client=wanted.client)
    else:
        p.error("give --wanted-file and --answers-file, or --bucket, --wanted-key and "
                "--answers-key")
    try:
        summary = run(wanted, answers, limits=_limits(os.environ))
    except Refused as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(summary))
    return 0 if summary.get("status") in ("done", "backing off", "no wanted list yet") else 1


if __name__ == "__main__":
    sys.exit(main())
