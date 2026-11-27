"""Planted tokens: how a sensor issues them and how it recognises one that comes back.

A planted token carries no fixed marker. Every value is derived from the private sensor
seed and has the length and alphabet of the real thing it imitates, so its shape says
nothing about where it came from. It is recognised by lookup instead: ``TokenIndex`` holds
every value this sensor can have issued (scenario honeytokens and per-source pairs) and
finds one inside a candidate string with one dictionary probe per position, over a bounded
prefix of the input.

    honeytoken_value(kind, seed, scenario, name) -> str     what the sensor issues now
    legacy_honeytoken_value(kind, seed, scenario, name)     the format earlier versions
                                                            issued; for recognition only
    source_pair(seed, key) -> (access_key_id, secret)       per-source AWS-style pair
    legacy_source_pair(seed, key)                           earlier per-source pair
    marker_value(seed, scenario, key, name) -> str          per-source HTTP marker
    TokenIndex(values).find(text) -> Optional[name]

AWS-style access key ids use the real shape, ``AKIA`` and 16 characters of A-Z2-7. Nothing
in the shape can promise that such an id was never issued to someone: any rule that did
(a reserved fragment, a character real ids never use) would be a constant an attacker
could search for. What makes a planted pair useless is the secret: it is 40 characters
derived from this sensor's seed, so it cannot be the secret of any real key, and a request
signed with it is refused by AWS whatever the key id. See docs/security-model.md.
"""

from __future__ import annotations

import hashlib
import hmac
import random
import string
from typing import Iterable, Optional

ALNUM = string.ascii_letters + string.digits
BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
BASE64 = string.ascii_uppercase + string.ascii_lowercase + string.digits + "+/"
BASE64URL = string.ascii_letters + string.digits + "-_"
# Characters that need no escaping in a URL's userinfo, a libpq or JDBC keyword string, a
# shell assignment or an INI value, so a password can be pasted into any of them.
URL_SAFE_SYMBOLS = "-._"

KINDS = ("aws_access_key", "api_key", "bearer_token", "db_password", "sip_trunk_password",
         "generic_password", "ssh_private_key_id")


def _rng(seed: str, *purpose: str) -> random.Random:
    digest = hashlib.sha256("|".join((seed,) + purpose).encode()).digest()
    return random.Random(int.from_bytes(digest[:8], "big"))  # noqa: S311 - seeded so decoy content is stable per sensor


def _pick(rng: random.Random, alphabet: str, n: int) -> str:
    return "".join(rng.choice(alphabet) for _ in range(n))


def honeytoken_value(kind: str, seed: str, scenario: str, name: str) -> str:
    """The value a sensor issues for one scenario honeytoken. No constant fragment beyond
    the real format's own prefix (``AKIA``, ``sk_test_``, ``SHA256:``)."""
    rng = _rng(seed, scenario, "honeytoken/2", name)
    if kind == "aws_access_key":
        return "AKIA" + _pick(rng, BASE32, 16)
    if kind == "api_key":
        # A payment-provider style test key: never the live prefix.
        return "sk_test_" + _pick(rng, ALNUM, 24)
    if kind == "bearer_token":
        # 32 random bytes in unpadded base64url, the usual opaque OAuth token.
        return _pick(rng, BASE64URL, 43)
    if kind == "sip_trunk_password":
        return _pick(rng, ALNUM, 16)
    if kind == "ssh_private_key_id":
        return "SHA256:" + _pick(rng, BASE64, 43)
    # db_password / generic_password: what an admin generates once and pastes everywhere.
    return _pick(rng, ALNUM, 10) + rng.choice(URL_SAFE_SYMBOLS) + str(rng.randrange(10, 99))


def legacy_honeytoken_value(kind: str, seed: str, scenario: str, name: str) -> str:
    """The value earlier versions issued for the same token. Recognition only: a sensor
    never hands this out again, but an attacker may still hold one."""
    rng = _rng(seed, scenario, "honeytoken", name)
    up = string.ascii_uppercase + string.digits
    if kind == "aws_access_key":
        return "AKIA" + "FAKE" + "".join(rng.choice(up) for _ in range(12))
    if kind == "api_key":
        return "sk_test_" + "hp_" + "".join(rng.choice(ALNUM) for _ in range(28))
    if kind == "bearer_token":
        return "hp" + "t_" + "".join(rng.choice(ALNUM) for _ in range(36))
    if kind == "sip_trunk_password":
        return "Tr" + "k" + "".join(rng.choice(ALNUM) for _ in range(13))
    if kind == "ssh_private_key_id":
        return "SHA256:" + "".join(rng.choice(ALNUM) for _ in range(43))
    return ("".join(rng.choice(ALNUM) for _ in range(10)) + rng.choice("!#%@")
            + str(rng.randrange(10, 99)))


def _source_secret(seed: str, key: str, digest: bytes) -> str:
    secret_bytes = hmac.new(seed.encode(), f"secret|{key}".encode(), hashlib.sha256).digest()
    return "".join(BASE64[b % 64] for b in (secret_bytes + digest)[:40])


def source_pair(seed: str, key: str) -> tuple[str, str]:
    """(access_key_id, secret) planted for one source, derived from the sensor seed."""
    digest = hmac.new(seed.encode(), f"plant|{key}".encode(), hashlib.sha256).digest()
    access = "AKIA" + "".join(BASE32[b % 32] for b in digest[12:28])
    return access, _source_secret(seed, key, digest)


def legacy_source_pair(seed: str, key: str) -> tuple[str, str]:
    """The pair earlier versions planted for the same source (recognition only)."""
    digest = hmac.new(seed.encode(), f"plant|{key}".encode(), hashlib.sha256).digest()
    access = "AKIA" + "FAKE" + "".join(BASE32[b % 32] for b in digest[:12])
    return access, _source_secret(seed, key, digest)


HEX = "0123456789abcdef"
LOWER_ALNUM = string.ascii_lowercase + string.digits


def marker_value(seed: str, scenario: str, key: str, name: str) -> str:
    """The value of ``{marker:NAME}`` served to one source. Its shape follows the name: a
    build or commit name gets a short hex hash, a ``client_id`` or other ``*_id`` a UUID, a
    key or token name a 32-character key, anything else 20 lowercase letters and digits.
    No fixed fragment; recognised by lookup of what was issued."""
    digest = hmac.new(seed.encode(), f"marker|{scenario}|{key}|{name}".encode(),
                      hashlib.sha256).digest()
    if any(w in name for w in ("build", "commit", "release", "sha")):
        return digest[:6].hex()
    if name.endswith("_id") or name == "id":
        h = digest[:16].hex()
        return f"{h[:8]}-{h[8:12]}-4{h[13:16]}-{'89ab'[digest[8] % 4]}{h[17:20]}-{h[20:32]}"
    if "key" in name or "token" in name:
        return "".join(ALNUM[b % 62] for b in digest[:32])
    return "".join(LOWER_ALNUM[b % 36] for b in digest[:20])


# ---- recognition --------------------------------------------------------------------------

PROBE = 8               # characters per probe; every indexed value is at least this long
SCAN_LIMIT = 16384      # characters of one input looked at; tokens sit near the start


class TokenIndex:
    """Every value this sensor may have issued, found inside text by lookup.

    ``find`` probes a dictionary keyed by each value's first ``PROBE`` characters once per
    position of the first ``SCAN_LIMIT`` characters, and compares the full value only on a
    probe hit. Its cost depends on the input length (bounded), not on how many tokens are
    indexed."""

    def __init__(self, values: Optional[dict[str, str]] = None) -> None:
        self._exact: dict[str, str] = {}
        self._probe: dict[str, list[tuple[str, str]]] = {}
        for value, name in (values or {}).items():
            self.add(value, name)

    def __len__(self) -> int:
        return len(self._exact)

    def __contains__(self, value: str) -> bool:
        return value in self._exact

    def add(self, value: str, name: str) -> None:
        if not isinstance(value, str) or len(value) < PROBE or value in self._exact:
            return
        self._exact[value] = name
        self._probe.setdefault(value[:PROBE], []).append((value, name))

    def update(self, values: dict[str, str]) -> None:
        for value, name in values.items():
            self.add(value, name)

    def find(self, text: Optional[str]) -> Optional[str]:
        if not text or not self._exact:
            return None
        hit = self._exact.get(text)
        if hit is not None:
            return hit
        text = text[:SCAN_LIMIT]
        probe = self._probe
        for i in range(len(text) - PROBE + 1):
            bucket = probe.get(text[i:i + PROBE])
            if bucket:
                for value, name in bucket:
                    if text.startswith(value, i):
                        return name
        return None

    def find_any(self, texts: Iterable[Optional[str]]) -> Optional[str]:
        for t in texts:
            hit = self.find(t)
            if hit:
                return hit
        return None
