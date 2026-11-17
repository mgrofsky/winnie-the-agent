"""The source tree must not trip secret scanners or leak environment details.

Fake secrets (honeytokens) are generated at runtime from the sensor seed, so nothing in
the tree needs to look like a real provider key. Literals that tests need are assembled at
runtime from fragments.
"""

import math
import re
import subprocess
from collections import Counter
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
BINARY_SUFFIXES = {".png", ".jpg", ".gif", ".ico", ".lock", ".pyc"}

SECRET_PATTERNS = {
    "aws access key id": r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA|AIPA)[0-9A-Z]{16}\b",
    "github token": r"\b(?:gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,})\b",
    "slack token": r"\bxox[abprs]-[0-9A-Za-z-]{10,}",
    "slack webhook": r"hooks\.slack\.com/services/T[0-9A-Z]{6,}/B[0-9A-Z]{6,}/[0-9A-Za-z]{20,}",
    "stripe key": r"\b(?:sk|rk|pk)_(?:live|test)_[0-9a-zA-Z]{16,}",
    "google api key": r"\bAIza[0-9A-Za-z_\-]{35}\b",
    "private key block": r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP |ENCRYPTED )?PRIVATE KEY-----",
    "jwt": r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}",
}
PASSWORD_ASSIGNMENT = re.compile(
    r"""(?i)\b(?:password|passwd|pwd|secret|api_?key|token)\s*[=:]\s*["']?([^\s"',;)]{16,})""")


def source_files() -> list[Path]:
    """Tracked and untracked, non-ignored files (what a public push would contain)."""
    out = subprocess.run(["git", "-C", str(ROOT), "ls-files", "-co", "--exclude-standard"],
                         capture_output=True, text=True, check=True).stdout.split()
    files = []
    for name in out:
        path = ROOT / name
        if path.is_file() and path.suffix not in BINARY_SUFFIXES:
            files.append(path)
    return files


def _text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return ""


def _entropy(value: str) -> float:
    counts = Counter(value)
    return -sum(n / len(value) * math.log2(n / len(value)) for n in counts.values())


def _hits(pattern: str) -> list[str]:
    rx = re.compile(pattern)
    hits = []
    for path in source_files():
        for m in rx.finditer(_text(path)):
            line = _text(path)[:m.start()].count("\n") + 1
            hits.append(f"{path.relative_to(ROOT)}:{line}")
    return hits


@pytest.mark.parametrize("name", sorted(SECRET_PATTERNS))
def test_no_provider_key_formats_in_source(name):
    assert _hits(SECRET_PATTERNS[name]) == []


def test_no_high_entropy_password_assignments():
    hits = []
    for path in source_files():
        for m in PASSWORD_ASSIGNMENT.finditer(_text(path)):
            value = m.group(1)
            code = "(" in value or re.fullmatch(r"[A-Za-z_][\w.]*", value)  # an expression
            template = value.startswith(("{{", "$", "<")) or "}}" in value  # template text
            if _entropy(value) >= 4.0 and not code and not template:
                hits.append(f"{path.relative_to(ROOT)}: {value[:6]}...")
    assert hits == []


def test_runtime_honeytokens_still_look_real_to_an_attacker():
    """The repository holds no key-shaped literals, but what the sensor serves does."""
    from agents.source_state import source_token
    from scenarios.loader import load_scenario

    access, _ = source_token("seed-" * 8, "203.0.113.5")
    assert re.fullmatch(SECRET_PATTERNS["aws access key id"], access)
    from scenarios.loader import list_scenarios

    served = [t.value for name in list_scenarios()
              for t in load_scenario(name, "seed-" * 8).honeytokens.values()
              if t.kind == "aws_access_key"]
    assert served and all(re.fullmatch(SECRET_PATTERNS["aws access key id"], v) for v in served)


# ---- environment and personal data -----------------------------------------------------------

# Well-known public resolver addresses referenced on purpose (common-token lists, a test that
# a public address is refused as an internal one). Nothing else public may appear.
KNOWN_PUBLIC_ADDRESSES = {"1.1.1.1", "8.8.8.8", "8.8.4.4"}
RESERVED_EMAIL_DOMAIN = re.compile(r"(?:^|\.)(?:example(?:\.com|\.org|\.net)?|test|invalid|localhost)$")


def test_no_machine_paths_usernames_or_hostnames():
    import getpass
    import socket

    # Assembled so this file does not match its own patterns.
    patterns = ["/" + "Users/[A-Za-z]", "/private" + "/var/folders/", "/private" + "/tmp/"]
    user = getpass.getuser()
    if len(user) >= 5 and user not in {"runner", "ubuntu", "admin", "user1", "build"}:
        patterns.append(rf"\b{re.escape(user)}\b")
    host = socket.gethostname().split(".")[0]
    if len(host) >= 6 and host.lower() not in {"localhost"}:
        patterns.append(rf"\b{re.escape(host)}\b")
    for pattern in patterns:
        assert _hits(pattern) == [], pattern


def test_no_real_email_addresses():
    hits = []
    for path in source_files():
        for m in re.finditer(r"[A-Za-z0-9._%+-]+@((?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,})\b", _text(path)):
            if not RESERVED_EMAIL_DOMAIN.search(m.group(1).lower()):
                hits.append(f"{path.relative_to(ROOT)}: {m.group(0)}")
    assert hits == []


def test_no_public_ip_addresses_outside_documentation_ranges():
    import ipaddress

    hits = []
    for path in source_files():
        for m in re.finditer(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])", _text(path)):
            try:
                ip = ipaddress.ip_address(m.group(0))
            except ValueError:
                continue
            if ip.is_global and not ip.is_multicast and m.group(0) not in KNOWN_PUBLIC_ADDRESSES:
                hits.append(f"{path.relative_to(ROOT)}: {m.group(0)}")
    assert hits == []


# AWS documentation account ids; any other 12-digit run could be a real account.
DOCUMENTATION_ACCOUNT_IDS = {"000000000000", "123456789012"}


def test_no_aws_account_ids_outside_documentation_examples():
    hits = []
    for path in source_files():
        for m in re.finditer(r"(?<![0-9A-Za-z])[0-9]{12}(?![0-9A-Za-z])", _text(path)):
            if m.group(0) not in DOCUMENTATION_ACCOUNT_IDS:
                hits.append(f"{path.relative_to(ROOT)}: {m.group(0)}")
    assert hits == []
