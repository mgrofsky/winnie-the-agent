"""Synthetic-data checker for scenario packs.

Scans every string in a loaded scenario (after honeytoken substitution) and every
generated table row for values that could be mistaken for, or actually be, real data.

    check_scenario(loaded) -> list[str]      one human-readable problem per finding
    python -m scenarios.check [names...]     exits 1 when any scenario has problems

Rules (see ``check_text``):
- card-like 13-19 digit numbers must FAIL Luhn (14-digit YYYYMMDDHHMMSS timestamps, as used
  by HL7, are skipped);
- IBAN-shaped strings with a real IBAN country code must FAIL mod-97;
- phone numbers (E.164 ``+...`` or formatted ``(NXX) NXX-XXXX``) must be in a fictional
  range: NANP 555-0100..0199, or the UK Ofcom drama ranges 01632 960xxx / 07700 900xxx;
- email domains must be example.com/org/net, under .example/.test/.invalid, or the
  scenario's own identity.domain (or a subdomain of it);
- identity.domain must itself be reserved (as above);
- US SSN-shaped ###-##-#### only with area 000, 666 or 9xx;
- AWS access-key-shaped AKIA... only when it is one of the sensor's own planted tokens
  (a literal one in a scenario could be someone's real key);
- no well-known real bank / hospital / carrier / vendor customer names;
- IPv4 addresses must be private, loopback, link-local, reserved, unspecified or in the
  documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24).
IPv6 literals are not checked. Generated HTTP decoy asset content is scanned like the rest.
"""

from __future__ import annotations

import datetime
import ipaddress
import re
import sys
from typing import Any, Iterator

RESERVED_EMAIL_DOMAINS = {"example.com", "example.org", "example.net"}
RESERVED_TLDS = (".example", ".test", ".invalid")

# Countries that issue IBANs (ISO 3166-1 alpha-2). A string using one of these and passing
# mod-97 could be a real account.
IBAN_COUNTRIES = set("""
AD AE AL AT AZ BA BE BG BH BI BR BY CH CR CY CZ DE DJ DK DO EE EG ES FI FK FO FR GB GE GI
GL GR GT HR HU IE IL IQ IS IT JO KW KZ LB LC LI LT LU LV LY MC MD ME MK MN MR MT MU NI NL
NO OM PK PL PS PT QA RO RS RU SA SC SD SE SI SK SM SO ST SV TL TN TR UA VA VG XK YE
""".split())

# Well-known real organisations that must never appear as the fake org or its customers.
DENYLIST = [
    "Bank of America", "Wells Fargo", "JPMorgan", "JP Morgan", "Chase Bank", "Citibank",
    "Citigroup", "Goldman Sachs", "Morgan Stanley", "Capital One", "HSBC", "Barclays",
    "Santander", "Deutsche Bank", "BNP Paribas", "Lloyds Bank", "NatWest", "PNC Bank",
    "Truist", "US Bancorp", "Charles Schwab", "American Express",
    "Mayo Clinic", "Cleveland Clinic", "Kaiser Permanente", "Johns Hopkins",
    "Mass General", "HCA Healthcare", "UnitedHealth", "Cerner", "Epic Systems",
    "Verizon", "AT&T", "T-Mobile", "Comcast", "Vodafone", "Deutsche Telekom", "Sprint Nextel",
    "Twilio", "Vonage", "RingCentral", "Five9", "Genesys", "NICE inContact", "Bandwidth.com",
    "Salesforce", "Zendesk", "Stripe", "PayPal", "Shopify", "Visa Inc", "Mastercard",
]
_DENY_RE = re.compile(
    r"(?<![A-Za-z0-9])(" + "|".join(re.escape(n) for n in DENYLIST) + r")(?![A-Za-z0-9])",
    re.IGNORECASE,
)

_CARD_CONTIG_RE = re.compile(r"(?<!\d)\d{13,19}(?!\d)")
_CARD_GROUPED_RE = re.compile(r"(?<!\d)(\d{4}([ -])\d{4}\2\d{4}\2\d{1,7})(?![\d])")
_IBAN_RE = re.compile(r"(?<![A-Za-z0-9])([A-Z]{2}\d{2}(?: ?[A-Z0-9]){10,30})(?![A-Za-z0-9])")
_E164_RE = re.compile(r"(?<![\w+])\+(\d[\d ().-]{6,20}\d)")
_FORMATTED_PHONE_RE = re.compile(r"(?<![\d+])(\(\d{3}\) ?|\d{3}[ .-])\d{3}[ .-]\d{4}(?!\d)")
_UK_PHONE_RE = re.compile(r"(?<![\w+])0\d{3,4} \d{3} ?\d{3,4}(?!\d)")  # spaced UK style
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@((?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,63})(?![A-Za-z0-9-])")
_SSN_RE = re.compile(r"(?<![\d-])(\d{3})-(\d{2})-(\d{4})(?![\d-])")
_AWS_RE = re.compile(r"AKIA[A-Z0-9]{16}")
_IPV4_RE = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])")

_DOC_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24",
                                                "203.0.113.0/24")]


def luhn_valid(number: str) -> bool:
    digits = [int(c) for c in number if c.isdigit()]
    if len(digits) < 2:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def iban_valid(candidate: str) -> bool:
    s = candidate.replace(" ", "").upper()
    if len(s) < 15 or len(s) > 34 or s[:2] not in IBAN_COUNTRIES:
        return False
    rearranged = s[4:] + s[:4]
    try:
        num = "".join(str(int(c, 36)) for c in rearranged)
    except ValueError:
        return False
    return int(num) % 97 == 1


def _is_timestamp14(digits: str) -> bool:
    if len(digits) != 14:
        return False
    try:
        datetime.datetime.strptime(digits, "%Y%m%d%H%M%S")
        return True
    except ValueError:
        return False


def phone_is_fictional(digits: str) -> bool:
    """``digits`` is the number with formatting stripped (country code included if given)."""
    if len(digits) == 11 and digits.startswith("1"):
        digits = digits[1:]
    if len(digits) == 10 and digits[0] in "23456789":
        return digits[3:6] == "555" and 100 <= int(digits[6:]) <= 199
    if digits.startswith("44"):
        digits = "0" + digits[2:]
    if digits.startswith("0"):
        # Ofcom numbers reserved for drama: 01632 960000-960999, 07700 900000-900999.
        return digits.startswith("01632960") or digits.startswith("07700900")
    return False


def domain_is_reserved(domain: str) -> bool:
    d = domain.lower().rstrip(".")
    if d in RESERVED_EMAIL_DOMAINS or any(d.endswith("." + r) for r in RESERVED_EMAIL_DOMAINS):
        return True
    return any(d.endswith(t) for t in RESERVED_TLDS)


def ip_is_allowed(ip: ipaddress.IPv4Address) -> bool:
    return (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
            or ip.is_unspecified or ip.is_multicast or any(ip in n for n in _DOC_NETS))


def check_text(text: str, own_domain: str = "", issued: frozenset = frozenset()) -> list[str]:
    """Return problems found in one string. ``issued`` holds token values the sensor itself
    generated (honeytokens), which may look like real keys."""
    problems: list[str] = []
    own = own_domain.lower()

    for m in _CARD_CONTIG_RE.finditer(text):
        digits = m.group(0)
        if _is_timestamp14(digits):
            continue
        if luhn_valid(digits):
            problems.append(f"card-like number passes Luhn: {digits}")
    for m in _CARD_GROUPED_RE.finditer(text):
        digits = re.sub(r"\D", "", m.group(1))
        if 13 <= len(digits) <= 19 and luhn_valid(digits):
            problems.append(f"card-like number passes Luhn: {m.group(1)}")

    for m in _IBAN_RE.finditer(text):
        if iban_valid(m.group(1)):
            problems.append(f"valid IBAN with real country code: {m.group(1)}")

    for m in _E164_RE.finditer(text):
        digits = re.sub(r"\D", "", m.group(1))
        if 8 <= len(digits) <= 15 and not phone_is_fictional(digits):
            problems.append(f"phone number outside fictional ranges: +{m.group(1)}")
    for m in _FORMATTED_PHONE_RE.finditer(text):
        digits = re.sub(r"\D", "", m.group(0))
        if not phone_is_fictional(digits):
            problems.append(f"phone number outside fictional ranges: {m.group(0)}")
    for m in _UK_PHONE_RE.finditer(text):
        digits = re.sub(r"\D", "", m.group(0))
        if len(digits) in (10, 11) and digits[1] in "1237" and not phone_is_fictional(digits):
            problems.append(f"UK-style phone number outside Ofcom drama ranges: {m.group(0)}")

    for m in _EMAIL_RE.finditer(text):
        dom = m.group(1).lower()
        if domain_is_reserved(dom) or (own and (dom == own or dom.endswith("." + own))):
            continue
        problems.append(f"email on non-reserved domain: {m.group(0)}")

    for m in _SSN_RE.finditer(text):
        area = m.group(1)
        if area in ("000", "666") or area.startswith("9"):
            continue
        problems.append(f"SSN-like value with issuable area number: {m.group(0)}")

    for m in _AWS_RE.finditer(text):
        if m.group(0) not in issued:
            problems.append(f"AWS access key id that is not a planted token: {m.group(0)}")

    for m in _DENY_RE.finditer(text):
        problems.append(f"real organisation name: {m.group(0)}")

    for m in _IPV4_RE.finditer(text):
        try:
            ip = ipaddress.IPv4Address(m.group(1))
        except ValueError:
            continue  # not an address (octet > 255), e.g. a version string
        if not ip_is_allowed(ip):
            problems.append(f"public IP address: {ip}")

    return problems


def _walk(obj: Any, path: str) -> Iterator[tuple[str, str]]:
    if isinstance(obj, bool) or obj is None or isinstance(obj, float):
        return
    if isinstance(obj, (str, int)):
        yield path, str(obj)
    elif isinstance(obj, dict):
        for k, v in obj.items():
            yield f"{path}.<key>", str(k)
            yield from _walk(v, f"{path}.{k}")
    elif isinstance(obj, (list, tuple)):
        for i, v in enumerate(obj):
            yield from _walk(v, f"{path}[{i}]")


def check_scenario(loaded) -> list[str]:
    """Check a ``scenarios.loader.LoadedScenario``; returns a list of problems (empty = ok)."""
    sc = loaded.scenario
    domain = sc.identity.domain
    problems: list[str] = []
    if not domain_is_reserved(domain):
        problems.append(f"{sc.name}: identity.domain {domain!r} is not under a reserved "
                        "TLD (.example/.test/.invalid) or example.com/org/net")

    # The scenario's own domain is only an acceptable email domain if it is itself reserved.
    own = domain if domain_is_reserved(domain) else ""

    issued = frozenset(loaded.recognised_tokens())

    def scan(path: str, text: str) -> None:
        for p in check_text(text, own, issued):
            problems.append(f"{sc.name}: {path}: {p}")

    for path, text in _walk(sc.model_dump(mode="json"), "scenario"):
        scan(path, text)

    from .web_assets import scenario_asset_texts
    for asset_path, text in scenario_asset_texts(loaded):
        scan(f"http asset {asset_path}", text)

    for svc_name in ("postgres", "mysql", "mssql"):
        svc = getattr(sc.services, svc_name)
        if svc is None:
            continue
        for db in svc.databases:
            for table in db.tables:
                _, rows = loaded.table_rows(db.name, table.name)
                for i, row in enumerate(rows):
                    for path, text in _walk(row, f"{svc_name}:{db.name}.{table.name}[{i}]"):
                        scan(path, text)
    return problems


def main(argv: list[str] | None = None) -> int:
    from .loader import list_scenarios, load_scenario

    names = list(argv if argv is not None else sys.argv[1:]) or list_scenarios()
    total = 0
    for name in names:
        try:
            loaded = load_scenario(name, seed="check")
        except Exception as exc:  # report and keep going
            print(f"{name}: FAILED TO LOAD: {exc}")
            total += 1
            continue
        problems = check_scenario(loaded)
        total += len(problems)
        status = "ok" if not problems else f"{len(problems)} problem(s)"
        print(f"{name}: {status}")
        for p in problems[:50]:
            print(f"  - {p}")
        if len(problems) > 50:
            print(f"  ... {len(problems) - 50} more")
    return 1 if total else 0


if __name__ == "__main__":
    sys.exit(main())
