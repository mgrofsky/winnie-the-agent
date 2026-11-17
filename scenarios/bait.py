"""Per-sensor bait: expand ``{{...}}`` templates in a scenario pack from the sensor seed.

A scenario pack may use a template in any string value (and any table key). The loader
expands every template once, before the pack is validated, so each sensor shows its own
organisation, hosts, people and credentials while one sensor stays identical across
restarts and across all its services. See ``docs/scenarios.md`` for the full table.

    {{org.name}} {{org.short}} {{org.slug}} {{org.abbr}} {{org.ABBR}} {{org.domain}}
    {{host:LABEL}}                  a host name for the role LABEL (pbx, db, app-edge)
    {{net:LABEL}}                   the first three octets of a private /24, e.g. 10.41.8
    {{person:N.FIELD}}              person N (1-99): first, last, full_name, username, email
    {{company:N.FIELD}}             another company N (1-99): name, short, slug, domain
    {{place:N}}                     an invented place name N (1-99), for branches and sites
    {{password:LABEL[:STYLE]}}      STYLE human (default), weak, user, service or random
    {{sha1:LABEL}}                  SHA-1 hex of {{password:LABEL}}
    {{secret:FORMAT:LABEL}}         FORMAT token, bearer, api_key, client_secret, session,
                                    uuid, aws_secret
    {{digits:N:LABEL}} {{hex:N:LABEL}} {{alnum:N:LABEL}}   N characters (1-128)
    {{ht:NAME}}                     the honeytoken NAME
    {{url:TEMPLATE}}                any template above, percent-encoded for a URL
    {{open}} {{close}}              literal "{{" and "}}"

The same template with the same label gives the same value everywhere in the pack. A label
used with two different arguments (``{{password:x}}`` and ``{{password:x:weak}}``), an
unknown template, a bad argument or an empty seed is a ``BaitError``. An operator may pin
the organisation, domain, host names and individual passwords (``Pins``).

All randomness is ``random.Random`` seeded with sha256(seed|scenario|purpose), the same
scheme as table rows and honeytokens, so values cannot be predicted without the seed.
"""

from __future__ import annotations

import hashlib
import random
import re
import string
import uuid
from urllib.parse import quote
from dataclasses import dataclass, field
from typing import Any, Callable, Iterator, Optional

TEMPLATE_RE = re.compile(r"\{\{([^{}]*)\}\}")
LABEL_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
HOST_LABEL_RE = re.compile(r"^[a-z][a-z0-9-]{0,30}$")

ORG_FIELDS = ("name", "short", "slug", "abbr", "ABBR", "domain")
COMPANY_FIELDS = ("name", "short", "slug", "domain")
PERSON_FIELDS = ("first", "last", "full_name", "username", "email")
PASSWORD_STYLES = ("human", "weak", "user", "service", "random")
SECRET_FORMATS = ("token", "bearer", "api_key", "client_secret", "session", "uuid",
                  "aws_secret")
SIZED_KINDS = ("digits", "hex", "alnum")
MAX_PERSONS = 99
RESERVED_TLDS = (".example", ".test", ".invalid")


class BaitError(ValueError):
    """A template could not be expanded. The message names the field and the template."""


# ---- word lists ---------------------------------------------------------------------------
# Common words and names, large enough that a value drawn from them says nothing about where
# it came from. Organisation names are built from invented halves; none is meant to be real.

FIRST_NAMES = """
Aaron Abigail Adam Adrian Aisha Alan Alex Alexis Alicia Allison Amanda Amber Amir Amy Ana
Andre Andrea Andrew Angela Anita Ann Anthony Antonio Arjun Ashley Austin Avery Beatriz Ben
Beth Bianca Blair Brandon Brenda Brian Brooke Bruce Caleb Cameron Carla Carlos Carmen Carol
Caroline Casey Catherine Chad Charles Chelsea Chloe Chris Christina Cindy Claire Cody Colin
Connor Craig Crystal Dakota Dale Damian Dana Daniel Danielle Darius Darren David Dean Deborah
Deepak Denise Derek Devon Diana Diego Dominic Donna Dylan Eddie Elena Eli Elijah Elizabeth
Ellen Ellis Emily Emma Eric Erica Erin Ethan Eva Evan Faith Farah Felix Fernando Fiona
Frank Gabriel Gary Gavin George Gina Grace Grant Greg Hannah Harper Hassan Heather Hector
Helen Henry Holly Hugo Ian Imani Irene Isaac Ivan Jack Jacob Jada Jamal James Jamie Jason
Javier Jay Jenna Jennifer Jeremy Jesse Jessica Jill Joanna Joel John Jonathan Jordan Jorge
Joseph Joshua Joy Juan Julia Julian Justin Kara Karen Karl Kate Katie Keith Kelly Kendall
Kenji Kevin Kim Kyle Laura Lauren Leah Lena Leo Leon Liam Linda Lisa Logan Lucas Lucy Luis
Luke Mackenzie Maggie Malik Mara Marco Maria Mark Marcus Martin Maya Megan Melissa Mia
Michael Michelle Miguel Mike Mila Mohammed Molly Monica Morgan Nadia Nancy Naomi Natalie
Nathan Neil Nicole Nina Noah Nora Olivia Omar Oscar Owen Paige Pamela Patrick Paul Paula
Peter Philip Priya Quinn Rachel Rafael Rahul Raj Ramon Rebecca Reese Riley Rita Rob Robin
Roger Rosa Ross Ruby Ryan Sam Samantha Sandra Sara Scott Sean Sergio Seth Shane Shannon
Sharon Simon Sofia Sophie Stacy Stephanie Steve Susan Tanya Tara Taylor Teresa Terry Theo
Thomas Tim Tina Todd Tom Tony Tracy Travis Trevor Tyler Valerie Vanessa Victor Vikram
Vincent Wade Walter Wendy Wesley Will Xavier Yasmin Yusuf Zach Zoe
""".split()

LAST_NAMES = """
Abbott Acosta Adams Aguilar Ahmed Alexander Ali Allen Alvarez Anderson Andrews Armstrong
Arnold Atkinson Bailey Baker Baldwin Banks Barnes Barrett Bauer Becker Bell Bennett Berg
Bishop Black Blake Bowen Boyd Bradley Brennan Brooks Brown Bryant Burke Burns Butler Byrne
Caldwell Campbell Carlson Carroll Carter Castillo Chan Chang Chapman Chavez Chen Clarke
Cohen Cole Coleman Collins Cooper Cortez Cruz Cunningham Daniels Davidson Davis Dawson Day
Delgado Dixon Doyle Duncan Dunn Edwards Elliott Ellis Erikson Evans Farrell Ferguson
Fernandez Fischer Fisher Fleming Flores Ford Foster Fox Francis Freeman Fuller Gallagher
Garcia Gardner Garza George Gibson Gill Gomez Gonzalez Gordon Graham Grant Gray Green
Gregory Griffin Gupta Hale Hall Hamilton Hansen Harper Harris Hart Harvey Hayes Henderson
Hernandez Hill Hoffman Holland Holmes Howard Hughes Hunt Hunter Ibrahim Jackson Jacobs
Jensen Jimenez Johnson Jones Jordan Kane Kaur Keller Kelly Kennedy Khan Kim King Klein
Knight Kowalski Kumar Lambert Lane Larson Lawrence Lee Lewis Lindqvist Little Lopez Lucas
Lynch Malik Marsh Marshall Martin Martinez Mason Matthews Meyer Miller Mills Mitchell
Moore Morales Moreno Morgan Morris Murphy Murray Myers Nakamura Nelson Newman Nguyen Nichols
Novak Obrien Okafor Oliver Olsen Ortiz Owens Palmer Park Parker Patel Patterson Payne
Pearson Perez Perry Peters Phillips Pierce Porter Powell Price Quinn Ramirez Ramos Reed
Reid Reyes Reynolds Rhodes Rice Richards Rivera Roberts Robertson Robinson Rodriguez Rogers
Romero Ross Russell Ryan Sanchez Sanders Santos Schmidt Schneider Scott Shah Shaw Silva
Simmons Singh Smith Snyder Sokolov Spencer Stanley Stewart Stone Sullivan Sutton Tanaka
Taylor Thomas Thompson Torres Tran Tucker Turner Vargas Vasquez Wagner Walker Wallace Walsh
Ward Warren Watson Weaver Webb Weber Wells West Wheeler White Williams Willis Wilson Wong
Wood Wright Yamamoto Young Zhang Zimmerman
""".split()

# Ordinary words people build passwords from.
PASSWORD_WORDS = """
access account admin alpha amber anchor angel apple april arrow atlas august autumn badger
banana baseball basket beach bear beaver bella berry birch black blue boston bravo bridge
bright brown buddy buffalo butter cactus camel canyon captain carbon castle cedar central
champion charlie cherry chicago chicken chocolate cinder circle citrus clover cobalt coffee
comet compass copper coral cosmos cotton cougar country cowboy coyote crimson crystal dakota
dallas delta denver desert diamond dolphin dragon eagle easter echo eclipse emerald empire
falcon ferrari fiesta finance fire flower forest fortune fox freedom friday frost galaxy
garden gemini ginger glacier golden gopher granite green guitar hammer happy harbor hawk
heart helpdesk hockey honey horizon hunter hurricane iceman indigo island ivory jaguar
jasmine jersey jupiter kansas kitten knight lakers lemon liberty lighthouse lily lincoln
lion london lucky magic mango maple marble marina matrix maverick meadow melon mercury
midnight mike mission monkey monday morning mountain mustang network nevada nimbus ninja
north oasis ocean office olive omega onyx orange orchid oregon panther paris pepper phoenix
pickle pilot pioneer pirate planet platinum pluto polar purple python quartz rabbit raider
rainbow ranger raven rebel redwood river robin rocket rose ruby saturn scorpion secure
shadow shamrock sierra silver skyline soccer solar sparrow spirit spring stallion star
station steel storm sugar summer summit sunset sunshine support swift system tango texas
thunder tiger titan topaz tornado tower trinity tulip turtle unicorn valley velvet venus
viking violet voyager walnut warrior welcome whisky william willow winter wizard wolf yankee
yellow zebra zephyr anvil aspen bandit biscuit blizzard bluebird bronco buckeye
canary cardinal cheetah chester cobra condor dallas daisy domino ember fender gator
honeybee jackson jumbo karma kodiak lobster marvel nugget otter pebble penguin
""".split()

SEASONS = ["Spring", "Summer", "Autumn", "Fall", "Winter"]
MONTHS = ["January", "February", "March", "April", "May", "June", "July", "August",
          "September", "October", "November", "December"]
KEYBOARD_WALKS = ["qwerty", "Qwerty", "qwer", "Qwer", "asdf", "Asdf", "zxcv", "1qaz2wsx",
                  "1qaz@WSX", "Zaq12wsx", "zaq1xsw2", "qazwsx", "Qazwsx", "1q2w3e4r",
                  "1q2w3e", "Q1w2e3r4", "qwertyuiop", "asdfgh", "Asdfgh", "poiuy",
                  "zxcvbnm", "!QAZ2wsx", "qweasd", "Qweasdzxc", "123qwe", "qwe123"]
# Default and commonly reused passwords that brute-force wordlists try first.
WEAK_PASSWORDS = """
admin admin123 admin1234 Admin123 Admin@123 administrator password password1 Password1
Password123 password123 passw0rd Passw0rd P@ssw0rd P@ssword1 123456 1234567 12345678
123456789 1234 12345 changeme changeme123 ChangeMe1 welcome welcome1 Welcome1 Welcome123
letmein letmein1 toor root root123 qwerty qwerty123 Qwerty123 test test123 test1234 guest
guest123 default secret secret123 support support123 service abc123 abc12345 master
monkey dragon iloveyou trustno1 111111 000000 654321 super superuser temp temp123 pass
pass123 pass1234 demo demo123 user user123 operator manager
""".split()
SYMBOLS = ["!", "!", "!", "!", "*", ".", "?", "-", "_"]

# Invented organisation names: an odd first half joined to a place-like second half. The
# halves cannot rebuild the fixed names earlier versions of the bundled packs used.
ORG_FIRST = """
Auber Bram Brenn Briar Brock Calder Cinder Coll Cress Dapple Dorn Dunmar Fallow Fenn
Gale Garr Gorse Hale Hatch Ivel Jessam Kell Kest Lind Loam Lorn Meer Nettle
Noll Orrin Osier Pell Pemm Quarr Rann Rill Rook Sable Sallow Sedge Shale Sorrel
Stave Tamar Tarn Teal Thistle Thorn Vell Wark Weld Whin Willet Wren Yarrow Brisk
Cadge Dunwold Eskel Farrow Garnock Haddle Ingle Jorvell Kilver Lammer Mirran Norrow Ottle Pellin
Quenby Raskel Sandle Tolver Ulver Varrow Wendle
""".split()
ORG_SECOND = """
bank barrow beck borough bourne bridge brook burn bury by cliff combe cote croft dale
den down ere fell field ford gate grove hallow haven hithe holm hurst ing lade land leigh
ley low mere minster moor more mouth ness port ridge rigg shaw stead stoke stone thorpe
ton vale wark water way well wick wood worth
""".split()
DEFAULT_ORG_SUFFIXES = ["Group", "Holdings", "Partners", "Systems", "Services"]
# What other companies (customers, tenants, partners) call themselves.
COMPANY_SUFFIXES = """
Analytics;Architects;Bakery;Builders;Cabinetry;Clinic;Commerce;Construction;Consulting;
Couriers;Creative;Dental;Design Studio;Distributors;Electric;Engineering;Family Dental;
Farms;Foods;Freight;Freight Co-op;Furniture;Grocers;Hardware;Health;Home Services;
Insurance Agency;Interiors;Labs;Landscaping;Law Group;Logistics;Machine Works;Marine;
Media;Medical Group;Motors;Outfitters;Packaging;Pet Care;Pharmacy;Plumbing;Print Co;
Properties;Realty;Roasters;Robotics;Supply;Textiles;Tools;Travel;Utilities;Veterinary;
Wholesale;Wireless
""".replace("\n", "").split(";")
GENERIC_ORG_WORDS = {"inc", "ltd", "llc", "co", "corp", "group", "plc", "the", "and", "of"}
SITE_CODES = ["atl", "aus", "bos", "chi", "dal", "den", "iad", "lax", "mia", "msp", "nyc",
              "pdx", "phx", "sea", "sfo", "slc", "stl", "yyz", "lon", "fra", "ams", "dub"]


# ---- the template engine ------------------------------------------------------------------

@dataclass(frozen=True)
class Template:
    text: str          # the whole template including braces
    kind: str          # org, host, net, person, password, sha1, secret, digits, ... ht
    key: str           # what makes two uses the same value (kind + label)
    args: tuple        # the rest; must agree between uses of the same key


def parse(inner: str) -> Template:
    """Parse the text between ``{{`` and ``}}``. Raises BaitError on anything unknown."""
    text = "{{" + inner + "}}"
    body = inner.strip()
    if body in ("open", "close"):
        return Template(text, body, body, ())
    if body.startswith("org."):
        name = body[4:]
        if name not in ORG_FIELDS:
            raise BaitError(f"unknown organisation field {name!r} (use one of "
                            f"{', '.join(ORG_FIELDS)})")
        return Template(text, "org", body, ())
    head, _, rest = body.partition(":")
    parts = rest.split(":") if rest else []
    if head == "ht":
        if len(parts) != 1 or not re.fullmatch(r"[a-z0-9_]+", parts[0]):
            raise BaitError("honeytoken template is {{ht:NAME}}")
        return Template(text, "ht", body, (parts[0],))
    if head == "url":
        if not rest:
            raise BaitError("url template is {{url:TEMPLATE}}, e.g. {{url:password:db}}")
        inner = parse(rest)
        if inner.kind in ("url", "open", "close"):
            raise BaitError("url template wraps one value template")
        return Template(text, "url", "url:" + inner.key, (inner,))
    if head == "company":
        m = re.fullmatch(r"([0-9]{1,2})\.([a-z]+)", rest)
        if not m or not 1 <= int(m.group(1)) <= MAX_PERSONS or m.group(2) not in COMPANY_FIELDS:
            raise BaitError(f"company template is {{{{company:N.FIELD}}}}, N 1-{MAX_PERSONS}, "
                            f"FIELD one of {', '.join(COMPANY_FIELDS)}")
        return Template(text, "company", body, (int(m.group(1)), m.group(2)))
    if head == "place":
        if not re.fullmatch(r"[0-9]{1,2}", rest) or not 1 <= int(rest) <= MAX_PERSONS:
            raise BaitError(f"place template is {{{{place:N}}}}, N 1-{MAX_PERSONS}")
        return Template(text, "place", body, (int(rest),))
    if head == "host":
        if len(parts) != 1 or not HOST_LABEL_RE.fullmatch(parts[0]):
            raise BaitError("host template is {{host:LABEL}}, LABEL like pbx or db-edge")
        return Template(text, "host", f"host:{parts[0]}", ())
    if head == "net":
        if len(parts) != 1 or not LABEL_RE.fullmatch(parts[0]):
            raise BaitError("net template is {{net:LABEL}}")
        return Template(text, "net", f"net:{parts[0]}", ())
    if head == "person":
        m = re.fullmatch(r"([0-9]{1,2})\.([a-z_]+)", rest)
        if not m or not 1 <= int(m.group(1)) <= MAX_PERSONS or m.group(2) not in PERSON_FIELDS:
            raise BaitError(f"person template is {{{{person:N.FIELD}}}}, N 1-{MAX_PERSONS}, "
                            f"FIELD one of {', '.join(PERSON_FIELDS)}")
        return Template(text, "person", body, (int(m.group(1)), m.group(2)))
    if head == "password":
        if not 1 <= len(parts) <= 2 or not LABEL_RE.fullmatch(parts[0]):
            raise BaitError("password template is {{password:LABEL}} or "
                            "{{password:LABEL:STYLE}}")
        style = parts[1] if len(parts) == 2 else "human"
        if style not in PASSWORD_STYLES:
            raise BaitError(f"unknown password style {style!r} (use one of "
                            f"{', '.join(PASSWORD_STYLES)})")
        return Template(text, "password", f"password:{parts[0]}", (style,))
    if head == "sha1":
        if len(parts) != 1 or not LABEL_RE.fullmatch(parts[0]):
            raise BaitError("sha1 template is {{sha1:LABEL}} (the hash of {{password:LABEL}})")
        return Template(text, "sha1", f"sha1:{parts[0]}", ())
    if head == "secret":
        if len(parts) != 2 or not LABEL_RE.fullmatch(parts[1]):
            raise BaitError("secret template is {{secret:FORMAT:LABEL}}")
        if parts[0] not in SECRET_FORMATS:
            raise BaitError(f"unknown secret format {parts[0]!r} (use one of "
                            f"{', '.join(SECRET_FORMATS)})")
        return Template(text, "secret", f"secret:{parts[1]}", (parts[0],))
    if head in SIZED_KINDS:
        if len(parts) != 2 or not parts[0].isdigit() or not 1 <= int(parts[0]) <= 128 \
                or not LABEL_RE.fullmatch(parts[1]):
            raise BaitError(f"{head} template is {{{{{head}:N:LABEL}}}}, N 1-128")
        return Template(text, head, f"{head}:{parts[1]}", (int(parts[0]),))
    raise BaitError(f"unknown template {text!r}")


def iter_strings(obj: Any, path: str = "") -> Iterator[tuple[str, str]]:
    """Every string (values and table keys) in a parsed TOML document, with its path."""
    if isinstance(obj, str):
        yield path, obj
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from iter_strings(v, f"{path}[{i}]")
    elif isinstance(obj, dict):
        for k, v in obj.items():
            sub = f"{path}.{k}" if path else str(k)
            yield sub, str(k)
            yield from iter_strings(v, sub)


def _rng(seed: str, *purpose: str) -> random.Random:
    digest = hashlib.sha256("|".join((seed,) + purpose).encode()).digest()
    return random.Random(int.from_bytes(digest[:8], "big"))


@dataclass
class Pins:
    """Operator-pinned identity. ``None`` means derive from the seed."""

    org_name: Optional[str] = None
    domain: Optional[str] = None
    org_suffixes: list[str] = field(default_factory=list)
    domain_words: list[str] = field(default_factory=list)
    hosts: dict[str, str] = field(default_factory=dict)
    passwords: dict[str, str] = field(default_factory=dict)


class Bait:
    """Expands templates for one (seed, scenario). Values are computed once and cached."""

    def __init__(self, seed: str, scenario: str, pins: Optional[Pins] = None,
                 honeytokens: Optional[dict[str, str]] = None) -> None:
        if not seed or not str(seed).strip():
            raise BaitError(f"scenario {scenario!r}: no sensor seed; per-sensor bait needs one "
                            "([scenario] seed or the seed file in the data directory)")
        self.seed = str(seed)
        self.scenario = scenario
        self.pins = pins or Pins()
        self.honeytokens = dict(honeytokens or {})
        self._declared: dict[str, Template] = {}
        self._values: dict[str, str] = {}
        self._org: Optional[dict[str, str]] = None
        self._people: list[tuple[str, str]] = []
        self._used_hosts: set[str] = set(self.pins.hosts.values())
        self._used_nets: set[str] = set()
        self._companies: list[str] = []
        self._conventions: Optional[tuple[int, int]] = None

    def r(self, *purpose: str) -> random.Random:
        return _rng(self.seed, self.scenario, "bait", *purpose)

    # ---- declaration and expansion --------------------------------------------------------

    def declare(self, tpl: Template, where: str) -> None:
        if tpl.kind == "url":
            self.declare(tpl.args[0], where)
        prior = self._declared.get(tpl.key)
        if prior is None:
            self._declared[tpl.key] = tpl
        elif prior.args != tpl.args or prior.kind != tpl.kind:
            raise BaitError(f"{where}: {tpl.text} conflicts with {prior.text}; one label must "
                            "always use the same arguments")

    def scan(self, doc: Any) -> None:
        """Parse and declare every template in ``doc`` (pass one)."""
        for path, text in iter_strings(doc):
            for m in TEMPLATE_RE.finditer(text):
                try:
                    tpl = parse(m.group(1))
                except BaitError as exc:
                    raise BaitError(f"{path}: {exc}") from None
                inner = tpl.args[0] if tpl.kind == "url" else tpl
                if inner.kind == "ht" and inner.args[0] not in self.honeytokens:
                    raise BaitError(f"{path}: unknown honeytoken {inner.args[0]!r}")
                self.declare(tpl, path)

    def expand_text(self, text: str, where: str = "") -> str:
        def one(m: re.Match) -> str:
            try:
                tpl = parse(m.group(1))
            except BaitError as exc:
                raise BaitError(f"{where}: {exc}" if where else str(exc)) from None
            self.declare(tpl, where)
            return self.value(tpl)

        return TEMPLATE_RE.sub(one, text)

    def expand(self, doc: Any, path: str = "") -> Any:
        """A copy of ``doc`` with every template replaced (pass two)."""
        if isinstance(doc, str):
            return self.expand_text(doc, path)
        if isinstance(doc, list):
            return [self.expand(v, f"{path}[{i}]") for i, v in enumerate(doc)]
        if isinstance(doc, dict):
            out = {}
            for k, v in doc.items():
                sub = f"{path}.{k}" if path else str(k)
                out[self.expand_text(str(k), sub)] = self.expand(v, sub)
            return out
        return doc

    def expansions(self) -> dict[str, str]:
        """{template: value} for every template expanded so far, honeytokens left out."""
        out = {}
        for _key, tpl in sorted(self._declared.items()):
            inner = tpl.args[0] if tpl.kind == "url" else tpl
            if inner.kind in ("ht", "open", "close"):
                continue  # honeytoken values are never listed, even percent-encoded
            out[tpl.text] = self.value(tpl)
        return out

    def value(self, tpl: Template) -> str:
        if tpl.kind == "open":
            return "{{"
        if tpl.kind == "close":
            return "}}"
        if tpl.kind == "ht":
            return self.honeytokens[tpl.args[0]]
        if tpl.kind == "url":
            # Unreserved characters (A-Z a-z 0-9 - . _ ~) stay; everything else is escaped,
            # so the value round-trips through a URL's userinfo, path or query.
            return quote(self.value(tpl.args[0]), safe="")
        cached = self._values.get(tpl.key)
        if cached is not None:
            return cached
        makers: dict[str, Callable[[Template], str]] = {
            "org": self._org_value, "host": self._host, "net": self._net,
            "person": self._person, "password": self._password, "sha1": self._sha1,
            "secret": self._secret, "digits": self._sized, "hex": self._sized,
            "alnum": self._sized, "company": self._company, "place": self._place,
        }
        val = makers[tpl.kind](tpl)
        self._values[tpl.key] = val
        return val

    # ---- organisation ---------------------------------------------------------------------

    def org(self) -> dict[str, str]:
        if self._org is not None:
            return self._org
        rng = self.r("org")
        if self.pins.org_name:
            name = self.pins.org_name
            short = next((w for w in re.findall(r"[A-Za-z][A-Za-z0-9]*", name)
                          if w.lower() not in GENERIC_ORG_WORDS), name.split()[0])
        else:
            short = rng.choice(ORG_FIRST) + rng.choice(ORG_SECOND)
            suffix = rng.choice(self.pins.org_suffixes or DEFAULT_ORG_SUFFIXES)
            name = f"{short} {suffix}"
        slug = re.sub(r"[^a-z0-9]", "", short.lower()) or "corp"
        initials = "".join(w[0] for w in re.findall(r"[A-Za-z][A-Za-z0-9]*", name)
                           if w.lower() not in GENERIC_ORG_WORDS).lower()
        abbr = initials if len(initials) >= 2 else slug[:3]
        if self.pins.domain:
            domain = self.pins.domain
        else:
            words = [re.sub(r"[^a-z0-9]", "", w.lower()) for w in self.pins.domain_words]
            words = [w for w in words if w]
            shapes = [f"{slug}"]
            if words:
                dw = rng.choice(words)
                shapes += [f"{slug}-{dw}", f"{slug}{dw}", f"{slug}-{dw}", f"{abbr}{dw}"]
            label = rng.choice(shapes)[:63]
            tld = ".example" if rng.random() < 0.8 else ".test"
            domain = label + tld
        self._org = {"name": name, "short": short, "slug": slug, "abbr": abbr,
                     "ABBR": abbr.upper(), "domain": domain}
        return self._org

    def _org_value(self, tpl: Template) -> str:
        return self.org()[tpl.key[4:]]

    # ---- other companies and places --------------------------------------------------------

    def _invented_words(self) -> list[str]:
        """Distinct invented words for companies and places, never the organisation's own."""
        if not self._companies:
            rng = self.r("companies")
            seen = {self.org()["short"].lower()}
            while len(self._companies) < 2 * MAX_PERSONS:
                word = rng.choice(ORG_FIRST) + rng.choice(ORG_SECOND)
                if word.lower() not in seen:
                    seen.add(word.lower())
                    self._companies.append(word)
        return self._companies

    def _company(self, tpl: Template) -> str:
        n, what = tpl.args
        short = self._invented_words()[n - 1]
        slug = short.lower()
        if what == "short":
            return short
        if what == "slug":
            return slug
        if what == "domain":
            return slug + ".example"
        rng = self.r("company", str(n))
        return f"{short} {rng.choice(COMPANY_SUFFIXES)}"

    def _place(self, tpl: Template) -> str:
        return self._invented_words()[MAX_PERSONS + tpl.args[0] - 1]

    # ---- hosts and networks ---------------------------------------------------------------

    def _host(self, tpl: Template) -> str:
        label = tpl.key.split(":", 1)[1]
        if label in self.pins.hosts:
            return self.pins.hosts[label]
        rng = self.r("host", label)
        for _ in range(50):
            n = rng.choice([1, 1, 1, 2, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12])
            shape = rng.randrange(6)
            if shape == 0:
                host = f"{label}{n:02d}"
            elif shape == 1:
                host = f"{label}{n}"
            elif shape == 2:
                host = f"{label}-{n:02d}"
            elif shape == 3:
                host = f"{label}-{rng.choice(SITE_CODES)}{n}"
            elif shape == 4:
                host = f"{rng.choice(SITE_CODES)}-{label}{n:02d}"
            else:
                host = f"{self.org()['abbr']}-{label}{n:02d}"
            host = host[:63]
            if host not in self._used_hosts:
                self._used_hosts.add(host)
                return host
        raise BaitError(f"could not find an unused host name for {tpl.text}")

    def _net(self, tpl: Template) -> str:
        rng = self.r("net", tpl.key)
        for _ in range(200):
            roll = rng.random()
            if roll < 0.7:
                net = f"10.{rng.randrange(0, 255)}.{rng.randrange(0, 255)}"
            elif roll < 0.85:
                net = f"172.{rng.randrange(16, 32)}.{rng.randrange(0, 255)}"
            else:
                net = f"192.168.{rng.randrange(0, 255)}"
            if net not in self._used_nets:
                self._used_nets.add(net)
                return net
        raise BaitError(f"could not find an unused network for {tpl.text}")

    # ---- people ---------------------------------------------------------------------------

    def _person(self, tpl: Template) -> str:
        n, what = tpl.args
        # All people are drawn at once in one fixed order, so person N never depends on
        # which templates were expanded first. No two share a name or a user name.
        if not self._people:
            rng = self.r("people")
            seen: set = set()
            while len(self._people) < MAX_PERSONS:
                first, last = rng.choice(FIRST_NAMES), rng.choice(LAST_NAMES)
                ident = (first[0], last)
                if first != last and (first, last) not in seen and ident not in seen:
                    seen.update({(first, last), ident})
                    self._people.append((first, last))
        first, last = self._people[n - 1]
        if what == "first":
            return first
        if what == "last":
            return last
        if what == "full_name":
            return f"{first} {last}"
        user_style, mail_style = self.conventions()
        f, l_ = first.lower(), last.lower()
        username = [f"{f[0]}{l_}", f"{f}{l_[0]}", f"{l_}{f[0]}", f"{f}_{l_}", f"{f}.{l_}"][
            user_style]
        if what == "username":
            # Dots are not valid in a local user name; that convention falls back to '_'.
            return username.replace(".", "_")[:32]
        local = [f"{f}.{l_}", f"{f[0]}{l_}", f"{f}", f"{f}{l_[0]}", f"{f}.{l_}"][mail_style]
        return f"{local}@{self.org()['domain']}"

    def conventions(self) -> tuple[int, int]:
        if self._conventions is None:
            rng = self.r("conventions")
            self._conventions = (rng.randrange(5), rng.randrange(5))
        return self._conventions

    # ---- credentials ----------------------------------------------------------------------

    def _password(self, tpl: Template) -> str:
        label = tpl.key.split(":", 1)[1]
        if label in self.pins.passwords:
            return self.pins.passwords[label]
        style = tpl.args[0]
        rng = self.r("password", label)
        if style == "weak":
            return rng.choice(WEAK_PASSWORDS)
        if style == "user":
            return user_password(rng, label)
        if style == "service":
            return service_password(rng, label)
        if style == "random":
            pool = string.ascii_letters + string.digits + "!*.?-_"
            while True:
                pw = "".join(rng.choice(pool) for _ in range(rng.randint(14, 20)))
                if any(c.isdigit() for c in pw) and any(c.isupper() for c in pw):
                    return pw
        return human_password(rng, self.org()["short"])

    def _sha1(self, tpl: Template) -> str:
        label = tpl.key.split(":", 1)[1]
        pw_key = f"password:{label}"
        pw_tpl = self._declared.get(pw_key) or Template(
            "{{password:" + label + "}}", "password", pw_key, ("human",))
        self._declared.setdefault(pw_key, pw_tpl)
        return hashlib.sha1(self.value(pw_tpl).encode()).hexdigest()

    def _secret(self, tpl: Template) -> str:
        fmt = tpl.args[0]
        rng = self.r("secret", tpl.key)
        alnum = string.ascii_letters + string.digits
        if fmt == "bearer":
            # 32 random bytes in unpadded base64url, the usual opaque OAuth access token.
            return "".join(rng.choice(alnum + "-_") for _ in range(43))
        if fmt == "token":
            return "".join(rng.choice(alnum) for _ in range(40))
        if fmt == "api_key":
            return "".join(rng.choice(alnum) for _ in range(32))
        if fmt == "client_secret":
            return "".join(rng.choice(alnum + "-_") for _ in range(40))
        if fmt == "session":
            # PHP's default session id: 26 characters of 0-9a-v.
            return "".join(rng.choice(string.digits + "abcdefghijklmnopqrstuv")
                           for _ in range(26))
        if fmt == "uuid":
            return str(uuid.UUID(int=rng.getrandbits(128), version=4))
        # aws_secret: 40 characters of base64, derived from the seed, so it is the secret of
        # no real key whatever key id it is paired with.
        return "".join(rng.choice(alnum + "/+") for _ in range(40))

    def _sized(self, tpl: Template) -> str:
        n = tpl.args[0]
        rng = self.r(tpl.kind, tpl.key)
        pool = {"digits": string.digits, "hex": "0123456789abcdef",
                "alnum": string.ascii_letters + string.digits}[tpl.kind]
        return "".join(rng.choice(pool) for _ in range(n))


# ---- password shapes ----------------------------------------------------------------------

def _year(rng: random.Random, short_ok: bool = True) -> str:
    year = rng.choice([2016, 2017, 2018, 2019, 2020, 2021, 2022, 2023, 2023, 2024, 2024,
                       2025, 2025, 2026])
    return str(year)[2:] if short_ok and rng.random() < 0.3 else str(year)


def _cap(rng: random.Random, word: str) -> str:
    roll = rng.random()
    if roll < 0.65:
        return word.capitalize()
    if roll < 0.9:
        return word.lower()
    return word.upper()


def human_password(rng: random.Random, org_short: str = "") -> str:
    """A password a person picked: the shapes found again and again in breach corpora."""
    sym = rng.choice(SYMBOLS)
    shape = rng.randrange(9)
    if shape == 0:      # word + year + symbol
        pw = f"{_cap(rng, rng.choice(PASSWORD_WORDS))}{_year(rng)}{sym}"
    elif shape == 1:    # season + year (+ symbol)
        pw = f"{rng.choice(SEASONS)}{_year(rng)}" + (sym if rng.random() < 0.6 else "")
    elif shape == 2:    # keyboard walk (+ digits)
        walk = rng.choice(KEYBOARD_WALKS)
        pw = walk + (rng.choice(["", "1", "12", "123", "!", "1!", "2024"])
                     if len(walk) < 10 else "")
    elif shape == 3:    # first name + digits (a birth year or two digits)
        tail = str(rng.randint(1965, 2004)) if rng.random() < 0.5 else f"{rng.randint(1, 99):02d}"
        pw = f"{_cap(rng, rng.choice(FIRST_NAMES))}{tail}" + (sym if rng.random() < 0.4 else "")
    elif shape == 4 and org_short:   # company name + year + symbol
        pw = f"{org_short}{_year(rng, short_ok=False)}{sym}"
    elif shape == 5:    # month + year
        pw = f"{rng.choice(MONTHS)}{_year(rng)}" + (sym if rng.random() < 0.5 else "")
    elif shape == 6:    # two words + digit
        pw = (f"{rng.choice(PASSWORD_WORDS).capitalize()}{rng.choice(PASSWORD_WORDS).capitalize()}"
              f"{rng.randint(1, 99)}")
    elif shape == 7:    # leetspeak word + digits
        word = rng.choice(PASSWORD_WORDS)
        leet = word.translate(str.maketrans({"a": "@", "o": "0", "e": "3", "i": "1", "s": "5"}))
        pw = f"{leet.capitalize()}{rng.randint(1, 999)}"
    else:               # word + digits
        pw = f"{_cap(rng, rng.choice(PASSWORD_WORDS))}{rng.randint(1, 9999)}"
    return pw[:64]


def user_password(rng: random.Random, label: str) -> str:
    """A password built from the account name, the way shared and default accounts are."""
    base = label.lower()
    shape = rng.randrange(7)
    if shape == 0:
        return base
    if shape == 1:
        return f"{base}123"
    if shape == 2:
        return f"{base}{_year(rng)}"
    if shape == 3:
        return f"{base.capitalize()}{_year(rng, short_ok=False)}{rng.choice(SYMBOLS)}"
    if shape == 4:
        return f"{base}{rng.choice(['pass', 'pw', '!', '1', '01', '2'])}"
    if shape == 5:
        return f"{base}{base}" if len(base) <= 6 else f"{base}1!"
    return f"{base.capitalize()}{rng.randint(1, 99)}"


def service_password(rng: random.Random, label: str) -> str:
    """An application or service account password set once by an admin and never rotated."""
    parts = [p for p in re.split(r"[^a-z0-9]+", label.lower()) if p] or ["svc"]
    sep = rng.choice(["_", "-", "", ""])
    base = sep.join(parts)
    shape = rng.randrange(6)
    if shape == 0:
        return f"{base}{sep}{_year(rng, short_ok=False)}"
    if shape == 1:
        return f"{base}{rng.choice(['pass', 'pw', 'pwd', 'secret'])}{_year(rng)}"
    if shape == 2:
        return f"{base.capitalize()}{rng.choice(SYMBOLS)}{_year(rng, short_ok=False)}"
    if shape == 3:
        return f"{''.join(p.capitalize() for p in parts)}{rng.randint(1, 99)}{rng.choice(SYMBOLS)}"
    if shape == 4:
        return f"{base}{sep or '_'}{rng.choice(PASSWORD_WORDS)}{rng.randint(1, 9)}"
    return f"{base}{sep}{rng.choice(['prod', 'live', 'app', 'svc', 'db'])}{_year(rng)}"


# ---- credential-field walk (used by the repository test and the checker) ------------------

def is_template_only(value: Any) -> bool:
    """True for an empty value or one made only of templates and masking characters."""
    if not isinstance(value, str):
        return value is None
    rest = TEMPLATE_RE.sub("", value)
    return rest.strip("*.- ") == ""
