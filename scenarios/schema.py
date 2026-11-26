"""Strict schema for scenario packs (``scenarios/<name>/scenario.toml``).

A scenario is the single source of truth for what the sensor pretends to be: identity,
which listeners run and how they behave, fake accounts, fake data, HTTP surface and
honeytokens.

Scenario files are human-authored. The tuner never edits them; its fenced changes live
in an overlay (``decoy/overlay.json``, see ``Overlay``) merged on top at load time.

Any string value may contain ``{{...}}`` templates (``{{ht:<name>}}`` honeytokens,
``{{password:<label>}}``, ``{{org.name}}`` and the rest, see ``scenarios.bait``). The loader
expands them from the sensor seed before validating, so every check below applies to the
expanded values. Fields marked ``credential`` (account passwords, columns with
``secret = true``) hold bait that differs per sensor; bundled packs fill them with templates.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Literal, NamedTuple, Optional, Union

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

# ---- shared fences (also used by the tuner) ----------------------------------------------
# Apply these with re.fullmatch (or pydantic ``pattern``, whose engine anchors '$' at the
# true end of input). With re.match/re.search, '$' also accepts a trailing newline.

USERNAME_RE = r"^[a-z_][a-z0-9_-]{0,31}$"
SIP_EXTENSION_RE = r"^[0-9]{2,6}$"
HOSTNAME_RE = r"^[a-z][a-z0-9-]{0,62}$"
DOMAIN_RE = r"^[a-z0-9-]{1,63}(\.[a-z0-9-]{1,63})+$"  # length capped by max_length
LURE_PATH_RE = r"^/(?:[A-Za-z0-9._-]{1,64}/){0,12}[A-Za-z0-9._-]{1,64}$"
SAFE_TEXT_RE = r"^[A-Za-z0-9 .,:;()&'/_+#@=*!?%-]*$"
PASSWORD_MAX = 64
SCENARIO_NAME_RE = r"^[a-z][a-z0-9_]{1,40}$"
IDENT_RE = r"^[A-Za-z_][A-Za-z0-9_]{0,63}$"
HTTP_PATH_RE = r"^/[A-Za-z0-9._~/{}-]{0,200}$"


def valid_password(value: str) -> bool:
    """Printable ASCII, <= 64 chars, no newline, no leading/trailing space."""
    if len(value) > PASSWORD_MAX:
        return False
    if value != value.strip():
        return False
    return all(0x20 <= ord(c) <= 0x7E for c in value)


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=False)


# ---- identity -----------------------------------------------------------------------------

class FakeUser(Strict):
    name: str = Field(pattern=USERNAME_RE)
    uid: int = Field(ge=0, le=65535)
    gecos: str = Field(default="", max_length=64, pattern=SAFE_TEXT_RE)
    home: str = Field(pattern=LURE_PATH_RE)
    shell: str = Field(default="/bin/bash", pattern=LURE_PATH_RE)


GpuModel = Literal["rtx3060", "rtx3090", "rtx4090", "t4", "a10g", "a100", "l4", "h100"]


class GpuSpec(NamedTuple):
    pci_class: str        # lspci class: a display card or a compute card
    pci_name: str         # lspci device text after the class
    product: str          # nvidia-smi "Product Name"
    brand: str
    architecture: str
    memory_mib: int
    power_cap_w: int


GPU_SPECS: dict[str, GpuSpec] = {
    "rtx3060": GpuSpec("VGA compatible controller", "NVIDIA Corporation GA106 [GeForce RTX 3060] (rev a1)",
                       "NVIDIA GeForce RTX 3060", "GeForce", "Ampere", 12288, 170),
    "rtx3090": GpuSpec("VGA compatible controller", "NVIDIA Corporation GA102 [GeForce RTX 3090] (rev a1)",
                       "NVIDIA GeForce RTX 3090", "GeForce", "Ampere", 24576, 350),
    "rtx4090": GpuSpec("VGA compatible controller", "NVIDIA Corporation AD102 [GeForce RTX 4090] (rev a1)",
                       "NVIDIA GeForce RTX 4090", "GeForce", "Ada Lovelace", 24564, 450),
    "t4": GpuSpec("3D controller", "NVIDIA Corporation TU104GL [Tesla T4] (rev a1)",
                  "Tesla T4", "NVIDIA", "Turing", 15360, 70),
    "a10g": GpuSpec("3D controller", "NVIDIA Corporation GA102GL [A10G] (rev a1)",
                    "NVIDIA A10G", "NVIDIA", "Ampere", 23028, 300),
    "a100": GpuSpec("3D controller", "NVIDIA Corporation GA100 [A100 PCIe 40GB] (rev a1)",
                    "NVIDIA A100-PCIE-40GB", "NVIDIA", "Ampere", 40960, 250),
    "l4": GpuSpec("3D controller", "NVIDIA Corporation AD104GL [L4] (rev a1)",
                  "NVIDIA L4", "NVIDIA", "Ada Lovelace", 23034, 72),
    "h100": GpuSpec("3D controller", "NVIDIA Corporation GH100 [H100 PCIe] (rev a1)",
                    "NVIDIA H100 PCIe", "NVIDIA", "Hopper", 81559, 350),
}
CPU_MODEL_RE = r"^[A-Za-z0-9 .,()@_/+-]+$"


class Hardware(Strict):
    """What the deterministic shell reports (``agents.shell``): ``nproc``, ``free``, ``df``,
    ``/proc``, ``lscpu``, ``lspci`` and ``nvidia-smi`` all agree with these values. The
    default is a small cloud VM with no GPU."""

    cpu_model: str = Field(default="Intel(R) Xeon(R) Platinum 8259CL CPU @ 2.50GHz",
                           min_length=4, max_length=64, pattern=CPU_MODEL_RE)
    cpus: int = Field(default=2, ge=1, le=64)
    memory_mb: int = Field(default=4096, ge=512, le=1_048_576)
    disk_gb: int = Field(default=40, ge=8, le=65_536)
    gpu: Optional[GpuModel] = None
    gpu_count: int = Field(default=1, ge=1, le=8)


# Cloud VM shapes a scenario without an ``[identity.hardware]`` table is given, one per
# sensor by its seed (``LoadedScenario.hardware``), so two sensors do not report the same
# machine. CPU models are ones whose family, model and stepping ``agents.shell`` reports
# correctly (Cascade Lake Xeon, Zen 3 EPYC).
HARDWARE_PRESETS: tuple[Hardware, ...] = (
    Hardware(),
    Hardware(cpus=4, memory_mb=16384, disk_gb=80),
    Hardware(cpu_model="Intel(R) Xeon(R) Platinum 8275CL CPU @ 3.00GHz", cpus=2,
             memory_mb=8192, disk_gb=50),
    Hardware(cpu_model="Intel(R) Xeon(R) Platinum 8275CL CPU @ 3.00GHz", cpus=8,
             memory_mb=32768, disk_gb=160),
    Hardware(cpu_model="AMD EPYC 7R13 Processor", cpus=2, memory_mb=4096, disk_gb=60),
    Hardware(cpu_model="AMD EPYC 7R13 Processor", cpus=4, memory_mb=8192, disk_gb=100),
)


class Identity(Strict):
    org_name: str = Field(min_length=2, max_length=80, pattern=SAFE_TEXT_RE)
    hostname: str = Field(pattern=HOSTNAME_RE)
    domain: str = Field(min_length=4, max_length=253, pattern=DOMAIN_RE)
    internal_ips: list[str] = Field(min_length=1, max_length=8)
    os_pretty_name: str = Field(max_length=64, pattern=SAFE_TEXT_RE)
    kernel: str = Field(max_length=160, pattern=r"^[A-Za-z0-9 .#:+_()/~-]+$")
    timezone: str = Field(default="UTC", pattern=r"^[A-Za-z_]+(/[A-Za-z_]+)?$")
    users: list[FakeUser] = Field(default_factory=list, max_length=16)
    lures: list[str] = Field(default_factory=list, max_length=25)
    hardware: Hardware = Field(default_factory=Hardware)

    @field_validator("internal_ips")
    @classmethod
    def _private_ips(cls, v: list[str]) -> list[str]:
        for ip in v:
            if not ipaddress.ip_address(ip).is_private:
                raise ValueError(f"internal IP must be private: {ip}")
        return v

    @field_validator("lures")
    @classmethod
    def _lures(cls, v: list[str]) -> list[str]:
        for p in v:
            if not re.fullmatch(LURE_PATH_RE, p):
                raise ValueError(f"bad lure path: {p!r}")
        return v


# ---- login policy and accounts ----------------------------------------------------------

class LoginPolicy(Strict):
    accept: Literal["all", "listed", "after_n", "none"] = "after_n"
    after_n_min: int = Field(default=2, ge=1, le=20)
    after_n_max: int = Field(default=6, ge=1, le=20)

    @model_validator(mode="after")
    def _bounds(self) -> "LoginPolicy":
        if self.after_n_min > self.after_n_max:
            raise ValueError("after_n_min must be <= after_n_max")
        return self


CREDENTIAL = {"credential": True}


class Account(Strict):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(default="", json_schema_extra=CREDENTIAL)

    @field_validator("username")
    @classmethod
    def _user(cls, v: str) -> str:
        if not (re.fullmatch(USERNAME_RE, v) or re.fullmatch(r"^[A-Za-z0-9._@-]{1,64}$", v)):
            raise ValueError("bad account username")
        return v

    @field_validator("password")
    @classmethod
    def _pw(cls, v: str) -> str:
        if "{{ht:" in v:
            return v
        if not valid_password(v):
            raise ValueError("bad account password")
        return v


class ServiceBase(Strict):
    enabled: bool = False
    port: int = Field(ge=0, le=65535)
    banner: Optional[str] = Field(default=None, max_length=200, pattern=r"^[\x20-\x7e]*$")
    version: Optional[str] = Field(default=None, max_length=100, pattern=r"^[\x20-\x7e]*$")
    policy: LoginPolicy = Field(default_factory=LoginPolicy)
    accounts: list[Account] = Field(default_factory=list, max_length=50)


# ---- fake data --------------------------------------------------------------------------

GeneratorKind = Literal[
    "seq", "uuid", "first_name", "last_name", "full_name", "email", "phone", "extension",
    "amount", "date", "datetime", "account_number", "card_number", "iban_like", "mrn",
    "word", "sentence", "bool", "int", "ip_private", "choice", "const",
]


class FieldGen(Strict):
    kind: GeneratorKind
    choices: list[Union[str, int, float, bool]] = Field(default_factory=list, max_length=50)
    min: Optional[float] = None
    max: Optional[float] = None
    value: Optional[Union[str, int, float, bool]] = None
    prefix: str = Field(default="", max_length=32, pattern=r"^[\x20-\x7e]*$")


class RowGenerator(Strict):
    count: int = Field(ge=0, le=500)
    fields: dict[str, FieldGen]


ColumnType = Literal["int", "bigint", "text", "varchar", "numeric", "bool", "date",
                     "timestamp", "uuid", "json"]
Scalar = Union[str, int, float, bool, None]


class Column(Strict):
    name: str = Field(pattern=IDENT_RE)
    type: ColumnType = "text"
    secret: bool = False   # seed_rows values in this column are credentials (templates)


class Table(Strict):
    name: str = Field(pattern=IDENT_RE)
    columns: list[Column] = Field(min_length=1, max_length=40)
    seed_rows: list[list[Scalar]] = Field(default_factory=list, max_length=50)
    generator: Optional[RowGenerator] = None

    @model_validator(mode="after")
    def _shape(self) -> "Table":
        names = {c.name for c in self.columns}
        for row in self.seed_rows:
            if len(row) != len(self.columns):
                raise ValueError(f"seed row width mismatch in table {self.name}")
        if self.generator:
            unknown = set(self.generator.fields) - names
            if unknown:
                raise ValueError(f"generator fields not in table {self.name}: {sorted(unknown)}")
        return self


class Database(Strict):
    name: str = Field(pattern=IDENT_RE)
    schema_name: str = Field(default="public", pattern=IDENT_RE)
    tables: list[Table] = Field(default_factory=list, max_length=40)


class FtpFile(Strict):
    path: str = Field(pattern=LURE_PATH_RE)
    content: Optional[str] = Field(default=None, max_length=16384)
    size: Optional[int] = Field(default=None, ge=0, le=50_000_000)  # displayed size
    mtime: Optional[str] = Field(default=None, pattern=r"^\d{4}-\d{2}-\d{2}( \d{2}:\d{2})?$")


class RedisKey(Strict):
    key: str = Field(min_length=1, max_length=200, pattern=r"^[\x21-\x7e]+$")
    type: Literal["string", "hash", "list", "set"] = "string"
    value: Union[str, dict[str, str], list[str]]


class HttpPage(Strict):
    path: str = Field(pattern=HTTP_PATH_RE)
    title: str = Field(max_length=120)
    body_html: str = Field(max_length=20000)
    requires_login: bool = True


class HttpRoute(Strict):
    method: Literal["GET", "POST", "PUT", "PATCH", "DELETE"] = "GET"
    path: str = Field(pattern=HTTP_PATH_RE)          # may contain {param}
    auth: Literal["none", "session", "basic", "bearer", "api_key", "any"] = "any"
    status: int = Field(default=200, ge=100, le=599)
    json_body: Optional[Union[dict, list]] = None    # canned JSON; may use {param}
    list_from: Optional[str] = Field(default=None, pattern=r"^[A-Za-z0-9_]+\.[A-Za-z0-9_]+$")
    list_limit: int = Field(default=20, ge=1, le=200)
    item_from: Optional[str] = Field(default=None, pattern=r"^[A-Za-z0-9_]+\.[A-Za-z0-9_]+$")
    item_key: Optional[str] = Field(default=None, pattern=IDENT_RE)

    @model_validator(mode="after")
    def _one_source(self) -> "HttpRoute":
        sources = [self.json_body is not None, self.list_from is not None,
                   self.item_from is not None]
        if sum(sources) > 1:
            raise ValueError(f"route {self.path}: choose one of json_body/list_from/item_from")
        if self.item_from and not self.item_key:
            raise ValueError(f"route {self.path}: item_from needs item_key")
        return self


# ---- services ---------------------------------------------------------------------------

class SipExtension(Strict):
    extension: str = Field(pattern=SIP_EXTENSION_RE)
    password: str = Field(default="", json_schema_extra=CREDENTIAL)
    display_name: str = Field(default="", max_length=64, pattern=SAFE_TEXT_RE)

    @field_validator("password")
    @classmethod
    def _pw(cls, v: str) -> str:
        if "{{ht:" in v:
            return v
        if not valid_password(v):
            raise ValueError("bad SIP password")
        return v


class SipService(ServiceBase):
    port: int = 5060
    udp: bool = True
    tcp: bool = True
    realm: str = Field(default="asterisk", max_length=100, pattern=r"^[A-Za-z0-9._-]+$")
    server_header: str = Field(default="Asterisk PBX 18.20.0", max_length=100,
                               pattern=r"^[\x20-\x7e]*$")
    extensions: list[SipExtension] = Field(default_factory=list, max_length=100)
    extension_ranges: list[str] = Field(default_factory=list, max_length=10)
    dial_plan_hints: list[str] = Field(default_factory=list, max_length=20)
    register_expires: int = Field(default=3600, ge=60, le=86400)

    @field_validator("extension_ranges")
    @classmethod
    def _ranges(cls, v: list[str]) -> list[str]:
        for r in v:
            if not re.fullmatch(r"^[0-9]{2,6}-[0-9]{2,6}$", r):
                raise ValueError(f"bad extension range {r!r}")
        return v


class FtpService(ServiceBase):
    port: int = 2121
    files: list[FtpFile] = Field(default_factory=list, max_length=200)
    retr_max_bytes: int = Field(default=65536, ge=0, le=1_048_576)


class TelnetService(ServiceBase):
    port: int = 2323


class SqlService(ServiceBase):
    databases: list[Database] = Field(default_factory=list, max_length=20)


class PostgresService(SqlService):
    port: int = 5432


class MysqlService(SqlService):
    port: int = 3306


class MssqlService(SqlService):
    port: int = 1433


class RedisService(ServiceBase):
    port: int = 6379
    keys: list[RedisKey] = Field(default_factory=list, max_length=200)


class SmtpService(ServiceBase):
    port: int = 2525


class HttpService(ServiceBase):
    port: int = 8080
    server_header: str = Field(default="nginx", max_length=100, pattern=r"^[\x20-\x7e]*$")
    login_path: str = Field(default="/login", pattern=HTTP_PATH_RE)
    login_title: str = Field(default="Sign in", max_length=120)
    branding: str = Field(default="", max_length=500)
    pages: list[HttpPage] = Field(default_factory=list, max_length=30)
    api_prefix: Optional[str] = Field(default=None, pattern=HTTP_PATH_RE)
    api_key_header: str = Field(default="X-API-Key", pattern=r"^[A-Za-z0-9-]{1,64}$")
    routes: list[HttpRoute] = Field(default_factory=list, max_length=100)
    openapi_path: Optional[str] = Field(default=None, pattern=HTTP_PATH_RE)
    openapi: Optional[dict] = None
    llm_unknown_api_routes: bool = False
    # Unknown paths outside the API prefix may be answered by the model when
    # ``[listeners] llm`` is on.
    llm_unknown_paths: bool = True


class MllpService(ServiceBase):
    port: int = 2575
    sending_facility: str = Field(default="EHR", max_length=40, pattern=r"^[A-Za-z0-9_ -]+$")


S3_BUCKET_RE = r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$"
# Object keys in a scenario: no leading slash, no empty or ".." segments. A key may hold one
# "{n}" or "{n:0Wd}" placeholder (W = 1..9) when the object spec describes a series.
S3_KEY_RE = r"^[A-Za-z0-9!_.*'()=+,@ {}:-][A-Za-z0-9!_.*'()=+,@ {}:/-]{0,399}$"
S3_SERIES_RE = r"\{n(?::0([1-9])d)?\}"
S3_REGION_RE = r"^[a-z]{2}(-[a-z]+)+-[0-9]$"
CONTENT_TYPE_RE = r"^[a-z]+/[A-Za-z0-9.+-]{1,80}(; ?charset=[A-Za-z0-9-]{1,20})?$"
S3_MAX_KEYS_PER_BUCKET = 100_000
S3_MAX_KEYS_TOTAL = 200_000
S3_MAX_PAPER_SIZE = 5 * 1024 ** 4       # the largest object S3 accepts


class S3Object(Strict):
    """One object, or a series of ``count`` objects whose key holds ``{n}``.

    The body is literal ``text`` (may embed ``{{ht:<name>}}``), a scenario ``table`` rendered
    as CSV, or else deterministic filler of ``size`` bytes generated on demand. ``size`` is
    the size on paper; downloads are capped by the service's ``get_max_bytes``."""

    key: str = Field(pattern=S3_KEY_RE)
    count: int = Field(default=1, ge=1, le=S3_MAX_KEYS_PER_BUCKET)
    size: Optional[int] = Field(default=None, ge=0, le=S3_MAX_PAPER_SIZE)
    content_type: str = Field(default="binary/octet-stream", pattern=CONTENT_TYPE_RE)
    text: Optional[str] = Field(default=None, max_length=16384)
    table: Optional[str] = Field(default=None, pattern=r"^[A-Za-z0-9_]+\.[A-Za-z0-9_]+$")
    table_limit: int = Field(default=200, ge=1, le=500)
    mtime: Optional[str] = Field(default=None, pattern=r"^\d{4}-\d{2}-\d{2}( \d{2}:\d{2})?$")

    @model_validator(mode="after")
    def _shape(self) -> "S3Object":
        segments = self.key.split("/")
        if any(seg in ("", ".", "..") for seg in segments[:-1]) or segments[-1] in (".", ".."):
            raise ValueError(f"bad object key {self.key!r}")
        holes = re.findall(S3_SERIES_RE, self.key)
        if re.sub(S3_SERIES_RE, "", self.key).count("{") or \
                re.sub(S3_SERIES_RE, "", self.key).count("}"):
            raise ValueError(f"object key {self.key!r}: only {{n}} placeholders are allowed")
        if self.count > 1 and len(holes) != 1:
            raise ValueError(f"object key {self.key!r}: a series needs exactly one {{n}}")
        if self.count == 1 and holes:
            raise ValueError(f"object key {self.key!r}: {{n}} needs count > 1")
        if self.text is not None and self.table is not None:
            raise ValueError(f"object {self.key!r}: choose text or table")
        if (self.text is not None or self.table is not None) and \
                (self.count > 1 or self.size is not None):
            raise ValueError(f"object {self.key!r}: text and table objects take no size or count")
        return self


class S3Bucket(Strict):
    name: str = Field(pattern=S3_BUCKET_RE)
    region: Optional[str] = Field(default=None, pattern=S3_REGION_RE)
    created: Optional[str] = Field(default=None, pattern=r"^\d{4}-\d{2}-\d{2}$")
    public_list: bool = False      # anonymous ListObjects (a misconfigured public bucket)
    public_read: bool = False      # anonymous GetObject / HeadObject
    objects: list[S3Object] = Field(default_factory=list, max_length=100)

    @model_validator(mode="after")
    def _shape(self) -> "S3Bucket":
        if ".." in self.name or re.fullmatch(r"\d+\.\d+\.\d+\.\d+", self.name):
            raise ValueError(f"bad bucket name {self.name!r}")
        if sum(o.count for o in self.objects) > S3_MAX_KEYS_PER_BUCKET:
            raise ValueError(f"bucket {self.name}: more than {S3_MAX_KEYS_PER_BUCKET} keys")
        return self


class S3Service(ServiceBase):
    port: int = 9000
    server_header: str = Field(default="AmazonS3", max_length=100, pattern=r"^[\x20-\x7e]*$")
    region: str = Field(default="us-east-1", pattern=S3_REGION_RE)
    owner_name: str = Field(default="ops", pattern=r"^[a-z][a-z0-9._-]{0,63}$")
    get_max_bytes: int = Field(default=4_194_304, ge=1024, le=16_777_216)
    buckets: list[S3Bucket] = Field(default_factory=list, max_length=20)

    @model_validator(mode="after")
    def _buckets(self) -> "S3Service":
        names = [b.name for b in self.buckets]
        if len(names) != len(set(names)):
            raise ValueError("duplicate bucket names")
        if sum(o.count for b in self.buckets for o in b.objects) > S3_MAX_KEYS_TOTAL:
            raise ValueError(f"more than {S3_MAX_KEYS_TOTAL} keys across buckets")
        return self


class SshService(Strict):
    """SSH/Telnet persona settings consumed by agents.persona and agents.hooks."""

    persona_prompt: str = Field(default="", max_length=6000)
    accounts: list[Account] = Field(default_factory=list, max_length=20)


class Services(Strict):
    sip: Optional[SipService] = None
    ftp: Optional[FtpService] = None
    telnet: Optional[TelnetService] = None
    postgres: Optional[PostgresService] = None
    mysql: Optional[MysqlService] = None
    mssql: Optional[MssqlService] = None
    redis: Optional[RedisService] = None
    smtp: Optional[SmtpService] = None
    http: Optional[HttpService] = None
    mllp: Optional[MllpService] = None
    s3: Optional[S3Service] = None


HoneytokenKind = Literal["aws_access_key", "api_key", "bearer_token", "db_password",
                         "sip_trunk_password", "generic_password", "ssh_private_key_id"]


class HoneytokenSpec(Strict):
    name: str = Field(pattern=r"^[a-z][a-z0-9_]{1,40}$")
    kind: HoneytokenKind
    planted_in: list[str] = Field(min_length=1, max_length=10)  # human description of locations


class BaitSpec(Strict):
    """``[bait]``: pins and hints for the per-sensor identity. Values here are literal.

    ``org_name`` and ``domain`` pin what ``{{org.*}}`` expands to; without them the name is
    invented from the seed (an invented word plus one of ``org_suffixes``) and the domain is
    built from it plus one of ``domain_words`` under a reserved TLD. ``hosts`` pins
    ``{{host:LABEL}}`` per label and ``passwords`` pins ``{{password:LABEL}}`` (whatever its
    style) per label, so credentials can survive a change of version or seed. A literal
    ``identity.org_name`` or ``identity.domain`` also counts as a pin."""

    org_name: Optional[str] = Field(default=None, min_length=2, max_length=80,
                                    pattern=SAFE_TEXT_RE)
    domain: Optional[str] = Field(default=None, min_length=4, max_length=253,
                                  pattern=DOMAIN_RE)
    org_suffixes: list[str] = Field(default_factory=list, max_length=20)
    domain_words: list[str] = Field(default_factory=list, max_length=20)
    hosts: dict[str, str] = Field(default_factory=dict)
    passwords: dict[str, str] = Field(default_factory=dict)

    @field_validator("passwords")
    @classmethod
    def _passwords(cls, v: dict[str, str]) -> dict[str, str]:
        if len(v) > 100:
            raise ValueError("max 100 pinned passwords")
        for label, pw in v.items():
            if not re.fullmatch(r"^[A-Za-z0-9_.-]{1,64}$", label) or not pw or \
                    not valid_password(pw) or "{{" in pw:
                raise ValueError(f"bad pinned password for label {label!r}")
        return v

    @field_validator("org_suffixes")
    @classmethod
    def _suffixes(cls, v: list[str]) -> list[str]:
        for s in v:
            if not (1 <= len(s) <= 40 and re.fullmatch(SAFE_TEXT_RE, s)):
                raise ValueError(f"bad organisation suffix {s!r}")
        return v

    @field_validator("domain_words")
    @classmethod
    def _domain_words(cls, v: list[str]) -> list[str]:
        for w in v:
            if not re.fullmatch(r"^[a-z0-9][a-z0-9-]{0,19}$", w):
                raise ValueError(f"bad domain word {w!r}")
        return v

    @field_validator("hosts")
    @classmethod
    def _hosts(cls, v: dict[str, str]) -> dict[str, str]:
        if len(v) > 40:
            raise ValueError("max 40 pinned hosts")
        for label, host in v.items():
            if not re.fullmatch(r"^[a-z][a-z0-9-]{0,30}$", label) or \
                    not re.fullmatch(HOSTNAME_RE, host):
                raise ValueError(f"bad pinned host {label!r} = {host!r}")
        return v


class Scenario(Strict):
    name: str = Field(pattern=SCENARIO_NAME_RE)
    title: str = Field(max_length=120)
    description: str = Field(max_length=2000)
    bait: BaitSpec = Field(default_factory=BaitSpec)
    identity: Identity
    ssh: SshService = Field(default_factory=SshService)
    services: Services = Field(default_factory=Services)
    honeytokens: list[HoneytokenSpec] = Field(default_factory=list, max_length=20)

    @model_validator(mode="after")
    def _honeytoken_refs(self) -> "Scenario":
        names = {h.name for h in self.honeytokens}
        if len(names) != len(self.honeytokens):
            raise ValueError("duplicate honeytoken names")
        dumped = self.model_dump_json()
        for ref in re.findall(r"\{\{ht:([a-z0-9_]+)\}\}", dumped):
            if ref not in names:
                raise ValueError(f"unknown honeytoken placeholder {ref!r}")
        return self


# ---- tuner overlay ----------------------------------------------------------------------

OVERLAY_SERVICES = ("ssh", "ftp", "telnet", "postgres", "mysql", "mssql", "redis", "smtp",
                    "http")


class OverlayAccount(Strict):
    username: str = Field(pattern=USERNAME_RE)
    password: str = ""

    @field_validator("password")
    @classmethod
    def _pw(cls, v: str) -> str:
        if not valid_password(v):
            raise ValueError("bad overlay password")
        return v


class OverlaySipExtension(Strict):
    extension: str = Field(pattern=SIP_EXTENSION_RE)
    password: str = ""

    @field_validator("password")
    @classmethod
    def _pw(cls, v: str) -> str:
        if not valid_password(v):
            raise ValueError("bad overlay SIP password")
        return v


class OverlayPolicy(Strict):
    after_n_min: int = Field(ge=1, le=20)
    after_n_max: int = Field(ge=1, le=20)

    @model_validator(mode="after")
    def _bounds(self) -> "OverlayPolicy":
        if self.after_n_min > self.after_n_max:
            raise ValueError("after_n_min must be <= after_n_max")
        return self


class Overlay(Strict):
    """Tuner-owned fenced fields layered on top of the active scenario. No free text."""

    hostname: Optional[str] = Field(default=None, pattern=HOSTNAME_RE)
    lures: list[str] = Field(default_factory=list, max_length=25)
    accounts: dict[str, list[OverlayAccount]] = Field(default_factory=dict)
    sip_extensions: list[OverlaySipExtension] = Field(default_factory=list, max_length=20)
    policies: dict[str, OverlayPolicy] = Field(default_factory=dict)

    @field_validator("lures")
    @classmethod
    def _lures(cls, v: list[str]) -> list[str]:
        for p in v:
            if not re.fullmatch(LURE_PATH_RE, p):
                raise ValueError(f"bad lure path: {p!r}")
        return v

    @field_validator("accounts")
    @classmethod
    def _accounts(cls, v: dict) -> dict:
        for svc, accts in v.items():
            if svc not in OVERLAY_SERVICES:
                raise ValueError(f"overlay accounts not allowed for {svc!r}")
            if len(accts) > 20:
                raise ValueError("max 20 overlay accounts per service")
        return v

    @field_validator("policies")
    @classmethod
    def _policies(cls, v: dict) -> dict:
        for svc in v:
            if svc not in OVERLAY_SERVICES + ("sip",):
                raise ValueError(f"overlay policy not allowed for {svc!r}")
        return v


# ---- credential fields --------------------------------------------------------------------

def _models_in(annotation) -> list[type[BaseModel]]:
    from typing import get_args

    if isinstance(annotation, type) and issubclass(annotation, BaseModel):
        return [annotation]
    out: list[type[BaseModel]] = []
    for arg in get_args(annotation):
        out += _models_in(arg)
    return out


def iter_credentials(raw, model: type[BaseModel] = None, path: str = ""):
    """Yield (path, value) for every credential in a parsed, unexpanded scenario document:
    fields marked ``credential`` in the schema and seed-row cells of ``secret`` columns."""
    model = model or Scenario
    if not isinstance(raw, dict):
        return
    for name, info in model.model_fields.items():
        if name not in raw:
            continue
        value, sub = raw[name], f"{path}.{name}" if path else name
        extra = info.json_schema_extra if isinstance(info.json_schema_extra, dict) else {}
        if extra.get("credential"):
            yield sub, value
            continue
        if model is Table and name == "seed_rows":
            secret = [i for i, c in enumerate(raw.get("columns") or [])
                      if isinstance(c, dict) and c.get("secret")]
            for r, row in enumerate(value if isinstance(value, list) else []):
                for i in secret:
                    if isinstance(row, list) and i < len(row):
                        yield f"{sub}[{r}][{i}]", row[i]
            continue
        for child in _models_in(info.annotation):
            items = value if isinstance(value, list) else [value]
            for i, item in enumerate(items):
                yield from iter_credentials(item, child,
                                            f"{sub}[{i}]" if isinstance(value, list) else sub)
