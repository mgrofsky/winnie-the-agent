"""Tiny fake SQL engine shared by the PostgreSQL, MySQL and MSSQL listeners.

``FakeSql.run(sql)`` classifies each statement and returns ``Result`` or ``SqlError``
objects; the protocol modules render them into wire bytes. Nothing is ever executed.

Order of decisions for one statement:
1. dangerous (file/program/exec primitives) -> believable permission error, logged with
   ``data.high_signal=true`` and ``data.signal="sql_exec_attempt"``;
2. hardcoded answers (versions, session info, SHOW/SET/transactions, catalog listings,
   scenario tables, pretend writes);
3. the budgeted model via ``ctx.llm_json`` with a strict schema (``LlmSqlAnswer``);
4. fallback: a protocol-correct syntax error.

Model output is only ever used as validated column names and capped cell values.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import os
import re
import uuid
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Annotated, Any, Optional, Union

from pydantic import (BaseModel, ConfigDict, Field, StrictBool, StrictFloat, StrictInt,
                      model_validator)

from agents.llm import untrusted_block

MAX_RESULT_ROWS = 200
MAX_CELL_CHARS = 1024
MAX_STATEMENTS = 20
MAX_STATEMENT_CHARS = 65536
MAX_LLM_STATEMENT_CHARS = 2000

DEFAULT_VERSIONS = {
    "postgres": "15.6 (Ubuntu 15.6-0ubuntu0.23.10.1)",
    "mysql": "8.0.36-0ubuntu0.22.04.1",
    "mssql": "15.0.4322.2",
}
PRODUCT = {"postgres": "PostgreSQL", "mysql": "MySQL", "mssql": "Microsoft SQL Server"}
DEFAULT_OS = "Ubuntu 22.04.4 LTS"   # host OS when no scenario is loaded

# Distribution details the database servers report, per OS family: the compiler string
# PostgreSQL prints in version(), the package suffix, and the data and plugin paths.
_GCC = {
    ("ubuntu", "20"): "(Ubuntu 9.4.0-1ubuntu1~20.04.2) 9.4.0",
    ("ubuntu", "22"): "(Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0",
    ("ubuntu", "24"): "(Ubuntu 13.2.0-23ubuntu4) 13.2.0",
    ("debian", "11"): "(Debian 10.2.1-6) 10.2.1 20210110",
    ("debian", "12"): "(Debian 12.2.0-14) 12.2.0",
    ("rhel", "8"): "(GCC) 8.5.0 20210514 (Red Hat 8.5.0-22)",
    ("rhel", "9"): "(GCC) 11.4.1 20231218 (Red Hat 11.4.1-3)",
}
_GCC_DEFAULT = {"ubuntu": _GCC[("ubuntu", "22")], "debian": _GCC[("debian", "12")],
                "rhel": _GCC[("rhel", "9")]}


def host_os(os_pretty_name: str) -> tuple[str, str]:
    """(family, major release) from an os-release PRETTY_NAME: family is ubuntu, debian or
    rhel (Red Hat Enterprise Linux and its rebuilds)."""
    name = os_pretty_name.lower()
    m = re.search(r"(\d+)", name)
    major = m.group(1) if m else ""
    if "ubuntu" in name:
        return "ubuntu", major
    if "debian" in name:
        return "debian", major
    if any(n in name for n in ("red hat", "rocky", "alma", "centos", "oracle linux")):
        return "rhel", major
    return "ubuntu", "22"
SYSTEM_DBS = {
    "postgres": ["postgres", "template0", "template1"],
    "mysql": ["information_schema", "mysql", "performance_schema", "sys"],
    "mssql": ["master", "tempdb", "model", "msdb"],
}

# Neutral built-in data used when no scenario is loaded.
DEFAULT_DB = "appdb"
DEFAULT_TABLES: dict[str, tuple[list[tuple[str, str]], list[list]]] = {
    "users": ([("id", "int"), ("username", "varchar"), ("email", "varchar"),
               ("created_at", "timestamp")],
              [[1, "admin", "admin@example.com", "2025-11-02 09:14:22"],
               [2, "jsmith", "jsmith@example.com", "2025-12-14 16:40:03"],
               [3, "svc_backup", "backup@example.com", "2026-01-20 02:00:11"]]),
    "settings": ([("name", "varchar"), ("value", "text")],
                 [["site_name", "Intranet"], ["maintenance_mode", "false"],
                  ["session_timeout", "3600"]]),
}

PG_TYPES = [(16, "bool"), (17, "bytea"), (18, "char"), (19, "name"), (20, "int8"),
            (21, "int2"), (23, "int4"), (25, "text"), (26, "oid"), (114, "json"),
            (700, "float4"), (701, "float8"), (1043, "varchar"), (1082, "date"),
            (1083, "time"), (1114, "timestamp"), (1184, "timestamptz"), (1700, "numeric"),
            (2950, "uuid"), (3802, "jsonb")]

LLM_COLUMN_RE = r"^[A-Za-z_][A-Za-z0-9_]{0,62}$"
LLM_ERROR_RE = r"^[A-Za-z0-9 .,:;()'\"_=<>*/+@#%!?\[\]-]*$"

LlmCell = Union[StrictBool, StrictInt, StrictFloat, Annotated[str, Field(max_length=200)], None]


class LlmSqlAnswer(BaseModel):
    """What the model may return: rows OR an error, nothing else."""

    model_config = ConfigDict(extra="forbid")

    columns: Optional[list[Annotated[str, Field(pattern=LLM_COLUMN_RE)]]] = Field(
        default=None, max_length=20)
    rows: Optional[list[Annotated[list[LlmCell], Field(max_length=20)]]] = Field(
        default=None, max_length=50)
    error: Optional[Annotated[str, Field(min_length=1, max_length=200,
                                         pattern=LLM_ERROR_RE)]] = None

    @model_validator(mode="after")
    def _one_shape(self) -> "LlmSqlAnswer":
        if self.error is not None:
            if self.columns is not None or self.rows:
                raise ValueError("error and rows are exclusive")
            return self
        if not self.columns:
            raise ValueError("columns or error required")
        for row in self.rows or []:
            if len(row) != len(self.columns):
                raise ValueError("row width mismatch")
        return self


@dataclass
class Result:
    columns: list[str]
    rows: list[list]
    tag: str = ""            # PostgreSQL command tag ("" -> "SELECT n")
    affected: int = 0        # MySQL/MSSQL affected rows for non-queries
    is_query: bool = True    # a result set (possibly empty) is returned


@dataclass
class SqlError:
    code: str                # PG/MySQL SQLSTATE, MSSQL error number as text
    message: str
    errno: int = 0           # MySQL errno / MSSQL error number
    severity: str = "ERROR"  # PostgreSQL severity
    klass: int = 16          # MSSQL class


Answer = Union[Result, SqlError]


@dataclass
class TableInfo:
    name: str
    columns: list[tuple[str, str]]
    db: str
    schema: str
    scenario: bool = True


@dataclass
class DbInfo:
    name: str
    schema: str
    tables: dict[str, TableInfo] = field(default_factory=dict)
    system: bool = False


# ---- text helpers -------------------------------------------------------------------------

_CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


def wire_text(value: Any, cap: int = MAX_CELL_CHARS) -> str:
    """Printable, capped text for the wire (tabs and newlines kept)."""
    return _CTRL.sub(" ", str(value))[:cap]


def safe_name(value: str, cap: int = 64) -> str:
    """Attacker-derived identifier echoed inside an error message."""
    return re.sub(r"[^\x20-\x7e]", "?", value)[:cap]


def _unquote_ident(s: str) -> str:
    s = s.strip()
    if len(s) >= 2 and s[0] in "\"`[" and s[-1] in "\"`]":
        return s[1:-1]
    return s


def _mask(s: str) -> list[bool]:
    """True where the char is at paren depth 0 and outside quotes."""
    out = []
    depth = 0
    quote = ""
    for ch in s:
        if quote:
            out.append(False)
            if ch == quote:
                quote = ""
            continue
        if ch in "'\"`":
            quote = ch
            out.append(False)
            continue
        if ch == "(":
            out.append(False)
            depth += 1
            continue
        if ch == ")":
            depth = max(0, depth - 1)
            out.append(False)
            continue
        out.append(depth == 0)
    return out


def _find_top(s: str, pattern: str, mask: Optional[list[bool]] = None, start: int = 0):
    mask = mask if mask is not None else _mask(s)
    for m in re.finditer(pattern, s[start:], re.IGNORECASE):
        pos = start + m.start()
        if pos < len(mask) and mask[pos]:
            return pos, start + m.end()
    return None


def _split_top(s: str, sep_pattern: str) -> list[str]:
    mask = _mask(s)
    parts, last = [], 0
    for m in re.finditer(sep_pattern, s, re.IGNORECASE):
        if mask[m.start()]:
            parts.append(s[last:m.start()])
            last = m.end()
    parts.append(s[last:])
    return [p.strip() for p in parts]


def strip_comments(sql: str, dialect: str = "mysql") -> str:
    """Remove SQL comments in one linear pass, leaving quoted text alone.

    ``--`` runs to the end of the line, ``/* */`` becomes a space, MySQL executable
    comments ``/*!40101 SET ... */`` keep their body (version digits and one blank
    dropped), and ``#`` starts a line comment for MySQL only. An unterminated block
    comment is left as is so the parser rejects it.
    """
    out: list[str] = []
    n = len(sql)
    i = 0
    plain = 0  # start of the pending run of ordinary characters
    hash_comment = dialect == "mysql"
    while i < n:
        ch = sql[i]
        if ch in "'\"`":
            end = sql.find(ch, i + 1)
            if end < 0:
                break
            i = end + 1
            continue
        nxt = sql[i + 1] if i + 1 < n else ""
        if (ch == "-" and nxt == "-") or (ch == "#" and hash_comment):
            out.append(sql[plain:i])
            end = sql.find("\n", i)
            i = n if end < 0 else end
            out.append(" ")
            plain = i
            continue
        if ch == "/" and nxt == "*":
            end = sql.find("*/", i + 2)
            if end < 0:
                break
            out.append(sql[plain:i])
            if i + 2 < n and sql[i + 2] == "!":
                j = i + 3
                while j < end and sql[j].isdigit():
                    j += 1
                if j < end and sql[j].isspace():
                    j += 1
                out.append(sql[j:end])
            else:
                out.append(" ")
            i = plain = end + 2
            continue
        i += 1
    out.append(sql[plain:])
    return "".join(out)



def split_statements(sql: str) -> list[str]:
    out, buf, quote = [], [], ""
    for ch in sql:
        if quote:
            buf.append(ch)
            if ch == quote:
                quote = ""
            continue
        if ch in "'\"`":
            quote = ch
            buf.append(ch)
            continue
        if ch == ";":
            out.append("".join(buf))
            buf = []
            continue
        buf.append(ch)
    out.append("".join(buf))
    return [s.strip() for s in out if s.strip()][:MAX_STATEMENTS + 1]


class _LikeSegment:
    """A run of literal chars and ``_`` between two ``%``: fixed length, literal chunks."""

    __slots__ = ("length", "chunks", "anchor")

    def __init__(self, tokens: list[Optional[str]]) -> None:
        self.length = len(tokens)
        self.chunks: list[tuple[int, str]] = []
        start = None
        for k, tok in enumerate(tokens + [None]):
            if tok is not None and start is None:
                start = k
            elif tok is None and start is not None:
                self.chunks.append((start, "".join(tokens[start:k])))  # type: ignore[arg-type]
                start = None
        # Search on the longest literal chunk to keep the candidate positions few.
        self.anchor = max(self.chunks, key=lambda c: len(c[1])) if self.chunks else None

    def at(self, value: str, pos: int) -> bool:
        return all(value.startswith(text, pos + off) for off, text in self.chunks)

    def find(self, value: str, start: int, last: int) -> int:
        """Leftmost position p in [start, last] where the segment matches, else -1."""
        if start > last:
            return -1
        if self.anchor is None:
            return start
        off, text = self.anchor
        stop = last + off + len(text)
        p = value.find(text, start + off, stop)
        while p >= 0:
            if self.at(value, p - off):
                return p - off
            p = value.find(text, p + 1, stop)
        return -1


class LikePattern:
    """SQL LIKE matcher (case-insensitive): ``%`` any run, ``_`` one char, ``escape``
    quotes the next char. No regex: the pattern is split at ``%`` into fixed-length
    segments; the first and last are anchored and each middle one is placed at its
    leftmost fit, which is optimal for fixed-length segments. Cost is about
    len(value) per segment, never exponential."""

    def __init__(self, pattern: str, escape: Optional[str] = "\\") -> None:
        segs: list[list[Optional[str]]] = [[]]
        i, n = 0, len(pattern)
        while i < n:
            ch = pattern[i]
            if escape and ch == escape and i + 1 < n:
                segs[-1].append(pattern[i + 1].lower())
                i += 2
                continue
            if ch == "%":
                if segs[-1] or len(segs) == 1:   # repeated % collapse
                    segs.append([])
            else:
                segs[-1].append(None if ch == "_" else ch.lower())
            i += 1
        self.exact = len(segs) == 1
        self.first = _LikeSegment(segs[0])
        self.last = _LikeSegment(segs[-1]) if not self.exact else None
        self.middle = [_LikeSegment(s) for s in segs[1:-1] if s]
        self.min_len = sum(len(s) for s in segs)

    def match(self, value: str) -> bool:
        v = value.lower()
        if self.exact:
            return len(v) == self.first.length and self.first.at(v, 0)
        if self.min_len > len(v) or not self.first.at(v, 0):
            return False
        assert self.last is not None
        tail = len(v) - self.last.length
        if not self.last.at(v, tail):
            return False
        pos = self.first.length
        for seg in self.middle:
            found = seg.find(v, pos, tail - seg.length)
            if found < 0:
                return False
            pos = found + seg.length
        return pos <= tail


@lru_cache(maxsize=32)
def _like_pattern(pattern: str, escape: Optional[str]) -> LikePattern:
    return LikePattern(pattern, escape)


def like_match(pattern: str, value: str, escape: Optional[str] = "\\") -> bool:
    return _like_pattern(pattern, escape).match(value)


# Column aliases are short; looking for one only near the end of an item keeps alias
# detection linear on hostile select lists (a plain regex over the whole item is
# quadratic on inputs like "x as [x as [x as [...").
ALIAS_WINDOW = 256
_AS_ALIAS_RX = re.compile(r"\s+as\s+(\"[^\"]+\"|`[^`]+`|\[[^\]]+\]|'[^']+'|[\w$]+)", re.I | re.S)
_BARE_ALIAS_RX = re.compile(r"\s+(\"[^\"]+\"|`[^`]+`|\[[^\]]+\]|[A-Za-z_][\w$]*)", re.S)
_BARE_EXPR_RX = re.compile(r"[\w$.@\"`\[\]]+")
_NOT_ALIASES = ("from", "end", "desc", "asc")


def _split_alias(item: str) -> tuple[str, Optional[str]]:
    """``expr AS alias`` / ``expr alias`` -> (expr, alias); otherwise (item, None)."""
    n = len(item)
    lo = max(1, n - ALIAS_WINDOW)
    for i in range(lo, n):  # leftmost "AS alias" that runs to the end
        if item[i].isspace():
            m = _AS_ALIAS_RX.fullmatch(item, i)
            if m:
                return item[:i].strip(), _unquote_ident(m.group(1)).strip("'")
    m = _BARE_EXPR_RX.match(item)
    bare = _BARE_ALIAS_RX.fullmatch(item, m.end()) if m else None
    if bare is None:  # "func(...) alias": rightmost ")" followed by an alias
        p = item.rfind(")", lo, n)
        while p >= lo:
            bare = _BARE_ALIAS_RX.fullmatch(item, p + 1)
            if bare:
                break
            p = item.rfind(")", lo, p)
    if bare is not None and bare.group(1).lower() not in _NOT_ALIASES:
        return item[:bare.start()].strip(), _unquote_ident(bare.group(1))
    return item, None


def _literal(text: str) -> tuple[bool, Any]:
    t = text.strip()
    if re.fullmatch(r"[+-]?\d{1,18}", t):
        return True, int(t)
    if re.fullmatch(r"[+-]?(\d+\.\d*|\.\d+)(e[+-]?\d+)?", t, re.I):
        return True, float(t)
    m = re.fullmatch(r"[nNeE]?'((?:[^']|'')*)'", t, re.S)
    if m:
        return True, m.group(1).replace("''", "'")
    m = re.fullmatch(r'"((?:[^"]|"")*)"', t, re.S)
    if m:
        return True, m.group(1)
    low = t.lower()
    if low == "null":
        return True, None
    if low in ("true", "false"):
        return True, low == "true"
    return False, None


def _sort_key(v: Any):
    if v is None:
        return (2, "")
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        return (0, v)
    return (1, str(v))


# ---- dangerous statements -----------------------------------------------------------------

def _w(low: str, word: str) -> bool:
    return re.search(r"\b" + word + r"\b", low) is not None


def classify_dangerous(low: str) -> Optional[tuple[str, str]]:
    """Return (name, detail) for exec/file primitives, else None. ``low`` is lowercase."""
    if _w(low, "copy"):
        if _w(low, "program"):
            return "copy_program", ""
        m = re.search(r"\b(to|from)\s+(?:e?'|\$)", low)
        if m:
            return "copy_file", m.group(1)
    m = re.search(r"\b(pg_read_file|pg_read_binary_file|pg_ls_dir|pg_stat_file|pg_ls_logdir|"
                  r"pg_ls_waldir|pg_ls_tmpdir|pg_file_write)\s*\(", low)
    if m:
        return "pg_file_access", m.group(1)
    m = re.search(r"\b(lo_import|lo_export)\s*\(", low)
    if m:
        return "large_object", m.group(1)
    if _w(low, "create") and re.search(r"\b(function|procedure)\b", low):
        m = re.search(r"\blanguage\s+['\"]?(c|plpython\w*|plperlu|pltclu|plsh|internal)\b", low)
        if m:
            return "untrusted_language", m.group(1)
        if _w(low, "soname"):
            return "udf_create", ""
    m = re.search(r"\bcreate\s+extension\b(?:\s+if\s+not\s+exists)?\s+['\"]?"
                  r"(plpython\w*|plperlu|pltclu|adminpack|dblink|postgres_fdw|file_fdw)", low)
    if m:
        return "untrusted_extension", m.group(1)
    if re.search(r"\binto\s+(outfile|dumpfile)\b", low):
        return "into_outfile", ""
    if re.search(r"\bload\s+data\b", low):
        return "load_data", "local" if re.search(r"\bload\s+data\b.*\blocal\b", low[:400]) else ""
    if re.search(r"\bload_file\s*\(", low):
        return "load_file", ""
    m = re.search(r"\b(sys_exec|sys_eval|sys_get|sys_set|lib_mysqludf_sys\w*)\b", low)
    if m:
        return "udf_exec", m.group(1)
    if _w(low, "xp_cmdshell"):
        return "xp_cmdshell", "xp_cmdshell"
    if _w(low, "sp_configure"):
        return "sp_configure", ""
    if re.search(r"\b(openrowset|opendatasource)\b", low):
        return "openrowset", ""
    m = re.search(r"\b(sp_oacreate|sp_oamethod)\b", low)
    if m:
        return "ole_automation", {"sp_oacreate": "sp_OACreate", "sp_oamethod": "sp_OAMethod"}[m.group(1)]
    m = re.search(r"\b(xp_dirtree|xp_fileexist|xp_subdirs|xp_regread|xp_regwrite)\b", low)
    if m:
        return "xp_filesystem", m.group(1)
    if re.search(r"\bcreate\s+assembly\b", low):
        return "clr_assembly", ""
    if re.search(r"\bbulk\s+insert\b", low):
        return "bulk_insert", ""
    return None


# ---- the engine ---------------------------------------------------------------------------

class FakeSql:
    def __init__(self, conn, dialect: str, user: str, database: str,
                 version: Optional[str] = None, port: int = 0) -> None:
        self.conn = conn
        self.ctx = conn.ctx
        self.dialect = dialect
        self.user = user
        self.version = version or DEFAULT_VERSIONS[dialect]
        self.port = port
        scen = self.ctx.scenario
        ident = scen.scenario.identity if scen is not None else None
        self.hostname = ident.hostname if ident else "db01"
        self.os_name = ident.os_pretty_name if ident else DEFAULT_OS
        self.os_family, self.os_major = host_os(self.os_name)
        self.org = ident.org_name if ident else ""
        self.internal_ip = ident.internal_ips[0] if ident else "10.0.0.12"
        self.pid = 1000 + int(hashlib.sha256(conn.task_name.encode()).hexdigest()[:6], 16) % 60000
        self.started = datetime.datetime(2026, 1, 1, 3, 12, 44)
        self.catalog = self._build_catalog()
        self._row_cache: dict[tuple[str, str], list[list]] = {}
        self.created: dict[str, list[str]] = {}
        default = next((d.name for d in self.catalog.values() if not d.system), None)
        if dialect == "postgres":
            self.database = database or user
        elif dialect == "mssql":
            self.database = database or "master"
        else:
            self.database = database or ""
        self.default_user_db = default
        self.password_encryption = "scram-sha-256"   # PostgreSQL; set by the listener

    # ---- catalog --------------------------------------------------------------------------

    def _build_catalog(self) -> dict[str, DbInfo]:
        cat: dict[str, DbInfo] = {}
        dschema = {"postgres": "public", "mysql": "", "mssql": "dbo"}[self.dialect]
        for name in SYSTEM_DBS[self.dialect]:
            cat[name.lower()] = DbInfo(name=name, schema=dschema or name, system=True)
        scen = self.ctx.scenario
        svc = getattr(scen.scenario.services, self.dialect, None) if scen is not None else None
        dbs = list(svc.databases) if svc is not None else []
        if dbs:
            for d in dbs:
                schema = d.schema_name if self.dialect == "postgres" else (
                    "dbo" if self.dialect == "mssql" else d.name)
                info = DbInfo(name=d.name, schema=schema)
                for t in d.tables:
                    info.tables[t.name.lower()] = TableInfo(
                        t.name, [(c.name, c.type) for c in t.columns], d.name, schema, True)
                cat[d.name.lower()] = info
        else:
            schema = dschema or DEFAULT_DB
            info = DbInfo(name=DEFAULT_DB, schema=schema)
            for tname, (cols, _rows) in DEFAULT_TABLES.items():
                info.tables[tname] = TableInfo(tname, cols, DEFAULT_DB, schema, False)
            cat[DEFAULT_DB] = info
        return cat

    def db_exists(self, name: str) -> bool:
        return name.lower() in self.catalog

    def current_db(self) -> Optional[DbInfo]:
        return self.catalog.get((self.database or "").lower())

    def table_rows(self, t: TableInfo) -> list[list]:
        key = (t.db, t.name)
        if key not in self._row_cache:
            if t.scenario and self.ctx.scenario is not None:
                try:
                    _cols, rows = self.ctx.scenario.table_rows(t.db, t.name)
                except Exception:  # noqa: BLE001 - bad scenario data must not crash a session
                    rows = []
            else:
                rows = [list(r) for r in DEFAULT_TABLES.get(t.name, ([], []))[1]]
            self._row_cache[key] = rows
        return self._row_cache[key]

    def user_dbs(self) -> list[DbInfo]:
        return [d for d in self.catalog.values() if not d.system]

    def find_table(self, parts: list[str]) -> Optional[TableInfo]:
        parts = [p for p in (_unquote_ident(x) for x in parts) if p]
        if not parts:
            return None
        name = parts[-1].lower()
        candidates = []
        if len(parts) >= 2:
            for qual in parts[:-1]:
                d = self.catalog.get(qual.lower())
                if d is not None:
                    candidates.append(d)
        cur = self.current_db()
        if cur is not None:
            candidates.append(cur)
        for d in candidates:
            if name in d.tables:
                return d.tables[name]
        return None

    # ---- error builders -------------------------------------------------------------------

    def syntax_error(self, stmt: str) -> SqlError:
        tok = re.match(r"\s*([A-Za-z_][A-Za-z0-9_]*|\S)", stmt)
        word = safe_name(tok.group(1) if tok else "", 40)
        if self.dialect == "postgres":
            return SqlError("42601", f'syntax error at or near "{word}"')
        if self.dialect == "mysql":
            near = safe_name(stmt.strip(), 80)
            return SqlError("42000", "You have an error in your SQL syntax; check the manual that "
                            "corresponds to your MySQL server version for the right syntax to "
                            f"use near '{near}' at line 1", errno=1064)
        return SqlError("102", f"Incorrect syntax near '{word}'.", errno=102, klass=15)

    def no_table(self, name: str) -> SqlError:
        name = safe_name(name)
        if self.dialect == "postgres":
            return SqlError("42P01", f'relation "{name}" does not exist')
        if self.dialect == "mysql":
            return SqlError("42S02", f"Table '{safe_name(self.database or 'mysql')}.{name}' "
                            "doesn't exist", errno=1146)
        return SqlError("208", f"Invalid object name '{name}'.", errno=208)

    def no_column(self, name: str) -> SqlError:
        name = safe_name(name)
        if self.dialect == "postgres":
            return SqlError("42703", f'column "{name}" does not exist')
        if self.dialect == "mysql":
            return SqlError("42S22", f"Unknown column '{name}' in 'field list'", errno=1054)
        return SqlError("207", f"Invalid column name '{name}'.", errno=207)

    def no_db(self, name: str) -> SqlError:
        name = safe_name(name)
        if self.dialect == "postgres":
            return SqlError("3D000", f'database "{name}" does not exist', severity="FATAL")
        if self.dialect == "mysql":
            return SqlError("42000", f"Unknown database '{name}'", errno=1049)
        return SqlError("911", f"Database '{name}' does not exist. Make sure that the name is "
                        "entered correctly.", errno=911)

    def _row_count(self, digits: str, rest: str) -> Union[int, SqlError]:
        """A LIMIT/OFFSET/TOP/FETCH count from the statement, range-checked the way the
        real server does (bigint, or unsigned bigint for MySQL)."""
        cap = (1 << 64) - 1 if self.dialect == "mysql" else (1 << 63) - 1
        if len(digits) <= 20 and int(digits) <= cap:
            return int(digits)
        if self.dialect == "postgres":
            return SqlError("22003", "bigint out of range")
        if self.dialect == "mysql":
            return SqlError("42000", "You have an error in your SQL syntax; check the manual that "
                            "corresponds to your MySQL server version for the right syntax to "
                            f"use near '{safe_name(rest.strip(), 80)}' at line 1", errno=1064)
        return SqlError("1060", "The number of rows provided for a TOP or FETCH clauses row "
                        "count parameter must be an integer.", errno=1060, klass=15)

    def no_db_selected(self) -> SqlError:
        return SqlError("3D000", "No database selected", errno=1046)

    def dangerous_error(self, name: str, detail: str, stmt: str) -> SqlError:
        d = self.dialect
        user = safe_name(self.user)
        if d == "postgres":
            if name == "copy_program":
                return SqlError("42501", "must be superuser or have privileges of the "
                                "pg_execute_server_program role to COPY to or from an external program")
            if name == "copy_file":
                role, direction = (("pg_write_server_files", "to") if detail == "to"
                                   else ("pg_read_server_files", "from"))
                return SqlError("42501", f"must be superuser or have privileges of the {role} "
                                f"role to COPY {direction} a file")
            if name in ("pg_file_access", "large_object"):
                return SqlError("42501", f"permission denied for function {detail}")
            if name == "untrusted_language":
                return SqlError("42501", f"permission denied for language {detail}")
            if name == "untrusted_extension":
                return SqlError("42501", f'permission denied to create extension "{detail}"')
            return self.syntax_error(stmt)
        if d == "mysql":
            if name == "into_outfile" or (name == "load_data" and not detail):
                return SqlError("HY000", "The MySQL server is running with the --secure-file-priv "
                                "option so it cannot execute this statement", errno=1290)
            if name == "load_data":
                return SqlError("42000", "Loading local data is disabled; this must be enabled on "
                                "both the client and server sides", errno=3948)
            if name == "load_file":
                return SqlError("42000", "Access denied; you need (at least one of) the FILE "
                                "privilege(s) for this operation", errno=1227)
            if name == "udf_create":
                return SqlError("42000", f"Access denied for user '{user}'@'%' to database 'mysql'",
                                errno=1044)
            if name == "udf_exec":
                return SqlError("42000", f"FUNCTION {safe_name(self.database or 'mysql')}."
                                f"{detail} does not exist", errno=1305)
            return self.syntax_error(stmt)
        if name in ("xp_cmdshell", "ole_automation", "xp_filesystem"):
            obj = detail or "xp_cmdshell"
            return SqlError("229", f"The EXECUTE permission was denied on the object '{obj}', "
                            "database 'mssqlsystemresource', schema 'sys'.", errno=229, klass=14)
        if name == "sp_configure":
            return SqlError("15247", "User does not have permission to perform this action.",
                            errno=15247)
        if name == "openrowset":
            return SqlError("15281", "SQL Server blocked access to STATEMENT "
                            "'OpenRowset/OpenDatasource' of component 'Ad Hoc Distributed Queries' "
                            "because this component is turned off as part of the security "
                            "configuration for this server. A system administrator can enable the "
                            "use of 'Ad Hoc Distributed Queries' by using sp_configure.",
                            errno=15281)
        if name == "clr_assembly":
            return SqlError("262", f"CREATE ASSEMBLY permission denied in database "
                            f"'{safe_name(self.database)}'.", errno=262, klass=14)
        if name == "bulk_insert":
            return SqlError("4834", "You do not have permission to use the bulk load statement.",
                            errno=4834)
        return self.syntax_error(stmt)

    # ---- session values --------------------------------------------------------------------

    def full_version(self) -> str:
        v = self.version
        if self.dialect == "postgres":
            gcc = _GCC.get((self.os_family, self.os_major), _GCC_DEFAULT[self.os_family])
            if self.os_family == "rhel":
                return f"PostgreSQL {v} on x86_64-redhat-linux-gnu, compiled by gcc {gcc}, 64-bit"
            if "(" not in v:   # distribution packages name themselves in the version
                tag = (f"Debian {v}-1.pgdg{self.os_major}0+1" if self.os_family == "debian"
                       else f"Ubuntu {v}-1.pgdg{self.os_major}.04+1")
                v = f"{v} ({tag})"
            return f"PostgreSQL {v} on x86_64-pc-linux-gnu, compiled by gcc {gcc}, 64-bit"
        if self.dialect == "mysql":
            return v
        return (f"Microsoft SQL Server 2019 (RTM-CU22) (KB5027702) - {v} (X64) \n"
                "\tJul 27 2023 21:42:42 \n\tCopyright (C) 2019 Microsoft Corporation\n"
                f"\tStandard Edition (64-bit) on Linux ({self.os_name}) <X64>")

    def _mysql_comment(self) -> str:
        mariadb = "mariadb" in self.version.lower()
        if self.os_family == "rhel":
            return "MariaDB Server" if mariadb else "Source distribution"
        if self.os_family == "debian":
            return f"Debian {self.os_major}" if mariadb else "MySQL Community Server - GPL"
        return f"Ubuntu {self.os_major}.04" if mariadb else "(Ubuntu)"

    def pg_params(self) -> dict[str, str]:
        return {
            "server_version": self.version, "server_version_num": self._pg_version_num(),
            "server_encoding": "UTF8", "client_encoding": "UTF8", "datestyle": "ISO, MDY",
            "timezone": "Etc/UTC", "transaction_isolation": "read committed",
            "default_transaction_isolation": "read committed",
            "standard_conforming_strings": "on", "integer_datetimes": "on",
            "max_connections": "100",
            "data_directory": ("/var/lib/pgsql/data" if self.os_family == "rhel"
                               else f"/var/lib/postgresql/{self._pg_major()}/main"),
            "search_path": '"$user", public', "is_superuser": "off", "lc_collate": "C.UTF-8",
            "lc_ctype": "C.UTF-8", "listen_addresses": "*", "port": str(self.port or 5432),
            "ssl": "off", "shared_buffers": "128MB", "work_mem": "4MB",
            "extra_float_digits": "1", "application_name": "", "statement_timeout": "0",
            "password_encryption": self.password_encryption, "log_statement": "none",
        }

    def _pg_major(self) -> str:
        m = re.match(r"(\d+)", self.version)
        return m.group(1) if m else "15"

    def _pg_version_num(self) -> str:
        m = re.match(r"(\d+)\.(\d+)", self.version)
        return f"{int(m.group(1))}{int(m.group(2)):04d}" if m else "150006"

    def mysql_vars(self) -> dict[str, Any]:
        return {
            "version": self.version, "version_comment": self._mysql_comment(),
            "hostname": self.hostname,
            "port": self.port or 3306, "datadir": "/var/lib/mysql/", "basedir": "/usr/",
            "secure_file_priv": "/var/lib/mysql-files/",
            "plugin_dir": ("/usr/lib64/mysql/plugin/" if self.os_family == "rhel"
                           else "/usr/lib/mysql/plugin/"),
            "sql_mode": "ONLY_FULL_GROUP_BY,STRICT_TRANS_TABLES,NO_ZERO_IN_DATE,NO_ZERO_DATE,"
                        "ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION",
            "character_set_client": "utf8mb4", "character_set_connection": "utf8mb4",
            "character_set_results": "utf8mb4", "character_set_server": "utf8mb4",
            "character_set_database": "utf8mb4", "character_set_system": "utf8mb3",
            "collation_connection": "utf8mb4_0900_ai_ci", "collation_server": "utf8mb4_0900_ai_ci",
            "collation_database": "utf8mb4_0900_ai_ci", "max_allowed_packet": 67108864,
            "autocommit": 1, "tx_isolation": "REPEATABLE-READ",
            "transaction_isolation": "REPEATABLE-READ", "transaction_read_only": 0,
            "tx_read_only": 0, "time_zone": "SYSTEM", "system_time_zone": "UTC",
            "lower_case_table_names": 0, "wait_timeout": 28800, "interactive_timeout": 28800,
            "net_write_timeout": 60, "net_buffer_length": 16384, "license": "GPL",
            "init_connect": "", "have_ssl": "DISABLED", "have_openssl": "DISABLED",
            "version_compile_os": "Linux", "version_compile_machine": "x86_64",
            "auto_increment_increment": 1, "auto_increment_offset": 1,
            "performance_schema": 1, "query_cache_size": 0, "query_cache_type": "OFF",
            "max_connections": 151, "local_infile": 0, "log_bin": 1, "server_id": 1,
            "default_authentication_plugin": "mysql_native_password", "general_log": 0,
            "sql_select_limit": 18446744073709551615, "default_storage_engine": "InnoDB",
        }

    def mysql_status(self) -> dict[str, Any]:
        return {"Uptime": 2764812, "Threads_connected": 3, "Threads_running": 1,
                "Questions": 1840221, "Slow_queries": 12, "Opens": 1622, "Open_tables": 812,
                "Connections": 30422, "Aborted_connects": 1187, "Bytes_received": 913223101,
                "Bytes_sent": 2214332871, "Com_select": 1203311, "Innodb_buffer_pool_pages_total":
                8192, "Ssl_cipher": "", "Uptime_since_flush_status": 2764812}

    def mssql_vars(self) -> dict[str, Any]:
        return {"version": self.full_version(), "servername": self.hostname.upper(),
                "servicename": "MSSQLSERVER", "spid": 50 + self.pid % 70, "language": "us_english",
                "trancount": 0, "rowcount": 0, "error": 0, "identity": None,
                "max_connections": 32767, "microsoftversion": 251662530, "langid": 0,
                "lock_timeout": -1, "textsize": 2147483647, "datefirst": 7, "options": 5496}

    def server_property(self, prop: str) -> Any:
        p = prop.strip().strip("'").lower()
        table = {"productversion": self.version, "productlevel": "RTM",
                 "productupdatelevel": "CU22", "edition": "Standard Edition (64-bit)",
                 "engineedition": 2, "machinename": self.hostname.upper(),
                 "servername": self.hostname.upper(), "instancename": None,
                 "isclustered": 0, "isintegratedsecurityonly": 0, "ishadrenabled": 0,
                 "collation": "SQL_Latin1_General_CP1_CI_AS", "processid": self.pid}
        return table.get(p)

    def _now(self) -> str:
        return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    # ---- entry point ---------------------------------------------------------------------

    async def run(self, sql: str, multi: bool = True) -> list[Answer]:
        """Answer every statement in ``sql``; stops after the first error."""
        text = strip_comments(sql if len(sql) <= MAX_STATEMENT_CHARS else sql[:MAX_STATEMENT_CHARS],
                              self.dialect)
        stmts = split_statements(text)
        if not stmts:
            self._log(sql, Result([], [], tag="EMPTY", is_query=False), {"kind": "empty"})
            return [Result([], [], tag="EMPTY", is_query=False)]
        if len(sql) > MAX_STATEMENT_CHARS or len(stmts) > MAX_STATEMENTS:
            err = self.syntax_error(stmts[-1])
            self._log(sql, err, {"kind": "too_large"})
            return [err]
        if not multi and len(stmts) > 1:
            # No multi-statement capability negotiated: check for exec primitives, then
            # fail the batch the way the real server would.
            for s in stmts:
                d = classify_dangerous(" ".join(s.split()).lower())
                if d:
                    err = self.dangerous_error(d[0], d[1], s)
                    self._log(s, err, {"kind": "refused", "high_signal": True,
                                       "signal": "sql_exec_attempt", "match": d[0]})
                    return [err]
            err = self.syntax_error(stmts[1])
            self._log(sql, err, {"kind": "multi_statement"})
            return [err]
        out: list[Answer] = []
        for s in stmts:
            ans, meta = await self._one(s)
            self._log(s, ans, meta)
            out.append(ans)
            if isinstance(ans, SqlError):
                break
        return out

    def _log(self, stmt: str, ans: Answer, meta: dict) -> None:
        data = {"statement": stmt[:2000], "database": self.database or "", "dialect": self.dialect}
        data.update(meta)
        if isinstance(ans, SqlError):
            data["result"] = f"error:{ans.code}"
        else:
            data["result"] = f"rows:{len(ans.rows)}" if ans.is_query else f"ok:{ans.affected}"
        token = self.ctx.honeytoken_in(stmt)
        if token:
            data["honeytoken"] = token
            data["high_signal"] = True
        self.conn.emit("command", "SQL statement", username=self.user, data=data)

    async def _one(self, stmt: str) -> tuple[Answer, dict]:
        s = " ".join(stmt.split())
        low = s.lower()
        d = classify_dangerous(low)
        if d:
            return self.dangerous_error(d[0], d[1], s), {
                "kind": "refused", "high_signal": True, "signal": "sql_exec_attempt", "match": d[0]}
        cred = self._cred_dump(low)
        if cred is not None:
            return cred, {"kind": "refused", "high_signal": True, "signal": "sql_cred_dump"}
        try:
            ans = self._hardcoded(s, low)
        except Exception:  # noqa: BLE001 - a parser bug must degrade to a protocol error
            ans = self.syntax_error(s)
            return ans, {"kind": "parse_error"}
        if ans is not None:
            return ans, {"kind": "hardcoded"}
        llm = await self._ask_model(s)
        if llm is not None:
            return llm, {"kind": "llm"}
        return self.syntax_error(s), {"kind": "fallback"}

    # ---- credential tables ---------------------------------------------------------------

    def _cred_dump(self, low: str) -> Optional[SqlError]:
        if self.dialect == "postgres" and re.search(r"\bfrom\s+(pg_catalog\.)?(pg_shadow|pg_authid)\b", low):
            name = "pg_authid"
            return SqlError("42501", f"permission denied for table {name}")
        if self.dialect == "mysql" and re.search(r"\bfrom\s+`?mysql`?\s*\.\s*`?user`?\b", low):
            return SqlError("42000", f"SELECT command denied to user '{safe_name(self.user)}'@"
                            f"'{safe_name(self.conn.src_ip)}' for table 'user'", errno=1142)
        if self.dialect == "mssql" and re.search(r"\b(sql_logins|syslogins|sysxlogins)\b", low):
            return SqlError("229", "The SELECT permission was denied on the object 'sql_logins', "
                            "database 'mssqlsystemresource', schema 'sys'.", errno=229, klass=14)
        return None

    # ---- hardcoded -----------------------------------------------------------------------

    def _ok(self, tag: str, affected: int = 0) -> Result:
        return Result([], [], tag=tag, affected=affected, is_query=False)

    def _hardcoded(self, s: str, low: str) -> Optional[Answer]:
        if re.match(r"^(begin|start transaction)\b", low):
            return self._ok("BEGIN")
        if re.match(r"^(commit|end)\b", low):
            return self._ok("COMMIT")
        if re.match(r"^(rollback|abort)\b", low):
            return self._ok("ROLLBACK")
        if re.match(r"^savepoint\b", low):
            return self._ok("SAVEPOINT")
        if re.match(r"^release\b", low):
            return self._ok("RELEASE")
        if re.match(r"^set\b", low):
            return self._set(s, low)
        if re.match(r"^use\b", low):
            if self.dialect == "postgres":
                return self.syntax_error(s)
            m = re.match(r"^use\s+([`\[\"]?[\w$-]+[`\]\"]?)$", s, re.I)
            if not m:
                return self.syntax_error(s)
            name = _unquote_ident(m.group(1))
            if not self.db_exists(name):
                return self.no_db(name)
            self.database = self.catalog[name.lower()].name
            return self._ok("USE")
        if re.match(r"^show\b", low):
            return self._show(s, low)
        m = re.match(r"^(?:describe|desc|explain)\s+([`\"\[\]\w.$]+)$", s, re.I)
        if m and self.dialect == "mysql":
            t = self.find_table(m.group(1).split("."))
            if t is None:
                return self.no_table(m.group(1).split(".")[-1])
            return self._describe(t)
        if re.match(r"^(?:exec|execute)?\s*(?:sp_databases)\b", low) and self.dialect == "mssql":
            rows = [[d.name, 8192 + 16 * i, None] for i, d in enumerate(self.catalog.values())]
            return Result(["DATABASE_NAME", "DATABASE_SIZE", "REMARKS"], rows)
        if re.match(r"^select\b", low):
            return self._select(s, low)
        if re.match(r"^(insert|update|delete|replace|merge|upsert)\b", low):
            return self._write(s, low)
        if re.match(r"^(create|drop|alter|truncate|grant|revoke|comment|analyze|vacuum|reindex|"
                    r"cluster|lock|discard|reset|deallocate|listen|unlisten|notify|checkpoint|"
                    r"flush|optimize|kill|rename|do)\b", low):
            return self._ddl(s, low)
        return None

    def _set(self, s: str, low: str) -> Answer:
        if self.dialect == "postgres":
            m = re.match(r"^set\s+(?:session\s+|local\s+)?(\w+)\s*(?:=|to)\s*(.+)$", s, re.I)
            if m and m.group(1).lower() == "role":
                return SqlError("42501", f'permission denied to set role "{safe_name(m.group(2).strip(chr(39)))}"')
            if m and m.group(1).lower() == "session_authorization":
                return SqlError("42501", "permission denied to set session authorization")
        if self.dialect == "mysql" and re.match(r"^set\s+(global|persist)\b", low):
            return SqlError("42000", "Access denied; you need (at least one of) the SUPER or "
                            "SYSTEM_VARIABLES_ADMIN privilege(s) for this operation", errno=1227)
        return self._ok("SET")

    def _describe(self, t: TableInfo) -> Result:
        type_map = {"int": "int", "bigint": "bigint", "text": "text", "varchar": "varchar(255)",
                    "numeric": "decimal(12,2)", "bool": "tinyint(1)", "date": "date",
                    "timestamp": "datetime", "uuid": "char(36)", "json": "json"}
        rows = []
        for i, (c, ty) in enumerate(t.columns):
            rows.append([c, type_map.get(ty, ty), "NO" if i == 0 else "YES",
                         "PRI" if i == 0 else "", None,
                         "auto_increment" if i == 0 and ty in ("int", "bigint") else ""])
        return Result(["Field", "Type", "Null", "Key", "Default", "Extra"], rows)

    def _create_table_ddl(self, t: TableInfo) -> str:
        type_map = {"int": "int", "bigint": "bigint", "text": "text", "varchar": "varchar(255)",
                    "numeric": "decimal(12,2)", "bool": "tinyint(1)", "date": "date",
                    "timestamp": "datetime", "uuid": "char(36)", "json": "json"}
        lines = []
        for i, (c, ty) in enumerate(t.columns):
            extra = " NOT NULL AUTO_INCREMENT" if i == 0 and ty in ("int", "bigint") else (
                " NOT NULL" if i == 0 else " DEFAULT NULL")
            lines.append(f"  `{c}` {type_map.get(ty, ty)}{extra}")
        lines.append(f"  PRIMARY KEY (`{t.columns[0][0]}`)")
        return (f"CREATE TABLE `{t.name}` (\n" + ",\n".join(lines) +
                "\n) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci")

    def _filter_like(self, items: list[tuple[str, Any]], low: str) -> list[tuple[str, Any]]:
        m = re.search(r"\blike\s+'((?:[^']|'')*)'", low)
        if not m:
            m2 = re.search(r"\bwhere\s+variable_name\s*=\s*'([^']*)'", low)
            if not m2:
                return items
            return [(k, v) for k, v in items if k.lower() == m2.group(1).lower()]
        pattern = m.group(1).replace("''", "'")
        return [(k, v) for k, v in items if like_match(pattern, k, self.like_escape)]

    def _show(self, s: str, low: str) -> Optional[Answer]:
        if self.dialect == "postgres":
            m = re.match(r"^show\s+(\w+)$", low)
            if not m:
                return self.syntax_error(s)
            name = m.group(1)
            params = self.pg_params()
            if name == "all":
                return Result(["name", "setting", "description"],
                              [[k, v, ""] for k, v in sorted(params.items())], tag="SHOW")
            if name not in params:
                return SqlError("42704", f'unrecognized configuration parameter "{safe_name(name)}"')
            return Result([name], [[params[name]]], tag="SHOW")
        if self.dialect != "mysql":
            return None
        if re.match(r"^show\s+(databases|schemas)\b", low):
            items = [(d.name, None) for d in self.catalog.values()]
            return Result(["Database"], [[k] for k, _ in self._filter_like(items, low)])
        m = re.match(r"^show\s+(full\s+)?tables(?:\s+(?:from|in)\s+([`\w$-]+))?", low)
        if m:
            dbname = _unquote_ident(m.group(2)) if m.group(2) else self.database
            if not dbname:
                return self.no_db_selected()
            d = self.catalog.get(dbname.lower())
            if d is None:
                return self.no_db(dbname)
            items = [(t.name, None) for t in d.tables.values()]
            names = [k for k, _ in self._filter_like(items, low)]
            col = f"Tables_in_{d.name}"
            if m.group(1):
                return Result([col, "Table_type"], [[n, "BASE TABLE"] for n in names])
            return Result([col], [[n] for n in names])
        if re.match(r"^show\s+(global\s+|session\s+|local\s+)?variables\b", low):
            items = sorted(self.mysql_vars().items())
            return Result(["Variable_name", "Value"],
                          [[k, v] for k, v in self._filter_like(items, low)])
        if re.match(r"^show\s+(global\s+|session\s+|local\s+)?status\b", low):
            items = sorted(self.mysql_status().items())
            return Result(["Variable_name", "Value"],
                          [[k, v] for k, v in self._filter_like(items, low)])
        if re.match(r"^show\s+grants\b", low):
            u = safe_name(self.user)
            rows = [[f"GRANT USAGE ON *.* TO `{u}`@`%`"]]
            for d in self.user_dbs():
                rows.append([f"GRANT SELECT, INSERT, UPDATE, DELETE ON `{d.name}`.* TO `{u}`@`%`"])
            return Result([f"Grants for {u}@%"], rows)
        if re.match(r"^show\s+(full\s+)?processlist\b", low):
            return Result(["Id", "User", "Host", "db", "Command", "Time", "State", "Info"],
                          [[5, "event_scheduler", "localhost", None, "Daemon", 2764800,
                            "Waiting on empty queue", None],
                           [self.pid, safe_name(self.user), f"{self.conn.src_ip}:{self.conn.src_port}",
                            self.database or None, "Query", 0, "init", "SHOW PROCESSLIST"]])
        if re.match(r"^show\s+(warnings|errors)\b", low):
            return Result(["Level", "Code", "Message"], [])
        m = re.match(r"^show\s+(?:full\s+)?(?:columns|fields)\s+(?:from|in)\s+([`\w$.-]+)"
                     r"(?:\s+(?:from|in)\s+([`\w$-]+))?", low)
        if m:
            parts = ([m.group(2)] if m.group(2) else []) + m.group(1).split(".")
            t = self.find_table(parts)
            if t is None:
                return self.no_table(m.group(1).split(".")[-1])
            return self._describe(t)
        m = re.match(r"^show\s+create\s+table\s+([`\w$.-]+)", low)
        if m:
            t = self.find_table(m.group(1).split("."))
            if t is None:
                return self.no_table(m.group(1).split(".")[-1])
            return Result(["Table", "Create Table"], [[t.name, self._create_table_ddl(t)]])
        if re.match(r"^show\s+create\s+database\s+", low):
            name = _unquote_ident(low.split()[-1])
            if not self.db_exists(name):
                return self.no_db(name)
            return Result(["Database", "Create Database"],
                          [[name, f"CREATE DATABASE `{name}` /*!40100 DEFAULT CHARACTER SET "
                                  "utf8mb4 COLLATE utf8mb4_0900_ai_ci */ /*!80016 DEFAULT "
                                  "ENCRYPTION='N' */"]])
        if re.match(r"^show\s+table\s+status\b", low):
            d = self.current_db()
            if d is None:
                return self.no_db_selected()
            return Result(["Name", "Engine", "Version", "Row_format", "Rows", "Collation"],
                          [[t.name, "InnoDB", 10, "Dynamic", len(self.table_rows(t)),
                            "utf8mb4_0900_ai_ci"] for t in d.tables.values()])
        if re.match(r"^show\s+engines\b", low):
            return Result(["Engine", "Support", "Comment", "Transactions", "XA", "Savepoints"],
                          [["InnoDB", "DEFAULT", "Supports transactions, row-level locking, and "
                            "foreign keys", "YES", "YES", "YES"],
                           ["MyISAM", "YES", "MyISAM storage engine", "NO", "NO", "NO"],
                           ["MEMORY", "YES", "Hash based, stored in memory, useful for temporary "
                            "tables", "NO", "NO", "NO"]])
        if re.match(r"^show\s+(index|indexes|keys)\b", low):
            return Result(["Table", "Non_unique", "Key_name", "Seq_in_index", "Column_name"], [])
        if re.match(r"^show\s+(master|binary\s+log|slave|replica)\s+status\b", low):
            if low.split()[1] in ("master", "binary"):
                return Result(["File", "Position", "Binlog_Do_DB", "Binlog_Ignore_DB",
                               "Executed_Gtid_Set"], [["binlog.000214", 157, "", "", ""]])
            return Result(["Replica_IO_State", "Source_Host", "Source_User"], [])
        if re.match(r"^show\s+(plugins)\b", low):
            return Result(["Name", "Status", "Type", "Library", "License"],
                          [["mysql_native_password", "ACTIVE", "AUTHENTICATION", None, "GPL"],
                           ["caching_sha2_password", "ACTIVE", "AUTHENTICATION", None, "GPL"],
                           ["InnoDB", "ACTIVE", "STORAGE ENGINE", None, "GPL"]])
        if re.match(r"^show\s+(character\s+set|charset)\b", low):
            return Result(["Charset", "Description", "Default collation", "Maxlen"],
                          [["utf8mb4", "UTF-8 Unicode", "utf8mb4_0900_ai_ci", 4],
                           ["latin1", "cp1252 West European", "latin1_swedish_ci", 1]])
        if re.match(r"^show\s+collation\b", low):
            return Result(["Collation", "Charset", "Id", "Default", "Compiled", "Sortlen"],
                          [["utf8mb4_0900_ai_ci", "utf8mb4", 255, "Yes", "Yes", 0],
                           ["latin1_swedish_ci", "latin1", 8, "Yes", "Yes", 1]])
        return None

    # ---- writes ---------------------------------------------------------------------------

    def _write(self, s: str, low: str) -> Answer:
        verb = low.split()[0]
        m = re.match(r"^(?:insert|replace|upsert)\s+(?:ignore\s+)?(?:into\s+)?([`\"\[\]\w$.]+)", s, re.I) \
            if verb in ("insert", "replace", "upsert") else \
            re.match(r"^update\s+(?:only\s+)?([`\"\[\]\w$.]+)", s, re.I) if verb == "update" else \
            re.match(r"^delete\s+(?:from\s+)?(?:only\s+)?([`\"\[\]\w$.]+)", s, re.I) \
            if verb == "delete" else None
        if verb == "merge":
            return self._ok("MERGE 1", 1)
        if not m:
            return self.syntax_error(s)
        parts = m.group(1).split(".")
        t = self.find_table(parts)
        name = _unquote_ident(parts[-1]).lower()
        if t is None and name not in self.created:
            if self.dialect == "mysql" and not self.database and len(parts) == 1:
                return self.no_db_selected()
            return self.no_table(_unquote_ident(parts[-1]))
        if verb in ("insert", "replace", "upsert"):
            n = len(re.findall(r"\)\s*,\s*\(", s)) + 1 if _w(low, "values") else 1
            return self._ok(f"INSERT 0 {n}", n)
        nrows = len(self.table_rows(t)) if t is not None else 0
        if _w(low, "where"):
            n = 1 if nrows else 0
        else:
            n = nrows
        return self._ok(f"{verb.upper()} {n}", n)

    def _ddl(self, s: str, low: str) -> Answer:
        words = [w for w in low.split() if w not in ("or", "replace", "unique", "temporary",
                                                     "temp", "if", "not", "exists", "global",
                                                     "local", "materialized", "unlogged")]
        verb = words[0]
        if verb == "create" and len(words) > 2 and words[1] == "table":
            m = re.match(r"^create\s+(?:temporary\s+|temp\s+)?table\s+(?:if\s+not\s+exists\s+)?"
                         r"([`\"\[\]\w$.]+)\s*\((.*)\)", s, re.I | re.S)
            if m:
                name = _unquote_ident(m.group(1).split(".")[-1]).lower()
                cols = []
                for item in _split_top(m.group(2), r","):
                    first = item.split()[0] if item.split() else ""
                    if first.lower() in ("primary", "unique", "key", "index", "constraint",
                                         "foreign", "check", "fulltext"):
                        continue
                    if first:
                        cols.append(_unquote_ident(first)[:63])
                if len(self.created) < 50:
                    self.created[name] = cols[:40]
        if verb == "create" and len(words) > 2 and words[1] == "database":
            pass
        if verb in ("create", "drop", "alter", "comment") and len(words) > 1:
            obj = words[1]
            if obj in ("table", "index", "view", "database", "schema", "user", "role", "sequence",
                       "function", "procedure", "trigger", "extension", "type", "policy",
                       "event", "login"):
                return self._ok(f"{verb.upper()} {obj.upper()}")
            if verb == "comment":
                return self._ok("COMMENT")
            return self._ok(f"{verb.upper()}")
        if verb == "truncate":
            return self._ok("TRUNCATE TABLE")
        tags = {"grant": "GRANT", "revoke": "REVOKE", "analyze": "ANALYZE", "vacuum": "VACUUM",
                "reindex": "REINDEX", "cluster": "CLUSTER", "lock": "LOCK TABLE",
                "discard": "DISCARD ALL", "reset": "RESET", "deallocate": "DEALLOCATE",
                "listen": "LISTEN", "unlisten": "UNLISTEN", "notify": "NOTIFY",
                "checkpoint": "CHECKPOINT", "flush": "FLUSH", "optimize": "OPTIMIZE",
                "kill": "KILL", "rename": "RENAME", "do": "DO"}
        if verb == "checkpoint" and self.dialect == "postgres":
            return SqlError("42501", "must be superuser or have privileges of pg_checkpoint "
                            "to do CHECKPOINT")
        return self._ok(tags.get(verb, verb.upper()))

    # ---- SELECT ---------------------------------------------------------------------------

    def _select(self, s: str, low: str) -> Optional[Answer]:
        mask = _mask(s)
        if _find_top(s, r"\b(union|intersect|except)\b", mask):
            return None
        body_start = len("select")
        top = None
        m = re.match(r"^select\s+top\s*\(?\s*(\d+)\s*\)?\s+", s, re.I)
        if m:
            top_or_err = self._row_count(m.group(1), s[m.start(1):])
            if isinstance(top_or_err, SqlError):
                return top_or_err
            top = top_or_err
            body_start = m.end()
        distinct = False
        m = re.match(r"\s*distinct\s+", s[body_start:], re.I)
        if m:
            distinct = True
            body_start += m.end()
        f = _find_top(s, r"\bfrom\b", mask, body_start)
        clauses_rx = (r"\b(where|group\s+by|order\s+by|limit|offset|having|fetch|for\s+update|"
                      r"into|window|procedure)\b")
        if f is None:
            end = _find_top(s, clauses_rx, mask, body_start)
            select_list = s[body_start:end[0] if end else len(s)]
            return self._select_no_from(select_list)
        select_list = s[body_start:f[0]]
        rest_start = f[1]
        end = _find_top(s, clauses_rx, mask, rest_start)
        from_part = s[rest_start:end[0] if end else len(s)].strip()
        tail = s[end[0]:] if end else ""
        if from_part.lower() == "dual":
            return self._select_no_from(select_list)
        if from_part.startswith("("):
            return None
        m = re.match(r"^([`\"\[\]\w$]+(?:\s*\.\s*[`\"\[\]\w$]*)*)", from_part)
        if not m:
            return None
        source = re.sub(r"\s+", "", m.group(1))
        parts = source.split(".")
        has_join = re.search(r"\bjoin\b", from_part, re.I) or "," in from_part
        rows_dicts, order = self._catalog_source(parts)
        if rows_dicts is not None:
            return self._project(select_list, rows_dicts, order, tail, lenient=True,
                                 distinct=distinct, top=top)
        t = self.find_table(parts)
        if t is None:
            created = self.created.get(_unquote_ident(parts[-1]).lower())
            if created is not None:
                return Result(created or ["?column?"], [])
            if self.dialect == "mysql" and not self.database and len(parts) == 1:
                return self.no_db_selected()
            return self.no_table(_unquote_ident(parts[-1]))
        if has_join:
            return None
        cols = [c for c, _ in t.columns]
        dicts = [dict(zip([c.lower() for c in cols], r, strict=False)) for r in self.table_rows(t)]
        return self._project(select_list, dicts, cols, tail, lenient=False,
                             distinct=distinct, top=top)

    def _items(self, select_list: str) -> list[tuple[str, Optional[str]]]:
        out: list[tuple[str, Optional[str]]] = []
        for item in _split_top(select_list, r","):
            if not item:
                continue
            out.append(_split_alias(item))
        return out

    def _default_name(self, expr: str, fname: Optional[str]) -> str:
        if self.dialect == "postgres":
            if fname:
                return fname
            ident = re.fullmatch(r"(?:[\w$\"]+\.)*([\w$\"]+)", expr)
            if ident and not _literal(expr)[0]:
                return _unquote_ident(ident.group(1)).lower()
            return "?column?"
        if self.dialect == "mysql":
            return expr[:64]
        return ""

    def _select_no_from(self, select_list: str) -> Optional[Answer]:
        cols, row = [], []
        for expr, alias in self._items(select_list):
            ok, value, fname = self._eval(expr)
            if not ok:
                return None
            cols.append(alias if alias is not None else self._default_name(expr, fname))
            row.append(value)
        if not cols:
            return None
        return Result(cols, [row])

    def _eval(self, expr: str) -> tuple[bool, Any, Optional[str]]:
        e = expr.strip()
        e = re.sub(r"::\s*[\w ]+(\[\])?$", "", e).strip()
        while e.startswith("(") and e.endswith(")") and _find_top(e[1:-1], r"[()]") is None \
                and e.count("(") == 1:
            e = e[1:-1].strip()
        concat = self._concat(e)
        if concat is not None:
            return concat
        ok, v = _literal(e)
        if ok:
            return True, v, None
        el = e.lower()
        d = self.dialect
        m = re.fullmatch(r"@@(?:(?:global|session|local)\.)?(\w+)", el)
        if m and d in ("mysql", "mssql"):
            table = self.mysql_vars() if d == "mysql" else self.mssql_vars()
            if m.group(1) in table:
                return True, table[m.group(1)], None
            if d == "mysql":
                return False, None, None
            return False, None, None
        keyword_funcs = ("current_user", "session_user", "user", "system_user", "current_date",
                         "current_timestamp", "localtimestamp", "current_schema",
                         "current_catalog", "current_role", "current_time")
        if el in keyword_funcs:
            if d == "mysql" and el in ("user", "system_user"):
                return False, None, None
            return self._func(el, "", keyword=True)
        m = re.fullmatch(r"(?:pg_catalog\.|sys\.|dbo\.)?(\w+)\s*\((.*)\)", e, re.S)
        if m:
            return self._func(m.group(1).lower(), m.group(2).strip())
        return False, None, None

    def _concat(self, e: str) -> Optional[tuple[bool, Any, Optional[str]]]:
        """T-SQL ``a + b`` and PostgreSQL ``a || b`` at the top level: strings concatenate,
        numbers add (T-SQL), NULL propagates. None when the expression is not one."""
        sep = r"\+" if self.dialect == "mssql" else (r"\|\|" if self.dialect == "postgres" else None)
        if sep is None or len(e) > 4096:
            return None
        parts = _split_top(e, sep)
        if len(parts) < 2 or any(not p for p in parts):
            return None
        values = []
        for part in parts[:32]:
            ok, v, _ = self._eval(part)
            if not ok:
                return None
            values.append(v)
        if any(v is None for v in values):
            return True, None, None
        if self.dialect == "mssql" and all(isinstance(v, (int, float)) and not isinstance(v, bool)
                                           for v in values):
            return True, sum(values), None
        return True, "".join(str(v) for v in values)[:8000], None

    def _func(self, f: str, args: str, keyword: bool = False) -> tuple[bool, Any, Optional[str]]:
        d = self.dialect
        name = f
        user_at = f"{self.user}@{self.conn.src_ip}"
        if f == "version" and d in ("postgres", "mysql"):
            return True, self.full_version(), name
        if f in ("current_user", "session_user", "user", "system_user", "suser_sname",
                 "suser_name", "original_login", "current_role"):
            if d == "mysql":
                return True, (f"{self.user}@%" if f == "current_user" else user_at), name
            if d == "mssql" and f in ("user", "current_user", "session_user"):
                return True, "dbo", name     # the database user; SYSTEM_USER is the login
            return True, self.user, name
        if f == "space" and d == "mssql":
            ok, n, _ = self._eval(args)
            if ok and isinstance(n, int) and not isinstance(n, bool):
                return True, (" " * n if 0 <= n <= 8000 else None), name
        if f == "user_name" and d == "mssql":
            return True, "dbo", name
        if f in ("current_database", "database", "db_name", "current_catalog"):
            return True, (self.database or None), name
        if f in ("current_schema", "schema", "schema_name"):
            if d == "postgres":
                cur = self.current_db()
                return True, (cur.schema if cur else "public"), name
            return True, ("dbo" if d == "mssql" else (self.database or None)), name
        if f in ("now", "current_timestamp", "sysdate", "getdate", "localtimestamp",
                 "sysdatetime", "utc_timestamp", "getutcdate", "statement_timestamp",
                 "transaction_timestamp", "clock_timestamp"):
            return True, self._now(), name
        if f in ("current_date", "curdate"):
            return True, self._now()[:10], name
        if f in ("current_time", "curtime"):
            return True, self._now()[11:], name
        if f in ("connection_id", "pg_backend_pid"):
            return True, self.pid, name
        if f in ("last_insert_id", "found_rows", "row_count", "scope_identity"):
            return True, 0, name
        if f == "pg_is_in_recovery":
            return True, False, name
        if f == "inet_server_addr":
            return True, self.internal_ip, name
        if f == "inet_server_port":
            return True, self.port or 5432, name
        if f == "inet_client_addr":
            return True, self.conn.src_ip, name
        if f == "current_setting" and d == "postgres":
            key = args.strip().strip("'").lower()
            params = self.pg_params()
            if key in params:
                return True, params[key], name
            return False, None, None
        if f == "pg_postmaster_start_time":
            return True, self.started.strftime("%Y-%m-%d %H:%M:%S+00"), name
        if f == "serverproperty" and d == "mssql":
            return True, self.server_property(args), name
        if f in ("is_srvrolemember", "is_member"):
            return True, 0, name
        if f == "has_dbaccess":
            return True, 1, name
        if f in ("uuid", "gen_random_uuid", "newid"):
            return True, str(uuid.uuid4()), name
        if f in ("sleep", "benchmark"):
            return True, 0, name
        if f == "pg_sleep":
            return True, "", name
        if f == "count" and args in ("*", "1"):
            return True, 1, name
        return False, None, None

    def _catalog_source(self, parts: list[str]) -> tuple[Optional[list[dict]], list[str]]:
        names = [_unquote_ident(p).lower() for p in parts if _unquote_ident(p)]
        if not names:
            return None, []
        last = names[-1]
        qual = names[-2] if len(names) >= 2 else ""
        d = self.dialect
        cur = self.current_db()
        if qual == "information_schema" or (d == "mssql" and qual == "information_schema"):
            return self._info_schema(last)
        if d == "postgres" and (qual in ("", "pg_catalog")):
            return self._pg_catalog(last, cur)
        if d == "mssql":
            if last in ("databases", "sysdatabases"):
                rows = [{"name": db.name, "database_id": i + 1, "dbid": i + 1,
                         "create_date": "2023-08-14 10:02:33.410", "state_desc": "ONLINE",
                         "owner_sid": "0x01", "compatibility_level": 150}
                        for i, db in enumerate(self.catalog.values())]
                return rows, ["name", "database_id", "create_date", "state_desc"]
            if last in ("tables", "objects", "sysobjects", "all_objects"):
                rows = [{"name": t.name, "object_id": 245575913 + i * 16, "id": 245575913 + i * 16,
                         "type": "U", "xtype": "U", "type_desc": "USER_TABLE", "schema_id": 1,
                         "uid": 1, "create_date": "2024-02-11 08:14:51.220"}
                        for i, t in enumerate(cur.tables.values())] if cur else []
                return rows, ["name", "object_id", "schema_id", "type", "type_desc", "create_date"]
            if last in ("schemas",):
                return ([{"name": "dbo", "schema_id": 1, "principal_id": 1},
                         {"name": "guest", "schema_id": 2, "principal_id": 2},
                         {"name": "sys", "schema_id": 4, "principal_id": 4}],
                        ["name", "schema_id", "principal_id"])
        return None, []

    def _pg_catalog(self, last: str, cur: Optional[DbInfo]) -> tuple[Optional[list[dict]], list[str]]:
        user = self.user
        if last == "pg_database":
            rows = []
            for i, db in enumerate(self.catalog.values()):
                rows.append({"datname": db.name, "oid": 16384 + i if not db.system else 1 + i * 3,
                             "datdba": 10, "encoding": "UTF8", "datcollate": "C.UTF-8",
                             "datctype": "C.UTF-8", "datistemplate": db.name.startswith("template"),
                             "datallowconn": db.name != "template0", "name": db.name,
                             "owner": "postgres", "collate": "C.UTF-8", "ctype": "C.UTF-8",
                             "icu locale": None, "locale provider": "libc",
                             "access privileges": None, "size": "8537 kB"})
            return rows, ["oid", "datname", "datdba", "encoding", "datcollate", "datctype",
                          "datistemplate", "datallowconn"]
        if last == "pg_namespace":
            schemas = sorted({cur.schema} if cur else {"public"})
            rows = [{"nspname": sname, "oid": 2200 + i, "nspowner": 10, "name": sname,
                     "owner": "postgres"} for i, sname in enumerate(schemas)]
            return rows, ["oid", "nspname", "nspowner"]
        if last in ("pg_class", "pg_tables", "pg_stat_user_tables", "pg_stat_all_tables",
                    "pg_statio_user_tables"):
            rows = []
            for i, t in enumerate(cur.tables.values() if cur else []):
                rows.append({"schemaname": t.schema, "tablename": t.name, "tableowner": "postgres",
                             "relname": t.name, "relkind": "r", "relnamespace": 2200,
                             "oid": 16400 + i * 7, "relid": 16400 + i * 7, "nspname": t.schema,
                             "schema": t.schema, "name": t.name, "type": "table",
                             "owner": "postgres", "n_live_tup": len(self.table_rows(t)),
                             "reltuples": float(len(self.table_rows(t))), "relowner": 10,
                             "hasindexes": True, "hasrules": False, "hastriggers": False,
                             "rowsecurity": False, "tablespace": None,
                             "persistence": "permanent", "access method": "heap",
                             "size": "16 kB", "description": None})
            return rows, (["schemaname", "tablename", "tableowner", "tablespace", "hasindexes",
                           "hasrules", "hastriggers", "rowsecurity"] if last == "pg_tables"
                          else ["oid", "relname", "relnamespace", "relkind", "relowner",
                                "reltuples"])
        if last == "pg_type":
            rows = [{"oid": oid, "typname": n, "typnamespace": 11, "typtype": "b",
                     "typarray": 0, "typelem": 0, "typbasetype": 0, "typlen": -1,
                     "typinput": f"{n}in", "typoutput": f"{n}out", "typcategory": "U",
                     "typdelim": ",", "typrelid": 0, "nspname": "pg_catalog"}
                    for oid, n in PG_TYPES]
            return rows, ["oid", "typname", "typnamespace", "typlen", "typtype", "typarray"]
        if last in ("pg_user", "pg_roles"):
            names = ["postgres"] + ([user] if user != "postgres" else [])
            scen = self.ctx.scenario
            if scen is not None:
                for u, _pw in scen.accounts_for("postgres")[:10]:
                    if u not in names:
                        names.append(u)
            rows = []
            for i, n in enumerate(names):
                sup = n == "postgres"
                rows.append({"usename": n, "rolname": n, "usesysid": 10 + i * 6000,
                             "oid": 10 + i * 6000, "usesuper": sup, "rolsuper": sup,
                             "usecreatedb": sup, "rolcreatedb": sup, "rolcreaterole": sup,
                             "rolinherit": True, "rolcanlogin": True, "rolreplication": sup,
                             "rolbypassrls": sup, "rolconnlimit": -1, "passwd": "********",
                             "rolpassword": "********", "valuntil": None, "rolvaliduntil": None,
                             "role name": n, "attributes": "Superuser, Create role, Create DB, "
                             "Replication, Bypass RLS" if sup else "", "member of": "{}"})
            return rows, (["usename", "usesysid", "usecreatedb", "usesuper", "passwd", "valuntil"]
                          if last == "pg_user" else
                          ["rolname", "rolsuper", "rolinherit", "rolcreaterole", "rolcreatedb",
                           "rolcanlogin", "rolconnlimit", "oid"])
        if last == "pg_settings":
            rows = [{"name": k, "setting": v, "unit": None, "category": "", "short_desc": ""}
                    for k, v in sorted(self.pg_params().items())]
            return rows, ["name", "setting", "unit", "category", "short_desc"]
        if last == "pg_stat_activity":
            rows = [{"datid": 16384, "datname": self.database, "pid": self.pid,
                     "usename": user, "application_name": "", "client_addr": self.conn.src_ip,
                     "client_port": self.conn.src_port, "state": "active",
                     "query": "select * from pg_stat_activity",
                     "backend_start": self._now()}]
            return rows, ["datid", "datname", "pid", "usename", "application_name",
                          "client_addr", "client_port", "backend_start", "state", "query"]
        if last == "pg_extension":
            return ([{"oid": 13561, "extname": "plpgsql", "extowner": 10, "extnamespace": 11,
                      "extversion": "1.0", "name": "plpgsql", "version": "1.0",
                      "schema": "pg_catalog", "description": "PL/pgSQL procedural language"}],
                    ["oid", "extname", "extowner", "extnamespace", "extversion"])
        return None, []

    def _info_schema(self, last: str) -> tuple[Optional[list[dict]], list[str]]:
        d = self.dialect
        if d == "mysql":
            dbs = list(self.catalog.values())
        else:
            cur = self.current_db()
            dbs = [cur] if cur else []
        catalog = "def"
        if last == "schemata":
            rows = []
            for db in (self.catalog.values() if d == "mysql" else dbs):
                rows.append({"catalog_name": catalog if d == "mysql" else db.name,
                             "schema_name": db.name if d == "mysql" else db.schema,
                             "schema_owner": "postgres" if d == "postgres" else "dbo",
                             "default_character_set_name": "utf8mb4",
                             "default_collation_name": "utf8mb4_0900_ai_ci"})
            return rows, ["catalog_name", "schema_name", "default_character_set_name",
                          "default_collation_name"]
        if last in ("tables", "columns", "views"):
            rows = []
            for db in dbs:
                for t in db.tables.values():
                    tcat = catalog if d == "mysql" else db.name
                    tschema = db.name if d == "mysql" else t.schema
                    if last == "views":
                        continue
                    if last == "tables":
                        rows.append({"table_catalog": tcat, "table_schema": tschema,
                                     "table_name": t.name, "table_type": "BASE TABLE",
                                     "engine": "InnoDB", "table_rows": len(self.table_rows(t)),
                                     "create_time": "2024-02-11 08:14:51",
                                     "table_collation": "utf8mb4_0900_ai_ci",
                                     "table_comment": ""})
                    else:
                        for i, (c, ty) in enumerate(t.columns):
                            rows.append({"table_catalog": tcat, "table_schema": tschema,
                                         "table_name": t.name, "column_name": c,
                                         "ordinal_position": i + 1, "data_type": ty,
                                         "column_type": ty, "is_nullable": "NO" if i == 0 else "YES",
                                         "column_default": None, "column_key": "PRI" if i == 0 else "",
                                         "character_maximum_length": 255 if ty == "varchar" else None,
                                         "extra": ""})
            if last == "tables":
                return rows, ["table_catalog", "table_schema", "table_name", "table_type"]
            if last == "columns":
                return rows, ["table_catalog", "table_schema", "table_name", "column_name",
                              "ordinal_position", "column_default", "is_nullable", "data_type",
                              "character_maximum_length"]
            return rows, ["table_catalog", "table_schema", "table_name", "view_definition"]
        return None, []

    # ---- projection / filtering -------------------------------------------------------------

    def _where(self, tail: str, rows: list[dict], lenient: bool) -> Union[list[dict], SqlError]:
        m = re.match(r"^\s*where\s+", tail, re.I)
        if not m:
            return rows
        body = tail[m.end():]
        end = _find_top(body, r"\b(group\s+by|order\s+by|limit|offset|having|fetch|for\s+update)\b")
        body = body[:end[0]] if end else body
        if _find_top(body, r"\bor\b"):
            return rows
        keys = set(rows[0].keys()) if rows else set()
        for cond in _split_top(body, r"\band\b"):
            m = re.fullmatch(r"\(?\s*(?:[\w\"`\[\]$]+\.)?[\"`\[]?(\w+)[\"`\]]?\s*"
                             r"(=|!=|<>|>=|<=|>|<|not\s+like|like|ilike)\s*(.+?)\s*\)?", cond, re.I | re.S)
            m_in = re.fullmatch(r"\(?\s*(?:[\w\"`\[\]$]+\.)?[\"`\[]?(\w+)[\"`\]]?\s+in\s*\((.*)\)\s*\)?",
                                cond, re.I | re.S)
            if m_in:
                col = m_in.group(1).lower()
                vals = [_literal(v) for v in _split_top(m_in.group(2), r",")]
                if col not in keys or not all(ok for ok, _ in vals):
                    if not lenient and col not in keys and rows:
                        return self.no_column(col)
                    continue
                wanted = {str(v) for _, v in vals}
                rows = [r for r in rows if str(r.get(col)) in wanted]
                continue
            if not m:
                continue
            col, op, raw = m.group(1).lower(), m.group(2).lower(), m.group(3)
            ok, val = _literal(raw)
            if col not in keys:
                if not lenient and rows and re.fullmatch(r"[A-Za-z_]\w*", m.group(1)) and ok:
                    return self.no_column(m.group(1))
                continue
            if not ok:
                continue
            rows = [r for r in rows if self._cmp(r.get(col), op, val, self.like_escape)]
        return rows

    @property
    def like_escape(self) -> Optional[str]:
        # MySQL and PostgreSQL default to backslash; SQL Server has no default escape.
        return None if self.dialect == "mssql" else "\\"

    @staticmethod
    def _cmp(left: Any, op: str, right: Any, escape: Optional[str] = "\\") -> bool:
        if op in ("like", "ilike", "not like"):
            hit = like_match(str(right), str(left), escape)
            return not hit if op == "not like" else hit
        if left is None or right is None:
            return False
        try:
            if isinstance(right, (int, float)) and not isinstance(right, bool):
                lv: Any = float(left)
                rv: Any = float(right)
            else:
                lv, rv = str(left).lower(), str(right).lower()
                if isinstance(left, bool):
                    lv = "true" if left else "false"
        except (TypeError, ValueError):
            return False
        return {"=": lv == rv, "!=": lv != rv, "<>": lv != rv, ">": lv > rv, "<": lv < rv,
                ">=": lv >= rv, "<=": lv <= rv}.get(op, False)

    def _project(self, select_list: str, rows: list[dict], order: list[str], tail: str,
                 lenient: bool, distinct: bool = False, top: Optional[int] = None) -> Optional[Answer]:
        filtered = self._where(tail, rows, lenient)
        if isinstance(filtered, SqlError):
            return filtered
        rows = filtered
        m = re.search(r"\border\s+by\s+(?:[\w\"`\[\]$]+\.)?[\"`\[]?(\w+)[\"`\]]?(\s+desc)?", tail, re.I)
        if m and rows and m.group(1).lower() in rows[0]:
            key = m.group(1).lower()
            rows = sorted(rows, key=lambda r: _sort_key(r.get(key)), reverse=bool(m.group(2)))
        offset: Any = 0
        limit: Any = top
        m = re.search(r"\blimit\s+(\d+)\s*,\s*(\d+)", tail, re.I)
        if m:
            offset = self._row_count(m.group(1), tail[m.start(1):])
            limit = self._row_count(m.group(2), tail[m.start(2):])
        else:
            m = re.search(r"\blimit\s+(\d+)", tail, re.I)
            if m:
                limit = self._row_count(m.group(1), tail[m.start(1):])
            m = re.search(r"\boffset\s+(\d+)", tail, re.I)
            if m:
                offset = self._row_count(m.group(1), tail[m.start(1):])
            m = re.search(r"\bfetch\s+(?:first|next)\s+(\d+)", tail, re.I)
            if m:
                limit = self._row_count(m.group(1), tail[m.start(1):])
        for v in (offset, limit):
            if isinstance(v, SqlError):
                return v
        items = self._items(select_list)
        if len(items) == 1 and re.fullmatch(r"count\s*\(\s*(\*|1|[\w.]+)\s*\)", items[0][0], re.I):
            expr, alias = items[0]
            name = alias or {"postgres": "count", "mysql": expr, "mssql": ""}[self.dialect]
            return Result([name], [[len(rows)]])
        rows = rows[offset:]
        if limit is not None:
            rows = rows[:limit]
        rows = rows[:MAX_RESULT_ROWS]
        out_cols: list[str] = []
        getters: list = []
        for expr, alias in items:
            e = expr.strip()
            if e == "*" or re.fullmatch(r"[\w\"`\[\]$]+\.\*", e):
                for c in order:
                    out_cols.append(c)
                    key = c.lower()
                    getters.append(lambda r, key=key: r.get(key))
                continue
            ident = re.fullmatch(r"(?:[\w\"`\[\]$]+\.)*([\w\"`\[\]$]+)", e)
            if ident and not _literal(e)[0]:
                key = _unquote_ident(ident.group(1))
                kl = key.lower()
                if rows and kl not in rows[0] and not lenient:
                    return self.no_column(key)
                if not rows and not lenient and kl not in (c.lower() for c in order):
                    return self.no_column(key)
                out_cols.append(alias if alias is not None else (
                    kl if self.dialect == "postgres" else key))
                getters.append(lambda r, k=kl: r.get(k))
                continue
            ok, value, fname = self._eval(e)
            if ok:
                out_cols.append(alias if alias is not None else self._default_name(e, fname))
                getters.append(lambda r, v=value: v)
                continue
            if not lenient:
                return None
            name = alias if alias is not None else "?column?"
            out_cols.append(name)
            key = name.lower()
            getters.append(lambda r, key=key: r.get(key))
        if not out_cols:
            return None
        result_rows = [[g(r) for g in getters] for r in rows]
        if distinct:
            seen, uniq = set(), []
            for r in result_rows:
                k = tuple(str(x) for x in r)
                if k not in seen:
                    seen.add(k)
                    uniq.append(r)
            result_rows = uniq
        return Result(out_cols, result_rows)

    # ---- model fallback ----------------------------------------------------------------------

    def _schema_summary(self) -> str:
        parts = []
        for db in self.catalog.values():
            if db.system:
                continue
            tables = "; ".join(f"{t.name}({', '.join(c for c, _ in t.columns)})"
                               for t in db.tables.values())
            parts.append(f"database {db.name}: {tables}")
        return "\n".join(parts)[:3000]

    async def _ask_model(self, stmt: str) -> Optional[Answer]:
        product = PRODUCT[self.dialect]
        system = (
            f"You emulate a {product} {self.version} server (host {self.hostname}"
            f"{', ' + self.org if self.org else ''}) inside a decoy. Answer the SQL statement in "
            "the untrusted block as the real server would, as JSON: either "
            '{"columns": [...], "rows": [[...]]} (at most 20 columns, 50 rows, short plausible '
            'values consistent with the schema below) or {"error": "<server error text>"}. '
            "Column names are plain identifiers. Never add explanations.\n"
            f"Schema:\n{self._schema_summary()}")
        payload = (f"session user: {self.user[:64]}\ncurrent database: {(self.database or '')[:64]}\n"
                   f"statement: {stmt[:MAX_LLM_STATEMENT_CHARS]}")
        user = untrusted_block("SQL statement", payload, os.urandom(8).hex())
        try:
            raw = await self.ctx.llm_json(self.conn.task_name, self.conn.src_ip, system, user,
                                          LlmSqlAnswer)
        except Exception:  # noqa: BLE001 - hostile/broken model output -> protocol error
            return None
        ans = validate_llm_answer(raw)
        if ans is None:
            return None
        if ans.error is not None:
            return self._model_error(ans.error)
        rows = [[wire_text(c, 200) if isinstance(c, str) else c for c in r]
                for r in (ans.rows or [])]
        return Result(list(ans.columns or []), rows)

    def _model_error(self, text: str) -> SqlError:
        t = text.lower()
        msg = wire_text(text, 200)
        if self.dialect == "postgres":
            code = ("42601" if "syntax" in t else "42P01" if "does not exist" in t
                    else "42501" if "permission" in t else "XX000")
            return SqlError(code, msg)
        if self.dialect == "mysql":
            if "syntax" in t:
                return SqlError("42000", msg, errno=1064)
            if "doesn't exist" in t or "does not exist" in t:
                return SqlError("42S02", msg, errno=1146)
            if "denied" in t:
                return SqlError("42000", msg, errno=1142)
            return SqlError("HY000", msg, errno=1105)
        if "syntax" in t:
            return SqlError("102", msg, errno=102, klass=15)
        if "invalid object" in t:
            return SqlError("208", msg, errno=208)
        if "permission" in t or "denied" in t:
            return SqlError("229", msg, errno=229, klass=14)
        return SqlError("50000", msg, errno=50000)


def validate_llm_answer(raw: Any) -> Optional[LlmSqlAnswer]:
    """Re-validate whatever came back; the JsonLLM implementation is not trusted."""
    if raw is None:
        return None
    try:
        if isinstance(raw, BaseModel):
            raw = raw.model_dump()
        return LlmSqlAnswer.model_validate(raw)
    except Exception:  # noqa: BLE001
        return None


def cell_text(value: Any, dialect: str) -> Optional[str]:
    """Text-protocol rendering of one cell (None stays None)."""
    if value is None:
        return None
    if isinstance(value, bool):
        return ("t" if value else "f") if dialect == "postgres" else ("1" if value else "0")
    if isinstance(value, float):
        return format(value, ".15g")
    if isinstance(value, (dict, list)):
        return wire_text(json.dumps(value, separators=(",", ":")))
    return wire_text(value)


def column_kind(rows: list[list], idx: int) -> str:
    """'int', 'float', 'bool' or 'text' for a result column."""
    kinds = set()
    for r in rows:
        if idx >= len(r):
            continue
        v = r[idx]
        if v is None:
            continue
        if isinstance(v, bool):
            kinds.add("bool")
        elif isinstance(v, int):
            kinds.add("int")
        elif isinstance(v, float):
            kinds.add("float")
        else:
            kinds.add("text")
    if len(kinds) == 1:
        return kinds.pop()
    if kinds == {"int", "float"}:
        return "float"
    return "text"
