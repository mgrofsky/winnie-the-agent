"""SSH/config.ini.TEMPLATE documents exactly the keys the code reads.

The code side is collected statically: reads of a config section with a literal key
(``config["llm"].get("model_name")``, ``section.getint("port")``, ``cp["scenario"]["active"]``),
keys taken from a literal tuple in a loop, f-string keys over the listener services, and the
sections built from dataclass fields (``[listeners]`` limits, ``[respond]``). The template
side is every active or commented ``key = value`` line under its section header.
"""

from __future__ import annotations

import ast
import dataclasses
import re
from pathlib import Path

from agents.respond import RespondSettings
from listeners.base import SERVICES, Limits

ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / "SSH" / "config.ini.TEMPLATE"
SOURCES = sorted([*ROOT.glob("agents/**/*.py"), *ROOT.glob("listeners/**/*.py"),
                  *ROOT.glob("scenarios/**/*.py"), ROOT / "SSH" / "ssh_server.py"])
CONNECTOR_ANY = "connector.*"          # keys read by code shared between connector sections
READ_METHODS = {"get", "getint", "getfloat", "getboolean"}
# Sections whose keys are not settings: [user_accounts] maps usernames to passwords.
FREE_FORM = {"user_accounts"}


def template_keys() -> dict[str, set[str]]:
    keys: dict[str, set[str]] = {}
    section = None
    for line in TEMPLATE.read_text().splitlines():
        header = re.match(r"^#?\[([a-z0-9_.]+)\]\s*$", line)
        if header:
            section = header.group(1)
            keys.setdefault(section, set())
            continue
        common = re.match(r"^#\s{3}([a-z][a-z0-9_]*) = ", line)   # shared connector keys
        if common:
            keys.setdefault(CONNECTOR_ANY, set()).add(common.group(1))
            continue
        key = re.match(r"^#?([a-z][a-z0-9_]*)\s*=", line)
        if key and section and section not in FREE_FORM:
            keys[section].add(key.group(1))
        # Per-service keys are documented once as a pattern, e.g. "<service>_port".
        if line.startswith("#"):
            for suffix in re.findall(r"<service>_([a-z]+)", line):
                keys.setdefault("listeners", set()).update(f"{svc}_{suffix}" for svc in SERVICES)
    return keys


def _str(node) -> str | None:
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


class _Reads(ast.NodeVisitor):
    """Collects (section, key) reads in one module."""

    def __init__(self, path: Path, sections: set[str], module_section: str | None):
        self.path, self.sections = path, sections
        self.module_section = module_section   # what a bare ``section``/``sec`` name means here
        self.consts = {}                       # module-level NAME = "connector.x"
        self.found: dict[str, set[str]] = {}

    # -- resolving what a receiver is -------------------------------------------------------
    def section_of(self, node, bound: dict) -> str | None:
        if isinstance(node, ast.IfExp):
            return self.section_of(node.body, bound)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) \
                and node.func.id == "_section" and len(node.args) == 2:
            key = _str(node.args[1])                       # _section(config, "honeypot")
            return key if key in self.sections else None
        if isinstance(node, ast.Subscript):
            key = _str(node.slice)
            if key is None and isinstance(node.slice, ast.Name):
                key = self.consts.get(node.slice.id)
            if key in self.sections:
                return key
            return None
        if isinstance(node, ast.Name):
            if node.id in bound:
                return bound[node.id]
            if node.id in ("section", "sec") and self.module_section:
                return self.module_section
        return None

    def add(self, section: str, key: str) -> None:
        self.found.setdefault(section, set()).add(key)

    def key_values(self, node, loops: dict) -> list[str]:
        if (s := _str(node)) is not None:
            return [s]
        if isinstance(node, ast.Name) and node.id in loops:
            return loops[node.id]
        if isinstance(node, ast.JoinedStr):   # f"{name}_port" over the listener services
            pattern = "".join(_str(v) or "{}" for v in node.values)
            if pattern.startswith("{}") and pattern.count("{}") == 1:
                return [pattern.format(svc) for svc in SERVICES]
        return []

    # -- walking -----------------------------------------------------------------------------
    def visit_Module(self, node):
        for stmt in node.body:
            if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 \
                    and isinstance(stmt.targets[0], ast.Name) and _str(stmt.value):
                self.consts[stmt.targets[0].id] = stmt.value.value
        self.scan(node, {}, {}, {})

    def scan(self, root, bound: dict, loops: dict, helpers: dict) -> None:
        bound, loops, helpers = dict(bound), dict(loops), dict(helpers)
        for node in ast.walk(root):
            if isinstance(node, ast.Assign) and len(node.targets) == 1 \
                    and isinstance(node.targets[0], ast.Name):
                sec = self.section_of(node.value, bound)
                if sec:
                    bound[node.targets[0].id] = sec
            elif isinstance(node, ast.For) and isinstance(node.target, ast.Name) \
                    and isinstance(node.iter, (ast.Tuple, ast.List)):
                values = [_str(e) for e in node.iter.elts]
                if values and all(v is not None for v in values):
                    loops[node.target.id] = values
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.args.args:
                helpers[node.name] = node.args.args[0].arg
                params = [a.arg for a in node.args.args]
                for inner in ast.walk(node):   # def f(section, key): section.get(key)
                    if isinstance(inner, ast.Call) and isinstance(inner.func, ast.Attribute) \
                            and inner.func.attr in READ_METHODS and inner.args \
                            and isinstance(inner.func.value, ast.Name) \
                            and isinstance(inner.args[0], ast.Name) \
                            and inner.func.value.id in params and inner.args[0].id in params:
                        self.section_key_helpers[node.name] = (
                            params.index(inner.func.value.id), params.index(inner.args[0].id))
        for node in ast.walk(root):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
                    and node.func.attr in READ_METHODS and node.args:
                sec = self.section_of(node.func.value, bound)
                if sec:
                    for key in self.key_values(node.args[0], loops):
                        self.add(sec, key)
                    param = node.args[0].id if isinstance(node.args[0], ast.Name) else None
                    for fname, first in helpers.items():   # def _int(name, ...): sec.get(name)
                        if first == param:
                            self.helper_reads[fname] = sec
            elif isinstance(node, ast.Subscript) and isinstance(node.ctx, ast.Load):
                sec = self.section_of(node.value, bound)
                key = _str(node.slice)
                if sec and key is not None:
                    self.add(sec, key)
        for node in ast.walk(root):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)):
                continue
            name = node.func.id
            if name in self.helper_reads and node.args and _str(node.args[0]):
                self.add(self.helper_reads[name], node.args[0].value)
            if name in SECTION_KEY_HELPERS:
                sec_i, key_i = SECTION_KEY_HELPERS[name]
                if len(node.args) > max(sec_i, key_i) and _str(node.args[key_i]):
                    sec = self.section_of(node.args[sec_i], bound)
                    if sec:
                        self.add(sec, node.args[key_i].value)

    helper_reads: dict
    section_key_helpers: dict


SECTION_KEY_HELPERS: dict[str, tuple[int, int]] = {}   # filled by a first pass over SOURCES


def code_keys(sections: set[str]) -> dict[str, set[str]]:
    found: dict[str, set[str]] = {}
    for _ in range(2):   # first pass finds helpers like parse_env_name(section, key)
        found = _scan_all(sections)
    found.setdefault("listeners", set()).update(f.name for f in dataclasses.fields(Limits))
    found.setdefault("respond", set()).update(f.name for f in dataclasses.fields(RespondSettings))
    return found


def _scan_all(sections: set[str]) -> dict[str, set[str]]:
    found: dict[str, set[str]] = {}
    for path in SOURCES:
        rel = path.relative_to(ROOT).as_posix()
        module_section = CONNECTOR_ANY if rel.startswith("agents/connectors/") else None
        visitor = _Reads(path, sections | {"connector.s3_events"}, module_section)
        visitor.helper_reads = {}
        visitor.section_key_helpers = SECTION_KEY_HELPERS
        visitor.visit(ast.parse(path.read_text(), filename=rel))
        for sec, keys in visitor.found.items():
            found.setdefault(sec, set()).update(keys)
    return found


def _connector_sections(keys: dict) -> list[str]:
    return [s for s in keys if s.startswith("connector.") and s != CONNECTOR_ANY]


def test_every_key_the_code_reads_is_in_the_template():
    tmpl = template_keys()
    code = code_keys(set(tmpl))
    missing = []
    connector_tmpl = set().union(*(tmpl[s] for s in _connector_sections(tmpl)),
                                 tmpl.get(CONNECTOR_ANY, set()))
    for sec, keys in sorted(code.items()):
        if sec in FREE_FORM:
            continue
        if sec == CONNECTOR_ANY:
            missing += [f"[connector.*] {k}" for k in sorted(keys - connector_tmpl)]
        elif sec not in tmpl:
            missing.append(f"[{sec}] (whole section)")
        else:
            extra = tmpl.get(CONNECTOR_ANY, set()) if sec.startswith("connector.") else set()
            missing += [f"[{sec}] {k}" for k in sorted(keys - tmpl[sec] - extra)]
    assert not missing, "read by the code but not in SSH/config.ini.TEMPLATE: " + ", ".join(missing)


def test_every_template_key_is_read_by_the_code():
    tmpl = template_keys()
    code = code_keys(set(tmpl))
    unread = []
    for sec, keys in sorted(tmpl.items()):
        if sec in FREE_FORM:
            continue
        readers = code.get(sec, set())
        if sec.startswith("connector.") or sec == CONNECTOR_ANY:
            readers = readers | code.get(CONNECTOR_ANY, set())
        unread += [f"[{sec}] {k}" for k in sorted(keys - readers)]
    assert not unread, "in SSH/config.ini.TEMPLATE but read by no code: " + ", ".join(unread)


def test_the_scan_sees_reads_of_every_kind():
    """Guards the scanner itself: one known key per reading style."""
    code = code_keys(set(template_keys()))
    assert "listen_host" in code["ssh"]                  # config['ssh'].get(...)
    assert "state_file" in code["budget"]                # section bound from config["budget"]
    assert "max_tokens_per_day" in code["budget"]        # for name in (...): section.get(name)
    assert "postgres_auth" in code["listeners"]          # f"{name}_auth"
    assert "max_objects_per_run" in code["connector.s3_events"]   # _int("...") helper
    assert "starttls" in code[CONNECTOR_ANY]             # connector module section.get(...)
    assert "secret_env" in code[CONNECTOR_ANY]           # parse_env_name(section, "secret_env")
    assert "data_dir" in code["honeypot"]                # _section(config, "honeypot").get(...)
