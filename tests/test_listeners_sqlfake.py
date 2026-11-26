"""Unit tests for the shared fake SQL engine: wildcard matching, comment stripping and
pathological input that must stay fast (all listeners share one event loop)."""

import asyncio
import threading
import time

import pytest

from listeners.base import ListenerContext
from listeners.events import EventWriter
from listeners import sqlfake
from listeners.sqlfake import FakeSql, Result, SqlError, like_match, strip_comments


class StubConn:
    def __init__(self, ctx):
        self.ctx = ctx
        self.task_name = "sql-test"
        self.src_ip = "198.51.100.7"
        self.dst_port = 0

    def emit(self, *args, **kwargs):
        pass



def _run(coro):
    # A private loop that is never installed as the thread's current loop: asyncio.run()
    # would leave the main thread without one, which breaks later tests that ask for it.
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def fake(dialect="mysql", database="appdb"):
    ctx = ListenerContext(EventWriter(None))
    return FakeSql(StubConn(ctx), dialect, "root", database)


def run_bounded(coro_factory, seconds):
    """Run in a daemon thread so a regression fails the test instead of hanging it."""
    box = {}

    def target():
        t0 = time.perf_counter()
        box["answers"] = _run(coro_factory())
        box["elapsed"] = time.perf_counter() - t0

    th = threading.Thread(target=target, daemon=True)
    th.start()
    th.join(seconds * 20)
    assert "elapsed" in box, "statement did not finish"
    return box["answers"], box["elapsed"]


def short_id(value):
    return value[:32] if isinstance(value, str) else None


# ---- LIKE matching ------------------------------------------------------------------------

@pytest.mark.parametrize("pattern,value,expected", [
    ("%", "", True),
    ("%", "anything", True),
    ("", "", True),
    ("", "a", False),
    ("abc", "ABC", True),
    ("a_c", "abc", True),
    ("a_c", "ac", False),
    ("a%c", "ac", True),
    ("a%c", "abbbbc", True),
    ("a%c", "abbbbd", False),
    ("%version%", "innodb_version", True),
    ("%version", "version_comment", False),
    ("version%", "version_comment", True),
    ("%_%", "x", True),
    ("%_%", "", False),
    ("%%a%%b%%", "xxaxxbxx", True),
    ("%%a%%b%%", "xxbxxaxx", False),
    ("a.c", "abc", False),
    ("a.c", "a.c", True),
    ("(x)*", "(x)*", True),
    ("line%", "line1\nline2", True),
    ("_", "\n", True),
    ("max\\_conn%", "max_connections", True),
    ("max\\_conn%", "maxXconnections", False),
    ("100\\%", "100%", True),
    ("100\\%", "1000", False),
    ("a\\\\b", "a\\b", True),
    ("trailing\\", "trailing\\", True),
])
def test_like_match_semantics(pattern, value, expected):
    assert like_match(pattern, value) is expected


def test_like_match_is_linear_on_pathological_patterns():
    value = "character_set_results_and_more_text_" * 4
    for pattern in ["%" * 50 + "!", "%a" * 50 + "!", "_%" * 200 + "!", "%" * 5000 + "x"]:
        t0 = time.perf_counter()
        assert like_match(pattern, value) is False
        assert time.perf_counter() - t0 < 0.05


def test_show_variables_like_many_percent_is_fast():
    db = fake("mysql")
    stmt = "SHOW VARIABLES LIKE '" + "%" * 50 + "!'"
    answers, elapsed = run_bounded(lambda: db.run(stmt), 0.05)
    assert elapsed < 0.05
    assert isinstance(answers[0], Result) and answers[0].rows == []
    # ordinary patterns still work
    answers = _run(db.run("SHOW VARIABLES LIKE '%version%'"))
    names = [r[0] for r in answers[0].rows]
    assert "version" in names and "version_comment" in names
    answers = _run(db.run("SHOW VARIABLES LIKE 'max\\_connections'"))
    assert [r[0] for r in answers[0].rows] == ["max_connections"]


@pytest.mark.parametrize("dialect", ["mysql", "postgres", "mssql"])
def test_where_like_many_percent_is_fast(dialect):
    db = fake(dialect)
    stmt = "SELECT * FROM users WHERE email LIKE '" + "%" * 50 + "!'"
    answers, elapsed = run_bounded(lambda: db.run(stmt), 0.05)
    assert elapsed < 0.05
    assert isinstance(answers[0], Result) and answers[0].rows == []
    answers = _run(db.run("SELECT username FROM users WHERE email LIKE '%@example.com'"))
    assert len(answers[0].rows) == 3
    answers = _run(db.run("SELECT username FROM users WHERE username NOT LIKE 'a%'"))
    assert [r[0] for r in answers[0].rows] == ["jsmith", "svc_backup"]


# ---- comment stripping --------------------------------------------------------------------

@pytest.mark.parametrize("sql,expected", [
    ("SELECT 1 -- trailing", "SELECT 1  "),
    ("SELECT /* x */ 1", "SELECT   1"),
    ("SELECT /* a\nb */ 1", "SELECT   1"),
    ("/*!40101 SET NAMES utf8 */", "SET NAMES utf8 "),
    ("/*!SET x=1*/", "SET x=1"),
    ("/*! 50503 SET y=2 */;", "50503 SET y=2 ;"),
    ("# comment\nSELECT 1", " \nSELECT 1"),
    ("SELECT '--not a comment', 'a/*b*/c'", "SELECT '--not a comment', 'a/*b*/c'"),
    ("SELECT \"x -- y\" -- z", "SELECT \"x -- y\"  "),
    ("SELECT 'it''s' -- c", "SELECT 'it''s'  "),
    ("SELECT 1 /* unterminated", "SELECT 1 /* unterminated"),
    ("SELECT 'unterminated -- x", "SELECT 'unterminated -- x"),
])
def test_strip_comments(sql, expected):
    assert strip_comments(sql) == expected


def test_hash_comment_only_mysql():
    assert strip_comments("SELECT 1 # c", dialect="mysql") == "SELECT 1  "
    assert strip_comments("SELECT 1 # c", dialect="postgres") == "SELECT 1 # c"


@pytest.mark.parametrize("payload", [
    "/*!" * 22000,
    "/*" * 32000,
    "/*!" + "1" * 60000,
    "'" * 65000,
    "-" * 65000,
    "SELECT " + "/* */" * 13000,
], ids=short_id)
def test_strip_comments_is_linear(payload):
    t0 = time.perf_counter()
    strip_comments(payload)
    assert time.perf_counter() - t0 < 0.2


@pytest.mark.parametrize("payload", [
    "/*!" * 22000,
    "SELECT " + "(" * 30000,
    "SELECT a AS " + " " * 60000 + "x",
    "SELECT * FROM users WHERE " + "a = 1 and " * 6000,
    "SELECT * FROM users WHERE email = " + "'" * 60000,
    "SELECT " + "x::" * 20000,
    "SELECT " + "@@" * 30000,
    "SELECT " + "f(" * 20000 + ")" * 20000,
    "SELECT * FROM users ORDER BY " + "x." * 30000,
    "SELECT * FROM " + "a ." * 20000,
    "SELECT " + "a," * 30000 + " FROM users",
    "SELECT " + "1 as " * 12000,
    "SELECT " + "x as [" * 10000,
    "SELECT " + 'x as "' * 10000,
    "SELECT f() " + '"x) ' * 15000,
    "SELECT " + "f() [" * 12000,
    "SELECT * FROM users WHERE " + "email like '" * 6000,
    "SHOW VARIABLES LIKE '" + "%_" * 30000 + "'",
    "SET " + "a" * 60000,
    "SELECT * FROM users WHERE " + "(a" * 20000,
])
@pytest.mark.parametrize("dialect", ["mysql", "postgres", "mssql"])
def test_pathological_statements_are_fast(dialect, payload):
    db = fake(dialect)
    answers, elapsed = run_bounded(lambda: db.run(payload), 1.0)
    assert elapsed < 1.0, f"{elapsed:.2f}s"
    assert answers and isinstance(answers[-1], (Result, SqlError))


# ---- integer range checks -----------------------------------------------------------------

@pytest.mark.parametrize("dialect,stmt,code", [
    ("postgres", "SELECT * FROM users LIMIT 99999999999999999999", "22003"),
    ("postgres", "SELECT * FROM users OFFSET 99999999999999999999", "22003"),
    ("postgres", "SELECT * FROM users LIMIT " + "9" * 5000, "22003"),
    ("mysql", "SELECT * FROM users LIMIT 99999999999999999999", "42000"),
    ("mysql", "SELECT * FROM users LIMIT 1, " + "9" * 5000, "42000"),
    ("mssql", "SELECT TOP 99999999999999999999 * FROM users", "1060"),
    ("mssql", "SELECT TOP " + "9" * 5000 + " * FROM users", "1060"),
], ids=short_id)
def test_out_of_range_integers_give_server_errors(dialect, stmt, code):
    answers = _run(fake(dialect).run(stmt))
    assert isinstance(answers[-1], SqlError) and answers[-1].code == code


@pytest.mark.parametrize("dialect,stmt", [
    ("postgres", "SELECT * FROM users LIMIT 9223372036854775807"),
    ("mysql", "SELECT * FROM users LIMIT 18446744073709551615"),
    ("mssql", "SELECT TOP 9223372036854775807 * FROM users"),
])
def test_largest_valid_limits_return_rows(dialect, stmt):
    answers = _run(fake(dialect).run(stmt))
    assert isinstance(answers[-1], Result) and len(answers[-1].rows) == 3


def test_a_created_database_can_be_selected_and_written_to():
    # The statements a database ransom script sends, in its order.
    f = fake("mysql", database="")
    script = ["SET AUTOCOMMIT=0", "CREATE DATABASE IF NOT EXISTS RECOVER_YOUR_DATA", "COMMIT",
              "USE RECOVER_YOUR_DATA",
              "CREATE TABLE RECOVER_YOUR_DATA (text VARCHAR(2048))",
              "INSERT INTO RECOVER_YOUR_DATA (text) VALUES ('note')", "COMMIT"]
    for stmt in script:
        assert not isinstance(_run(f.run(stmt))[-1], SqlError), stmt
    assert f.database == "RECOVER_YOUR_DATA"
    listed = [r[0] for r in _run(f.run("SHOW DATABASES"))[-1].rows]
    assert "RECOVER_YOUR_DATA" in listed
    again = _run(f.run("CREATE DATABASE RECOVER_YOUR_DATA"))[-1]
    assert isinstance(again, SqlError) and again.errno == 1007
    assert not isinstance(_run(f.run("DROP DATABASE RECOVER_YOUR_DATA"))[-1], SqlError)
    gone = _run(f.run("USE RECOVER_YOUR_DATA"))[-1]
    assert isinstance(gone, SqlError) and gone.errno == 1049
    # A database from another connection is not there.
    other = _run(fake("mysql", database="").run("USE RECOVER_YOUR_DATA"))[-1]
    assert isinstance(other, SqlError)


def test_created_databases_are_bounded_and_scenario_ones_cannot_be_dropped():
    f = fake("mysql")
    for i in range(sqlfake.MAX_SESSION_DBS + 30):
        _run(f.run(f"CREATE DATABASE d{i}"))
    assert len(f.session_dbs) == sqlfake.MAX_SESSION_DBS
    before = set(f.catalog) - f.session_dbs
    for name in list(before):
        _run(f.run(f"DROP DATABASE {name}"))
    assert before <= set(f.catalog)
    assert not isinstance(_run(fake("mssql").run("CREATE DATABASE x; USE x"))[-1], SqlError)


def test_string_concatenation_and_login_functions_match_real_servers():
    # The query common MSSQL clients (impacket) send to build their prompt.
    rows = _run(fake("mssql").run('select system_user + SPACE(2) + current_user as "username"'))[-1]
    assert rows.columns == ["username"] and rows.rows[0][0].endswith("  dbo")
    assert _run(fake("mssql").run("select 1 + 2"))[-1].rows == [[3]]
    assert _run(fake("mssql").run("select 'a' + NULL"))[-1].rows == [[None]]
    assert _run(fake("mssql").run("select SPACE(9000)"))[-1].rows == [[None]]   # over the limit
    pg = _run(fake("postgres").run("select current_user || '@' || current_database()"))[-1]
    assert pg.rows[0][0].count("@") == 1


def _scenario_fake(scenario: str, dialect: str, version: str):
    from scenarios.loader import load_scenario

    ctx = ListenerContext(EventWriter(None), scenario=load_scenario(scenario, "a" * 64))
    return FakeSql(StubConn(ctx), dialect, "root", "appdb", version=version)


@pytest.mark.parametrize("scenario,family,absent", [
    ("saas", "Ubuntu", ("Debian", "Red Hat")),           # Ubuntu 24.04
    ("sip_provider", "Debian", ("Ubuntu", "Red Hat")),   # Debian 12
    ("healthcare", "Red Hat", ("Ubuntu", "Debian")),     # Rocky Linux 9
    ("bank", "Red Hat", ("Ubuntu", "Debian")),           # RHEL 9
])
def test_database_version_strings_match_the_scenario_host_os(scenario, family, absent):
    pg = _scenario_fake(scenario, "postgres", "15.7")
    text = pg.full_version() + " " + " ".join(str(v) for v in pg.pg_params().values())
    assert family in pg.full_version()
    assert not any(other in text for other in absent)
    my = _scenario_fake(scenario, "mysql", "8.0.39")
    vars_text = " ".join(str(v) for v in my.mysql_vars().values())
    assert not any(other in vars_text for other in absent)
    ms = _scenario_fake(scenario, "mssql", "15.0.4322.2")
    assert not any(other in ms.full_version() for other in absent)


def test_mariadb_on_debian_reports_the_debian_comment():
    my = _scenario_fake("sip_provider", "mysql", "10.11.6-MariaDB-0+deb12u1")
    assert my.mysql_vars()["version_comment"] == "Debian 12"
