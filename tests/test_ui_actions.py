"""Operator console decisions: approve, reject and unblock go through the same respond calls
as the CLI, with the stale-view check, connector refusal, fixed error text, the shell's
read-only refusal and one execution under concurrent approvals."""

import datetime
import http.client
import json
import secrets
import socket
import threading
import urllib.parse
from configparser import ConfigParser
from pathlib import Path

import pytest

from ui_fixture import IMG, SCRIPT, build_tree

import agents.__main__ as cli
from agents import runtime, triage
from agents.connectors.base import ConnectorResult
from agents.playbooks import Playbook
from agents.respond import approve as respond_approve
from agents.respond import queue_enforce_action, reject as respond_reject
from agents.ui import api as api_mod
from agents.ui.api import Api
from agents.ui.server import UiSettings, build_server

pytestmark = pytest.mark.usefixtures("public_test_net")

OPERATOR = "night shift"
NO_CONNECTOR = "connector not available here; approve with the CLI in the agents container"
HOSTILE = (SCRIPT, IMG, "a-0000000000001", "../../etc/passwd", "198.51.100.7<x>")


class FakeConnectors:
    """Records every send; ``enabled`` names the connectors this process has."""

    def __init__(self, enabled=("ticket", "block_webhook"), delay: float = 0.0):
        self._enabled = set(enabled)
        self.delay = delay
        self.calls: list[tuple] = []
        self.lock = threading.Lock()

    def enabled(self, name):
        return name in self._enabled

    def open_ticket(self, payload):
        with self.lock:
            self.calls.append(("ticket", payload))
        return ConnectorResult(True, "sent")

    def block(self, ip, reason):
        if self.delay:
            threading.Event().wait(self.delay)
        with self.lock:
            self.calls.append(("block", ip, reason))
        return ConnectorResult(True, "sent")


@pytest.fixture
def tree(tmp_path):
    return build_tree(tmp_path / "tree")


def make_api(tree, conns=None, **kw):
    kw.setdefault("operator", OPERATOR)
    return Api(tree.api_paths(), cache_seconds=0,
               connectors=(lambda: conns) if conns is not None else None, **kw)


def snapshot(root: Path) -> dict:
    return {str(p.relative_to(root)): p.read_bytes() for p in sorted(root.rglob("*"))
            if p.is_file()}


def queue_items(api) -> dict:
    status, body = api.get("/api/queue", {"all": "1", "per": "200"})
    assert status == 200
    return {i["approval"]["id"]: i for i in body["items"]}


def on_disk(tree, aid) -> dict:
    return json.loads((tree.state / "approvals" / f"{aid}.json").read_text())


def audit(tree, aid) -> list[dict]:
    return [json.loads(p.read_text()) for p in (tree.reports / "response").glob(f"*-{aid}.json")]


def queue_extra(tree, action: str, params=None) -> str:
    """Queue one more enforce action for the fixture's redis source."""
    record = next(r for r in triage.load_records(tree.reports) if r.id == tree.ids["redis"])
    pb = Playbook.model_validate({"name": "extra_pb", "when": {"signals": ["redis_takeover"]},
                                  "steps": [{"action": action}]})
    _, aid = queue_enforce_action(tree.state, pb, record, pb.steps[0], tree.now, 72,
                                  params or {}, summary=f"{action} {SCRIPT}")
    assert aid
    return aid


def decide(api, aid, verb, hash_=None):
    if hash_ is None:
        hash_ = queue_items(api)[aid]["view_hash"]
    return api.post(f"/api/queue/{aid}/{verb}", {"view_hash": hash_})


# ---- approve -------------------------------------------------------------------------------

def test_approve_export_blocklist_writes_blocklist_state_and_audit(tree):
    api = make_api(tree)
    aid = tree.ids["pending"]
    assert queue_items(api)[aid]["can_approve_here"] is True
    status, body = decide(api, aid, "approve")
    assert status == 200, body
    a = body["approval"]
    assert a["status"] == "done" and a["approved_by"] == "ui:" + OPERATOR
    assert "198.51.100.21" in (tree.reports / "blocklist" / "approved.txt").read_text().split()
    assert "198.51.100.21" in json.loads((tree.state / "approved_blocklist.json").read_text())
    assert on_disk(tree, aid)["status"] == "done"
    [record] = audit(tree, aid)
    assert record["approval"]["approved_by"].startswith("ui:")
    # The queue route sees the decision at once (its cache was invalidated).
    item = queue_items(api)[aid]
    assert item["approval"]["status"] == "done" and item["view_hash"] is None
    assert item["can_approve_here"] is False


def test_operator_falls_back_to_the_os_user_and_is_sanitised(tree, monkeypatch):
    monkeypatch.setattr(api_mod.getpass, "getuser", lambda: "svc\x1b[31m<b>")
    api = make_api(tree, operator="")
    status, body = decide(api, tree.ids["pending"], "approve")
    assert status == 200 and body["approval"]["approved_by"] == "ui:svc31mb"


@pytest.mark.parametrize("action,call", [("open_ticket", "ticket"), ("block_webhook", "block")])
def test_approve_fires_the_connector_once(tree, action, call):
    aid = queue_extra(tree, action, {"priority": "high"} if action == "open_ticket" else {})
    conns = FakeConnectors()
    api = make_api(tree, conns)
    assert queue_items(api)[aid]["can_approve_here"] is True
    status, body = decide(api, aid, "approve")
    assert status == 200 and body["approval"]["status"] == "done"
    assert [c[0] for c in conns.calls] == [call]
    assert conns.calls[0][1] == "198.51.100.21" or conns.calls[0][1]["source"] == "198.51.100.21"
    assert len(audit(tree, aid)) == 1


@pytest.mark.parametrize("action", ["open_ticket", "block_webhook"])
@pytest.mark.parametrize("conns", [None, FakeConnectors(enabled=())], ids=["none", "disabled"])
def test_connector_action_without_its_connector_is_refused_and_stays_pending(tree, action,
                                                                             conns):
    aid = queue_extra(tree, action)
    api = make_api(tree, conns)
    item = queue_items(api)[aid]
    assert item["can_approve_here"] is False
    before = snapshot(tree.root)
    assert decide(api, aid, "approve", item["view_hash"]) == (400, {"error": NO_CONNECTOR})
    assert snapshot(tree.root) == before
    assert on_disk(tree, aid)["status"] == "pending"
    # Reject is always allowed.
    status, body = decide(api, aid, "reject", item["view_hash"])
    assert status == 200 and body["approval"]["status"] == "rejected"


def test_expired_item_is_refused(tree):
    api = make_api(tree)
    aid = tree.ids["overdue"]
    item = queue_items(api)[aid]
    assert item["approval"]["status"] == "expired" and item["view_hash"] is None
    # An operator who loaded the page before it expired holds the hash of the file as is.
    status, body = decide(api, aid, "approve", api.view_of(aid).digest)
    assert status == 400 and body["error"].startswith(f"{aid} expired at ")
    assert on_disk(tree, aid)["status"] == "expired"
    assert not (tree.detections / "approved" / "0a1b2c3d-ssh-download-execute.yml").exists()


def test_never_act_on_gives_the_same_refusal_as_the_cli(tmp_path):
    cfg = tmp_path / "config.ini"
    cfg.write_text("[respond]\nnever_act_on = 198.51.100.0/28, 198.51.100.16/28\n")
    cp = ConfigParser()
    cp.read(cfg)
    ui_tree, cli_tree = build_tree(tmp_path / "ui"), build_tree(tmp_path / "cli")
    api = make_api(ui_tree, respond_settings=lambda: runtime.respond_settings(cp))
    status, body = decide(api, ui_tree.ids["pending"], "approve")
    assert status == 200
    ui_result = body["approval"]["result"]
    out = cli.run(["approve", cli_tree.ids["pending"], "--config", str(cfg),
                   "--reports-dir", str(cli_tree.reports),
                   "--detections-dir", str(cli_tree.detections)])
    cli_result = out["approval"]["result"]
    assert ui_result == cli_result and ui_result["ok"] is False
    assert ui_result["status"].startswith("refused: ")
    assert not (ui_tree.reports / "blocklist" / "approved.txt").read_text().count("198.51.100.21")


# ---- reject and unblock --------------------------------------------------------------------

def test_reject_writes_audit_and_suppresses_requeue(tree):
    api = make_api(tree)
    aid = tree.ids["pending"]
    status, body = decide(api, aid, "reject")
    assert status == 200
    a = body["approval"]
    assert a["status"] == "rejected" and a["rejected_by"] == "ui:" + OPERATOR
    [record] = audit(tree, aid)
    assert record["approval"]["rejected_by"] == "ui:" + OPERATOR
    record_ = next(r for r in triage.load_records(tree.reports) if r.id == tree.ids["redis"])
    pb = Playbook.model_validate({"name": "fixture_pb", "when": {"signals": ["redis_takeover"]},
                                  "steps": [{"action": "export_blocklist"}]})
    status, again = queue_enforce_action(tree.state, pb, record_, pb.steps[0], tree.now, 72, {})
    assert status == "suppressed: rejected" and again is None


def test_unblock_removes_the_entry_and_writes_an_audit_record(tree):
    api = make_api(tree)
    assert {e["target"] for e in api.get("/api/blocklist", {})[1]["items"]} == \
        {"198.51.100.7", "198.51.100.8"}
    status, body = api.post("/api/blocklist/unblock", {"target": " 198.51.100.7 "})
    assert status == 200 and body["removed"] == ["198.51.100.7"] and body["entries"] == 1
    assert (tree.reports / "blocklist" / "approved.txt").read_text().split() == ["198.51.100.8"]
    [path] = (tree.reports / "response").glob("*-unblock-*.json")
    record = json.loads(path.read_text())["unblock"]
    assert record == {"target": "198.51.100.7", "removed": ["198.51.100.7"],
                      "by": "ui:" + OPERATOR}
    # A /32 spelling of the remaining entry is the same key.
    status, body = api.post("/api/blocklist/unblock", {"target": "198.51.100.8/32"})
    assert status == 200 and body["removed"] == ["198.51.100.8"] and body["entries"] == 0


UNBLOCK_REFUSED = (400, {"error": "target must be one blocklist entry exactly as listed; "
                                  "unblock a range with the CLI (python -m agents unblock)"})


@pytest.mark.parametrize("target", [None, 7, ["198.51.100.7"], "", "198.51.100.300",
                                    "fe80::1%eth0", "host.example", "1" * 65, SCRIPT])
def test_unblock_refuses_a_bad_target_with_fixed_text(tree, target):
    api = make_api(tree)
    before = snapshot(tree.root)
    body = {} if target is None else {"target": target}
    assert api.post("/api/blocklist/unblock", body) == UNBLOCK_REFUSED
    assert snapshot(tree.root) == before


@pytest.mark.parametrize("target", ["0.0.0.0/0", "::/0", "198.51.100.0/24", "198.51.100.0/25",
                                    "198.51.100.7/24", "198.51.100.9", "2001:db8::/64",
                                    "::ffff:198.51.100.7"])
def test_unblock_takes_only_an_exact_entry(tree, target):
    api = make_api(tree)
    before = snapshot(tree.root)
    assert api.post("/api/blocklist/unblock", {"target": target}) == UNBLOCK_REFUSED
    assert snapshot(tree.root) == before
    assert {e["target"] for e in api.get("/api/blocklist", {})[1]["items"]} == \
        {"198.51.100.7", "198.51.100.8"}


def test_unblock_exact_ipv6_key(tree):
    from agents.respond import _blocklist_store

    store = _blocklist_store(tree.state)
    entries = json.loads(store.read_text())
    entries["2001:db8:1:2::/64"] = dict(entries["198.51.100.7"])
    store.write_text(json.dumps(entries))
    api = make_api(tree)
    for wrong in ("2001:db8:1:2::1", "2001:db8:1::/48", "2001:db8:1:2::/96"):
        assert api.post("/api/blocklist/unblock", {"target": wrong}) == UNBLOCK_REFUSED
    status, body = api.post("/api/blocklist/unblock", {"target": "2001:DB8:1:2:0::/64"})
    assert status == 200 and body["removed"] == ["2001:db8:1:2::/64"] and body["entries"] == 2


# ---- refusals that change nothing ----------------------------------------------------------

def test_stale_view_is_409_and_changes_nothing(tree):
    api = make_api(tree)
    aid = tree.ids["pending"]
    seen = queue_items(api)[aid]["view_hash"]
    before = snapshot(tree.root)
    assert decide(api, aid, "approve", "0" * 64) == (409, {"error": "changed"})
    assert decide(api, aid, "reject", "f" * 64) == (409, {"error": "changed"})
    assert snapshot(tree.root) == before
    # Someone else rejects it with the CLI; the console's view is now stale.
    respond_reject(aid, tree.state, by="cli", reports_dir=tree.reports)
    before = snapshot(tree.root)
    for verb in ("approve", "reject"):
        assert decide(api, aid, verb, seen) == (409, {"error": "changed"})
    assert snapshot(tree.root) == before


@pytest.mark.parametrize("aid", ["a-XYZ", "a-0123456789abc", "a-0123456789a", "..", "%2e%2e",
                                 "a-0123456789ab.json", "A-0123456789AB", "a-000000000000"])
def test_malformed_and_unknown_ids_are_404(tree, aid):
    api = make_api(tree)
    before = snapshot(tree.root)
    for verb in ("approve", "reject"):
        assert api.post(f"/api/queue/{aid}/{verb}", {"view_hash": "0" * 64}) == \
            (404, {"error": "not found"})
    assert snapshot(tree.root) == before


def test_unknown_routes_and_bad_bodies(tree):
    api = make_api(tree)
    aid = tree.ids["pending"]
    before = snapshot(tree.root)
    assert api.post(f"/api/queue/{aid}/execute", {})[0] == 404
    assert api.post(f"/api/queue/{aid}", {})[0] == 404
    assert api.post("/api/blocklist/block", {"target": "198.51.100.9"})[0] == 404
    for body in ({}, {"view_hash": None}, {"view_hash": 5}, {"view_hash": "ABC"},
                 {"view_hash": "0" * 63}, {"view_hash": "0" * 64 + "\n"}):
        status, out = api.post(f"/api/queue/{aid}/approve", body)
        assert status == 400 and "view_hash" in out["error"]
    assert snapshot(tree.root) == before


def test_invalid_respond_settings_refuse_every_decision(tree):
    def broken():
        raise ValueError("never_act_on: not an address or network: 'x'")

    api = make_api(tree, respond_settings=broken)
    aid = tree.ids["pending"]
    before = snapshot(tree.root)
    for status, body in (decide(api, aid, "approve"), decide(api, aid, "reject"),
                         api.post("/api/blocklist/unblock", {"target": "198.51.100.7"})):
        assert status == 500 and body["error"].startswith("[respond] settings are invalid")
    assert snapshot(tree.root) == before


def test_request_input_never_appears_in_an_error_body(tree):
    api = make_api(tree)
    aid = tree.ids["pending"]
    bodies = []
    for value in HOSTILE:
        bodies.append(api.post(f"/api/queue/{value}/approve", {"view_hash": value}))
        bodies.append(api.post(f"/api/queue/{aid}/approve", {"view_hash": value}))
        bodies.append(api.post(f"/api/queue/{aid}/reject", {"view_hash": value, value: value}))
        bodies.append(api.post("/api/blocklist/unblock", {"target": value}))
    for status, body in bodies:
        assert status in (400, 404)
        text = json.dumps(body)
        for value in HOSTILE:
            assert value not in text and json.dumps(value)[1:-1] not in text
    # An ApprovalError carries only the validated id and what respond read from disk.
    respond_reject(aid, tree.state, by="cli")
    status, body = decide(api, aid, "approve", api.view_of(aid).digest)
    assert (status, body) == (400, {"error": f"{aid} is rejected, not pending"})


# ---- concurrency ---------------------------------------------------------------------------

def test_double_approve_executes_once(tree, monkeypatch):
    aid = queue_extra(tree, "block_webhook")
    conns = FakeConnectors(delay=0.2)
    api = make_api(tree, conns)
    hash_ = queue_items(api)[aid]["view_hash"]
    # Both requests pass the view check before either reaches respond's lock.
    barrier = threading.Barrier(2, timeout=10)

    def approve_after_barrier(*args, **kwargs):
        barrier.wait()
        return respond_approve(*args, **kwargs)

    monkeypatch.setattr(api_mod, "approve", approve_after_barrier)
    results = []

    def worker():
        results.append(decide(api, aid, "approve", hash_))

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=20)
    statuses = sorted(s for s, _ in results)
    assert statuses == [200, 400], results
    refused = next(b for s, b in results if s == 400)
    assert refused["error"] in (f"{aid} is executing, not pending", f"{aid} is done, not pending")
    assert len(conns.calls) == 1 and len(audit(tree, aid)) == 1


# ---- connectors are built without sending anything -----------------------------------------

def test_real_connectors_are_built_without_network(tree, monkeypatch):
    def no_network(*a, **k):
        raise AssertionError("network used")

    monkeypatch.setattr(socket, "getaddrinfo", no_network)
    monkeypatch.setattr(socket, "create_connection", no_network)
    cp = ConfigParser()
    cp.read_string("[connector.ticket]\nenabled = true\nurl = https://tickets.example.com/api\n"
                   "[connector.block_webhook]\nenabled = true\n"
                   "url = https://block.example.com/api\n")
    built = []

    def factory():
        built.append(1)
        return runtime.respond_connectors(cp, tree.state)

    ticket = queue_extra(tree, "open_ticket")
    api = Api(tree.api_paths(), cache_seconds=0, operator=OPERATOR, connectors=factory)
    before = set(snapshot(tree.root))
    assert queue_items(api)[ticket]["can_approve_here"] is True
    assert set(snapshot(tree.root)) == before            # building wrote no counter file
    status, body = decide(api, tree.ids["pending"], "approve")
    assert status == 200 and body["approval"]["status"] == "done"
    assert built == [1]


# ---- the ui subcommand ---------------------------------------------------------------------

def _ui_args(tmp_path, tree, section=""):
    cfg = tmp_path / "config.ini"
    cfg.write_text("[ui]\noperator = alice\n" + section)
    return ["ui", "--config", str(cfg), "--reports-dir", str(tree.reports),
            "--detections-dir", str(tree.detections), "--data-dir", str(tree.data),
            "--overlay", str(tree.overlay)]


def test_ui_subcommand_wires_decisions_like_the_cli(tmp_path, tree, monkeypatch):
    from agents.ui import server

    seen = {}
    monkeypatch.setattr(server, "serve", lambda s, routes: seen.update(settings=s, routes=routes))
    monkeypatch.delenv("WINNIE_UI_TOKEN", raising=False)
    cli.run(_ui_args(tmp_path, tree, "[respond]\nblocklist_format = csv\n"))
    api = seen["routes"]
    assert api.operator == "alice" and api.respond_settings().blocklist_format == "csv"
    status, body = decide(api, tree.ids["pending"], "approve")
    assert status == 200 and body["approval"]["approved_by"] == "ui:alice"
    assert (tree.reports / "blocklist" / "approved.txt").read_text().startswith("ip,approved_at")
    cli.run(_ui_args(tmp_path, tree, "[respond]\nnever_act_on = nonsense\n"))
    status, _ = seen["routes"].post("/api/blocklist/unblock", {"target": "198.51.100.7"})
    assert status == 500


def test_empty_ui_token_is_treated_as_unset(tmp_path, tree, monkeypatch):
    from agents.ui import server

    seen = {}
    monkeypatch.setattr(server, "serve", lambda s, routes: seen.update(settings=s))
    monkeypatch.setenv("WINNIE_UI_TOKEN", "")
    assert cli.run(_ui_args(tmp_path, tree)) == {"ui": {"status": "stopped"}}
    assert seen["settings"].token == ""
    srv = build_server(UiSettings(port=0, token=""), make_api(tree))
    try:
        assert len(srv.token) >= server.MIN_TOKEN_LENGTH
    finally:
        srv.server_close()


# ---- end to end through the server ---------------------------------------------------------

class Client:
    def __init__(self, srv):
        self.srv = srv
        self.port = srv.server_address[1]
        self.host = f"127.0.0.1:{self.port}"
        self.cookie = ""

    def request(self, method, target, headers=None, body=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            hdrs = {"Host": self.host, **(headers or {})}
            if self.cookie:
                hdrs["Cookie"] = self.cookie
            conn.request(method, target, body=body, headers=hdrs)
            resp = conn.getresponse()
            return resp.status, resp.getheader("Set-Cookie"), resp.read()
        finally:
            conn.close()

    def sign_in(self):
        status, set_cookie, _ = self.request(
            "GET", "/?token=" + urllib.parse.quote(self.srv.token, safe=""))
        assert status == 303
        self.cookie = set_cookie.split(";")[0]

    def get(self, target):
        status, _, raw = self.request("GET", target)
        return status, json.loads(raw)

    def post(self, target, payload):
        csrf = self.get("/api/session")[1]["csrf"]
        status, _, raw = self.request("POST", target, body=json.dumps(payload).encode(), headers={
            "Origin": f"http://{self.host}", "X-Winnie-CSRF": csrf,
            "Content-Type": "application/json"})
        return status, json.loads(raw)


@pytest.fixture
def serve_api():
    servers = []

    def _start(api, actions):
        srv = build_server(UiSettings(port=0, token=secrets.token_urlsafe(32), actions=actions,
                                      operator=OPERATOR), api)
        threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.05},
                         daemon=True).start()
        servers.append(srv)
        client = Client(srv)
        client.sign_in()
        return client

    yield _start
    for srv in servers:
        srv.shutdown()
        srv.server_close()


def test_end_to_end_approve_reject_unblock(tree, serve_api):
    ticket = queue_extra(tree, "open_ticket")
    conns = FakeConnectors()
    c = serve_api(make_api(tree, conns), actions=True)
    status, queue = c.get("/api/queue")
    items = {i["approval"]["id"]: i for i in queue["items"]}
    status, body = c.post(f"/api/queue/{tree.ids['pending']}/approve",
                          {"view_hash": items[tree.ids["pending"]]["view_hash"]})
    assert status == 200 and body["approval"]["approved_by"] == "ui:" + OPERATOR
    status, body = c.post(f"/api/queue/{ticket}/reject",
                          {"view_hash": items[ticket]["view_hash"]})
    assert status == 200 and body["approval"]["status"] == "rejected" and conns.calls == []
    status, body = c.post(f"/api/queue/{tree.ids['pending']}/approve",
                          {"view_hash": items[tree.ids["pending"]]["view_hash"]})
    assert (status, body) == (409, {"error": "changed"})
    status, body = c.post("/api/blocklist/unblock", {"target": "198.51.100.8"})
    assert status == 200 and body["removed"] == ["198.51.100.8"]
    status, body = c.post("/api/queue/a-zz/approve", {"view_hash": SCRIPT})
    assert (status, body) == (404, {"error": "not found"})


def test_every_post_is_refused_by_a_read_only_server(tree, serve_api):
    api = make_api(tree, FakeConnectors())
    c = serve_api(api, actions=False)
    hash_ = queue_items(api)[tree.ids["pending"]]["view_hash"]
    before = snapshot(tree.root)
    for target, payload in ((f"/api/queue/{tree.ids['pending']}/approve", {"view_hash": hash_}),
                            (f"/api/queue/{tree.ids['pending']}/reject", {"view_hash": hash_}),
                            ("/api/blocklist/unblock", {"target": "198.51.100.7"})):
        assert c.post(target, payload) == (403, {"error": "read-only"})
    assert snapshot(tree.root) == before
    assert datetime.datetime.now(datetime.timezone.utc) < \
        datetime.datetime.fromisoformat(on_disk(tree, tree.ids["pending"])["expires_at"])
