"""ZAP scan hooks for the operator console (zap-baseline.py / zap-full-scan.py --hook).

Runs inside the ZAP container. ``zap_started`` signs in the way an operator does (the
sign-in link sets the session cookie, /api/session gives the CSRF value) and adds replacer
rules so every request ZAP sends carries the cookie, the CSRF header and a matching Origin.
It then requests each API route with the synthetic tree's ids from ``lab.json``, and one
approval POST, because the console is a single-page app the spiders cannot see into.
``zap_pre_shutdown`` writes what was reached to ``coverage-<scan>.json`` for the runner to
check. The token comes from ``WINNIE_UI_TOKEN`` and is never written anywhere.

Where Docker has no host networking (Docker Desktop), ``ZAP_RELAY_PORT`` starts a relay
from 127.0.0.1:<port> inside the container to the same port on ``host.docker.internal``, so
ZAP still addresses the console as 127.0.0.1 and the console still sees a loopback Host.
"""

import json
import os
import socket
import threading
import urllib.error
import urllib.parse
import urllib.request

WORK = "/zap/wrk"
SCAN = os.environ.get("ZAP_SCAN", "scan")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def _pipe(src, dst):
    try:
        while True:
            chunk = src.recv(65536)
            if not chunk:
                break
            dst.sendall(chunk)
    except OSError:
        pass
    finally:
        for sock in (src, dst):
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


def _relay(port):
    listener = socket.create_server(("127.0.0.1", port), backlog=128)

    def connect(client):
        try:
            upstream = socket.create_connection(("host.docker.internal", port), timeout=30)
            upstream.settimeout(None)
        except OSError:
            client.close()
            return
        for a, b in ((client, upstream), (upstream, client)):
            threading.Thread(target=_pipe, args=(a, b), daemon=True).start()

    def serve():
        while True:
            client, _ = listener.accept()
            threading.Thread(target=connect, args=(client,), daemon=True).start()

    threading.Thread(target=serve, daemon=True).start()


if os.environ.get("ZAP_RELAY_PORT"):
    _relay(int(os.environ["ZAP_RELAY_PORT"]))


def _sign_in(base):
    token = os.environ["WINNIE_UI_TOKEN"]
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        opener.open(base + "/?token=" + urllib.parse.quote(token, safe=""), timeout=10)
        raise RuntimeError("sign-in did not redirect")
    except urllib.error.HTTPError as exc:
        if exc.code != 303:
            raise RuntimeError("sign-in answered %d" % exc.code)
        cookie = exc.headers["Set-Cookie"].split(";", 1)[0]
    req = urllib.request.Request(base + "/api/session", headers={"Cookie": cookie})
    with urllib.request.urlopen(req, timeout=10) as res:
        csrf = json.load(res)["csrf"]
    return cookie, csrf


def zap_started(zap, target):
    base = target.rstrip("/")
    host = urllib.parse.urlsplit(base).netloc
    if urllib.parse.urlsplit(base).hostname != "127.0.0.1":
        raise RuntimeError("this hook scans only the console on 127.0.0.1")
    cookie, csrf = _sign_in(base)
    for name, value in (("Cookie", cookie), ("X-Winnie-CSRF", csrf), ("Origin", base)):
        zap.replacer.add_rule(description="console " + name, enabled="true",
                              matchtype="REQ_HEADER", matchregex="false", matchstring=name,
                              replacement=value, url="^" + base.replace(".", "\\.") + "/.*")
    with open(os.path.join(WORK, "lab.json"), encoding="utf-8") as f:
        ids = json.load(f)["ids"]
    record, session = ids["redis"], ids["session_b"]
    paths = ["/api/session", "/api/overview", "/api/records?judgement=MALICIOUS&q=redis",
             "/api/records/" + record, "/api/records/" + ids["session_a"] + "/transcript",
             "/api/records/" + ids["session_a"] + "/replies", "/api/activity?src=198.51.100.7",
             "/api/activity/session/" + session, "/api/queue?all=1", "/api/blocklist",
             "/api/digests", "/api/decoy", "/api/playbooks", "/api/detections",
             "/api/honeytokens", "/api/map?window=1h"]
    for path in paths:
        zap.core.access_url(url=base + path, followredirects="false")
    body = json.dumps({"view_hash": _view_hash(zap, base, ids["pending"])})
    request = ("POST %s/api/queue/%s/approve HTTP/1.1\r\nHost: %s\r\n"
               "Content-Type: application/json\r\nContent-Length: %d\r\n\r\n%s"
               % (base, ids["pending"], host, len(body), body))
    zap.core.send_request(request=request, followredirects="false")


def _view_hash(zap, base, approval):
    """The pending item's view hash, read through ZAP so the request is in its history."""
    [message] = zap.core.send_request(
        request="GET %s/api/queue?all=1 HTTP/1.1\r\nHost: %s\r\n\r\n"
        % (base, urllib.parse.urlsplit(base).netloc), followredirects="false")
    items = json.loads(message["responseBody"])["items"]
    return next(i["view_hash"] for i in items if i["approval"]["id"] == approval)


def zap_pre_shutdown(zap):
    hosts, api_ok, post_ok, total = set(), set(), 0, int(zap.core.number_of_messages())
    for start in range(0, total, 500):
        for msg in zap.core.messages(start=str(start + 1), count="500"):
            method, url = msg["requestHeader"].split(" ", 2)[:2]
            parts = urllib.parse.urlsplit(url)
            hosts.add(parts.netloc)
            if " 200 " in msg["responseHeader"].split("\r\n", 1)[0] + " ":
                if parts.path.startswith("/api/"):
                    api_ok.add(parts.path)
                if method == "POST":
                    post_ok += 1
    with open(os.path.join(WORK, "coverage-%s.json" % SCAN), "w", encoding="utf-8") as f:
        json.dump({"messages": total, "hosts": sorted(hosts), "api_200": sorted(api_ok),
                   "post_200": post_ok}, f, indent=2)
