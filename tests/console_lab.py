"""The operator console on loopback with the synthetic fixture tree, for browser tests and DAST.

``start(root)`` builds the tree from ``ui_fixture.build_tree`` under ``root`` and serves the
console on 127.0.0.1 with actions on, in a background thread. The TEST-NET-2 range the
fixture uses counts as public while it runs, so approvals can be decided. Run it as a
process for a scanner::

    WINNIE_UI_TOKEN=<24+ characters> python tests/console_lab.py <dir> --port 8480

It prints one JSON line with the port and the tree's ids once it is serving, then serves
until interrupted. The token comes only from ``WINNIE_UI_TOKEN`` or is generated, and is
never printed.
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
import threading
from contextlib import ExitStack
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TESTS = Path(__file__).resolve().parent
for entry in (ROOT, TESTS):
    if str(entry) not in sys.path:
        sys.path.insert(0, str(entry))

from ui_fixture import Tree, build_tree  # noqa: E402

from agents.addresses import public_for_tests  # noqa: E402
from agents.ui.api import Api  # noqa: E402
from agents.ui.server import UiServer, UiSettings, build_server  # noqa: E402

OPERATOR = "lab operator"
FIXTURE_NET = "198.51.100.0/24"


@dataclass
class Lab:
    server: UiServer
    tree: Tree
    token: str
    _stack: ExitStack

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.server.server_address[1]}"

    @property
    def sign_in_url(self) -> str:
        return f"{self.base_url}/?token={self.token}"

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self._stack.close()


def start(root: Path | str, port: int = 0, token: str = "") -> Lab:
    """Build the fixture tree under ``root`` and serve the console on 127.0.0.1:``port``."""
    stack = ExitStack()
    stack.enter_context(public_for_tests(FIXTURE_NET))
    try:
        tree = build_tree(root)
        token = token or secrets.token_urlsafe(32)
        api = Api(tree.api_paths(), cache_seconds=0, operator=OPERATOR)
        server = build_server(UiSettings(bind="127.0.0.1", port=port, token=token,
                                         actions=True, operator=OPERATOR), api)
    except BaseException:
        stack.close()
        raise
    threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05},
                     daemon=True).start()
    return Lab(server=server, tree=tree, token=token, _stack=stack)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("root", help="empty directory for the synthetic data tree")
    parser.add_argument("--port", type=int, default=8480)
    args = parser.parse_args(argv)
    lab = start(args.root, args.port, os.environ.get("WINNIE_UI_TOKEN", ""))
    print(json.dumps({"url": lab.base_url, "ids": lab.tree.ids}), flush=True)
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        pass
    finally:
        lab.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
