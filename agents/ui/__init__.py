"""Operator console: a small loopback web UI next to the agents.

``server`` is the HTTP shell (transport, sign-in, request checks, response headers, static
files). The data API plugs into it as a ``Routes`` object.
"""

from agents.ui.server import Routes, UiServer, UiSettings, build_server, serve

__all__ = ["Routes", "UiServer", "UiSettings", "build_server", "serve"]
