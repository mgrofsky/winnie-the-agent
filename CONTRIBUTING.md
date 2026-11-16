# Contributing

Issues and pull requests are welcome. For security problems, follow
[SECURITY.md](SECURITY.md) instead of opening a public issue.

## Setup and tests

```bash
uv sync
uv run pytest                        # skips the slow timing and scale tests
uv run pytest -m "slow or not slow"  # everything, as CI runs it
```

`pyproject.toml` and `uv.lock` are the source of truth for dependencies; there is no
`requirements.txt`. CI runs `uv sync --frozen` and the full suite on Python 3.11, 3.12 and
3.13 for pushes and pull requests to `main` and `dev`.

Rules for tests:

- **No network.** Tests may use loopback only. Nothing calls a real model or a real
  connector endpoint. Agents take their model as a `JsonLLM` by injection; use the fakes in
  `tests/agent_fakes.py`. Connectors take an injected `Transport` (and resolver), so their
  tests never open a socket to the outside.
- **No real secrets or personal data.** `tests/test_repo_hygiene.py` fails on
  provider-key formats, high-entropy password assignments, home-directory paths, the
  local user or host name, email addresses outside reserved domains (`example.com`,
  `.example`, `.test`, `.invalid`) and public IPv4 addresses outside the documentation
  ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24). When a test needs a literal that
  looks like a key, assemble it at runtime from fragments.
- Listener changes that parse client input should extend
  `tests/test_listeners_pathological.py`, which checks that long runs of a protocol's
  special characters are handled within a time bound and that the listener keeps serving
  other clients.

## Adding a scenario

See [docs/scenarios.md](docs/scenarios.md#adding-a-scenario). Everything in a scenario must
be invented; `uv run python -m scenarios.check <name>` must pass.

## Adding or changing a playbook

Playbooks are TOML files in `playbooks/`; the file name must equal the `name` field. Check
them with `uv run python -m agents playbooks --validate` and see what they would do with
`uv run python -m agents respond --dry-run`. New condition types or actions are code changes
in `agents/playbooks.py`; an action's tier is part of the code, not the playbook. See
[docs/playbooks.md](docs/playbooks.md).

## Code and comments

- Keep `SSH/ssh_server.py` close to upstream DECEIVE. Put new behaviour in `agents/hooks.py`
  and call it from the server in as few, clearly marked places as possible.
- Treat every value that came from the network or from a model as untrusted: cap its
  length, validate it against a schema or pattern, and never use it to choose code paths,
  file paths or destinations.
- Comments and docstrings describe what the code does and why, in plain present tense.
  They do not narrate how the change came about.
- No emojis in code, comments or documentation.
