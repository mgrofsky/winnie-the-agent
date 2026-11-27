# Contributing

Issues and pull requests are welcome. For security problems, follow
[SECURITY.md](SECURITY.md) instead of opening a public issue.

## Setup and tests

```bash
uv sync
uv run pytest                        # skips the slow timing and scale tests
uv run pytest -m "(slow or not slow) and not browser"  # everything but the browser tests, as CI runs it
```

`pyproject.toml` and `uv.lock` are the source of truth for dependencies; there is no
`requirements.txt`. CI runs `uv sync --frozen` and the full suite on Python 3.11, 3.12 and
3.13 for pushes and pull requests to `main` and `dev`.

## Security checks

The `Security` workflow runs three jobs on every pull request and every push to `main`.
Each runs locally as well:

- **Browser tests.** Playwright drives the operator console in Chromium on loopback with the
  synthetic tree from `tests/ui_fixture.py`: sign-in, every section, Activity, one approval
  end to end, and attacker strings rendered as text with nothing executed (checked with the
  page's CSP bypassed, so the console's own escaping is what is tested). They carry the
  `browser` marker and are left out of the default run.

  ```bash
  uv sync --group browser
  uv run playwright install chromium
  uv run pytest -m browser tests/browser
  ```

- **DAST.** OWASP ZAP (pinned image) runs a passive baseline and then a full scan with
  active rules against the console on 127.0.0.1, started by `tests/console_lab.py` with
  the synthetic tree and actions on. Both scans are signed in as an operator is (session
  cookie, CSRF header, matching Origin). `tests/dast/zap-rules.tsv` sets every rule to
  FAIL, WARN or IGNORE, with the reason for each IGNORE; a FAIL alert fails the job, and the
  HTML and JSON reports are kept as the `zap-reports` artifact. The scan targets only the
  console: the protocol traps are built to look vulnerable and are never scanned. Needs
  Docker.

  ```bash
  tests/dast/run_zap.sh /path/to/reports
  ```

- **SAST and dependency audit.** Ruff's flake8-bandit rules (`S`) over the product code,
  configured in `pyproject.toml`; a deliberate case carries `# noqa: S<nnn> - <reason>` on
  its line, and a rule that repeats through one file is ignored for that file in
  `pyproject.toml` with its reason. pip-audit checks every package in `uv.lock`, all extras and groups, by hash.
  PYSEC-2026-2447 is ignored: diskcache, pulled in only by the test-only pysigma, unpickles
  what is in its cache directory, so it needs someone who can write there, and no fixed
  release exists.

  ```bash
  uv sync --group security
  uv run ruff check
  uv export --frozen --format requirements-txt --all-extras --all-groups --no-emit-project \
      -o /tmp/requirements.txt
  uv run pip-audit -r /tmp/requirements.txt --require-hashes --disable-pip \
      --ignore-vuln PYSEC-2026-2447
  ```

CodeQL (GitHub default setup), secret scanning and Dependabot run alongside.

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
