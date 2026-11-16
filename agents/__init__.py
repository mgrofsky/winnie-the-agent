"""Agent layer of Winnie the Agent.

Four agents share one threat model: everything an attacker types is hostile text.
Models return JSON only, every output is validated against a strict pydantic schema,
and all file writes are done by this package's Python code after validation.

- persona  (agents.persona + agents.hooks): the decoy host the attacker talks to.
- triage   (agents.triage): per-session TriageRecord and a daily digest.
- tuner    (agents.tuner): changes bait inside a fence, one git commit per run.
- detect   (agents.detect): draft Sigma rules and blocklist candidates only.
"""

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
