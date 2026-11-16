# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub's security advisories: open the
repository's **Security** tab and choose **Report a vulnerability**. Do not open a public
issue for a security problem.

Useful details: the component (SSH server, a specific listener, triage, response engine, a
connector, the Docker setup), the version or commit, steps or input to reproduce, and what
an attacker gains. A minimal packet capture or client command is ideal for listener bugs.

Especially relevant reports:

- a way for network input to execute code, read or write files outside the quarantine, or
  make a front-end open an outbound connection;
- a way to use the SIP or any other listener as a reflector or amplifier;
- a way for attacker input or model output to change configuration, the overlay, which
  playbook actions run, or what a connector sends, beyond what is documented;
- a way to get a per-source action applied to an address the attacker does not control;
- a bypass of a connector's destination checks;
- a way to stall or crash every listener from one connection;
- a bypass of the model budgets.

Model output that is merely wrong or unconvincing (a poor shell imitation, a bad triage
judgement) is a normal bug, not a vulnerability.

## Supported versions

Only the `main` branch is supported. Fixes are made there; there are no maintained release
branches.

## Threat model in short

This is a honeypot: every byte that reaches it is assumed hostile, including text written to
manipulate the language models it uses.

- Nothing behind the traps is real. Commands, SQL, Redis commands and mail are never
  executed or relayed; uploads are quarantined and never opened.
- Front-ends do not connect out. The only outbound traffic they originate is a model API
  call, when a model is configured.
- Over UDP, SIP responses are never larger than the request by default and are rate-capped.
- Every model call is budgeted in code before it is made.
- Models have no tools, files or network. Analyst output must validate against strict
  schemas; the tuner only chooses among code-generated candidates; playbooks are matched
  and executed by code.
- Actions outside the honeypot need explicit human approval. Spoofable (unverified UDP),
  non-global and operator-excluded addresses never receive per-source actions.
- Outbound connectors are off by default, https only, pinned to validated public
  addresses, without retries or redirects, and capped per day.

Out of scope: attackers with code execution on the sensor host, a compromised model
provider or connector endpoint, and the operator's own configuration choices (for example
`allow_private = true` or `include_narrative = true`).

The full model is in [docs/security-model.md](docs/security-model.md). Operating a honeypot
safely also depends on deployment; see [docs/operations.md](docs/operations.md).
