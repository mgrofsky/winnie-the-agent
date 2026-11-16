"""Login traps: SIP, FTP, Telnet, PostgreSQL, MySQL, MSSQL, Redis, SMTP, HTTP, HL7 MLLP.

Each one looks real long enough to capture credentials and what follows, and writes
ListenerEvents (see ``listeners.events``). Authentication and protocol handling never use a
model. After login, only free-form answers can (unknown SQL statements, unknown API routes,
the telnet shell), and only when ``[listeners] llm`` is enabled, through the shared budget,
with a protocol-correct fallback.
"""
