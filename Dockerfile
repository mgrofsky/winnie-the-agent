# Winnie the Agent: one image for the SSH honeypot, the listeners and the agents.
FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_PROJECT_ENVIRONMENT=/opt/venv \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    PATH="/opt/venv/bin:${PATH}" \
    WINNIE_DATA_DIR=/data \
    WINNIE_OVERLAY=/overlay/overlay.json

COPY --from=ghcr.io/astral-sh/uv:0.12.23 /uv /usr/local/bin/uv

WORKDIR /app
COPY pyproject.toml uv.lock .python-version ./
RUN uv sync --frozen --no-dev --no-install-project --no-cache

COPY SSH ./SSH
COPY agents ./agents
COPY listeners ./listeners
COPY scenarios ./scenarios
COPY playbooks ./playbooks

# Volume mount points owned by the runtime user, so fresh named volumes inherit the owner.
RUN useradd --uid 10001 --create-home --shell /usr/sbin/nologin winnie \
    && mkdir -p /data /agents /overlay \
    && chown winnie:winnie /data /agents /overlay \
    && chmod 0750 /data /agents /overlay
USER 10001

EXPOSE 8022
CMD ["python", "SSH/ssh_server.py", "--config", "/app/SSH/config.ini", "--log-file", "/data/ssh_log.log"]
