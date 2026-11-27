#!/usr/bin/env bash
# Scan the operator console with OWASP ZAP: a passive baseline, then a full scan (spider and
# active rules). Each scan gets a fresh console on 127.0.0.1 with the synthetic fixture tree
# and actions on; ZAP runs in Docker and is pointed only at that address. Both scans are
# signed in (tests/dast/zap_hook.py) and judged by tests/dast/zap-rules.tsv.
#
#   tests/dast/run_zap.sh [output-dir]
#
# Exits non-zero on any FAIL-level alert, or when a scan did not reach the signed-in API.
set -euo pipefail

ZAP_IMAGE="${ZAP_IMAGE:-ghcr.io/zaproxy/zaproxy@sha256:9624669db72f54d86c4b46a7064518bd9bf79d8c61a4c31befa9923489f328af}"  # 2.17.0
PORT="${ZAP_CONSOLE_PORT:-8480}"
here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
out="${1:-$(mktemp -d)}"
mkdir -p "$out"
out="$(cd "$out" && pwd)"
cp "$here/zap_hook.py" "$here/zap-rules.tsv" "$out/"
chmod -R a+rwX "$out"   # the image runs as uid 1000

# Linux runs ZAP on the host network. Docker Desktop has none, so the hook relays loopback
# inside the container to the host.
if [ "$(uname -s)" = Linux ]; then
    network=(--network host)
else
    network=(-e "ZAP_RELAY_PORT=$PORT")
fi

console=""
tree=""
stop_console() {
    if [ -n "$console" ]; then
        kill "$console" 2>/dev/null || true
        wait "$console" 2>/dev/null || true
    fi
    [ -n "$tree" ] && rm -rf "$tree"
    console=""
    tree=""
}
trap stop_console EXIT

start_console() {  # start_console <name>
    local name=$1
    tree="$(mktemp -d)"
    WINNIE_UI_TOKEN="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
    export WINNIE_UI_TOKEN
    : > "$out/lab.json"
    (cd "$repo" && exec uv run --frozen python tests/console_lab.py "$tree/tree" --port "$PORT") \
        > "$out/lab.json" 2> "$out/console-$name.log" &
    console=$!
    for _ in $(seq 1 60); do
        [ -s "$out/lab.json" ] && return 0
        kill -0 "$console" 2>/dev/null || break
        sleep 1
    done
    cat "$out/console-$name.log" >&2
    echo "console did not start" >&2
    exit 1
}

scan() {  # scan <name> <script> [options...]
    local name=$1 script=$2 rc=0
    shift 2
    start_console "$name"
    docker run --rm "${network[@]}" -v "$out:/zap/wrk:rw" -e WINNIE_UI_TOKEN \
        -e "ZAP_SCAN=$name" -e PYTHONDONTWRITEBYTECODE=1 "$ZAP_IMAGE" \
        "$script" -t "http://127.0.0.1:$PORT/" -c zap-rules.tsv --hook=/zap/wrk/zap_hook.py \
        -r "$name.html" -J "$name.json" -I -s "$@" || rc=$?
    stop_console
    return "$rc"
}

status=0
scan baseline zap-baseline.py -m 1 || status=$?
scan full zap-full-scan.py -m 1 -T 20 || status=$?

python3 - "$out" "$PORT" <<'PY' || status=1
import json, sys
out, port = sys.argv[1], sys.argv[2]
for name in ("baseline", "full"):
    cov = json.load(open(f"{out}/coverage-{name}.json"))
    print(f"{name}: {cov['messages']} messages, {len(cov['api_200'])} API paths answered 200, "
          f"{cov['post_200']} POSTs answered 200, hosts {cov['hosts']}")
    assert cov["hosts"] == [f"127.0.0.1:{port}"], f"{name} reached another host: {cov['hosts']}"
    assert len(cov["api_200"]) >= 12, f"{name} did not reach the signed-in API"
    assert cov["post_200"] >= 1, f"{name} sent no accepted POST"
PY
rm -f "$out/zap_hook.py" "$out/lab.json"
echo "reports in $out"
exit "$status"
