#!/bin/bash
# Model access on a sensor host with PersonaModelId or AnalystModelId set
# (deploy/aws/sensor.yaml, installed by its ModelStep; the endpoints and the roles are
# deploy/aws/models.yaml's).
#
# The model's callers are the ssh container (PersonaModelId) and the agents container
# (AnalystModelId). Both are bridged, run as uid 10001, cannot open a connection and cannot
# reach the metadata service. Each caller gets exactly two things, and no other container
# gets either:
#   - one DOCKER-USER accept: from its fixed address to the bedrock-runtime endpoint's one
#     address, tcp 443. The endpoint's name is pinned in its /etc/hosts, so it needs no DNS.
#     When the address changes, the old accepts go and the pin is rewritten.
#   - credentials of its own role (ssh: <NamePrefix>-model-persona, agents:
#     <NamePrefix>-model-analyst), assumed here with the instance role through the sts
#     endpoint for one hour, in its own tmpfs directory that only it mounts, read-only.
#     boto3 reads them through credential_process and reads them again before they expire;
#     the timer renews them every 15 minutes. Each role may only call bedrock:InvokeModel
#     on its own caller's model, and only through the stack's bedrock-runtime endpoint.
#
#   sensor-model.sh setup IMAGE
#                           the timer and the boot hook from IMAGE, config.ini's [llm] and
#                           [agents], the compose overlay, then the rest (the bootstrap,
#                           before the stack starts)
#   sensor-model.sh         firewall rules, the overlay if the address changed, and
#                           credentials (sensor-model.timer, and sensor-firewall.sh at boot)
#
# Every value is checked before use. The endpoint's address must be inside the VPC: an
# answer from public DNS (the endpoint's private name not in effect) is refused, and the
# last good address is kept.
set -euo pipefail
. "${SENSOR_MODEL_ENV:-/etc/sensor-model.env}"
D=${SENSOR_MODEL_DIR:-/run/sensor-model}
S=${SENSOR_MODEL_STATE:-/var/lib/sensor-model}
O=${SENSOR_HOME:-/opt/sensor}
F=${SENSOR_FIREWALL:-/usr/local/sbin/sensor-firewall.sh}
U=${SENSOR_UNIT_DIR:-/etc/systemd/system}
id='^(((us|us-gov|eu|apac|jp|au|global)\.)?[a-z0-9-]+\.[a-z0-9-]+(:[a-z0-9]+){0,2})?$'
[[ $REGION =~ ^[a-z0-9-]{1,32}$ && $SUFFIX =~ ^[a-z0-9.]{1,32}$ && $PERSONA_MODEL =~ $id \
   && $ANALYST_MODEL =~ $id && $ROLE_ARN =~ ^arn:aws[a-z-]*:iam::[0-9]{12}:role/[a-z0-9-]{1,40}$ \
   && $VPC_CIDR =~ ^[0-9.]{7,15}/[0-9]{1,2}$ ]] \
  && python3 -c 'import ipaddress as i,sys; n=i.ip_network(sys.argv[1]); sys.exit(not (n.is_private and 8 <= n.prefixlen <= 28))' "$VPC_CIDR" 2>/dev/null \
  || { echo "sensor-model: bad settings in the env file" >&2; exit 1; }
NAME=bedrock-runtime.$REGION.$SUFFIX
# Each caller: its credentials directory and role suffix, and its fixed address.
callers=()
[ -z "$PERSONA_MODEL" ] || callers+=(persona:172.30.0.10)
[ -z "$ANALYST_MODEL" ] || callers+=(analyst:172.30.1.10)
inside() { python3 -c 'import ipaddress as i,sys; sys.exit(i.ip_address(sys.argv[1]) not in i.ip_network(sys.argv[2]))' "$1" "$VPC_CIDR" 2>/dev/null; }

# One run at a time: the timer's first run starts while setup is still running.
mkdir -p "$S"
exec 9>> "$S/lock"
flock -w 600 9 || { echo "sensor-model: another run holds the lock" >&2; exit 1; }

IMAGE=${2:-}
if [ "${1:-}" = setup ]; then
  # First, so a later failure is still retried: the timer (started now; cloud-init runs
  # after timers.target, so without --now it would wait for the next boot), and a line in
  # the boot-time firewall script (which must not fail, hence the echo).
  [[ $IMAGE =~ ^[0-9]{12}\.dkr\.ecr\.[a-z0-9.-]+/[a-z0-9-]+:[A-Za-z0-9._-]+$ ]] \
    || { echo "sensor-model: setup needs the sensor image" >&2; exit 1; }
  for u in sensor-model.service sensor-model.timer; do
    docker run --rm --network none --entrypoint cat "$IMAGE" /app/deploy/aws/host/$u > "$U/$u"
  done
  grep -q sensor-model "$F" || echo '/usr/local/sbin/sensor-model.sh || echo "model: FAILED"' >> "$F"
  systemctl daemon-reload
  systemctl enable --now sensor-model.timer
fi

# The endpoint's address, looked up again on every run; a failed lookup keeps the saved one.
# setup waits up to 150 seconds for the endpoint's private name to take effect.
for i in 1 2 3 4 5 6 7 8 9 10; do
  a=$(getent ahostsv4 "$NAME" | awk 'NR==1{print $1}') || a=""
  if [[ $a =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] && inside "$a"; then echo "$a" > "$S/endpoint"; break; fi
  [ "${1:-}" = setup ] || break
  sleep "${SENSOR_MODEL_RETRY_SECONDS:-15}"
done
EP=$(cat "$S/endpoint" 2>/dev/null || :)
[[ $EP =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] && inside "$EP" \
  || { echo "sensor-model: no address inside the VPC for $NAME (is models.yaml deployed?)" >&2; exit 1; }

# The overlay: each caller's fixed address, the endpoint's name pinned to EP, its own
# credentials directory read-only, two variables. Written beside the old one, checked by
# Compose with the other files, then renamed over it, so a refused overlay changes nothing.
# COMPOSE_FILE keeps what the console step wrote.
cd "$O"
f=$(sed -n 's/^COMPOSE_FILE=//p' .env 2>/dev/null || :)
f=${f:-docker-compose.yml:docker-compose.override.yml}
f=${f//:docker-compose.model.yml/}
svc() { printf '  %s:\n    networks: {%s: {ipv4_address: %s}}\n    extra_hosts: ["%s:%s"]\n    environment: {AWS_CONFIG_FILE: /model/config, AWS_EC2_METADATA_DISABLED: "true"}\n    volumes: ["%s/%s:/model:ro"]\n' "$1" "$2" "$3" "$NAME" "$EP" "$D" "$4"; }
overlay() {
  {
    echo "services:"
    [ -z "$PERSONA_MODEL" ] || svc ssh frontend 172.30.0.10 persona
    [ -z "$ANALYST_MODEL" ] || svc agents backend 172.30.1.10 analyst
  } > docker-compose.model.new.yml
  COMPOSE_FILE=$f:docker-compose.model.new.yml docker compose config --quiet
  mv -f docker-compose.model.new.yml docker-compose.model.yml
}

if [ "${1:-}" = setup ]; then
  # The overlay first; config.ini changes only after it passed, so a failure here leaves
  # the persona and analyst without a model rather than with a model they cannot reach.
  overlay
  python3 render_config.py models config.ini "$PERSONA_MODEL" "$ANALYST_MODEL" "$REGION"
  chown 10001:10001 config.ini
  chmod 0400 config.ini
  { grep -v '^COMPOSE_FILE=' .env || :; echo "COMPOSE_FILE=$f:docker-compose.model.yml"; } > .env.new
  mv -f .env.new .env
fi

# The accept to the current address first, then every caller accept to any other address
# goes: an old address may since belong to something else in the VPC.
for c in "${callers[@]}"; do
  iptables -w -C DOCKER-USER -s "${c#*:}" -d "$EP" -p tcp --dport 443 -j ACCEPT 2>/dev/null \
    || iptables -w -I DOCKER-USER 1 -s "${c#*:}" -d "$EP" -p tcp --dport 443 -j ACCEPT
done
stale='^-A DOCKER-USER -s (172\.30\.[01]\.10)/32 -d ([0-9.]+)/32 -p tcp -m tcp --dport 443 -j ACCEPT$'
rules=$(iptables -w -S DOCKER-USER)
while read -r line; do
  [[ $line =~ $stale ]] && [ "${BASH_REMATCH[2]}" != "$EP" ] || continue
  iptables -w -D DOCKER-USER -s "${BASH_REMATCH[1]}" -d "${BASH_REMATCH[2]}" -p tcp --dport 443 -j ACCEPT
done <<< "$rules"

# The address changed since the overlay was written: pin the new one and recreate only the
# running callers. Until then they still resolve the old address, which no rule lets them
# reach any more, so their calls fail rather than go elsewhere.
if [ "${1:-}" != setup ] && [ -f docker-compose.model.yml ] \
    && ! grep -qF "\"$NAME:$EP\"" docker-compose.model.yml; then
  overlay
  for s in ssh agents; do
    grep -q "^  $s:" docker-compose.model.yml || continue
    [ -z "$(docker compose ps -q --status running "$s" 2>/dev/null || :)" ] \
      || docker compose up -d --no-deps "$s"
  done
fi

# Credentials, per caller, from its own role into its own directory: written beside the
# old ones and renamed over them, so a reader never sees half a file. The directory is
# mounted, not the file, so the rename reaches the container.
install -d -m 0700 "$D"
umask 077
renew() {
  install -d -m 0500 -o 10001 -g 10001 "$D/$1"
  printf '[default]\ncredential_process = cat /model/creds.json\n' > "$D/$1/config.new"
  for i in 1 2 3; do
    if aws sts assume-role --region "$REGION" --endpoint-url "https://sts.$REGION.$SUFFIX" \
        --role-arn "$ROLE_ARN-$1" --role-session-name "sensor-$1" --duration-seconds 3600 \
        --query Credentials --output json \
        | python3 -c 'import json,sys; c=json.load(sys.stdin); json.dump(dict(Version=1, **{k: c[k] for k in ("AccessKeyId", "SecretAccessKey", "SessionToken", "Expiration")}), sys.stdout)' \
        > "$D/$1/creds.new"; then
      chown 10001:10001 "$D/$1/creds.new" "$D/$1/config.new"
      chmod 0400 "$D/$1/creds.new" "$D/$1/config.new"
      mv -f "$D/$1/config.new" "$D/$1/config"
      mv -f "$D/$1/creds.new" "$D/$1/creds.json"
      return 0
    fi
    sleep "${SENSOR_MODEL_RETRY_SECONDS:-15}"
  done
  rm -f "$D/$1/creds.new" "$D/$1/config.new"
  echo "sensor-model: could not assume the $1 model role; its calls fail until the next run" >&2
  return 1
}
rc=0
for c in "${callers[@]}"; do
  renew "${c%%:*}" || rc=1
done
exit $rc
