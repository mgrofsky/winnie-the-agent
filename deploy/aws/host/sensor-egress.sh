#!/bin/bash
# The exporter's egress limits on a sensor host with the tailnet option on
# (deploy/aws/sensor.yaml, TailscaleEnabled=true; installed by its EgressStep).
#
# The option opens tcp 443 to anywhere in the instance security group, for tailscaled. The
# only unprivileged process on the host network is the exporter, uid 10001, which holds the
# instance role. OUTPUT sends every uid 10001 packet through SENSOR-UID and rejects whatever
# that chain does not accept: nothing out tailscale0, and otherwise exactly what the security
# group allowed before the option existed: tcp 443 into the VPC (the interface endpoints)
# and to the CIDRs of the S3 prefix list (the gateway endpoint), the metadata service, and
# DNS (the local stub and the VPC resolver). uid 10001 gets no IPv6 (tailscale0 carries
# IPv6). Root (tailscaled, dockerd, the SSM agent) is not matched.
#
#   sensor-egress.sh            rebuild the rules from the saved prefix list (at boot, from
#                               sensor-firewall.sh, before the stack starts)
#   sensor-egress.sh refresh    look the prefix list up first (sensor-egress.timer)
#
# The lookup is ec2:GetManagedPrefixListEntries through the stack's ec2 interface endpoint.
# A failed or malformed answer keeps the last saved list; with none saved, uid 10001 reaches
# no S3 address and the export waits. SENSOR-UID is rebuilt by flush and refill, and the
# REJECT after its jump in OUTPUT refuses a packet that arrives mid-rebuild: this never
# fails open.
set -euo pipefail
. "${SENSOR_EGRESS_ENV:-/etc/sensor-egress.env}"
C=${SENSOR_EGRESS_DIR:-/var/lib/sensor-egress}/s3-cidrs
ip4="^[0-9]{1,3}(\.[0-9]{1,3}){3}/[0-9]{1,2}$"
# An IPv4 CIDR no wider than a /8: a /0 from anywhere would undo the point of this script.
good() { [[ $1 =~ $ip4 ]] && [ "${1#*/}" -ge 8 ] && [ "${1#*/}" -le 32 ]; }
[[ $REGION =~ ^[a-z0-9-]{1,32}$ && $PREFIX_LIST =~ ^pl-[0-9a-f]{8,17}$ ]] && good "$VPC_CIDR" \
  || { echo "sensor-egress: bad REGION, PREFIX_LIST or VPC_CIDR" >&2; exit 1; }
if [ "${1:-}" = refresh ]; then
  mkdir -p "${C%/*}"
  l=""
  for i in 1 2 3 4 5 6 7 8; do
    l=$(aws ec2 get-managed-prefix-list-entries --region "$REGION" --prefix-list-id "$PREFIX_LIST" --query 'Entries[].Cidr' --output text 2>/dev/null) && [ -n "$l" ] && break
    l=""
    sleep "${SENSOR_EGRESS_RETRY_SECONDS:-15}"
  done
  ok=$l
  for c in $l; do good "$c" || ok=""; done
  if [ -n "$ok" ]; then
    printf '%s\n' $l > "$C.new"
    mv -f "$C.new" "$C"
  else
    echo "s3 prefix list: lookup failed, keeping the last list" >&2
  fi
fi
w="iptables -w"
u="-m owner --uid-owner 10001"
$w -C OUTPUT $u -j REJECT 2>/dev/null || $w -I OUTPUT 1 $u -j REJECT
$w -N SENSOR-UID 2>/dev/null || $w -F SENSOR-UID
$w -C OUTPUT $u -j SENSOR-UID 2>/dev/null || $w -I OUTPUT 1 $u -j SENSOR-UID
$w -A SENSOR-UID -o tailscale0 -j REJECT
$w -A SENSOR-UID -o lo -d 127.0.0.53 -p udp --dport 53 -j ACCEPT
$w -A SENSOR-UID -o lo -d 127.0.0.53 -p tcp --dport 53 -j ACCEPT
$w -A SENSOR-UID -d 169.254.169.254 -p tcp --dport 80 -j ACCEPT
$w -A SENSOR-UID -d 169.254.169.253 -p udp --dport 53 -j ACCEPT
$w -A SENSOR-UID -d "$VPC_CIDR" -p udp --dport 53 -j ACCEPT
$w -A SENSOR-UID -d "$VPC_CIDR" -p tcp --dport 443 -j ACCEPT
for c in $(cat "$C" 2>/dev/null || :); do if good "$c"; then $w -A SENSOR-UID -d "$c" -p tcp --dport 443 -j ACCEPT; fi; done
ip6tables -w -C OUTPUT $u -j REJECT 2>/dev/null || ip6tables -w -I OUTPUT 1 $u -j REJECT
