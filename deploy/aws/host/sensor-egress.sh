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
#   sensor-egress.sh deny       only the two REJECTs below, which need no settings
#                               (sensor-egress-boot.service, before Docker starts)
#   sensor-egress.sh            rebuild the rules from the saved prefix list (at boot, right
#                               after the deny, and from sensor-firewall.sh)
#   sensor-egress.sh refresh    look the prefix list up first (sensor-egress.timer)
#
# iptables rules do not survive a reboot, and Docker starts the containers itself. So
# sensor-egress-boot.service runs this script before docker.service at every boot, and
# Docker requires it: if even the deny cannot be installed, Docker does not start. The
# REJECTs go in first, before the settings are read, so a bad or missing settings file
# leaves uid 10001 with no egress at all rather than with the open path.
#
# The lookup is ec2:GetManagedPrefixListEntries through the stack's ec2 interface endpoint.
# A failed or malformed answer keeps the last saved list; with none saved, uid 10001 reaches
# no S3 address and the export waits. SENSOR-UID is rebuilt by flush and refill, and the
# REJECT after its jump in OUTPUT refuses a packet that arrives mid-rebuild: this never
# fails open.
#
# INTERNETDB_LOOKUP=true in /etc/sensor-egress-idb.env, read after the main settings when it
# exists (sensor.yaml writes it only with InternetDbLookup; absent means false), also lets uid 10001 reach tcp 443 on the IPv4 addresses internetdb.shodan.io
# resolves to, for the exporter's own InternetDB lookups ([connector.internetdb_exchange]
# kind = lookup). On refresh, root resolves the name; every address must be a global
# unicast IPv4 address (any other answer keeps the last saved set), at most 8 are kept,
# saved where the exporter can read them (it connects only to those, checking the
# certificate for the fixed name). A failed or empty answer keeps the last saved set; with
# none saved nothing is opened. Each is one /32 ACCEPT after all the rules above. Those
# addresses are a shared CDN's, so they also serve other sites: the exporter, the only
# process allowed, sends nothing but an address in the path. Off, nothing here changes.
#
# OTX_SUBMIT=true in /etc/sensor-egress-otx.env (sensor.yaml writes it only with OtxSubmit;
# absent means false) does the same for otx.alienvault.com, for the exporter's OTX
# submissions ([connector.otx]): the same checks, at most 8 addresses saved as
# exporter/otx-addresses, one /32 tcp 443 ACCEPT each after every rule above. Off, nothing
# here changes.
set -euo pipefail
w="iptables -w"
u="-m owner --uid-owner 10001"
$w -C OUTPUT $u -j REJECT 2>/dev/null || $w -I OUTPUT 1 $u -j REJECT
ip6tables -w -C OUTPUT $u -j REJECT 2>/dev/null || ip6tables -w -I OUTPUT 1 $u -j REJECT
[ "${1:-}" != deny ] || exit 0
. "${SENSOR_EGRESS_ENV:-/etc/sensor-egress.env}"
X=${SENSOR_EGRESS_IDB_ENV:-/etc/sensor-egress-idb.env}
[ ! -f "$X" ] || . "$X"
C=${SENSOR_EGRESS_DIR:-/var/lib/sensor-egress}/s3-cidrs
ip4="^[0-9]{1,3}(\.[0-9]{1,3}){3}/[0-9]{1,2}$"
# An IPv4 CIDR no wider than a /8: a /0 from anywhere would undo the point of this script.
good() { [[ $1 =~ $ip4 ]] && [ "${1#*/}" -ge 8 ] && [ "${1#*/}" -le 32 ]; }
[[ $REGION =~ ^[a-z0-9-]{1,32}$ && $PREFIX_LIST =~ ^pl-[0-9a-f]{8,17}$ ]] && good "$VPC_CIDR" \
  || { echo "sensor-egress: bad REGION, PREFIX_LIST or VPC_CIDR" >&2; exit 1; }
IDB=${INTERNETDB_LOOKUP:-false}
[[ $IDB = true || $IDB = false ]] || { echo "sensor-egress: bad INTERNETDB_LOOKUP" >&2; exit 1; }
I=${SENSOR_EGRESS_DIR:-/var/lib/sensor-egress}/exporter/internetdb-addresses
Y=${SENSOR_EGRESS_OTX_ENV:-/etc/sensor-egress-otx.env}
[ ! -f "$Y" ] || . "$Y"
OTX=${OTX_SUBMIT:-false}
[[ $OTX = true || $OTX = false ]] || { echo "sensor-egress: bad OTX_SUBMIT" >&2; exit 1; }
O=${I%/*}/otx-addresses
# One global unicast IPv4 address, written canonically (no leading zeros). The documentation
# ranges count as public only for the tests (SENSOR_EGRESS_TEST_DOC_RANGES=1).
pub() {
  [[ $1 =~ ^(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})$ ]] || return 1
  local a=${BASH_REMATCH[1]} b=${BASH_REMATCH[2]} c=${BASH_REMATCH[3]} d=${BASH_REMATCH[4]}
  [ "$a" -le 255 ] && [ "$b" -le 255 ] && [ "$c" -le 255 ] && [ "$d" -le 255 ] || return 1
  case "$a.$b.$c." in
    0.*|10.*|127.*|169.254.*|192.168.*|192.0.0.*|192.88.99.*|198.18.*|198.19.*) return 1 ;;
    192.0.2.*|198.51.100.*|203.0.113.*) [ "${SENSOR_EGRESS_TEST_DOC_RANGES:-}" = 1 ] || return 1 ;;
  esac
  [ "$a" -lt 224 ] || return 1
  if [ "$a" = 100 ] && [ "$b" -ge 64 ] && [ "$b" -le 127 ]; then return 1; fi
  if [ "$a" = 172 ] && [ "$b" -ge 16 ] && [ "$b" -le 31 ]; then return 1; fi
  return 0
}
# Resolve name $1 as root, save its addresses to $2 for the exporter; $3 names it in errors.
pin() {
  install -d -m 0755 "${2%/*}"
  local n=() bad="" a _
  while read -r a _; do
    pub "$a" || bad=1
    [[ " ${n[*]:-} " = *" $a "* ]] || n+=("$a")
  done < <(getent ahostsv4 "$1" 2>/dev/null || :)
  if [ -z "$bad" ] && [ "${#n[@]}" -gt 0 ]; then
    printf '%s\n' "${n[@]:0:8}" > "$2.new"
    chmod 0644 "$2.new"
    mv -f "$2.new" "$2"
  else
    echo "$3: lookup failed, keeping the last addresses" >&2
  fi
}
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
  [ "$IDB" != true ] || pin internetdb.shodan.io "$I" internetdb
  [ "$OTX" != true ] || pin otx.alienvault.com "$O" otx
fi
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
[ "$IDB" != true ] || for a in $(head -n 8 "$I" 2>/dev/null || :); do if pub "$a"; then $w -A SENSOR-UID -d "$a/32" -p tcp --dport 443 -j ACCEPT; fi; done
[ "$OTX" != true ] || for a in $(head -n 8 "$O" 2>/dev/null || :); do if pub "$a"; then $w -A SENSOR-UID -d "$a/32" -p tcp --dport 443 -j ACCEPT; fi; done
