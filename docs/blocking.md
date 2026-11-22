# Blocking: Approve, Enforce and pulling the lists

Winnie does not change your firewalls. It publishes lists of addresses, and your own
systems pull those lists and decide what to do with them. The one exception is the
optional `block_webhook` connector, which sends one address to an endpoint you run.

This page covers:

- [The lifecycle of an entry](#the-lifecycle-of-an-entry)
- [The files](#the-files)
- [How the lists leave the sensor](#how-the-lists-leave-the-sensor)
- [How a consumer should pull](#how-a-consumer-should-pull)
- [Recipes](#recipes)

The settings are in `[respond]` of `config.ini`. The approval queue and the commands are in
[playbooks.md](playbooks.md#approval-workflow).

## The lifecycle of an entry

1. **Candidate.** A playbook step `export_blocklist` or `block_webhook` matches a source.
   With `[respond] queue_enforce = true` the step goes into the approval queue. With it off
   (the default) the step is recorded and nothing else happens. A queued item expires
   if nobody decides it within `approval_ttl_hours` (default 72).
2. **Approve.** A person approves the item, with `python -m agents approve <id>` or in
   the console. The source gates run again: the source must be verified, a public address
   and outside `never_act_on`. What happens next depends on `track_before_enforce`:
   - **Off (the default).** `export_blocklist` writes the address straight to the
     blocklist file. It is blocked as soon as your systems pull the file.
     `block_webhook` calls the block connector and writes nothing to the file.
   - **On.** Both actions put the address on the tracked list with status `tracked`.
     Nothing is blocked and no connector is called. The address is in `tracked.json` but
     not in the blocklist file.
3. **Enforce.** Only with `track_before_enforce` on. A person runs
   `python -m agents enforce <address>` or presses Enforce in the console. The entry's
   status becomes `enforced`. It is added to the blocklist file, and the block connector is
   called if it is enabled. Enforce runs the approval checks again and refuses an entry
   that is missing, expired or already enforced.
4. **Expiry.** Every entry expires `blocklist_ttl_days` (default 30) after it was
   approved. **Enforce does not extend the expiry.** An entry approved on the 1st and
   enforced on the 20th still expires on the 31st with the default setting. Approving the
   same address again gives it a new expiry: an enforced entry stays enforced, a tracked
   entry starts again as tracked. An expired entry is dropped from the files the next time
   they are written, which is the next respond run at the latest.
5. **Unblock.** `python -m agents unblock <address-or-network>`, or Unblock in the
   console, removes an entry before it expires. It works on tracked and enforced entries.
   A network removes every entry inside it.

Expiry and unblock never call the block connector. If you use `block_webhook`, the
system behind it must remove the address on its own schedule. See
[The block webhook](#the-block-webhook).

Turning `track_before_enforce` on leaves existing entries enforced. Turning it off leaves
tracked entries tracked until they are enforced, unblocked or expire. Details are in
[playbooks.md](playbooks.md#track-before-enforce).

## The files

All files are rewritten whole on every change, by writing a new file and renaming it into
place. A reader never sees half a file.

| File | Where | Written when | Holds |
|---|---|---|---|
| Blocklist file | `[respond] blocklist_file`, default `reports/blocklist/approved.txt` | an approval, an enforce or an unblock changes it; a respond run drops an expired entry or finds the file missing | enforced entries only |
| `tracked.json` | the same directory as the blocklist file | the same changes, and every respond run while `track_before_enforce` is on | every live entry, tracked and enforced |

With `track_before_enforce` off, `tracked.json` is not written. Entries approved while it
was off have no status and count as enforced.

Each entry is keyed by an IPv4 address or an IPv6 /64 network. An IPv6 source is always
listed as its /64.

The blocklist file is readable by everyone on the host (mode 644). `tracked.json` is
readable by its owner only (mode 600). In the containers the owner is user id 10001.

### Blocklist file, `blocklist_format = plain`

One entry per line, sorted as text. No header, no times.

```
198.51.100.7
2001:db8:4:5::/64
203.0.113.45
```

### Blocklist file, `blocklist_format = csv`

A header, then one entry per line. Times are ISO 8601 in UTC.

```
ip,approved_at,expires_at
198.51.100.7,2026-11-17T22:14:03+00:00,2026-12-17T22:14:03+00:00
2001:db8:4:5::/64,2026-11-10T08:02:41+00:00,2026-12-10T08:02:41+00:00
203.0.113.45,2026-11-12T10:30:00+00:00,2026-12-12T10:30:00+00:00
```

### Blocklist file, `blocklist_format = nftables`

A complete file for `nft -f`. It defines `table inet winnie` with two interval sets,
`winnie_block_v4` and `winnie_block_v6`. It flushes both sets and fills them again, so a
removed or expired entry is gone after the next load. A family with no entries gets no
`add element` line.

```
#!/usr/sbin/nft -f
# Approved blocklist written by the winnie response engine. Load with nft -f.
table inet winnie {
	set winnie_block_v4 {
		type ipv4_addr
		flags interval
	}
	set winnie_block_v6 {
		type ipv6_addr
		flags interval
	}
}
flush set inet winnie winnie_block_v4
flush set inet winnie winnie_block_v6
add element inet winnie winnie_block_v4 { 198.51.100.7, 203.0.113.45 }
add element inet winnie winnie_block_v6 { 2001:db8:4:5::/64 }
```

The file defines only the sets. Your own rules use them (see the
[host firewall recipe](#host-firewall-with-nftables)).

### `tracked.json`

Every live entry, tracked and enforced, sorted by address. Keys are sorted.

```json
{
  "entries": [
    {
      "address": "192.0.2.10",
      "approved_at": "2026-11-18T07:55:12+00:00",
      "expires_at": "2026-12-18T07:55:12+00:00",
      "status": "tracked"
    },
    {
      "address": "198.51.100.7",
      "approved_at": "2026-11-17T22:14:03+00:00",
      "expires_at": "2026-12-17T22:14:03+00:00",
      "status": "enforced"
    },
    {
      "address": "2001:db8:4:5::/64",
      "approved_at": "2026-11-10T08:02:41+00:00",
      "expires_at": "2026-12-10T08:02:41+00:00",
      "status": "enforced"
    }
  ],
  "generated_at": "2026-11-18T09:00:00+00:00",
  "sensor": "sensor-1",
  "version": 1
}
```

| Field | Meaning |
|---|---|
| `version` | always 1 |
| `generated_at` | when the file was written, UTC |
| `sensor` | `[honeypot] sensor_name`, else the host name; letters, digits, `.`, `_` and `-` only |
| `entries[].address` | an IPv4 address, or an IPv6 /64 |
| `entries[].status` | `tracked` (watch only) or `enforced` (block) |
| `entries[].approved_at` | when the entry was last approved |
| `entries[].expires_at` | when the entry expires |

Nothing else is in the file: no approval ids, playbooks, operator names or secrets.

`tracked.json` is the best source for a consumer. It is the only file with the status of
every entry, an expiry on every entry and a time that shows the sensor is still writing.

### Audit records

Each approval, enforce and unblock also writes a JSON record to `reports/response/`. These
are for people reviewing decisions. Consumers should not read them.

## How the lists leave the sensor

There are three ways. All of them are off until you set them up.

### Tracked export to object storage or HTTPS

`[connector.tracked_export]` sends `tracked.json` off the sensor. It runs in
`python -m agents ship` and at the end of `run-all`.

- `kind = s3` writes one object with `PutObject`. The sensor needs permission for that one
  key and nothing else. `endpoint_url` points it at another store that speaks the S3 API.
- `kind = https` sends one `PUT` or `POST` of the document to a URL you run.

The document is sent whole when its content changes (any change but `generated_at`), and
at least once every 24 hours otherwise. So the remote copy's `generated_at` is never more
than about a day old while the sensor is healthy and `track_before_enforce` is on. A
failed send is logged and tried again on the next run.

The tracked export sends `tracked.json` only. It does not send the blocklist file. Every
key is in [operations.md](operations.md#tracked-export).

### The block webhook

`[connector.block_webhook]` sends one `POST` per approved address:

```json
{"ip": "198.51.100.7", "reason": "honeytoken_reuse"}
```

An IPv6 entry is sent as `{"network": "2001:db8:4:5::/64", "reason": "..."}`. The reason
is the playbook name, or `enforce` when the entry has no playbook.

It is called:

- with `track_before_enforce` off, when a `block_webhook` item is approved;
- with `track_before_enforce` on, when an entry is enforced, and at no other time.

It is never called for an unblock or an expiry, and nothing is retried. The receiving
system must give each address its own expiry and must accept the same address more than
once. Prefer a pulled list where you can; the webhook is the one place the sensor pushes.
It follows the [connector rules](playbooks.md#connectors).

### Reading the file on the host

A system on the sensor host can read the files directly. In the Docker Compose layout the
agents write them in the `agentdata` volume, under `/agents/reports/blocklist/`. To read
them from the host, mount a host directory there, or set `[respond] blocklist_file` to a
path inside a directory you mount. `tracked.json` follows the blocklist file's directory.
The directory must be writable by user id 10001, and `tracked.json` is readable by that
user only.

Copy the file off the host with a job you run there, for example to the hosts whose
firewall uses it. Do not block listed addresses on the sensor itself; that stops it
seeing them.

## How a consumer should pull

A consumer is whatever turns a Winnie list into a rule: a script, a scheduled job, a
function in your cloud. Treat the list as evidence from an exposed host, not as an
authority. The general rules are in
[operations.md](operations.md#using-the-intelligence-outside-the-sensor). For these lists
in particular:

- **Read the whole list every time and replace your copy.** Do not add new entries to what
  you had. Winnie drops expired and unblocked entries by leaving them out. A consumer that
  only adds keeps them forever.
- **Match status to action.** `tracked` means watch: alert or record a match, never block.
  `enforced` means block, if you block at all. The plain, csv and nftables files hold
  enforced entries only.
- **Apply the expiry yourself.** Leave out any entry whose `expires_at` has passed, even if
  the file still lists it. The file is cleaned at the next respond run, up to one run
  interval later (an hour with the default Docker Compose setting).
- **Validate every entry.** An IPv4 address or an IPv6 /64, public, not inside your
  allow-list, with a valid expiry. Drop anything else and log it.
- **Keep your own allow-list.** List your offices, VPN egress, carriers, monitoring,
  partners and the scanners you pay for. Check it on the consumer side, even though the
  sensor has `never_act_on`. The two lists protect against different mistakes.
- **Cap how many new entries one run may add.** Compare the new list with your last copy.
  If more new addresses arrive than your cap (for example 50), apply none of the new
  ones, keep removals, and alert a person. Also cap the total size of the list.
- **Fail safe when the source is stale.** Check `generated_at` in `tracked.json`. If it is
  older than your limit (for example 48 hours, which allows for the 24-hour refresh), or
  the file is missing or does not parse, add nothing new. Keep applying expiry and
  removals to your last good copy, and alert a person. A stale source must never grow
  your list.
- **Start in count mode.** Have a new rule count or log matches for a while before it
  drops anything.
- **Keep a single switch to remove everything** that came from the sensor, such as one
  address set or one rule you can disable.

The plain, csv and nftables files have no `generated_at`, and with
`track_before_enforce` off they are only rewritten when something changes. Their age
does not show the sensor is alive. If you need a freshness check, turn
`track_before_enforce` on and read `tracked.json`.

A consumer in Python that applies these rules to `tracked.json` (not tested by this
project):

```python
import datetime, ipaddress, json

MAX_AGE = datetime.timedelta(hours=48)
MAX_NEW = 50
ALLOW = [ipaddress.ip_network(n) for n in ("192.0.2.0/24",)]   # your allow-list

def load(path, previous):
    """Return (watch, block) sets, or None to keep the previous copy and alert."""
    now = datetime.datetime.now(datetime.timezone.utc)
    try:
        doc = json.load(open(path))
        age = now - datetime.datetime.fromisoformat(doc["generated_at"])
    except (OSError, ValueError, KeyError):
        return None
    if doc.get("version") != 1 or age > MAX_AGE:
        return None
    watch, block = set(), set()
    for e in doc.get("entries", []):
        try:
            net = ipaddress.ip_network(e["address"])
            expires = datetime.datetime.fromisoformat(e["expires_at"])
        except (KeyError, TypeError, ValueError):
            continue
        if expires <= now or not net.is_global:
            continue
        if net.prefixlen != (32 if net.version == 4 else 64):
            continue
        if any(net.version == a.version and net.overlaps(a) for a in ALLOW):
            continue
        if e.get("status") == "enforced":
            block.add(str(net))
        elif e.get("status") == "tracked":
            watch.add(str(net))
    if len((watch | block) - previous) > MAX_NEW:
        return None
    return watch, block
```

When `load` returns `None`, keep your last good copy, remove from it the entries whose
expiry has passed, and alert.

## Recipes

Each recipe says whether this project tests it. "Not tested" means no test in this
repository runs it. Read it as a starting point, and try it in count mode first.

### Cloud WAF address set

**Not tested by this project.**

Shape: a scheduled job reads `tracked.json` from the bucket the tracked export writes to,
applies the consumer rules above, and replaces the whole contents of one WAF address set
with the `enforced` entries. A WAF rule matches that set. Use one set per address family
if your WAF needs it. IPv4 entries become `/32`; IPv6 entries are already `/64`.

For example, with an AWS WAF IP set, the job calls `UpdateIPSet` with the full address
list. That call replaces the list, so removed and expired entries drop out:

```bash
# Not tested by this project. block-v4.txt holds one CIDR per line, e.g. 198.51.100.7/32.
TOKEN=$(aws wafv2 get-ip-set --scope REGIONAL --name winnie-block-v4 --id "$SET_ID" \
        --query LockToken --output text)
aws wafv2 update-ip-set --scope REGIONAL --name winnie-block-v4 --id "$SET_ID" \
    --lock-token "$TOKEN" --addresses $(cat block-v4.txt)
```

Run the rule that uses the set in count mode first. Give the job read access to the one
tracked object and write access to the one address set, nothing more. The sensor gets no
access to the WAF.

### Cloud threat-detection list

**Not tested by this project.**

A threat list raises findings when a listed address talks to your systems. It never
blocks, so both `tracked` and `enforced` entries fit here. This is the safest place to
start.

Shape: a scheduled job reads `tracked.json`, applies the consumer rules, writes the
addresses one per line to a text object, and tells the threat-detection service to read
it again.

For example, with an AWS GuardDuty threat list in plain text format:

```bash
# Not tested by this project.
aws s3 cp threat-list.txt "s3://$LIST_BUCKET/winnie/threat-list.txt"
aws guardduty update-threat-intel-set --detector-id "$DETECTOR_ID" \
    --threat-intel-set-id "$SET_ID" \
    --location "https://s3.amazonaws.com/$LIST_BUCKET/winnie/threat-list.txt" --activate
```

Write the whole file each time so expired entries drop out. Check whether your service
accepts IPv6 networks; if it does not, leave them out. Keep the list bucket separate from
the bucket the sensor writes to, so the sensor cannot write the list your detection
service reads.

### Host firewall with nftables

**Not tested by this project.** Tests check the content of the nftables file Winnie
writes. No test loads it into `nft`.

Set `blocklist_format = nftables`, and copy the file to the host that will use it (not the
sensor). On that host, load Winnie's file first, then your own rules once. Your rules go in
the same table, so they can use the sets:

```
# /etc/nftables.d/winnie-rules.nft, loaded once after the first Winnie file
table inet winnie {
	chain input {
		type filter hook input priority filter - 5; policy accept;
		ip saddr @winnie_block_v4 counter
		ip6 saddr @winnie_block_v6 counter
	}
}
```

These rules only count matches. When the counts look right, add `drop` to both lines.

Each time a new copy arrives:

```bash
# Not tested by this project.
nft -c -f /etc/winnie/approved.nft && nft -f /etc/winnie/approved.nft
```

`nft -c` checks the file without loading it. Loading it flushes and refills the two
sets in one transaction, so removed and expired entries go at once, and your chain is
left alone. To remove everything from the sensor in one step, delete the chain or the
table: `nft delete table inet winnie`.

The nftables file has no expiry times and no freshness time. If the copy job cannot fetch
a new file, it keeps the last one. To expire entries when the sensor goes quiet, read
`tracked.json` (or the csv format) instead and build the set from it.
