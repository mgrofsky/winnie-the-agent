# AWS deployment example

Two CloudFormation templates that run one Winnie the Agent sensor on one EC2 host, with its
events shipped one way to a bucket in another account. Use them as a starting point; read
them before deploying, and run the checks below after every change.

| File | Deploy in | Creates |
|---|---|---|
| `events-bucket.yaml` | a separate account (for example your security or log archive account), in the sensor's region | the events bucket and its policy |
| `sensor.yaml` | a dedicated account for the sensor | VPC, endpoints, ECR repository, instance role, log groups, optional trail, launch template, instance, Elastic IP |
| `check.py` | nowhere: run locally | offline checks of both templates (`tests/test_deploy_aws.py` runs them too) |
| `strip_comments.py` | nowhere: run locally | writes the copy of `sensor.yaml` you deploy, without its comments (see [Template size](#facts-learned-from-deploying-it)) |

## What gets created

- **Network.** One VPC, one public subnet, an internet gateway and no NAT. The route to
  the internet gateway exists only so replies to inbound connections leave; the instance
  security group allows outbound traffic only on 443 to the S3 prefix list and to six
  interface endpoints (SSM, SSM messages, EC2 messages, ECR API, ECR registry, CloudWatch
  Logs). The S3 gateway endpoint policy allows `PutObject` to the events prefix and reads
  from the Amazon Linux package, ECR layer and SSM agent buckets only. VPC flow logs go to
  CloudWatch Logs (`FlowLogsEnabled`).
- **Inbound.** One security group rule per public port, each from `InboundCidr` only, each
  present only with `InboundEnabled=true` and only when the scenario runs that service.
  The `ScenarioServices` mapping in `sensor.yaml` lists each scenario's services;
  `tests/test_deploy_aws.py` keeps it equal to the scenarios. Public ports: SSH 22, FTP 21
  and 30000-30019, Telnet 23, SMTP 25 (only with `SmtpEnabled=true`), HTTP 80, MSSQL 1433,
  MySQL 3306, SIP 5060 UDP and TCP, PostgreSQL 5432, Redis 6379, HL7 MLLP 2575, and the S3
  trap on `S3Port` (default 9000).
- **Host.** Amazon Linux 2023, IMDSv2 required with a hop limit of 1, no key pair; the
  host's own sshd is masked so port 22 is the fake SSH service and administration is SSM
  Session Manager only. The bootstrap installs Docker, turns the userland proxy off,
  writes the compose files and two config files from the image's template, and runs the
  stack as a systemd unit.
- **Containment on the host.** `DOCKER-USER` rules drop traffic from every bridged
  container to 169.254.169.254 and drop every new connection from the front-end
  (172.30.0.0/24) and agents (172.30.1.0/24) networks; only replies pass.
- **Exporter.** A fifth container runs `python -m agents ship` every five minutes on the
  host network. It is the only container that can use the instance role, which may pull
  this one image, write this one log group and `s3:PutObject` under the events prefix.
  It has its own `config-ship.ini` with `[connector.s3_events]` on (`passwords = hash`,
  `bucket_owner` sent as `ExpectedBucketOwner`); the shared `config.ini` keeps the export
  off, because `run-all` in the agents container would otherwise try to ship without
  credentials or egress. Of the agents' data it mounts only the `blocklist` volume,
  read-only (see [Tracked blocklist export](#tracked-blocklist-export-optional)).
- **Bucket.** Versioned, encrypted, public access blocked, lifecycle expiry. Its policy
  lets the sensor role (matched by ARN) put under the events prefix and denies everything
  else to every principal in the sensor account, so nothing there can read, list or
  delete. Requests without TLS are denied. With `TrailEnabled=true` in both stacks, the
  sensor account's own multi-region trail delivers under `cloudtrail/`.

Optional, all off by default: the operator console (`UiEnabled`, with `UiActions` to let
it act), and reaching that console over a Tailscale tailnet (`TailscaleEnabled`, see
[Console over a tailnet](#console-over-a-tailnet-optional)), which adds one egress rule
and one scoped role policy and opens nothing inbound.

No model calls: the host has no route to a model API, so `[listeners] llm = false`, the
SSH persona gives canned replies and triage is deterministic.

### Cost

Roughly 70 to 90 USD a month in a typical region on demand, most of it the six interface
endpoints (seven, about 7 USD more, with `TailscaleEnabled=true`). A `t3.small`, its volume and the Elastic IP add up to roughly 20 USD; S3, logs,
flow logs and the first trail's management events are usually a few dollars, but log
ingestion grows with attack traffic. Watch the host and flow log groups during the first
weeks. Check current prices for your region; these are orders of magnitude, not a quote.

## Facts learned from deploying it

- **Docker Compose on Amazon Linux 2023.** AL2023 does not package the Docker Compose
  plugin, and a host without an internet route cannot download it. The bootstrap copies
  the binary out of a copy of the `docker/compose-bin` image pushed to the stack's own ECR
  repository (`ComposeImageTag`). The repository's lifecycle rule expires untagged images
  only, so that copy never expires; keep it that way if you change the rule.
- **Real client addresses.** Docker's userland proxy rewrites every source address to the
  bridge gateway. The bootstrap sets `"userland-proxy": false`, so events, per-source
  limits and blocklists see the real client.
- **No default for `InboundCidr`.** CloudFormation rejects a parameter default that fails
  the parameter's own `AllowedPattern`, and an open default would expose the host by
  accident. Every deploy passes the range explicitly.
- **First launch in a new account.** A new AWS account's first EC2 launch can be held
  briefly for account validation. Deploy with `HostEnabled=false` first; the network,
  repository and role do not wait for it, and the image can be pushed meanwhile.
- **SMTP is off by default.** An open-looking mail service draws abuse reports against
  the sensor's address. To run it in a scenario that has SMTP (`sip-provider`, `saas`),
  redeploy with `SmtpEnabled=true`: it opens port 25 and stops setting
  `[listeners] smtp_enabled = false` in the generated config.
- **Template size.** `aws cloudformation deploy --template-file` (and `--template-body`)
  refuses a template over 51,200 bytes, and `sensor.yaml` with its comments is larger.
  Deploy the copy that `strip_comments.py` writes: it drops whole comment lines only, keeps
  the scripts byte for byte, and writes nothing unless the copy parses to the same document
  and fits. `check.py` runs the same two checks, so a change that would break the deploy
  fails locally first. The other way round the limit, an S3 template URL, needs a bucket
  in the sensor account that the deploying principal can write; this example avoids it.
- **User data size.** EC2 refuses user data over 16,384 bytes. The bootstrap's comments are
  YAML comments above `UserData`, and its static files live in the image (below).
  `check.py` measures the script at the longest value every parameter allows, with every
  optional step on (about 14,300 bytes today).
- **Template and image.** The bootstrap copies `deploy/aws/render_config.py` (which writes
  `config.ini` and `config-ship.ini`) and, with `TailscaleEnabled`, the files under
  `deploy/aws/host/` out of the image it runs, instead of carrying them in the user data.
  **Rebuild and push the image whenever you take a new `sensor.yaml`**: an image built
  before these files existed makes the bootstrap stop at the copy, before the stack
  starts. `check.py` checks that the `Dockerfile` puts them where the bootstrap reads them,
  and runs `render_config.py` and `sensor-egress.sh`'s rules from the repository.

## Deploy

Every stack change is created as a change set, reviewed, then executed. Replace the
placeholders; `B` is the bucket account's profile and `S` the sensor account's.

```bash
B="--profile <bucket-account-profile> --region us-east-1"
S="--profile <sensor-account-profile> --region us-east-1"
```

### 1. Local checks

```bash
uv run python deploy/aws/check.py                 # prints ok
uv run pytest tests/test_deploy_aws.py
uvx cfn-lint deploy/aws/sensor.yaml deploy/aws/events-bucket.yaml   # optional
mkdir -p build
uv run python deploy/aws/strip_comments.py deploy/aws/sensor.yaml build/sensor.deploy.yaml
```

The last line writes the copy of `sensor.yaml` that steps 3 and 5 deploy (`build/` is
ignored by git). Write it again after every change to `sensor.yaml`.

### 2. Events bucket (bucket account)

```bash
aws cloudformation deploy --stack-name winnie-events \
  --template-file deploy/aws/events-bucket.yaml $B \
  --parameter-overrides BucketName=example-winnie-events SensorAccountId=<sensor account id> \
    SensorRoleName=winnie-sensor-host TrailEnabled=false \
  --no-execute-changeset
aws cloudformation describe-change-set --change-set-name <change set arn> $B \
  --query "Changes[].ResourceChange.{Action:Action,Id:LogicalResourceId,Type:ResourceType}" --output table
aws cloudformation execute-change-set --change-set-name <change set arn> $B
aws cloudformation wait stack-create-complete --stack-name winnie-events $B
```

Expect two `Add` changes: the bucket and its policy. Deploy the bucket in the same region
as the sensor: the sensor reaches S3 only through its gateway endpoint, which serves its
own region. Never deploy this stack in the sensor account: its deny statements cover every
principal of that account.

### 3. Sensor network, repository and role (host off)

```bash
aws ec2 describe-managed-prefix-lists $S \
  --filters Name=prefix-list-name,Values=com.amazonaws.us-east-1.s3 --query "PrefixLists[0].PrefixListId"
aws cloudformation deploy --stack-name winnie-sensor \
  --template-file build/sensor.deploy.yaml --capabilities CAPABILITY_NAMED_IAM $S \
  --parameter-overrides InboundCidr=<your address>/32 HostEnabled=false \
    Scenario=sip-provider S3PrefixListId=<pl-...> \
    EventsBucketName=example-winnie-events EventsBucketOwner=<bucket account id> \
  --no-execute-changeset
aws cloudformation describe-change-set --change-set-name <change set arn> $S \
  --query "Changes[].ResourceChange.{Action:Action,Id:LogicalResourceId,Type:ResourceType}" --output table
aws cloudformation execute-change-set --change-set-name <change set arn> $S
aws cloudformation describe-stacks --stack-name winnie-sensor $S --query "Stacks[0].Outputs"
```

Expect only `Add` actions and no `LaunchTemplate`, `Instance` or `EipAssociation` (host
off). For the optional trail, first redeploy the bucket stack with `TrailEnabled=true`
(and `TrailName=<NamePrefix>-trail`), then pass `TrailEnabled=true` here.

### 4. Images

From the repository root, for `linux/amd64` (the AMI is x86_64):

```bash
R=<RepositoryUri output>
aws ecr get-login-password $S | docker login --username AWS --password-stdin "${R%%/*}"
docker buildx build --platform linux/amd64 -t "$R:<git sha>" --push .
docker pull --platform linux/amd64 docker/compose-bin:<compose version>
docker tag docker/compose-bin:<compose version> "$R:compose-bin"
docker push "$R:compose-bin"
aws ecr describe-image-scan-findings --repository-name winnie-sensor --image-id imageTag=<git sha> $S
```

Tags are immutable. A newer Compose binary goes under a new tag, passed as
`ComposeImageTag`.

The image carries files the bootstrap copies onto the host (`deploy/aws/render_config.py`
and `deploy/aws/host/`), so build it from the same commit as the `sensor.yaml` you deploy.

### 5. Turn the host on

Repeat step 3 with `HostEnabled=true ImageTag=<git sha>` and the same other values, as its
own reviewed change set. Expect `LaunchTemplate`, `Instance` and `EipAssociation` to be
added. Keep `InboundCidr` at your own address until the checklist below passes.

## Containment checklist

Open a shell with `aws ssm start-session --target <InstanceId> $S`, then `sudo -i` and
`cd /opt/sensor`.

- [ ] `tail /var/log/sensor-bootstrap.log` ends with `bootstrap complete`; `docker compose
      ps` shows ssh, listeners, agents and exporter running (and ui with
      `UiEnabled=true`); `systemctl is-enabled sshd` prints `masked`.
- [ ] `iptables -S DOCKER-USER` shows the two 169.254.169.254 drops and the two
      `! --ctstate RELATED,ESTABLISHED` drops.
- [ ] Containers cannot connect out. Each command must time out (not be refused, not
      answer):

      for s in listeners agents; do
        docker compose exec -T $s python -c "import socket; socket.create_connection(('192.0.2.1', 443), timeout=5)"
        docker compose exec -T $s python -c "import urllib.request; urllib.request.urlopen('https://s3.amazonaws.com', timeout=5)"
      done

- [ ] Containers cannot reach the metadata service (each times out; the exporter, on the
      host network, can reach it by design):

      for s in listeners agents; do
        docker compose exec -T $s python -c "import urllib.request as u; u.urlopen(u.Request('http://169.254.169.254/latest/api/token', method='PUT', headers={'X-aws-ec2-metadata-token-ttl-seconds': '60'}), timeout=5)"
      done

- [ ] The role can put and cannot get, list or delete (on the host, which uses the role):

      B=example-winnie-events
      echo verify | aws s3 cp - s3://$B/events/verify/$(date +%s).txt       # succeeds
      aws s3 ls s3://$B/events/                                             # AccessDenied
      aws s3api get-object --bucket $B --key events/verify/<key> /dev/null  # AccessDenied
      aws s3api delete-object --bucket $B --key events/verify/<key>         # AccessDenied
      echo verify | aws s3 cp - s3://$B/other/verify.txt                    # AccessDenied

- [ ] Events show real client addresses: connect from your own address (for example
      `nc -vz <PublicIp> 22`) and check that `docker compose logs listeners ssh` or the
      host log group shows that address, not 172.30.0.1.
- [ ] An exported object appears: within about five minutes of that connection, from the
      bucket account, `aws s3 ls s3://example-winnie-events/events/ --recursive $B | tail`
      lists a new object.

Only then widen `InboundCidr` (to `0.0.0.0/0` for an internet-facing sensor) in a new
reviewed change set.

## Operator console (optional)

`UiEnabled=true` also runs the operator console (`python -m agents ui`, see
[docs/operations.md](../../docs/operations.md#operator-console)) in read-only mode. It is off
by default. Turning it on changes no security group, role or endpoint: the console is on
the agents' backend network, which the host firewall already stops from opening
connections, mounts every volume read-only, and is published on the host's
`127.0.0.1:8480` only. You reach it through SSM.

Turn it on with a reviewed change set as in step 5, adding `UiEnabled=true`. The setting
is in the user data, so the change set replaces the instance (see Limits). The bootstrap
writes `COMPOSE_PROFILES=ui` to `/opt/sensor/.env`; with `UiEnabled=false` that line is
empty and the `ui` service does not start.

`UiActions=true` (needs `UiEnabled=true`) lets the console approve, reject, unblock and
enforce, recorded as `ui:<UiOperator>` (default `ui:console`). The bootstrap sets `[ui]
actions` and `operator` in `config.ini` and adds `docker-compose.actions.yml`, which mounts
the agent data and `blocklist` volumes read-write for the `ui` service only (approvals
write the queue, the blocklist file and `tracked.json`); the event log and overlay stay
read-only. Anyone who can sign in can then change what the sensor blocks. A failure is
logged as `console: FAILED` and the console stays read-only. `AgentsIntervalSeconds`
(default 3600) sets how often the agents run `run-all`; records cover closed hours, so a
shorter interval only shortens the wait after each hour.

Sign in:

1. In a normal session (`aws ssm start-session --target <InstanceId> $S`, then `sudo -i`,
   `cd /opt/sensor`), run `docker compose logs ui` and copy the sign-in link. The console
   logs to the host only (`driver: local`), so the link never reaches CloudWatch. The link
   changes every time the container starts.
2. On your workstation, forward the port:

       aws ssm start-session --target <instance-id> \
           --document-name AWS-StartPortForwardingSession \
           --parameters '{"portNumber":["8480"],"localPortNumber":["8480"]}'

3. Open the link in a browser on the workstation (it starts with `http://127.0.0.1:8480/`).

The loopback publish is confirmed on a real instance built from this template's compose
layout, with Docker's `"userland-proxy": false`: `curl http://127.0.0.1:8480/` on the host
answers (401 before sign-in), `ss -tlnp` shows dockerd holding `127.0.0.1:8480` and nothing
on another address, `iptables -t nat -S DOCKER` has one rule for 8480 with destination
`127.0.0.1/32`, and the port does not answer on the public address. The SSM port forward
itself (step 2) is not yet confirmed: the SSM agent has to connect to 127.0.0.1:8480,
where dockerd holds the port but does not proxy it; the DNAT rule does the work. Check that it reaches
the console before relying on it, and repeat the four checks above after any change to
the Docker or compose setup. If `S3Port` is ever set to 8480, the trap and the console
collide; pick another port.

The console can also be reached over a private mesh VPN through an HTTPS proxy on the
instance; see
[Reaching it over a private network](../../docs/operations.md#reaching-it-over-a-private-network)
for how that works in general. The next section sets it up with Tailscale. SSM port
forwarding keeps working either way.

## Console over a tailnet (optional)

`TailscaleEnabled=true` joins the host to a Tailscale tailnet and serves the console on the
node's tailnet HTTPS name, for example `https://sensor-1.example-tailnet.ts.net/`, to the
devices the tailnet's access rules let in. Nothing new is reachable from the internet. It
needs `UiEnabled=true`, `TailscaleImageTag`, `TailscaleHostname` and `TailnetSuffix`; the
stack's rules refuse a deploy without them. With `TailscaleEnabled=false` (the default)
none of what follows exists and the bootstrap is as before.

What it adds:

- **One egress rule**, tcp 443 to anywhere, for the coordination server, the DERP relays and
  the certificate service. No UDP, so the node always relays through DERP over HTTPS,
  which is plenty for the console. No inbound rule: tailscaled's WireGuard port listens on
  the host, but the security group admits nothing to it.
- **Host rules that keep the exporter where it was.** A security group cannot tell one
  process from another, so that rule alone would let the exporter (uid 10001 on the host
  network, holding the instance role, parsing data attackers wrote) send the role's
  credentials to any HTTPS server, or anything out `tailscale0`. `sensor-egress.sh` (in
  the image, `deploy/aws/host/`) sends every uid 10001 packet through an `OUTPUT` chain
  that accepts only what the security group allowed before the option: tcp 443 into the
  VPC (the interface endpoints) and to the CIDRs of the S3 prefix list (the gateway
  endpoint), the metadata service, and DNS. Everything else, including anything out
  `tailscale0` and all IPv6, is rejected. Root processes (tailscaled, dockerd, the SSM
  agent) are not matched. Bridged containers are unaffected either way: the `DOCKER-USER`
  rules still drop every new connection from them, whatever the port.
- **The S3 prefix list's CIDRs** come from `ec2:GetManagedPrefixListEntries`, looked up
  through a new `ec2` interface endpoint (`Ec2Endpoint`, about 7 USD a month, with a
  policy that allows that one call on that one list) at boot and every 15 minutes
  (`sensor-egress.timer`). AWS changes that list rarely; a new CIDR is picked up within 15
  minutes, and exports to it fail and are retried until then. A failed or malformed lookup
  (or a CIDR wider than a /8) keeps the last saved list; with none saved the exporter
  reaches no S3 address and the export waits. Nothing in this path fails open: the chain
  is rebuilt behind a `REJECT`, and a failure to install the rules stops the bootstrap
  before the stack starts.
- **One role policy**, `ssm:GetParameter` and `ssm:PutParameter` on
  `/<NamePrefix>/tailscale-state` (the node state, the only parameter the role can write),
  `ssm:GetParameter` on `/<NamePrefix>/tailscale-authkey` and `/<NamePrefix>/ui-token`,
  and `ec2:GetManagedPrefixListEntries` on the S3 prefix list. `check.py` fails on any
  other action, name or wildcard, and on any other policy resource in the template.
- **Bootstrap steps.** Before the stack starts, the egress rules above (with the
  `DOCKER-USER` drop of anything forwarded in from `tailscale0`, so no tailnet device
  reaches the honeypot ports), then `/usr/local/sbin/sensor-console.sh`, which reads the
  console token into `/opt/sensor/ui-token.env` (root only, given to the `ui` service
  alone) and sets `[ui] external_host` to the tailnet name. After the stack is up,
  `/usr/local/sbin/sensor-tailscale.sh` copies `tailscale` and `tailscaled` out of the
  image copy, runs tailscaled as a hardened unit (`deploy/aws/host/tailscaled.service`) in
  kernel (TUN) mode with `--netfilter-mode=off`, joins with no SSH, routes, DNS or exit
  node, checks that the node got exactly the expected name, and runs `tailscale serve
  --https=443 http://127.0.0.1:8480`. A failure in the console or node step is one
  `FAILED` line in `/var/log/sensor-bootstrap.log`; the sensor starts anyway. Both scripts
  can be run again by hand: they rewrite what they wrote before, and the node script
  replaces the binaries and restarts tailscaled, so it also upgrades a running node.

The node state (machine and node keys, the serve config) lives in the
`/<NamePrefix>/tailscale-state` SecureString, through tailscaled's own AWS store
(`--state=arn:...`), not on the instance. So a rebuilt host comes back as the same node,
with the same name and address, without a join key or a person. The join key is only a
fallback for when that parameter holds no logged-in node.

`UiTailnetSignIn=true` also serves `/go` on the tailnet name: a page that signs the visitor
in with the console token, so nobody has to handle the token. Then the tailnet's access
rules are the only gate in front of the console (and, with `UiActions=true`, in front of
approving blocks). Leave it off unless those rules name only the people who should sign in.

### One-time setup

In the tailnet's admin console, by a person:

- [ ] MagicDNS and HTTPS certificates are on (`tailscale serve` needs both).
- [ ] A tag for the sensor, for example `tag:sensor`, owned by the admins.
- [ ] Access rules: the operators' devices may reach `tag:sensor` on tcp 443 only;
      `tag:sensor` may reach nothing. No SSH rule for the tag.
- [ ] A pre-approved, tagged (`tag:sensor`), single-use, non-ephemeral auth key with a short
      expiry. A key without a tag joins the host as the person who made it, with that
      person's access to the whole tailnet; see
      [Joining the sensor to the VPN](../../docs/operations.md#joining-the-sensor-to-the-vpn).
- [ ] A console token: 24 to 128 characters of `A-Z a-z 0-9 _ -` (for example
      `openssl rand -hex 32`), kept in your password manager.

`TailscaleHostname` with `TailnetSuffix` gets a public certificate, so the name is listed
in certificate transparency logs. Pick a neutral name that does not say what the host is.

In the sensor account, the two secrets as SecureStrings under the default `aws/ssm` key,
read into variables without echo and sent on stdin, so they are never on a command line
or in shell history:

```bash
read -rs TS_AUTHKEY; echo
read -rs UI_TOKEN; echo
printf '{"Name":"/winnie-sensor/tailscale-authkey","Type":"SecureString","Value":"%s"}' "$TS_AUTHKEY" \
  | aws ssm put-parameter --cli-input-json file:///dev/stdin $S
printf '{"Name":"/winnie-sensor/ui-token","Type":"SecureString","Value":"%s"}' "$UI_TOKEN" \
  | aws ssm put-parameter --cli-input-json file:///dev/stdin $S
unset TS_AUTHKEY UI_TOKEN
```

(`winnie-sensor` is the default `NamePrefix`.) Do not create `/winnie-sensor/tailscale-state`:
tailscaled writes it on first start. The host has no route to Docker Hub, so copy the
official image into the stack's repository, as for Compose:

```bash
docker pull --platform linux/amd64 tailscale/tailscale:v<version>
docker tag tailscale/tailscale:v<version> "$R:tailscale-v<version>"
docker push "$R:tailscale-v<version>"
```

The bootstrap expects static `tailscale` and `tailscaled` binaries at `/usr/local/bin` in
the image, as in the official one. The `--state=arn:` store must be compiled in; it is in
the official linux/amd64 builds this was tried with.

### Turning it on

A reviewed change set as in step 5, adding `TailscaleEnabled=true
TailscaleImageTag=tailscale-v<version> TailscaleHostname=<neutral name>
TailnetSuffix=<tailnet>.ts.net` (and `UiTailnetSignIn=true` or `UiActions=true` if wanted).
Expect `Add` of `InstanceEgressTailscale`, `Ec2Endpoint` and `InstanceTailscaleParameters`, `Modify` of
`LaunchTemplate`, and the instance and its address association replaced. Anything under
an inbound rule, the other endpoints, the bucket or the repository means something is wrong.
The image must be one built from this commit or later (see
[Template and image](#facts-learned-from-deploying-it)).
The `TailnetConsoleUrl` output is the address to open.

Then check, on the host (`sudo -i`):

- [ ] `grep -E 'FAILED|tailscale: ' /var/log/sensor-bootstrap.log` shows a state line and no
      `FAILED`. On the first start the state is `NeedsLogin` and the join key is used.
- [ ] `tailscale status` lists the node under its name, tagged, with no user. Confirm the
      tag in the admin console too.
- [ ] `tailscale serve status` shows the tailnet name proxying to `http://127.0.0.1:8480`,
      tailnet only (no Funnel), and `/go` only with `UiTailnetSignIn=true`.
- [ ] `tailscale debug prefs | grep -E '"(RunSSH|RouteAll|CorpDNS|AdvertiseRoutes|ExitNodeID|NetfilterMode)"'`
      shows `false`, `false`, `false`, `null`, `""` and `0`.
- [ ] `iptables -S DOCKER-USER` includes `-i tailscale0 -j DROP`, and `iptables -S | grep -c ts-`
      is 0 (tailscaled added no chains of its own).
- [ ] `iptables -S OUTPUT` starts with the `--uid-owner 10001 -j SENSOR-UID` jump and the
      `--uid-owner 10001 -j REJECT` right after it; `iptables -S SENSOR-UID` lists the S3
      CIDRs from `cat /var/lib/sensor-egress/s3-cidrs`; `ip6tables -S OUTPUT` rejects uid
      10001; `systemctl list-timers sensor-egress.timer` shows the next refresh.
- [ ] The exporter cannot reach the internet or the tailnet; each must be refused at once:

      cd /opt/sensor
      docker compose exec -T exporter python -c "import socket; socket.create_connection(('192.0.2.1', 443), timeout=5)"
      docker compose exec -T exporter python -c "import socket; socket.create_connection(('<an operator device 100.x>', 443), timeout=5)"

- [ ] The export still works: within about five minutes of a connection to a honeypot
      port, a new object is listed under `events/` (as in the containment checklist), and
      `docker compose logs exporter` shows no connection errors.
- [ ] `systemctl cat tailscaled | grep -- --state=arn:`, and `ls /var/lib/tailscale` has no
      `tailscaled.state`.
- [ ] `grep -c tskey /var/log/sensor-bootstrap.log` is 0 and `/run/ts-key` does not exist.
- [ ] From a device the access rules let in, the `TailnetConsoleUrl` with `?token=<token>`
      signs in (or `/go`), and the response carries `Strict-Transport-Security`.
- [ ] From outside the tailnet, `nc -vz -w 5 <PublicIp> 443` and `8480` time out, and the
      containment checklist above still passes.

After the first join, the auth key is not needed. Delete the parameter, then revoke the
key in the admin console:

```bash
aws ssm delete-parameter --name /winnie-sensor/tailscale-authkey $S
```

A key left in Parameter Store stays readable by the instance role (and so by anything that
takes over the exporter) for as long as it is valid. Put a new single-use key there only
when a rebuild needs one (see below), and delete it again after the join.

### What a rebuild does

Every change that replaces the instance (any user data or AMI change) builds a new host.
With the state in Parameter Store:

- The new tailscaled reads the state and the node logs in as before: same name, same
  tailnet address, same tag, no join key. Only if that fails (the state is gone, or the
  node was removed from the tailnet) is the join key read; if there is none, the log says
  `tailscale: not logged in and no join key; running without the tailnet` and the console
  is reachable through SSM only. Put a new tagged key in `/<NamePrefix>/tailscale-authkey`
  and run `/usr/local/sbin/sensor-tailscale.sh` on the host.
- If the state was lost while the old device is still in the tailnet, a join key registers
  the node as `<name>-1`, whose certificate the console would refuse. The node step checks
  the name and logs `tailscale: joined as <name>-1..., not <name> (remove the old device)`
  followed by `tailscale: FAILED`. Remove both devices in the admin console, put a new key
  in the parameter and run `/usr/local/sbin/sensor-tailscale.sh` again.
- The old and new hosts should not run the node at the same time: both would hold the same
  keys and write the same parameter. CloudFormation starts the new instance before it
  terminates the old one, so just before executing the change set, stop the node on the
  old host (`systemctl stop tailscaled`). The tailnet console is then down until the new
  host has joined; SSM port forwarding still works.
- **Certificates are requested again.** The certificate lives on the instance's disk, not
  in the state, so each rebuild asks Let's Encrypt for a new one for the same name. Let's
  Encrypt issues at most five certificates for the same name in a week. A sixth rebuild
  within seven days leaves the console without a certificate until the week has passed;
  SSM port forwarding still works. Batch changes, or use a new `TailscaleHostname` if you
  must rebuild more often.
- Every state change is a new parameter version and a CloudTrail `PutParameter` event from
  the instance role. Parameter Store keeps 100 versions; do not label any of them.

The state parameter is a credential: whoever can read it can run a copy of the node on the
tailnet. The instance role can read every parameter anyway (`AmazonSSMManagedInstanceCore`
grants `ssm:GetParameter` on `*`), so keep the sensor in its own account, as this example
assumes, and limit who else there can decrypt parameters.

### Rollback of the tailnet option

- **Cut it off now, no rebuild:** remove the device in the tailnet admin console, or on the
  host `tailscale down && systemctl disable --now tailscaled`. The sensor and the loopback
  console keep running.
- **Sign-in page only:** on the host, `tailscale serve --https=443 --set-path /go off` and
  `rm /var/lib/tailscale/go.html`; then redeploy with `UiTailnetSignIn=false`.
- **Remove it:** a change set with `TailscaleEnabled=false` (and `UiTailnetSignIn=false`).
  Expect `Remove` of the egress rule, the `ec2` endpoint and the role policy, and the
  instance replaced (the new host has none of the `uid 10001` rules). Then
  remove the device from the tailnet and delete the three parameters
  (`aws ssm delete-parameters --names /winnie-sensor/tailscale-state /winnie-sensor/tailscale-authkey /winnie-sensor/ui-token $S`):
  a stale copy of a node's keys should not stay around.

### What has and has not been run

The design (node state in Parameter Store, the egress rule, the role policy, the firewall
rule, `--netfilter-mode=off`, `tailscale serve`, `/go`, console actions) has run on a real
AWS account in a private deployment built from a fork of this template: a rebuilt
instance came back as the same node without a join key, the console answered over the
tailnet and from `/go` before and after a reboot, tailscaled added no firewall chains, and
443 and 8480 stayed closed from the internet. These are not yet run as written here:

- this template's own version of the steps (the combined console step, `[ui] actions` set
  in `config.ini` rather than a command line, the read-write `blocklist` mount, the
  parameter names derived from `NamePrefix`, the name check, files copied out of the image);
- the exporter's host rules and everything they rely on: the `ec2` endpoint and the
  prefix-list ARN form `arn:aws:ec2:<region>:aws:prefix-list/<id>` that the IAM statement
  and the endpoint policy name (if AWS evaluates another form, the lookup is refused and
  the export waits, it does not open), the exporter's DNS going to `127.0.0.53` or the VPC
  resolver, and the export still reaching S3 through the gateway endpoint under the rules.
  `tests/test_deploy_aws.py` runs `sensor-egress.sh` against a fake `iptables`, which
  proves the order and the fail-closed paths of the script, not the kernel's behaviour;
- a first join with the state in Parameter Store from the start: that deployment moved
  an existing node's state into the parameter. tailscaled's AWS store writes `{}` when
  the parameter does not exist and then starts logged out (read in its source, not
  observed), and the join key does the rest;
- a replacement without stopping the old node first (two hosts with the same keys for a
  few minutes);
- a partition other than `aws`.

## Tracked blocklist export (optional)

`TrackedExport=true` sets `[respond] track_before_enforce = true` in both config files:
approving `export_blocklist` then only puts the address on the tracked list, and a second,
separate decision enforces it (see `[respond]` in `SSH/config.ini.TEMPLATE`). The agents
write the list as `tracked.json` next to the blocklist file, and the exporter puts it,
whole and only when it changed, to `<EventsPrefix>/<TrackedKey>` (default
`events/tracked/tracked.json`). `[connector.tracked_export]` is on in `config-ship.ini`
only; `config.ini` keeps it off for the same reason as the event export. It is off by
default.

`TrackedKey` is relative to `EventsPrefix` and its pattern refuses a leading `/`, `..`, empty
parts and anything but lower case letters, digits, `.`, `_` and `-`, so the object always
lands under the events prefix. It must start with a letter, so it never lands among the
events themselves, which are written under `<EventsPrefix>/YYYY/MM/DD/`. That is why no IAM, endpoint or bucket policy changes: the
instance role, the S3 gateway endpoint policy and the bucket policy already allow
`s3:PutObject` on `<EventsPrefix>/*` and nothing else. The object also falls under the
bucket's `expire-events` lifecycle rule; it is sent again whenever the list changes and at
least once a day, so it does not expire while the sensor runs (as long as `ExpirationDays`
is more than one). Older versions are kept for `ExpirationDays`.

Anything that reads the events prefix (for example a SIEM ingesting `events/`) should skip
`events/tracked/`: that object is one JSON document, not JSON lines.

**The `blocklist` volume.** The blocklist directory (`approved.txt` and `tracked.json`) is
its own named volume, mounted read-write by the agents at `/agents/reports/blocklist`
(inside `agentdata`), read-only by the console at the same path, and read-only by the
exporter at `/blocklist`. So the exporter, the one container holding the instance role,
reads only the directory it has to send, and none of the agents' approvals, state or
reports. It does see `approved.txt` there, which it never sends. `check.py` fails if the
exporter mounts anything else of the agents' data or if any service but the agents can
write the volume.

On an upgrade the new, empty `blocklist` volume hides the old blocklist file under
`/agents/reports/blocklist`; the next agents run (at most an hour) writes it again from
the stored list, along with `tracked.json` when `TrackedExport=true`.

**Sightings are not fetched here.** `[connector.sightings]` with `kind = s3` needs
`s3:GetObject`, which this deployment's write-only bucket design refuses on purpose. Leave
it off on AWS, or feed `sightings.json` another way.

Not proven without a real deploy:

- Mounting `blocklist` inside an existing `agentdata` volume. Docker has to create the
  mount point `/agents/reports/blocklist` inside `agentdata`; the agents' read-write mount
  does that, and the console (read-only) starts after the agents for that reason. A
  fresh `agentdata` gets the directory from the image.
- Ownership of a fresh `blocklist` volume. The image creates `/agents/reports/blocklist` and
  `/blocklist` owned by uid 10001, so a fresh volume should inherit that owner from
  whichever container mounts it first; check with `docker compose exec agents ls -ld
  /agents/reports/blocklist` and `docker compose exec exporter ls -l /blocklist` after the
  first approval.
- The PutObject itself: from the bucket account, `aws s3api head-object --bucket
  example-winnie-events --key events/tracked/tracked.json $B` should succeed after the
  first approval with `TrackedExport=true`.

## Stop and rollback

- **Fast stop:** redeploy with `InboundEnabled=false`. Every inbound rule is removed; the
  host keeps running and shipping. Without waiting for a change set: `aws ec2
  stop-instances --instance-ids <InstanceId> $S` (`start-instances` resumes; the systemd
  units start the stack again).
- **Host off, network kept:** redeploy with `HostEnabled=false`.
- **Tailnet only:** see [Rollback](#rollback-of-the-tailnet-option) under Console over a
  tailnet.
- **Remove the sensor:** `aws cloudformation delete-stack --stack-name winnie-sensor $S`.
  The ECR repository is retained on purpose; delete it by hand when done. The bucket stack
  is not touched, and the bucket itself is retained even if its stack is deleted.

## Limits

- One host in one Availability Zone of one region. Replacing the instance starts the event
  log, the export cursor and the per-source state from zero; events already exported are
  kept in the bucket.
- The events bucket must be in the sensor's region.
- No TLS anywhere on the sensor: the HTTP and S3 traps speak plain HTTP, so publishing
  them on 443 is pointless.
- No model calls: adding a model provider means an egress path (for Bedrock, a
  `bedrock-runtime` interface endpoint and an `InvokeModel` grant) and a review of what
  the front-ends may then reach.
