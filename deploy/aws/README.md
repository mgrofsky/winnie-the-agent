# AWS deployment example

Two CloudFormation templates that run one Winnie the Agent sensor on one EC2 host, with its
events shipped one way to a bucket in another account. Use them as a starting point; read
them before deploying, and run the checks below after every change.

| File | Deploy in | Creates |
|---|---|---|
| `models.yaml` | the sensor account, after `sensor.yaml` (optional) | the `bedrock-runtime` and `sts` endpoints and a model role per caller, for [Models on Bedrock](#models-on-bedrock-optional) |
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

No model by default: the host has no route to a model API, so `[listeners] llm = false`,
the SSH persona gives canned replies and triage is deterministic. [Models on
Bedrock](#models-on-bedrock-optional) adds a private path to Amazon Bedrock for the persona,
the analyst or both, in a second stack (`models.yaml`).

### Cost

Roughly 70 to 90 USD a month in a typical region on demand, most of it the six interface
endpoints (seven, about 7 USD more, with `TailscaleEnabled=true`; two more with
[Models on Bedrock](#models-on-bedrock-optional), plus the model's token prices). A `t3.small`, its volume and the Elastic IP add up to roughly 20 USD; S3, logs,
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
  optional step on (about 15,000 bytes today).
- **Template and image.** The bootstrap copies `deploy/aws/render_config.py` (which writes
  `config.ini` and `config-ship.ini`) and, with `TailscaleEnabled` or a model id set, the
  files under `deploy/aws/host/` out of the image it runs, instead of carrying them in the user data.
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
uvx cfn-lint deploy/aws/sensor.yaml deploy/aws/events-bucket.yaml deploy/aws/models.yaml   # optional
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
- **The rules at every boot, before any container.** iptables rules do not survive a
  reboot, and Docker restarts the containers itself, before anything ordered after
  `docker.service` runs. So `sensor-egress-boot.service` runs before `docker.service`, and
  Docker requires it (`RequiredBy=docker.service`). It runs `sensor-egress.sh deny` first:
  the two `REJECT`s for uid 10001, which need no settings. If even that fails, Docker does
  not start, and the sensor is down until it is fixed. Then it rebuilds the full rules from
  the saved list. If that step fails (a bad settings file, say), Docker still starts, but
  the exporter has no egress at all until `sensor-firewall.sh` or the timer rebuilds them.
  Holding all of Docker back for that case would stop the honeypot without making the
  exporter any safer. On the first boot the bootstrap applies the rules itself before the
  stack starts; the only containers before that are `docker run --network none` copies.
  Do not `systemctl stop` or `restart` this unit: Docker requires it, so stopping it stops
  Docker. Rerun `/usr/local/sbin/sensor-egress.sh` instead.
- **Docker restarts and flushes.** `systemctl restart docker`, or a Docker package upgrade
  that restarts the daemon, leaves the rules alone: they are in the filter table's
  `OUTPUT` chain and in `SENSOR-UID`, which Docker does not manage. A manual `iptables -F`
  removes them (and Docker's own rules, and `DOCKER-USER`'s). The timer puts back the
  `OUTPUT` jump, the `REJECT` and `SENSOR-UID` within 15 minutes, but not `DOCKER-USER`:
  after a flush, run `/usr/local/sbin/sensor-firewall.sh` and restart Docker, or reboot.
  `ip6tables` is not touched by `iptables -F`.
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
- [ ] After a reboot, the rules were in place before the exporter started:
      `systemctl is-active sensor-egress-boot.service` is `active`,
      `systemctl show -p Requires docker.service` lists it, and the unit finished before the
      exporter's container started (compare
      `systemctl show -p ExecMainExitTimestamp sensor-egress-boot.service` with
      `docker inspect -f '{{.State.StartedAt}}' "$(docker compose ps -q exporter)"`, in UTC).
      Then repeat the next check.
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
443 and 8480 stayed closed from the internet.

The exporter's host rules have run there too, from the host files in this repository
copied out of an image built from it: the prefix-list lookup through the `ec2` endpoint
succeeded (the ARN form `arn:aws:ec2:<region>:aws:prefix-list/<id>` is accepted by IAM and
by the endpoint policy); as the exporter's user on the host network, connections to a
public address, out `tailscale0` and over IPv6 were refused, while the metadata service,
S3 through the gateway endpoint and an interface endpoint connected; root still reached
the internet; a bridged container reached neither the internet nor the metadata service.
After a reboot `sensor-egress-boot.service` had finished before Docker started and before
the exporter's container did, the same probes gave the same answers, and
`systemctl restart docker` left the rules unchanged. `tests/test_deploy_aws.py` also runs
`sensor-egress.sh` against a fake `iptables` for the order and the fail-closed paths.

These are not yet run as written here:

- this template's own version of the steps (the combined console step, `[ui] actions` set
  in `config.ini` rather than a command line, the read-write `blocklist` mount, the
  parameter names derived from `NamePrefix`, the name check, files copied out of the image);
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

## Models on Bedrock (optional)

Off by default. With it off the sensor has no model: the SSH persona gives canned replies
and triage is deterministic. With it on, the SSH persona, the analyst or both call a model
on Amazon Bedrock in the sensor's own account and region, through a private endpoint,
with nothing else opened.

Two parts, both needed:

- **`models.yaml`**, a second stack in the sensor account and region. It adds two
  interface endpoints in the sensor's network, `bedrock-runtime` and `sts`, behind the
  existing endpoint security group (which already admits tcp 443 from the instance only,
  so no rule is added), and one role per caller: `<NamePrefix>-model-persona` (if
  `PersonaModelId` is set) may call `bedrock:InvokeModel` on the persona's model only, and
  `<NamePrefix>-model-analyst` (if `AnalystModelId` is set) on the analyst's model only,
  each only through that `bedrock-runtime` endpoint (`aws:SourceVpce`), for at most an
  hour per session. The instance role gets one permission, `sts:AssumeRole` on those
  roles, and nothing on Bedrock itself. It is a separate stack because `sensor.yaml`'s deploy copy must stay under
  CloudFormation's 51,200-byte inline template limit and these resources do not fit there.
- **`PersonaModelId` and `AnalystModelId`** on the sensor stack, the same values as in
  `models.yaml`. Either may be empty; empty means that part stays without a model. With
  both empty (the default) `sensor.yaml` adds nothing and its user data is the same as
  without the option. `sensor.yaml` itself never gains a resource for this.

A model id is either an inference profile id, a geographic prefix (`us.`, `us-gov.`,
`eu.`, `apac.`, `jp.`, `au.` or `global.`) and then the model id
(`us.anthropic.claude-haiku-5-5`, `eu.anthropic.claude-sonnet-5-5`), or a plain model id
(`<provider>.<model>[:<version>]`). Many current models, every current Anthropic model
among them, can only be called on demand through an inference profile: a plain
`anthropic.claude-haiku-5-5` is refused by Bedrock even though the templates accept it.
Use the profile id for your geography unless the model's page in the Bedrock console says
it is offered on demand in the sensor's region. Both templates refuse anything else:
wildcards, ARNs, slashes, spaces, other prefixes, and a dot inside the model's name (the
grant derives the profile's model from the parts of the id).

### Which API calls, and the grant

Both clients use the Converse API without streaming: the persona through
`langchain_aws` `ChatBedrockConverse` (`ainvoke`, never `astream`), the analyst through
boto3 `converse`. IAM authorises Converse as `bedrock:InvokeModel`; there is no
`bedrock:Converse` action. `bedrock:InvokeModelWithResponseStream` (what ConverseStream
needs) is not granted, so a client that started streaming would be refused, not widened.
`ChatBedrockConverse` (langchain-aws 1.4) also builds a `bedrock` control-plane client but
calls it only for application inference profile ARNs, which the id pattern does not
allow.

The endpoint policy grants both callers' models; each caller's role grants its own model
only, so the persona's credentials cannot invoke the analyst's model and the reverse
(`check.py` evaluates both roles with different models for the two callers):

| Model id | Resources granted `bedrock:InvokeModel` |
|---|---|
| `us.anthropic.claude-haiku-5-5` (any of the prefixes) | `arn:aws:bedrock:<region>:<account>:inference-profile/us.anthropic.claude-haiku-5-5` and `arn:aws:bedrock:*::foundation-model/anthropic.claude-haiku-5-5` |
| `<provider>.<model>` (plain) | `arn:aws:bedrock:<region>::foundation-model/<provider>.<model>` |

An inference profile sends each call to a region of its own choosing, and Bedrock checks
the grant on the foundation model in that region too. Which regions a profile uses
differs by model and changes over time, so the foundation-model ARN has `*` for the
region (which also matches the empty region of a `global.` profile's model) and keeps
the model exact. To narrow it, look the profile up (`aws bedrock get-inference-profile
--inference-profile-identifier <id>`) and edit the region in `models.yaml` by hand.

**Accounts with a region-restricting policy** (an SCP or permission boundary that denies
on `aws:RequestedRegion`): a geographic profile (`us.`, `eu.`, `apac.` and so on) needs
every region it routes to allowed, and a `global.` profile can route to any commercial
region. If those regions are denied, calls
through the profile fail even though this grant allows them; allow the profile's regions
for `bedrock:InvokeModel` on the model roles, or use a plain model id in the sensor's
region where the model is offered on demand there. Seen on a real account with a `us.`
profile: calls served in another region were denied by a region-restricting SCP until it
excepted the profile (a condition on `bedrock:InferenceProfileArn` keeps the exception to
that profile), and succeeded after. An organization policy that denies Bedrock outright
needs the two model roles excepted in the same way.

**Model access.** The account must have access to each model enabled in the Bedrock
console (Model access) in the sensor's region, and for a profile, in the regions it
routes to. Without it calls fail with `AccessDeniedException` and the persona falls back
to canned replies.

Models sold through AWS Marketplace (Anthropic's among them) are subscribed on the first
call in an account, and that call must come from a principal allowed
`aws-marketplace:Subscribe` and `aws-marketplace:ViewSubscriptions`. The model roles are
not, on purpose. Make the first call for each model from an administrator before
deploying, or the roles' calls work for a few minutes and then fail with an
`AccessDeniedException` that names those two actions. After the subscribing call, wait
ten minutes or so without retrying; repeated calls while it settles kept failing in the
run described below.

### Which containers make the calls, and what they gain

The persona runs in the `ssh` container and the analyst in the `agents` container. Both
are bridged (front-end network 172.30.0.0/24 and agents network 172.30.1.0/24), run as uid
10001 with every capability dropped, and today can open no connection (`DOCKER-USER`
drops everything but replies) and cannot reach the metadata service (dropped, and the
IMDS hop limit of 1 stops a bridged container's answer anyway). The option keeps all of
that and adds, for exactly the containers whose model id is set:

| Container | Before | After (only if its model id is set) |
|---|---|---|
| `ssh` (persona; faces attackers) | no outbound connection, no metadata service, no AWS credentials | tcp 443 to one address, the `bedrock-runtime` endpoint's, from its fixed address 172.30.0.10; read-only credentials of `<NamePrefix>-model-persona` (the persona's model only) |
| `agents` (analyst) | same as `ssh` | the same from 172.30.1.10, with `<NamePrefix>-model-analyst` (the analyst's model only) |
| `listeners`, `ui` | no outbound connection, no metadata service, no AWS credentials | unchanged |
| `exporter` (host network, instance role) | the instance role | can also assume the two model roles |
| host (root) | the instance role | assumes each configured caller's role every 15 minutes through the `sts` endpoint |

How it is wired (`deploy/aws/host/sensor-model.sh`, run by the bootstrap's model step and
then by `sensor-model.timer` and at every boot):

- **Network.** One `DOCKER-USER` accept per caller: `-s 172.30.0.10 -d <endpoint address>
  -p tcp --dport 443 -j ACCEPT` (and the same from 172.30.1.10). The endpoint's address is
  looked up on the host and must be inside the VPC; the containers get the endpoint's name
  pinned in `/etc/hosts` (`extra_hosts`), so they need no DNS. Each caller is given its
  fixed address by a compose overlay (`docker-compose.model.yml`), added to
  `COMPOSE_FILE` after the console step's files. Every run looks the address up again.
  When it has changed, the accept to the new address goes in, every caller accept to any
  other address is removed (an old address may since belong to something else in the
  VPC), and then the overlay is rewritten with the new pin, checked by `docker compose
  config`, and only the running callers are recreated (`docker compose up -d --no-deps
  ssh` or `agents`). If the new overlay is refused, the containers keep the old pin, which
  no rule lets them reach any more, so their calls fail until the next run succeeds.
- **Credentials.** For each configured caller the host assumes that caller's role with
  the instance role (one-hour sessions) and writes the credentials to its own directory,
  `/run/sensor-model/persona` or `/run/sensor-model/analyst` (tmpfs, directory uid 10001
  mode 0500, files mode 0400, under a root-only `/run/sensor-model`). `ssh` mounts only
  the persona's directory and `agents` only the analyst's, read-only, at `/model`. boto3
  reads them through `credential_process = cat /model/creds.json`
  (`AWS_CONFIG_FILE=/model/config`) and reads them again before they expire. The bootstrap
  enables and starts `sensor-model.timer` (cloud-init runs after `timers.target`, so a
  timer only enabled would wait for the next boot); it renews them every 15 minutes, so
  the file always has at least 45 minutes left once the timer runs. Runs take a lock, so
  the timer's first run waits for set-up to finish. `AWS_EC2_METADATA_DISABLED=true` stops boto3 trying
  the metadata service. The instance role's credentials never reach a container.
- **Config.** `render_config.py models` sets `[llm] llm_provider = AWS`, `model_name`,
  `aws_region` and `aws_credentials_profile = default` (persona) and `[agents] provider =
  bedrock`, `model`, `aws_region` (analyst) in `config.ini`, only after the overlay has
  passed `docker compose config`. `[listeners] llm` stays `false`.

**Why this is acceptable for the attacker-facing `ssh` container.** The persona sends
attacker input to the model as text and never runs it; reaching the container's own
code is what an attacker would need. If they did, they would gain: one address on tcp
443 that answers only Bedrock runtime calls; credentials that allow only
`bedrock:InvokeModel` on the persona's model (not the analyst's, which needs the other
role and the other directory) and only through this VPC's endpoint, so copied out of the
host they are refused everywhere; at most an hour of validity. They could spend tokens
of the persona's model outside the persona's budget, up to the account's Bedrock quotas
for that model, and nothing else: no other model, no other AWS action, no other address,
no metadata service, no instance role. Watch the model's spend (a budget alarm on
Bedrock) as the backstop. If both callers use the same model id, the persona's role can
of course call that model too; give the analyst a different model if you want its quota
kept apart.

**The design not taken.** The obvious alternative is to let the callers use the instance
role: raise the IMDS hop limit to 2 and allow their addresses to reach 169.254.169.254,
plus `bedrock:InvokeModel` on the instance role. It needs no `sts` endpoint and no second
role, but the attacker-facing container would then hold the instance role's credentials,
which carry `AmazonSSMManagedInstanceCore` (including reading any SecureString parameter
in the account, such as the tailnet join key and console token), ECR pulls, the log group
and the events bucket, and are usable from anywhere. The model roles keep all of that out
of reach for one more interface endpoint.

### Budgets (on in both cases)

The limits in `config.ini` stay on and apply to Bedrock as to any provider; with the
template defaults:

- **Persona** (`[budget]`): 400,000 tokens per session, 1,000,000 per source per UTC day,
  3,000,000 per UTC day for the whole sensor, 200 commands per session, 20 sessions at
  once (3 per source). Tokens are input plus output, from Bedrock's usage figures. A
  source in `deep` mode gets twice the per-session and per-source limits; the daily total
  does not change. A day at the cap is therefore 3,000,000 tokens for the persona; once
  it is reached every session gets the canned reply until the next UTC day.
- **Analyst** (`[agents]`): at most 20 calls per run and 500 per UTC day, each answer at
  most 2,048 output tokens, so a day at the cap is at most about 1,000,000 output tokens.
  Each call's input is a session or campaign summary that triage clips (commands,
  indicators and the narrative are cut to fixed lengths); there is no token cap on it, so
  measure it in the first days.

The counters persist on the host, so a restart does not reset the day.

### The `sts` endpoint and other STS calls on the host

The `sts` endpoint's private DNS name applies to the whole VPC, so every regional STS call
from the sensor's network goes through it, not only the model step's. Its policy allows
assuming the two model roles and `sts:GetCallerIdentity` (which needs no permission and
only names the caller), and nothing else. So `aws sts get-caller-identity` in a session on
the host works as before, but any other STS call from the host, such as an operator's
`aws sts assume-role` into another role, is refused with `AccessDenied` while
`models.yaml` is deployed. Make such calls from another machine; the global endpoint
(`sts.amazonaws.com`) is no way round it, since the host has no route out.

### Cost

Two more interface endpoints, each priced as one interface endpoint (about 7 USD a month
in a typical region), plus the model's own token prices on Bedrock. Nothing else.

### Turning it on

Enable model access first (see above). Then, with the sensor stack's outputs:

```bash
aws cloudformation describe-stacks --stack-name winnie-sensor $S --query "Stacks[0].Outputs"
aws cloudformation deploy --stack-name winnie-models \
  --template-file deploy/aws/models.yaml --capabilities CAPABILITY_NAMED_IAM $S \
  --parameter-overrides NamePrefix=winnie-sensor VpcId=<VpcId> SubnetId=<SubnetId> \
    EndpointSecurityGroupId=<EndpointSecurityGroupId> \
    PersonaModelId=us.anthropic.claude-haiku-5-5 AnalystModelId= \
  --no-execute-changeset
```

Expect `Add` changes for `BedrockEndpoint`, `StsEndpoint`, `InstanceAssumeModelRole` and
one role per model id set: `PersonaRole`, `AnalystRole` or both. Then a reviewed change set as in step 5 with the same
`PersonaModelId` and `AnalystModelId` (the image must be built from this commit or later).
Expect `Modify` of `LaunchTemplate` and the instance and its address association
replaced, nothing else. Models stack first: the bootstrap waits up to two and a half
minutes for the endpoint's private name and otherwise starts without a model.

Then check, on the host (`sudo -i`, `cd /opt/sensor`):

- [ ] `grep model /var/log/sensor-bootstrap.log` shows no `FAILED`;
      `systemctl list-timers sensor-model.timer` shows it scheduled and already run once
      (without waiting for a reboot).
- [ ] `ls -l /run/sensor-model/*/` shows `creds.json` and `config` at `-r--------`, uid
      10001, in a directory per configured caller only; `docker inspect` of `ssh` shows
      only `/run/sensor-model/persona` mounted, and of `agents` only
      `/run/sensor-model/analyst`.
- [ ] `aws sts get-caller-identity` on the host names the instance role; `aws sts
      assume-role` into any other role is refused.
- [ ] `iptables -S DOCKER-USER` shows one `-s 172.30.0.10/32 -d <address>/32 -p tcp -m tcp
      --dport 443 -j ACCEPT` per configured caller, above the drops, and nothing else new.
- [ ] The callers reach nothing else: `docker compose exec -T ssh python -c "import socket;
      socket.create_connection(('192.0.2.1', 443), timeout=5)"` times out, as does the
      same to the `sts` endpoint's address; from `listeners`, a connection to the
      `bedrock-runtime` endpoint's address times out too.
- [ ] An SSH session to the sensor gets model replies, and the host log group shows no
      `Model error` events. With the analyst on, the next `run-all` reports `llm_used`.
- [ ] From outside the sensor's VPC, credentials copied from
      `/run/sensor-model/persona/creds.json` are refused for `bedrock-runtime converse`
      (the `aws:SourceVpce` condition). With both models on and different, the persona's
      credentials are refused for the analyst's model on the host as well. Delete the
      copy afterwards.

### Rollback

A change set on the sensor stack with both model ids empty (instance replaced, back to no
model), then delete the `winnie-models` stack. Deleting the models stack alone leaves the
sensor configured for a model it can no longer reach: every call fails and falls back to
canned replies, and the timer logs a failure every 15 minutes.

### What has and has not been run

The option has been run once on a real AWS account: one sensor in `us-east-1`, a `us.`
inference profile for each caller (a different Anthropic model each), and the console over
a tailnet. Seen there:

- the endpoint policy and each role's grant against real calls through a `us.` profile,
  including calls the profile served in another region (`aws:SourceVpce` held on those);
- each container calling its own model and refused the other's;
- the `ssh` container reaching the Bedrock endpoint and nothing else (the internet, the
  metadata service, the `sts` endpoint and S3 all refused);
- Compose merging the overlay's networks and fixed addresses;
- the private DNS name of the `sts` endpoint answering the host's `aws sts assume-role`;
- the timer's first run during set-up, and the same order, rules and model access after a
  reboot;
- an SSH session answered by the model for commands the built-in shell does not know.

What is checked offline on every change: `check.py` evaluates the endpoint policy and each
caller's role for sample ids (every geographic prefix among them) and refuses any
widening, including a role that covers the other caller's model (the mutation tests in
`tests/test_deploy_aws.py` cover each rule); the user data with both ids empty is byte for
byte what it was before the option for every console and tailnet switch combination; and
`sensor-model.sh` runs in the tests against fake `aws`, `getent`, `iptables` and `docker`.

Still unproven:

- that CloudFormation leaves `LaunchTemplate` and the instance alone on a stack updated
  to this template with both ids empty (the user data is the same, but the template text
  of the launch template is not; check the change set);
- a plain model id and a `global.` profile;
- the credentials renewing in a running container across the hour (boto3's refresh of
  `credential_process` credentials);
- the endpoint's address changing under a running sensor: the accepts move and the pin is
  rewritten in the tests, but `docker compose up -d --no-deps` recreating only the callers
  on a real host has not been seen.

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
- Models only on Amazon Bedrock in the sensor's own account and region, and only through
  `models.yaml` (see [Models on Bedrock](#models-on-bedrock-optional)); no other model
  provider has an egress path. `[listeners] llm` stays off.
- No address locations (`[geoip]`, see the operations guide, "Where addresses are"). The
  database files would have to reach the host, and the instance has no read path for that
  by design (its role writes events and nothing else); this stack does not add one.
